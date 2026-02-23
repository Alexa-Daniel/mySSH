#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>

extern int errno;

int port=6097;

struct termios default_term;

SSL *ssl_sv=NULL;

void handle_resize(int sig)
{
    struct winsize ws;
    if(ioctl(1, TIOCGWINSZ, &ws) != -1 && ssl_sv != NULL)
    {
        char cmd[64];
        sprintf(cmd, ":win_res:%d:%d", ws.ws_row, ws.ws_col);
        SSL_write(ssl_sv, cmd, strlen(cmd));
    }
}

void reset()
{
  tcsetattr(0, TCSAFLUSH, &default_term);
}

void make_raw()
{
  struct termios raw;
  if(!isatty(0))
  {
    return;
  }
  tcgetattr(0, &default_term);
  atexit(reset);

  raw=default_term;
  raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
  raw.c_oflag &= ~(OPOST);
  raw.c_cflag |= (CS8);
  raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);

  tcsetattr(0, TCSANOW, &raw);
}

void send_file_to_server(SSL *ssl, char *cmd)
{
    char filename[256];

    cmd[strcspn(cmd, "\r\n")]=0;

    if(strlen(cmd)<=7)
    {
        printf("\n[client] Eroare: Lipseste numele fisierului. Sintaxa: upload <fisier>\n");

        SSL_write(ssl, "\n", 1);
        return;
    }
    strcpy(filename, cmd+7);

    FILE *fp=fopen(filename, "rb");
    if(!fp)
    {
        printf("\n[client] Eroare: Nu se poate deschide fisierul '%s'\n", filename);

        SSL_write(ssl, "\n", 1);
        return;
    }

    fseek(fp, 0, SEEK_END);
    long filesize=ftell(fp);
    fseek(fp, 0, SEEK_SET);

    printf("\nStarting upload: %s (%ld bytes)...\n", filename, filesize);

    char header[512];
    sprintf(header, ":file_start:%s:%ld", filename, filesize);
    if(SSL_write(ssl, header, strlen(header)) <= 0)
    {
        perror("[client] Eroare la trimitere header");
        fclose(fp);
        return;
    }

    char file_buf[4096];
    long sent=0;
    while(sent < filesize)
    {
        int bytes_read=fread(file_buf, 1, sizeof(file_buf), fp);
        if(bytes_read > 0)
        {
            int bytes_written=SSL_write(ssl, file_buf, bytes_read);
            if(bytes_written <= 0)
            {
                perror("[client] Eroare la trimitere date");
                break;
            }
            sent += bytes_written;
            printf("\r[client] Sent: %ld / %ld bytes", sent, filesize);
        }
        else
        {
            break;
        }
    }

    fclose(fp);
    printf("\n[client] Upload successful.\n");
}

int main(int argc, char *argv[])
{
  int sd, bytes;
  struct sockaddr_in server;
  char msg[8192];

  if(argc != 2)
  {
      printf ("Syntax: %s <user>@<server_address>\n", argv[0]);
      return -1;
  }

  if((sd=socket (AF_INET, SOCK_STREAM, 0)) == -1)
  {
      perror ("[client] Eroare la socket().\n");
      return errno;
  }

  server.sin_family=AF_INET;
  char* idx=strchr(argv[1], '@');

  if(idx != NULL)
  {
    server.sin_addr.s_addr=inet_addr(idx+1);
  }
  else
  {
    printf("Invalid format. Use syntax: user@ip\n");
    return -1;
  }

  server.sin_port=htons (port);


  if(connect (sd, (struct sockaddr *) &server,sizeof (struct sockaddr)) == -1)
  {
    perror ("[client]Eroare la connect().\n");
    return errno;
  }

  SSL_library_init();
  SSL_CTX *ctx=SSL_CTX_new(SSLv23_client_method());
  SSL *ssl=SSL_new(ctx);
  SSL_set_fd(ssl, sd);

  if(SSL_connect(ssl)==-1)
  {
    ERR_print_errors_fp(stderr);
    return 1;
  }

  bzero(&bytes, 4);
  bytes=idx-argv[1];
  if(SSL_write(ssl, &bytes, 4)<0)
  {
    perror("[client]Eroare la scrierea nr de bytes\n");
    return errno;
  }
  if(SSL_write(ssl, argv[1], bytes)<=0)
  {
    perror("[client]Eroare la write-ul pt user\n");
    return errno;
  }
  bzero(&bytes, 4);
  bytes=strlen(argv[1])-(idx+1-argv[1]);
  if(SSL_write(ssl, &bytes, 4)<0)
  {
    perror("[client]Eroare la scrierea nr de bytes\n");
    return errno;
  }
  if(SSL_write(ssl, argv[1]+(idx+1-argv[1]), bytes)<=0)
  {
    perror("[client]Eroare la write-ul pt IP\n");
    return errno;
  }

  bzero(&bytes, 4);
  if(SSL_read(ssl, &bytes, 4)<0)
  {
    perror("[client]Eroare la citirea nr de bytes\n");
    return errno;
  }
  if(SSL_read(ssl, msg, bytes)<0)
  {
    perror("[client]Eroare la read-ul cu mesajul de confirmare\n");
    return errno;
  }

  //printf("msg: %s", msg);
  if(strcmp(msg, "0")==0)
  {
    printf("User: %.*s doesn't exist.\n", (int)(idx-argv[1]), argv[1]);
    return errno;
  }

  bzero(msg, sizeof(msg));
  char check='a';
  while(check != '1')
  {
    printf("%.*s's password: ", (int)(idx-argv[1]), argv[1]);
    fflush(stdout);

    bzero(msg, sizeof(msg));
    struct termios old, new;
    tcgetattr(0, &old);
    new=old;
    new.c_lflag &= ~ECHO;
    tcsetattr(0, TCSANOW, &new);

    if(read(0, msg, sizeof(msg))<0)
    {
      perror("[client]Eroare la read parola\n");
      return errno;
    }
    //printf("Received pass from input: %s\n", msg);
    msg[strcspn(msg, "\r\n")]=0;
    tcsetattr(0, TCSANOW, &old);
    printf("\n");
    bzero(&bytes, 4);
    bytes=strlen(msg);
    if(SSL_write(ssl, &bytes, 4)<0)
    {
      perror("[client]Eroare la citirea nr de bytes\n");
      return errno;
    }
    if(SSL_write(ssl, msg, bytes)<=0)
    {
      perror("[client]Eroare la write-ul pt pass\n");
      return errno;
    }

    bzero(&bytes, 4);
    if(SSL_read(ssl, &bytes, 4)<0)
    {
      perror("[client]Eroare la citirea nr de bytes\n");
      return errno;
    }
    if(SSL_read(ssl, &check, bytes)<0)
    {
      perror("[client]Eroare la read-ul cu mesajul de confirmare pt pass\n");
      return errno;
    }
    if(check != '1')
    {
      printf("Authentification failed! Try again.\n\n");
    }
  }
  printf("Authentification successful!\n\nTo upload a file to the server press CTRL+B\n");

  ssl_sv=ssl;
  signal(SIGWINCH, handle_resize);
  handle_resize(0);

  make_raw();

  fd_set fds;
  char buf[4096];
  int sock_fd=SSL_get_fd(ssl);

  fcntl(sock_fd, F_SETFL, O_NONBLOCK);
  fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);

  while(1)
  {
    if(SSL_pending(ssl)>0)
    {
      int n=SSL_read(ssl, buf, sizeof(buf));
      if(n>0)
      {
        write(STDOUT_FILENO, buf, n);
        continue;
      }
    }

    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    FD_SET(sock_fd, &fds);

    int max_fd=(STDIN_FILENO>sock_fd) ? STDIN_FILENO : sock_fd;
    struct timeval tv;
    tv.tv_sec=1;
    tv.tv_usec=0;

    int active=select(max_fd+1, &fds, NULL, NULL, &tv);

    if(active>0 && FD_ISSET(STDIN_FILENO, &fds))
    {
      int n=read(STDIN_FILENO, buf, sizeof(buf));
      if(n>0)
      {
        if(buf[0] == 2)
        {
            reset();

            int flags=fcntl(STDIN_FILENO, F_GETFL, 0);
            fcntl(STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK);

            printf("\n-----UPLOAD MODE------\n");
            printf("Syntax: upload <file_name>\n");
            printf("Input: ");
            fflush(stdout);

            char line[256];
            if(fgets(line, sizeof(line), stdin))
            {
                line[strcspn(line, "\r\n")]=0;

                if(strncmp(line, "upload ", 7) == 0)
                {
                    send_file_to_server(ssl, line);
                }
                else
                {
                  if(strlen(line) > 0)
                  {
                    printf("[client] Unknown command: %s\n", line);
                  }
                  SSL_write(ssl, "\n", 1);
                }
            }

            printf("-----EXITED UPLOAD MODE-----\n");

            make_raw();

            handle_resize(0);
            continue;
        }
        SSL_write(ssl, buf, n);
      }
      else if(n==0)
      {
        break;
      }
    }

    if(active>0 && FD_ISSET(sock_fd, &fds))
    {
      int n=SSL_read(ssl, buf, sizeof(buf));
      if(n>0)
      {
        write(STDOUT_FILENO, buf, n);
      }
      else
      {
        int err=SSL_get_error(ssl, n);
        if(err==SSL_ERROR_ZERO_RETURN)
        {
          break;
        }
        if(err!=SSL_ERROR_WANT_READ && err!=SSL_ERROR_WANT_WRITE)
        {
          break;
        }
      }
    }
  }

  reset();
  printf("\r\nSession ended.\n");
  SSL_free(ssl);
  SSL_CTX_free(ctx);

  close (sd);
}
