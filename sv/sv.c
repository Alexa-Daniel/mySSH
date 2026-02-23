#include <errno.h>
#include <netinet/in.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "cJSON.h"

#define PORT 6097

extern int errno;
bool zombie=0, child=0;
SSL *global_ssl=NULL;

void wait_for_child(int s)
{
  while(waitpid(-1, NULL, WNOHANG)>0);
  zombie=1;
}

void sha256_hash(char* string, char output[])
{
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashLg=0;

  EVP_MD_CTX *context=EVP_MD_CTX_create();

  if(context != NULL)
  {
      if(EVP_DigestInit_ex(context, EVP_sha256(), NULL))
      {
          if(EVP_DigestUpdate(context, string, strlen(string)))
          {
              if(EVP_DigestFinal_ex(context, hash, &hashLg)) {}
          }
      }
      EVP_MD_CTX_destroy(context);
  }

  for(int i=0; i<hashLg; i++)
  {
      sprintf(output+(i*2), "%02x", hash[i]);
  }
  output[64]=0;
}

void openssl_init()
{
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

void openssl_cleanup()
{
  EVP_cleanup();
}

SSL_CTX* create_ctx()
{
  const SSL_METHOD *method;
  SSL_CTX* ctx;

  method=SSLv23_server_method();
  ctx=SSL_CTX_new(method);
  if(!ctx)
  {
    perror("[server]Eroare la crearea contextului.\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  return ctx;
}

void configure_ctx(SSL_CTX* ctx)
{
  if(SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM)<=0)
  {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  if(SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM)<=0)
  {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}

void make_shell(char user[], char ip[])
{
  char aux[256];
  sprintf(aux, "PS1=\\[\e[1;31m\\]%s@%s\\[\e[0m\\]:\\[\e[1;34m\\]\\w\\[\e[0m\\]$ ", user, ip);
  char* env[]={"TERM=xterm-256color", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", aux, NULL};
  execle("/bin/bash", "bash", "--norc", "-i", NULL, env);
  exit(1);
}

void add_to_log(char *msg)
{
  FILE *fp=fopen("server.log", "a");
  if(fp==NULL)
  {
    return;
  }

  time_t curr_time;
  time(&curr_time);
  char *date=ctime(&curr_time);

  date[strlen(date) - 1]='\0';

  fprintf(fp, "[%s] %s\n", date, msg);
  fclose(fp);
}

bool is_shell_active(int master_fd)
{
  int pid;

  if(ioctl(master_fd, TIOCGPGRP, &pid) == -1)
  {
      return 1;
  }

  char path[64], name[64];
  sprintf(path, "/proc/%d/comm", pid);

  FILE *fd=fopen(path, "r");
  if(!fd)
  {
    return 1;
  }

  if(fgets(name, sizeof(name), fd))
  {
    name[strcspn(name, "\r\n")]=0;
  }
  fclose(fd);

  if(strcmp(name, "bash")==0)
  {
    return 1;
  }

  return 0;
}

void handle_sigint(int sig)
{
  if(child)
  {
    if(global_ssl)
    {
      char *msg="\r\nConnection interrupted due to server shutdown.\r\n";
      SSL_write(global_ssl, msg, strlen(msg));
      SSL_shutdown(global_ssl);
      SSL_free(global_ssl);
    }

    exit(0);
  }
  else
  {
    add_to_log("All users disconnected. Connection interrupted due to server shutdown.\n");
    printf("\n");
    exit(0);
  }
}

void run_proxy(SSL *ssl, int master_fd, char *user, int bash_pid)
{
  char rec[4096], log[2048];
  fd_set fds;
  int sock_fd=SSL_get_fd(ssl);
  struct timeval tv;
  bool shell, app=0;
  int cmd_pos=0;
  char cmd[256];

  int receiving_file=0;
  FILE *recv_fp=NULL;
  long total_bytes=0;

  fcntl(sock_fd, F_SETFL, O_NONBLOCK);
  fcntl(master_fd, F_SETFL, O_NONBLOCK);

  zombie=0;

  while(!zombie)
  {
    FD_ZERO(&fds);
    FD_SET(sock_fd, &fds);
    FD_SET(master_fd, &fds);

    int max = (sock_fd > master_fd) ? sock_fd : master_fd;

    tv.tv_sec=1;
    tv.tv_usec=0;

    int pending=SSL_pending(ssl);
    int active=0;
    if(pending == 0)
    {
      active=select(max+1, &fds, NULL, NULL, &tv);
    }

    if(pending>0 || (active>0 && FD_ISSET(sock_fd, &fds)))
    {
      int n=SSL_read(ssl, rec, sizeof(rec));
      if(n>0)
      {
        bool for_bash=1;
        if(receiving_file)
        {
          fwrite(rec, 1, n, recv_fp);
          total_bytes -= n;

          if(total_bytes <= 0)
          {
            fclose(recv_fp);
            receiving_file=0;
            recv_fp=NULL;

            write(master_fd, "\n", 1);
          }
          for_bash=0;
        }
        else
        {
          rec[n]='\0';
          if(strncmp(rec, ":file_start:", 12) == 0)
          {
            char path[256];
            long filesize;

            if(sscanf(rec, ":file_start:%255[^:]:%ld", path, &filesize)==2)
            {
              char *filename=strrchr(path, '/');
              if(filename)
              {
                filename++;
              }
              else
              {
                filename=path;
              }

              char cwd[512];
              char link[64];

              sprintf(link, "/proc/%d/cwd", bash_pid);
              int len=readlink(link, cwd, sizeof(cwd)-1);
              if(len!=-1)
              {
                  cwd[len]='\0';
              }
              else
              {
                  strcpy(cwd, ".");
              }

              char full_path[1024];
              sprintf(full_path, "%s/%s", cwd, filename);
              recv_fp=fopen(full_path, "wb");
              if(recv_fp)
              {
                receiving_file=1;
                total_bytes=filesize;
                bzero(log, sizeof(log));
                sprintf(log, "User: %s uploaded file: %s", user, full_path);
                add_to_log(log);
              }
              else
              {
                char *err="\r\n[server] Eroare: Nu se poate crea fisierul pe server.\r\n";
                SSL_write(ssl, err, strlen(err));

                write(master_fd, "\n", 1);
              }
            }
            for_bash=0;
          }

          if(strncmp(rec, ":win_res:", 9) == 0)
          {
            int rows, cols;
            if(sscanf(rec, ":win_res:%d:%d", &rows, &cols) == 2)
            {
              struct winsize ws;
              ws.ws_row=rows;
              ws.ws_col=cols;
              ioctl(master_fd, TIOCSWINSZ, &ws);
            }
            for_bash=0;
          }
        }

        if(for_bash)
        {
          write(master_fd, rec, n);

          shell=is_shell_active(master_fd);

          if(!shell && !app)
          {
            bzero(log, sizeof(log));
            sprintf(log, "User: %s entered the app", user);
            add_to_log(log);
            app=1;
            bzero(cmd, sizeof(cmd));
            cmd_pos=0;
          }

          if(shell && app)
          {
            bzero(log, sizeof(log));
            sprintf(log, "User: %s exited the app.", user);
            add_to_log(log);
            app=0;
          }

          if(!shell)
          {
            continue;
          }

          for(int i=0; i<n; i++)
          {
            if(rec[i] == 27)
            {
              if(i+2<n && rec[i+1] == '[')
              {
                i += 2;
              }
              continue;
            }
            if(rec[i] == '\r' || rec[i] == '\n')
            {
              if(cmd_pos)
              {
                cmd[cmd_pos]='\0';
                bzero(log, sizeof(log));
                sprintf(log, "User: %s ran command: %s", user, cmd);
                add_to_log(log);

                cmd_pos=0;
                bzero(cmd, sizeof(cmd));
              }
            }
            else if(rec[i] == '\t')
            {
                if(cmd_pos < sizeof(cmd) - 6)
                {
                    strcat(cmd, "[TAB]");
                    cmd_pos += 5;
                }
            }
            else if(rec[i] == 127)
            {
              if(cmd_pos)
              {
                cmd_pos--;
              }
            }
            else if(rec[i] == 3)
            {
              bzero(log, sizeof(log));
              sprintf(log, "User: %s pressed CTRL+C", user);
              add_to_log(log);
            }
            else if(rec[i] >= 32 && rec[i] <= 126)
            {
              if(cmd_pos < sizeof(cmd) - 1)
              {
                cmd[cmd_pos++]=rec[i];
              }
            }
          }
        }
      }

      else
      {
        int err=SSL_get_error(ssl, n);
        if(err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
        {
          break;
        }
      }
    }
    if(active>0 && FD_ISSET(master_fd, &fds))
    {
      int n=read(master_fd, rec, sizeof(rec));
      if(n>0)
      {
        SSL_write(ssl, rec, n);
      }
      else if(n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
      {
        break;
      }
    }
  }
  if(receiving_file && recv_fp)
  {
    fclose(recv_fp);
  }
}

bool get_pass(char *input_user, char *pass_buffer)
{
    FILE *fp=fopen("config.json", "r");
    if(!fp)
    {
        perror("[server] Nu pot deschide config.json");
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    long length=ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char data[8192];
    bzero(data, sizeof(data));

    if(length>=sizeof(data))
    {
      printf("[server]Eroare: Fisierul config.json e prea mare pentru buffer!\n");
      fclose(fp);
      return 0;
    }

    fread(data, 1, length, fp);
    data[length]='\0';
    fclose(fp);

    cJSON *json=cJSON_Parse(data);
    bool found=0;

    if(json)
    {
        cJSON *users_array=cJSON_GetObjectItemCaseSensitive(json, "users");
        cJSON *user;

        cJSON_ArrayForEach(user, users_array)
        {
            cJSON *name=cJSON_GetObjectItemCaseSensitive(user, "username");
            cJSON *pass=cJSON_GetObjectItemCaseSensitive(user, "password");

            if(cJSON_IsString(name) && name->valuestring!=NULL && cJSON_IsString(pass) && pass->valuestring!=NULL)
            {
                if(strcmp(input_user, name->valuestring)==0)
                {
                    strcpy(pass_buffer, pass->valuestring);
                    found=1;
                    break;
                }
            }
        }
        cJSON_Delete(json);
    }

    return found;
}

int main()
{
  struct sockaddr_in server;
  struct sockaddr_in from;
  char msg[8192];
  char msgrasp[8192]=" ";
  int sd;

  signal(SIGINT, handle_sigint);

  openssl_init();
  SSL_CTX* ctx=create_ctx();
  configure_ctx(ctx);

  if((sd=socket(AF_INET, SOCK_STREAM, 0)) == -1)
  {
    perror("[server]Eroare la socket().\n");
    return errno;
  }

  int on=1;
  setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

  bzero(&server, sizeof(server));
  bzero(&from, sizeof(from));

  server.sin_family=AF_INET;
  server.sin_addr.s_addr=htonl(INADDR_ANY);
  server.sin_port=htons(PORT);

  if(bind(sd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
  {
    perror("[server]Eroare la bind().\n");
    return errno;
  }

  if(listen(sd, 10) == -1)
  {
    perror("[server]Eroare la listen().\n");
    return errno;
  }

  struct sigaction sa;
  sa.sa_handler=wait_for_child;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags=SA_RESTART;

  if(sigaction(SIGCHLD, &sa, NULL) == -1)
  {
      perror("[server]: Eroare la sigaction");
  }

  while(1)
  {
    int client, bytes;
    int length=sizeof(from);

    printf("[server] Asteptam la portul %d...\n", PORT);
    fflush(stdout);

    client=accept(sd, (struct sockaddr *)&from, &length);

    if(client < 0)
    {
      perror("[server]Eroare la accept().\n");
      continue;
    }

      int pid;
      if((pid=fork()) == -1)
      {
        perror("[server]: Eroare la fork()\n");
      }

      if(!pid)
      {
        child=1;
        SSL *ssl=SSL_new(ctx);
        SSL_set_fd(ssl, client);
        if(SSL_accept(ssl)<=0)
        {
          ERR_print_errors_fp(stderr);
          close(client);
          exit(0);
        }
        global_ssl=ssl;

        char user[512], ip[16];
        bzero(&bytes, 4);
        if(SSL_read(ssl, &bytes, 4)<0)
        {
          perror("[server]Eroare la citirea nr de bytes\n");
          return errno;
        }
        bzero(user, sizeof(user));
        if(SSL_read(ssl, user, bytes)<0)
        {
          perror("[server]Eroare la read-ul user-ului\n");
          return errno;
        }
        user[strcspn(user, "\r\n")]=0;
        bzero(&bytes, 4);
        if(SSL_read(ssl, &bytes, 4)<0)
        {
          perror("[server]Eroare la citirea nr de bytes\n");
          return errno;
        }
        bzero(ip, sizeof(ip));
        if(SSL_read(ssl, ip, bytes)<0)
        {
          perror("[server]Eroare la read-ul IP-ului\n");
          return errno;
        }

        char log[1024];
        bzero(log, sizeof(log));
        printf("[server] User: %s is trying to log in\n", user);
        sprintf(log, "User: %s is logging in", user);
        add_to_log(log);

        char line[1024], pass[65], pass_cli[256], pass_cli_hash[65];
        bzero(pass_cli_hash, sizeof(pass_cli_hash));
        bzero(pass_cli, sizeof(pass_cli));
        bzero(pass, sizeof(pass));
        bzero(line, sizeof(line));

        bool found=0;
        if(get_pass(user, pass))
        {
            found=1;

            bzero(&bytes, 4);
            bytes=1;
            if(SSL_write(ssl, &bytes, 4) < 0)
            {
                perror("[server]Eroare la scrierea nr de bytes\n");
                return errno;
            }
            SSL_write(ssl, "1", bytes);
        }

        if(!found)
        {
          bzero(&bytes, 4);
          bytes=1;
          if(SSL_write(ssl, &bytes, 4)<0)
          {
            perror("[server]Eroare la scrierea nr de bytes\n");
            return errno;
          }

          bzero(log, sizeof(log));
          sprintf(log, "User: %s doesn't have an account", user);
          add_to_log(log);
          SSL_write(ssl, "0", bytes);
        }
        else
        {
          while(strcmp(pass, pass_cli)!=0)
          {
            int bytes_read;
            bzero(&bytes, 4);
            if(SSL_read(ssl, &bytes, 4)<0)
            {
              perror("[server]Eroare la citirea nr de bytes\n");
              return errno;
            }
            bzero(pass_cli_hash, sizeof(pass_cli_hash));
            if((bytes_read=SSL_read(ssl, pass_cli_hash, bytes))<=0)
            {
              perror("[server]Eroare la read-ul pass-ului\n");
              return errno;
            }
            pass_cli_hash[bytes_read]=0;
            pass_cli_hash[strcspn(pass_cli_hash, "\r\n")]=0;
            //printf("Received pass: %s\n", user);

            bzero(pass_cli, sizeof(pass_cli));
            sha256_hash(pass_cli_hash, pass_cli);

            //printf("Pass's hash: %s, size: %ld\n", pass, sizeof(pass));
            //printf("Pass_cli's hash: %s, size: %ld\n\n", pass_cli, sizeof(pass_cli));
            if(strcmp(pass, pass_cli)==0)
            {
              bzero(&bytes, 4);
              bytes=1;
              if(SSL_write(ssl, &bytes, 4)<0)
              {
                perror("[server]Eroare la scrierea nr de bytes\n");
                return errno;
              }
              SSL_write(ssl, "1", bytes);
              printf("[server] User: %s successfully logged in.\n", user);
              bzero(log, sizeof(log));
              sprintf(log, "User: %s entered the correct password", user);
              add_to_log(log);
            }
            else
            {
              bzero(&bytes, 4);
              bytes=1;
              if(SSL_write(ssl, &bytes, 4)<0)
              {
                perror("[server]Eroare la scrierea nr de bytes\n");
                return errno;
              }
              SSL_write(ssl, "0", bytes);
              printf("[server] User: %s entered the wrong password.\n", user);
              bzero(log, sizeof(log));
              sprintf(log, "User: %s entered the wrong password", user);
              add_to_log(log);
            }
          }

          int manager, pidty;
          if((pidty=forkpty(&manager, NULL, NULL, NULL))<0)
          {
            perror("[server]Eroare la forkpty\n");
            return errno;
          }
          if(!pidty)
          {
            make_shell(user, ip);
          }
          run_proxy(ssl, manager, user, pidty);
        }

        bzero(log, sizeof(log));
        sprintf(log, "User: %s logged out", user);
        add_to_log(log);

        printf("[server] %s's session ended.\n", user);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
        exit(0);
      }
      else
      {
        close(client);
      }
  }
  SSL_CTX_free(ctx);
  openssl_cleanup();
}
