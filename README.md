# mySSH
mySSH is a client-server application that emulates the functionality of the Secure Shell (SSH) network protocol, including end-to-end encryption and file-upload capabilities to the server.

# Prerequisites

To be able to run and compile the application, a Linux based operating system is needed, as well as the following packages installed:
```
sudo apt-get update
sudo apt-get install gcc make libssl-dev libutil-dev
```

# Configuration

The application uses OpenSSL to ensure the information is encrypted, which requires a private key and certificate for the TLS connection. These can be generated using the following command:
```
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt
```

The `config.JSON` file contains the users username and their passwords (stored in SHA256 hash form), and the structure looks like this:
```
{
  "users": [
    {
      "username": "example1",
      "password": "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    },
    {
      "username": "example2",
      "password": "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459234f978d7c846f4"
    },
    ...
  ]
}
```

To work properly, the folder containing your server must include the following files (the ones from the sv folder in the repository, plus the keys you just generated):
- server.key
- server.crt
- config.json
- cJSON.c
- cJSON.h
- sv.c

# Compilation

To compile run the following commands:
```
gcc sv.c cJSON.c -o server -lssl -lcrypto -lutil (in the server folder)
gcc cl.c -o client -lssl -lcrypto (in the client folder)
```

# Running the app

To run the server, use the following command: `./server`

To run the client, use the following command: `./client username@ip_address`
