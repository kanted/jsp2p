#ifndef SSL_SOCKET_H
#define SSL_SOCKET_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>

#define CA_CERT "root.pem"

typedef struct
{
    SSL* ssl;
    SSL_CTX* ctx;
} SSLSocket;

SSLSocket* SSL_socket(int baseSocket, char* keyFile, char* password);

void SSL_close(SSLSocket* secureSocket);

#endif
