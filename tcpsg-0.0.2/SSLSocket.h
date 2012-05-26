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

typedef struct
{
    SSL* ssl;
    SSL_CTX* ctx;
} SSLSocket;

SSLSocket* SSLOpen(int baseSocket, char* keyFile, char* password, char* caFile);

inline int SSLAccept(SSLSocket* secureSocket);

inline int SSLConnect(SSLSocket* secureSocket);

inline int SSLRead(SSLSocket* secureSocket, void* buffer, int bufferSize);

inline int SSLGetError(SSLSocket* secureSocket, int err);

inline int SSLWrite(SSLSocket* secureSocket, void* buffer, int bufferSize);

int checkCertificate(SSLSocket* secureSocket, char* hostname);

void SSLClose(SSLSocket* secureSocket);

#endif
