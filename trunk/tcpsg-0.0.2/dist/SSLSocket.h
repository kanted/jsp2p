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

struct SSLSocket;

struct SSLSocket* SSLOpen(int baseSocket, char* keyFile, char* password, char* caFile);

int SSLAccept(struct SSLSocket* secureSocket);

int SSLConnect(struct SSLSocket* secureSocket);

int SSLRead(struct SSLSocket* secureSocket, void* buffer, int bufferSize);

int SSLGetError(struct SSLSocket* secureSocket, int err);

int SSLWrite(struct SSLSocket* secureSocket, void* buffer, int bufferSize);

int checkCertificate(struct SSLSocket* secureSocket, char* hostname);

void SSLClose(struct SSLSocket* secureSocket);

#endif
