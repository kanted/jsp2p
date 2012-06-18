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

struct _SSLSocket;
typedef _SSLSocket SSLSocket;

SSLSocket* SSLOpen(int baseSocket, char* keyFile, char* password, char* caFile);

int SSLAccept(SSLSocket* secureSocket);

int SSLConnect(SSLSocket* secureSocket);

int SSLRead(SSLSocket* secureSocket, void* buffer, int bufferSize);

int SSLGetError(SSLSocket* secureSocket, int err);

int SSLWrite(SSLSocket* secureSocket, void* buffer, int bufferSize);

int checkCertificate(SSLSocket* secureSocket, char* hostname);

void SSLClose(SSLSocket* secureSocket);

#endif
