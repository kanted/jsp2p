#ifndef _common_h
#define _common_h

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

#define CA_LIST "root.pem"
#define HOST	"localhost"
#define RANDOM  "random.pem"
#define PORT	4433
#define BUFSIZZ 1024

extern BIO *bio_err;

void initialize_SSL(char* keyfile,char* password,int socket,SSL** ssl, SSL_CTX** ctx);
void destroy_SSL(SSL_CTX *ctx, SSL *ssl);

#endif


