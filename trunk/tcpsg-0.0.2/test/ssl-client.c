#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "../SSLSocket.h"


#define DATA "Nel mezzo del cammin di nostra vita . . ."
#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 2300
#define BUFFER_SIZE 1024
#define KEYFILE "client.pem"
#define PASSWORD "abcd"

//TODO MAKEFILE
//TODO COMMENTI
//TODO RELAZIONE
//TODO COMMENTI PRIMO PROGETTO
//TODO MAKEFILE PRIMO PROGETTO
//TODO VALGRIND

int checkCertificate(SSL* ssl)
  {
    X509 *peer;
    char peer_CN[256];    
    if(SSL_get_verify_result(ssl)!=X509_V_OK){
         printf("CLIENT: Certificate doesn't verify\n");
         return -1;
    }
    peer=SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
    if(strcasecmp(peer_CN,SERVER_ADDR)){
        printf("CLIENT: Common name doesn't match host name\n");
        return -1;
    }
    return 0;
  }


int main(int argc, char *argv[])
  {
    int clientSocket;
    struct sockaddr_in server;
    struct sockaddr_in client;
    int clientLen;
    struct hostent *hp;
    char buf[BUFFER_SIZE]; 
    int i;
    char *request=0;
    int r;
    SSLSocket* secureSocket;

    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0){
     printf("CLIENT: Failed opening socket\n");
     return -1;
    }
    bzero((char *) &server, sizeof(server));
    server.sin_family = AF_INET;
    if ((hp = gethostbyname(SERVER_ADDR)) == NULL) {
     printf("CLIENT: Unknown host\n");
     return -1;
    }
    bcopy(hp->h_addr, &server.sin_addr, hp->h_length);
    server.sin_port = htons((u_short) SERVER_PORT); //TODO ???
    if (connect(clientSocket, (struct sockaddr *) &server, sizeof(server)) < 0)
    {
     printf("CLIENT: Connect failed\n");
     return -1;
    }    
    secureSocket = SSL_socket(clientSocket, KEYFILE, PASSWORD);
    if(secureSocket == NULL)
        return -1;
    if(SSL_connect(secureSocket->ssl)<=0)
    {
        printf("CLIENT: SSL connect error\n");
        goto exceptionHandler;
    }
    if(checkCertificate(secureSocket->ssl)<0){
        goto exceptionHandler; 
    }
    if (getsockname(clientSocket, (struct sockaddr *) &client, &clientLen))
    {
        printf("CLIENT: Getting socket name\n");
        goto exceptionHandler;
    }
    printf("CLIENT: Client socket has port %hu\n", ntohs(client.sin_port));
    r = SSL_write(secureSocket->ssl, DATA, sizeof(DATA));
    if((r = SSL_get_error(secureSocket->ssl,r)) != SSL_ERROR_NONE){      
                printf("CLIENT: SSL write problem, error: %i\n",r);
                goto exceptionHandler;
    }
    printf("CLIENT: wrote %s\n", DATA);
    bzero(buf, sizeof(buf));
    printf("CLIENT: reading\n"); 
    r = SSL_read(secureSocket->ssl, buf, BUFFER_SIZE);
    if((r = SSL_get_error(secureSocket->ssl,r)) != SSL_ERROR_NONE){
      printf("CLIENT: SSL write problem error: %i\n",r);
      goto exceptionHandler;
    }
    printf("CLIENT: read %s\n", buf);
    SSL_close(secureSocket);
    close(sock);
    printf("CLIENT: socket closed\n");
    return 0;
    
exceptionHandler:
    SSL_close(secureSocket);
    close(sock);
    return -1;    
}
