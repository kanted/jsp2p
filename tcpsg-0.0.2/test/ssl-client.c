#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "../SSLSocket.h"


#define MSG "Nel mezzo del cammin di nostra vita . . ."
#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 2300
#define BUFFER_SIZE 1024
#define KEYFILE "client.pem"
#define PASSWORD "abcd"
#define CAFILE "root.pem"


int main(int argc, char *argv[])
{
    int clientSocket;
    struct sockaddr_in server;
    struct sockaddr_in client;
    struct hostent *hp;
    char buf[BUFFER_SIZE]; 
    int r;
    SSLSocket* secureSocket;

    if((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
     printf("CLIENT: Failed opening socket\n");
     return -1;
    }
    bzero((char *) &server, sizeof(server));
    server.sin_family = AF_INET;
    if((hp = gethostbyname(SERVER_ADDR)) == NULL)
    {
     printf("CLIENT: Unknown host\n");
     return -1;
    }
    bcopy(hp->h_addr, &server.sin_addr, hp->h_length);
    server.sin_port = htons((unsigned short) SERVER_PORT);
    if (connect(clientSocket, (struct sockaddr *) &server, sizeof(server)) < 0)
    {
     printf("CLIENT: Connect failed\n");
     return -1;
    }    
    secureSocket = SSLOpen(clientSocket, KEYFILE, PASSWORD, CAFILE);
    if(secureSocket == NULL)
        return -1;
    if(SSLConnect(secureSocket)<=0)
    {
        printf("CLIENT: SSL connect error\n");
        goto exceptionHandler;
    }
    if(checkCertificate(secureSocket,SERVER_ADDR)<0){
        printf("CLIENT: Check Certificate error\n");
        goto exceptionHandler; 
    }
    printf("CLIENT: Client socket has port %hu\n", ntohs(client.sin_port));
    r = SSLWrite(secureSocket, MSG, sizeof(MSG));
    if((r = SSLGetError(secureSocket,r)) != SSL_ERROR_NONE){      
                printf("CLIENT: SSL write problem, error: %i\n",r);
                goto exceptionHandler;
    }
    printf("CLIENT: wrote %s\n", MSG);
    bzero(buf, sizeof(buf));
    printf("CLIENT: reading\n"); 
    r = SSLRead(secureSocket, buf, BUFFER_SIZE);
    if((r = SSLGetError(secureSocket,r)) != SSL_ERROR_NONE){
      printf("CLIENT: SSL write problem, error: %i\n",r);
      goto exceptionHandler;
    }
    printf("CLIENT: read %s\n", buf);
    SSLClose(secureSocket);
    close(clientSocket);
    printf("CLIENT: socket closed\n");
    return 0;
    
exceptionHandler:
    SSLClose(secureSocket);
    close(clientSocket);
    return -1;    
}
