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


void checkCertificate(SSL* ssl)
  {
    X509 *peer;
    char peer_CN[256];
    
    if(SSL_get_verify_result(ssl)!=X509_V_OK){
         printf("Certificate doesn't verify"); //TODO
        exit(1);
    }

    peer=SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
    if(strcasecmp(peer_CN,SERVER_ADDR)){
        printf("Common name doesn't match host name"); //TODO
        exit(1);
    }
  }


int main(int argc, char *argv[]) {

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

   /* Open 3 sockets and send same message each time. */

   for (i = 0; i < 3; ++i)
   {
      
      if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0){
         printf("Opening stream socket"); //TODO
         return -1;
     }
      
      bzero((char *) &server, sizeof(server));
      server.sin_family = AF_INET;
      if ((hp = gethostbyname(SERVER_ADDR)) == NULL) {
         printf("Unknown host"); //TODO
         return -1;
      }
      bcopy(hp->h_addr, &server.sin_addr, hp->h_length);
      server.sin_port = htons((u_short) SERVER_PORT);

      if (connect(clientSocket, (struct sockaddr *) &server, sizeof(server)) < 0)
      {
         printf("Connect failed"); //TODO
         return -1;
      }

      SSL_socket(clientSocket, KEYFILE, PASSWORD);//TODO errori??
       
      if(SSL_connect(clientSocket->ssl)<=0)
      {
            printf("SSL connect error");//TODO
            return -1;
      }

      checkCertificate(clientSocket->ssl); //TODO controllo errori
      
      if (getsockname(sock, (struct sockaddr *) &client, &clientLen))
      {
            printf("Getting socket name");//TODO
            return -1;
      }
      printf("Client socket has port %hu\n", ntohs(client.sin_port));

      r = SSL_write(secureSocket->ssl, DATA, sizeof(DATA));
      switch(SSL_get_error(secureSocket->ssl,r)){      
      case SSL_ERROR_NONE:
        if(sizeof(DATA)!=r)
          printf("Incomplete write!");
        return -1; //TODO + farlo anche nel tcpsg??
        default:
          printf("SSL write problem");
          return -1; //TODO
      }
      
	  printf("C: Ho scritto al TCPSG %s\n", DATA);
      bzero(buf, sizeof(buf));
      printf("C: Aspetto di leggere dal TCPSG\n"); 
      r = SSL_read(secureSocket->ssl, buf, BUFFER_SIZE);
      if(SSL_get_error(secureSocket->ssl,r) != SSL_ERROR_NONE){
          printf("SSL write problem");
          return -1; //TODO
      }
      printf("C: Ho letto dal TCPSG %s\n", buf);
      SSL_close(secureSocket);

      close(sock);
      printf("C: Per me il socket e' chiuso\n");
   }

   return 0;

}
