#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>


#define DATA ". . . mi ritrovai per una selva oscura"
#define TRUE 1
#define SERVER_PORT 23
#define BUFFER_SIZE 1024

int main(void) {

   int sock;
   int msgsock;
   struct sockaddr_in server;
   struct sockaddr_in client;
   int rval;
   char buf[BUFFER_SIZE];

   if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
      printf("Error opening socket");
      return -1;
   }

   bzero((char *) &server, sizeof(server));
   server.sin_family = AF_INET;
   server.sin_addr.s_addr = INADDR_ANY;
   server.sin_port = htons(SERVER_PORT);
   if (bind(sock, (struct sockaddr *) &server, sizeof(server))){
      printf("Erorr binding socket");
      return -1;
   }

   printf("Socket has port %hu\n", ntohs(server.sin_port));

   listen(sock, 5);

   while (TRUE) {
      if ((msgsock = accept(sock, (struct sockaddr *) &client, &clientLen)) == -1){
         printf("Erorr in accept");
         return -1;
      }
      else {
         printf("Client IP: %s\n", inet_ntoa(client.sin_addr));
         printf("Client Port: %hu\n", ntohs(client.sin_port));

         do {   
            bzero(buf, sizeof(buf));
            printf("S: vivo in attesa di roba da leggere\n");
            if ((rval = read(msgsock, buf, BUFFER_SIZE)) < 0){
               printf("Read error\n");
               return -1;
            }
            if (rval == 0){
               printf("Ending connection\n");
               return -1;
            }
            else
               printf("S: Ho letto %s\n", buf);
            printf("S: Scrivo %s\n", DATA);
            if (write(msgsock, DATA, sizeof(DATA)) < 0){
             printf("Write error\n");
               return -1;
            }

         } while (rval != 0);
      }
      close(msgsock);
   }

   exit(0);

}

