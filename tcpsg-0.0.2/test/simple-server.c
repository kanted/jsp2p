#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#define MSG ". . . mi ritrovai per una selva oscura"
#define SERVER_PORT 23
#define BUFFER_SIZE 1024

int main (int argc, char *argv[]){

   int sock;
   int msgsock;
   struct sockaddr_in server;
   struct sockaddr_in client;
   int rval;
   char buf[BUFFER_SIZE];

   if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
      printf("SERVER: Error opening socket\n");
      return -1;
   }
   bzero((char *) &server, sizeof(server));
   server.sin_family = AF_INET;
   server.sin_addr.s_addr = INADDR_ANY;
   server.sin_port = htons(SERVER_PORT);
   if (bind(sock, (struct sockaddr *) &server, sizeof(server))){
      printf("SERVER: Erorr binding socket\n");
      return -1;
   }
   printf("SERVER: Socket has port %hu\n", ntohs(server.sin_port));
   listen(sock, 5);
   while (1) {
      if ((msgsock = accept(sock, (struct sockaddr *) &client, sizeof(client))) == -1){
         printf("SERVER: Erorr in accept\n");
         return -1;
      }
      else {
         printf("SERVER: Client IP: %s\n", inet_ntoa(client.sin_addr));
         printf("SERVER: Client Port: %hu\n", ntohs(client.sin_port));
         do {   
            bzero(buf, sizeof(buf));

            if ((rval = read(msgsock, buf, BUFFER_SIZE)) < 0){
               printf("SERVER: read error\n");
               break;
            }
            if (rval == 0){
               printf("SERVER: ending connection\n");
               break;
            }
            else
               printf("SERVER: read %s\n", buf);
            if (write(msgsock, MSG, sizeof(MSG)) < 0){
             printf("SERVER: Write error\n");
               break;
            }
            printf("SERVER: wrote %s\n", MSG);
         } while (rval != 0);
      }
      close(msgsock);
   }
   return 0;
}

