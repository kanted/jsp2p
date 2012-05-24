/**********************************************************************
 * client.c --- Demonstrate a simple client.
 * Tom Kelliher
 *
 * This program will connect to a simple iterative server and exchange
 * messages.  The single command line argument is the server's hostname.
 * The server is expected to be accepting connection requests from
 * SERVER_PORT.
 *
 * The same message is sent three times over separate connections, 
 * demonstrating that different ephemeral ports are used for each
 * connection.
 **********************************************************************/


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "common.h"


#define DATA "Nel mezzo del cammin di nostra vita . . ."
#define SERVER_PORT 2300
#define BUFFER_SIZE 1024


/* prototypes */
void die(const char *);
void pdie(const char *);


/* Check that the common name matches the
   host name*/
void check_cert(ssl,host)
  SSL *ssl;
  char *host;
  {
    X509 *peer;
    char peer_CN[256];
    
    if(SSL_get_verify_result(ssl)!=X509_V_OK)
      berr_exit("Certificate doesn't verify");

    /*Check the cert chain. The chain length
      is automatically checked by OpenSSL when
      we set the verify depth in the ctx */

    /*Check the common name*/
    peer=SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID
      (X509_get_subject_name(peer),
      NID_commonName, peer_CN, 256);
    if(strcasecmp(peer_CN,host))
    err_exit
      ("Common name doesn't match host name");
  }



/**********************************************************************
 * main
 **********************************************************************/

int main(int argc, char *argv[]) {

   int sock;   /* fd for socket connection */
   struct sockaddr_in server;   /* Socket info. for server */
   struct sockaddr_in client;   /* Socket info. about us */
   int clientLen;   /* Length of client socket struct. */
   struct hostent *hp;   /* Return value from gethostbyname() */
   char buf[BUFFER_SIZE];   /* Received data buffer */
   int i;   /* loop counter */
   char *request=0;
   int r;
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio;
   int require_server_auth=0;


   /* Open 3 sockets and send same message each time. */

   //for (i = 0; i < 3; ++i)
   //{
      /* Open a socket --- not bound yet. */
      /* Internet TCP type. */
      if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
         pdie("Opening stream socket");
      
      /* Prepare to connect to server. */
      bzero((char *) &server, sizeof(server));
      server.sin_family = AF_INET;
      if ((hp = gethostbyname("localhost")) == NULL) {
         sprintf(buf, "%s: unknown host\n", argv[1]);
         die(buf);
      }
      bcopy(hp->h_addr, &server.sin_addr, hp->h_length);
      server.sin_port = htons((u_short) SERVER_PORT);
      
      /* Try to connect */
      if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0)
         pdie("Connecting stream socket");

         /* Build our SSL context*/
    ctx=initialize_ctx("client.pem","password");

     /* Connect the SSL socket */
    ssl=SSL_new(ctx);
    sbio=BIO_new_socket(sock,BIO_NOCLOSE);
    SSL_set_bio(ssl,sbio,sbio);
    if(SSL_connect(ssl)<=0)
      berr_exit("SSL connect error");
    if(require_server_auth)
      check_cert(ssl,"127.0.0.1");
 
    /* Determine what port client's using. */
      clientLen = sizeof(client);
      if (getsockname(sock, (struct sockaddr *) &client, &clientLen))
         pdie("Getting socket name");
      
      if (clientLen != sizeof(client))
         die("getsockname() overwrote name structure");
      
      printf("Client socket has port %hu\n", ntohs(client.sin_port));

      /* Write out message. */
      r = SSL_write(ssl, DATA, sizeof(DATA));
      switch(SSL_get_error(ssl,r)){      
      case SSL_ERROR_NONE:
        if(sizeof(DATA)!=r)
          err_exit("Incomplete write!");
        break;
        default:
          berr_exit("SSL write problem");
      }
    

	  printf("C: Ho scritto al TCPSG %s\n", DATA);
      /* Prepare our buffer for a read and then read. */
      bzero(buf, sizeof(buf));
      printf("C: Aspetto di leggere dal TCPSG\n"); 
      r = SSL_read(ssl, buf, BUFFER_SIZE);
      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          break;
        default:
          berr_exit("SSL read problem");
      }
      
      printf("C: Ho letto dal TCPSG %s\n", buf);
      SSL_shutdown(ssl);
      SSL_free(ssl);

      /* Shutdown the socket */
      destroy_ctx(ctx);
      
       
      /* Close this connection. */
      close(sock);
      printf("C: Per me il socket e' chiuso\n");
   //}

   exit(0);

}


/**********************************************************************
 * pdie --- Call perror() to figure out what's going on and die.
 **********************************************************************/

void pdie(const char *mesg) {

   perror(mesg);
   exit(1);
}


/**********************************************************************
 * die --- Print a message and die.
 **********************************************************************/

void die(const char *mesg) {

   fputs(mesg, stderr);
   fputc('\n', stderr);
   exit(1);
}


