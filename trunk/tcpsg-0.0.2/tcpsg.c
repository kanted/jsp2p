/*
 * tcpsg - TCP Simple Gateway
 * 
 * Released under GNU Public License v2.0 (see included COPYING file)
 *
 * Copyright (C) 2002  Juan Fajardo (jfajardo@unillanos.edu.co)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * *****************************************************************
 */


/* Standard headers */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>


#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sys/shm.h>
#include <sys/ipc.h>

/* Network Headers */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* Security Headers */
#include "common.h"
#include <openssl/ssl.h>

/* 
 * ****************************************************************
 * Define section
 * 
 * MAX_BACKLOG:		Maximum number of simultaneous connections.
 * BUFFER_SIZE:		Size of the forward buffer: 4096.
 * MAX_SERVERS:     Maximun number of servers to work with
 * 
 * ****************************************************************
 */


#define MAX_BACKLOG 10
#define BUFFER_SIZE 4096
#define MAX_SERVERS 10

#define TRUE 1
#define FALSE 0

#define IDLE 0
#define WORKING 1
#define DOWN 2

#define KEYFILE_LENGTH 256
#define PWD_LENGTH 128


/*
 * *****************************************************************
 * Global Variables Section
 * 
 * child_count:		    Store the number of child processes running.
 * main_opt:			Struct to store various options.
 * 
 * *****************************************************************
 */

/* Errors when getting configuration from file /etc/tcpsg.conf */

char *errors[]={"No error","Unable to open file","undefined localport",
                "undefined serverport","undefined maxclients","undefined servers"};


static int child_count;
static int *state;
struct options {
	int max_clients;
	int localport;
	int serverport;
	char serverhost[MAX_SERVERS][20];
        int num_servers;
    char keyfile[KEYFILE_LENGTH];
    int sslflag;
} main_opt;


/*
 * *****************************************************************
 * Functions Section
 * *****************************************************************
 */

/* Write messages/alerts/errors */
void writemsg(char *message){
	if (errno > 0)
		perror(message);
	else if (message)
		printf("\n%s\n", message);
}
/* Signal handling functions */
void (*Signal (int signo, void (*sig_handler)(int))) (int){
	struct sigaction sa_new, sa_old;

	sa_new.sa_handler = sig_handler;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	if (signo == SIGALRM) {
#ifdef SA_INTERRUPT
		sa_new.sa_flags |= SA_INTERRUPT;
#endif
	} else {
#ifdef SA_RESTART
		sa_new.sa_flags |= SA_RESTART;
#endif
	}
	if ( sigaction(signo, &sa_new, &sa_old) < 0 )
		return(SIG_ERR);
	return(sa_old.sa_handler);
}

/*
 * Handler for the SIG_CHLD signal
 * We use waitpid() inside a while to prevent loss of signals
 * when two or more children terminate at aproximately the same time.
 * 
 * Notice that to use waitpid() inside a loop, we need to set it non
 * blocking, with the parameter WNOHANG.
 * 
 */
static void catch_sigchld(int signo){
	pid_t pid;
	int stat;

	while ( (pid = waitpid(-1, &stat, WNOHANG)) > 0 ) {
		if (child_count > 0)
			child_count--;
		else
			writemsg("WARNING: SIGCHLD received when child_count < 1");
	}
}


/* Get configuration from file /etc/tcpsg.conf */
int read_config(char *configFileName)
{
 FILE *configFileHandle;
 char tmpString[500];
 char tmpChar;
 unsigned long configFileLength;
 int lp,sp,mc,kf,sf;
 lp=sp=mc=kf=sf=FALSE;

 main_opt.num_servers=0;
 if ((configFileHandle=fopen(configFileName,"rb"))!=NULL) 
 {
      fseek(configFileHandle,0,SEEK_END);
      configFileLength=ftell(configFileHandle);
      if (configFileLength==0) return 1;
      rewind(configFileHandle);
      while (ftell(configFileHandle)<configFileLength)
      {
         fscanf (configFileHandle,"%s",tmpString);
         if (tmpString[0]=='#') 
         {
             do {
		  fscanf(configFileHandle,"%c",&tmpChar);
	       } 
              while ((tmpChar!='\r')&&(tmpChar!='\n')&&(ftell(configFileHandle)<configFileLength));
		tmpString[0]=0;	   
         }
         if (strcasecmp(tmpString,"keyfile")==0) 
         {
           bzero(tmpString, 500);
           bzero(main_opt.keyfile, KEYFILE_LENGTH);
           fscanf(configFileHandle,"%s",tmpString);
           strncpy(main_opt.keyfile,tmpString,KEYFILE_LENGTH);
           kf=TRUE;
  	 }
        if (strcasecmp(tmpString,"sslflag")==0) 
         {
           fscanf(configFileHandle,"%s",tmpString);
	   main_opt.sslflag=atoi(tmpString);
           sf=TRUE;
  	 }
         if (strcasecmp(tmpString,"localport")==0) 
         {
           fscanf(configFileHandle,"%s",tmpString);
	   main_opt.localport=atoi(tmpString);
           lp=TRUE;
  	 }
         if (strcasecmp(tmpString,"serverport")==0) 
         {
           fscanf(configFileHandle,"%s",tmpString);
	   main_opt.serverport=atoi(tmpString);
           sp=TRUE;
  	 }
         if (strcasecmp(tmpString,"maxclients")==0) 
         {
           fscanf(configFileHandle,"%s",tmpString);
	   main_opt.max_clients=atoi(tmpString);  
           mc=TRUE;
  	 }
         if (strcasecmp(tmpString,"server")==0) 
         {
           fscanf(configFileHandle,"%s",tmpString);
	   strcpy(main_opt.serverhost[main_opt.num_servers],tmpString);     
           main_opt.num_servers++;
  	 }
       }
        if (!lp) return 2;
        if (!sp) return 3;
        if (!mc) return 4;
        if (main_opt.num_servers==0) return 5;
        if (!kf) return 6;
        if (!sf) return 7;
  }
 else
 {
   return 1;
 } 
 fclose(configFileHandle);
 return 0;
}


/* 
 * Get the configuration parameters
 * and set the main_opt struct
 *
 * Returns: 0 if success, or error number on error with the .conf file
 * 	
 */


int set_config()
{
  int i,j;
  i=read_config("/usr/local/etc/tcpsg.conf");
  if (i==0)
  {
    for (i=0;i<main_opt.num_servers;i++)
      state[i]=IDLE;
    printf("\n localport %d",main_opt.localport);
    printf("\n serverport %d",main_opt.serverport);
    printf("\n maxclients %d",main_opt.max_clients);
    printf("\n Servers: ");
    for (j=0;j<main_opt.num_servers;j++)
    printf("\n\t== %s ==",main_opt.serverhost[j]);
    writemsg("\n\nDaemon Started..\n");
    return 0;
  }
  else
   return i;
}

/* 
 * Create a new local socket, turn it into a listenning socket
 * and return its file descriptor.
 * This socket will listen for incoming connections.
 *
 * Returns: A new file descriptor, or a negative value on error.
 * 	
 */
int local_socket(int portno){
	int newfd;
	struct sockaddr_in servaddr;
	
	if ( (newfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return(-1);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(portno);

	if ( (bind(newfd, (struct sockaddr *) &servaddr, sizeof(servaddr))) < 0)
		return(-1);

	if ( (listen(newfd, MAX_BACKLOG)) < 0)
		return(-1);

	return(newfd);
}


/*
 * Connect to the server.
 * All arriving data will be redirected to it.
 * 
 * Returns:	A file descriptor, or a negative value on error.
 * 	
 */

int connect_to(char *address, int *portno){
	int newfd;
	struct sockaddr_in servaddr;
	
	if ( (newfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
		return(-1); 
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(*portno);
	if ( (inet_pton(AF_INET, address, &servaddr.sin_addr) ) <= 0 )
		return(-1);
	if (connect(newfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0 )
		return(-1);

	return(newfd);
}

/*
 * Secure redirect of all arriving data to the real server.
 * There is a separate instance of this function for
 * each connection.
 *
 * Returns: 0 if OK. A negative value on errors.
 *
 */
int secureRedirect(int client_sockfd, char *serv_address, int 
*serv_portno, char* password){

	BIO* sbio;
	SSL_CTX* ctx;
	SSL* ssl;
	int r;
	fd_set frwd_fds;
    BIO *io,*ssl_bio;
	char frwd_buffer[BUFFER_SIZE]; // Buffer to forward data 
	int server_sockfd, nbytes;

	if ( (server_sockfd = connect_to(serv_address, serv_portno)) < 0 )
		return(server_sockfd);

	nbytes = 0;
	memset (&frwd_buffer, 0, BUFFER_SIZE);

	ctx = initialize_ctx(main_opt.keyfile,password);
	load_dh_params(ctx,main_opt.dhfile);
	sbio = BIO_new_socket(s,BIO_NOCLOSE);
	ssl = SSL_NEW(ctx);
	SSL_set_bio(ssl,sbio,sbio);
	if(r = SSL_accept(ssl)<=0)
		return r;

	while(TRUE){
		FD_ZERO(&frwd_fds);
		FD_SET(server_sockfd, &frwd_fds);
		FD_SET(client_sockfd, &frwd_fds);
		select(FD_SETSIZE, &frwd_fds, NULL, NULL, NULL);
    
        io=BIO_new(BIO_f_buffer());
        ssl_bio=BIO_new(BIO_f_ssl());
        BIO_set_ssl(ssl_bio,ssl,BIO_CLOSE);
        BIO_push(io,ssl_bio);
		
		if (FD_ISSET(client_sockfd, &frwd_fds)) {
			// Read from client and write to server... 
            r = BIO_gets(io,buf,BUFSIZZ-1);
            if(SSL_get_error(ssl,r) != SSL_ERROR_NONE)
                return -1;//TODO

            if ( (nbytes = send(server_sockfd, frwd_buffer, nbytes, 0)) < 1 )
				return(nbytes);
			
		}
		
		if (FD_ISSET(server_sockfd, &frwd_fds)) {
			// Read from server and write to client... 
			if ( (nbytes = recv(server_sockfd, frwd_buffer, BUFFER_SIZE, 0)) < 1 )
				return(nbytes);
                
            r=BIO_puts(io,frwd_buffer, nbytes);
			if(SSL_get_error(ssl,r) != SSL_ERROR_NONE)
                return -1;//TODO
            if((r=BIO_flush(io))<0)
                return -1;//TODO
		}
		
		bzero (frwd_buffer, BUFFER_SIZE);
	}
    SSL_shutdown(ssl);
	close(client_sockfd);
	close(server_sockfd);
	return(0);
}
/*
 * Redirect all arriving data to the real server.
 * There is a separate instance of this function for
 * each connection.
 *
 * Returns: 0 if OK. A negative value on errors.
 *
 */
int redirect(int client_sockfd, char *serv_address, int *serv_portno){
	fd_set frwd_fds;
	char frwd_buffer[BUFFER_SIZE]; /* Buffer to forward data */
	int server_sockfd, nbytes;

	if ( (server_sockfd = connect_to(serv_address, serv_portno)) < 0 )
		return(server_sockfd);

	nbytes = 0;
	memset (&frwd_buffer, 0, BUFFER_SIZE);
	while(TRUE){
		FD_ZERO(&frwd_fds);
		FD_SET(server_sockfd, &frwd_fds);
		FD_SET(client_sockfd, &frwd_fds);
		select(FD_SETSIZE, &frwd_fds, NULL, NULL, NULL);
		
		if (FD_ISSET(client_sockfd, &frwd_fds)) {
			/* Read from client and write to server... */
			if ( (nbytes = recv(client_sockfd, frwd_buffer, BUFFER_SIZE, 0)) < 1 )
				return(nbytes);

			if ( (nbytes = send(server_sockfd, frwd_buffer, nbytes, 0)) < 1 )
				return(nbytes);
		}
		
		if (FD_ISSET(server_sockfd, &frwd_fds)) {
			/* Read from server and write to client... */
			if ( (nbytes = recv(server_sockfd, frwd_buffer, BUFFER_SIZE, 0)) < 1 )
				return(nbytes);
		
			if ( (nbytes = send(client_sockfd, frwd_buffer, nbytes, 0)) < 1 )
				return(nbytes);
		}
		
		bzero (frwd_buffer, BUFFER_SIZE);
	} 
	close(client_sockfd);
	close(server_sockfd);
	return(0);
}

/* 
 * Select a server checking the state and 
 * the server to use acording to the use ,
 * priority and availability
 *
 * Returns: The server id
 * 	
 */

int select_server()
{
 int id,i,found=FALSE;
 int server_sockfd; 
 for (i=0;i<main_opt.num_servers && !found;i++)
 {
  if ((server_sockfd = connect_to(main_opt.serverhost[i], &main_opt.serverport )) < 0 )
  {
     state[i]=DOWN;   
  }
  else
  {
   if (state[i]==DOWN) state[i]=IDLE;
   close(server_sockfd);
  }
  if (state[i]==IDLE)
    {
      id=i;
      found=TRUE;
    }
 }
 if (!found)
 {
  for (i=0;i<main_opt.num_servers && !found;i++)
  {
     if (state[i]!=DOWN)
     {
       id=i;
       found=TRUE;
     }
  }
 }
 if (!found) return -1;
 return id;
}

/* main, finally */
int main(int argc, char **argv)
{
	int listenfd, connfd;
        int server_id;
	pid_t pid;
        int shm_id,error;
        shm_id= shmget(IPC_PRIVATE,sizeof(int)*MAX_SERVERS,IPC_CREAT | SHM_R | SHM_W);
        state=(int *) shmat(shm_id,0,0); 
        error=set_config();
    if(argc < 2){
        printf("Usage tcpsg keyfilepassword");
        exit(0);
    }
	if (error==0)
        {
	/* Daemonize our process */
	     if ( (pid = fork()) != 0 )
		exit(0);						/* Parent terminates. 1st child continues */
	     setsid();							/* 1st child becomes session leader */
	     if ( (pid = fork()) != 0)
		exit(0);						/* 1st child terminates. 2nd child continues */
		/* if OK, now we're running as a daemon  */


	/* Handler for SIGCHLD - to avoid zombie processes */
	Signal(SIGCHLD, catch_sigchld);
	
	if ( ( listenfd = local_socket(main_opt.localport) ) < 0 ) {
		writemsg("Error creating listenning socket");
		exit(1);
	}

	/*
	 * if the parent receives a SIGCHLD in a blocked accept, it forces accept
	 * to return an "Interrupted system call" error (EINTR), and the program
	 * aborts.
	 * So, we must check for a possible EINTR error returned by accept() and,
	 * in this case, force a loop in the while().
	 */
	while(TRUE){
			if ( (connfd = accept( listenfd, (struct sockaddr *) NULL, NULL) ) < 0 ) 
			{
				if (errno == EINTR)
					continue;
				else{
					writemsg("Error accepting connections");
					exit(1);
			}
		}

		
		/*
		 * Create a child process to handle each new connection.
		 * Each file descriptor will be shared (duplicated) with
		 * parent and child processes.
		 * 
		 */
		if (child_count < main_opt.max_clients){
			if ( (pid = fork()) == 0) {
			close (listenfd);		/* Child closes his listening socket */
                              
                    server_id=select_server(); 
                    if (server_id==-1)
                    {
                      writemsg("All the servers are down");
                      close(connfd);
                      exit(0); 
                    }
                    state[server_id]=WORKING; 

		   if (main_opt.sslflag) TODO
	 	   {
			if(secureRedirect(connfd, 
			   main_opt.serverhost[server_id],
		           &main_opt.serverport, argv[1]) < 0)
				writemsg("Failed to attempt to redirect data");
		   }
		   else{
                   	if (redirect(connfd, main_opt.serverhost[server_id], 
                                          &main_opt.serverport) < 0)
                         writemsg("Failed attempting to redirect data");
		  // }
   		    close(connfd);			/* Child closes his connected socket */
              
	            state[server_id]=IDLE;  

                    exit(0);				/* End of the child process */
			}
			if (pid > 0)
                       child_count++;			/* Parent increments child counter */
                    else
				writemsg("Error forking");
		}
		close(connfd);				/* Parent closes his connected socket */
	}
       }
       else
       {
          printf("\n Configuration error: %s \n",errors[error]);  
       }
  return 0;
}
		
