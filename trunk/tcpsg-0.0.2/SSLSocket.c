#include "SSLSocket.h"

static char* staticPassword;
  
static int passwordCopy(char* buffer, int n, int rwFlag, void* userData)
{
    int len = strlen(staticPassword);
    if(n < len + 1) return 0;
    strcpy(buffer, staticPassword);
    return len;
}

/* Initialize a secure socket*/
SSLSocket* SSLOpen(int baseSocket, char* keyFile, char* password)
{
    SSL_METHOD* method;
    BIO* sbio;
    SSL_library_init();
    SSL_load_error_strings();
    method = SSLv23_method();
    SSLSocket* secureSocket = malloc(sizeof(SSLSocket));
    secureSocket->ctx = SSL_CTX_new(method);
    if(!(SSL_CTX_use_certificate_chain_file(secureSocket->ctx, keyFile))){
        printf("SSL: Error reading certificate in %s\n",keyFile);
        goto exceptionHandler;
    }
    staticPassword = password;
    SSL_CTX_set_default_passwd_cb(secureSocket->ctx, passwordCopy);
    if(!(SSL_CTX_use_PrivateKey_file(secureSocket->ctx, keyFile, SSL_FILETYPE_PEM)))
    {
        printf("SSL: Error reading private key\n");
        goto exceptionHandler;
    }
    if(!(SSL_CTX_load_verify_locations(secureSocket->ctx, CA_CERT, 0)))
    {
        printf("SSL: Error loading CA\n");
        goto exceptionHandler;
    }
    sbio = BIO_new_socket(baseSocket, BIO_NOCLOSE);
    secureSocket->ssl = SSL_new(secureSocket->ctx);
    if(secureSocket->ssl == NULL){
        printf("SSL: Error initializing secure socket\n");
        goto exceptionHandler;
    }
    SSL_set_bio(secureSocket->ssl, sbio, sbio);
    return secureSocket;

    exceptionHandler:
        SSL_CTX_free(secureSocket->ctx);
        free(secureSocket);
        return NULL;
}

inline int SSLAccept(SSLSocket* secureSocket)
{
    return SSL_accept(secureSocket->ssl);
}

inline int SSLConnect(SSLSocket* secureSocket)
{
    return SSL_connect(secureSocket->ssl);
}


inline int SSLRead(SSLSocket* secureSocket, void* buffer, int bufferSize)
{
    return SSL_read(secureSocket->ssl, buffer, bufferSize);
}

inline int SSLGetError(SSLSocket* secureSocket, int err)
{
    return SSL_get_error(secureSocket->ssl, err);
}

inline int SSLWrite(SSLSocket* secureSocket, void* buffer, int bufferSize)
{
    return  SSL_write(secureSocket->ssl, buffer, bufferSize);
}

int checkCertificate(SSLSocket* secureSocket, char* hostname)
{
    X509 *peer;
    char peer_CN[256];    
    if(SSL_get_verify_result(secureSocket->ssl)!=X509_V_OK){
         return -1;
    }
    peer=SSL_get_peer_certificate(secureSocket->ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
    if(strcasecmp(peer_CN,hostname)){
        return -1;
    }
    return 0;
}

/* Destroy a secure socket*/
void SSLClose(SSLSocket* secureSocket)
{
    SSL_shutdown(secureSocket->ssl);
    SSL_free(secureSocket->ssl);
    SSL_CTX_free(secureSocket->ctx);
    free(secureSocket);
}
