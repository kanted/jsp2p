#include "SSLSocket.h"

static char* staticPassword;
  
static int passwordCopy(char* buffer, int n, int rwFlag,void* userData)
{
    if(n < strlen(staticPassword) + 1) return 0;
    strcpy(buffer, staticPassword);
    return(strlen(staticPassword));
}

SSLSocket* SSL_socket(int baseSocket, char* keyFile, char* password)
{
    SSL_METHOD* method;
    BIO* sbio;
    SSL_library_init();
    SSL_load_error_strings();
    method = SSLv23_method();
    SSLSocket* secureSocket = malloc(sizeof(SSLSocket));
    secureSocket->ctx = SSL_CTX_new(method);
    if(!(SSL_CTX_use_certificate_chain_file(secureSocket->ctx, keyFile))){
        printf("Error reading certificate\n"); //TODO
        goto exceptionHandler;
    }
    staticPassword = password;
    SSL_CTX_set_default_passwd_cb(secureSocket->ctx, passwordCopy);
    if
    (
        !(SSL_CTX_use_PrivateKey_file(secureSocket->ctx, keyFile, SSL_FILETYPE_PEM))
        ||
        !(SSL_CTX_load_verify_locations(secureSocket->ctx, CA_LIST, 0))
    )
    {
        printf("Error reading private key\n"); //TODO
        goto exceptionHandler;
    }
    //load_dh_params(secureSocket->ctx, main_opt.dhfile);
    sbio = BIO_new_socket(baseSocket, BIO_NOCLOSE);
    secureSocket->ssl = SSL_new(secureSocket->ctx);
    SSL_set_bio(secureSocket->ssl, sbio, sbio);
    return secureSocket;

    exceptionHandler:
        free(secureSocket);
        return NULL;
}

void SSL_close(SSLSocket* secureSocket)
{
    SSL_shutdown(secureSocket->ssl);
    SSL_free(secureSocket->ssl);
    SSL_CTX_free(secureSocket->ctx);
    free(secureSocket);
}
