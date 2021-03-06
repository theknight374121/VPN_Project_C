/* serv.cpp  -  Minimal ssleay server for Unix
   30.9.1996, Sampo Kellomaki <sampo@iki.fi> */


/* mangled to work with SSLeay-0.9.0b and OpenSSL 0.9.2b
   Simplified to be even more minimal
   12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CERTF  HOME "server.crt"
#define KEYF  HOME  "server.key"
#define CACERT HOME "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int main ()
{
   	int err;
   	int listen_sd;
   	int s_sd;
   	struct sockaddr_in sa_serv;
   	struct sockaddr_in sa_cli;
   	size_t client_len;
   	SSL_CTX* s_ctx;
   	SSL*     s_ssl;
   	X509*    client_cert;
   	char*    s_str;
   	char     buf [4096];
   	SSL_METHOD *s_meth;

/* SSL preliminaries. We keep the certificate and key with the context. */

   	SSL_load_error_strings();
   	SSLeay_add_ssl_algorithms();
   	s_meth = SSLv23_server_method();
   	s_ctx = SSL_CTX_new (s_meth);
   	if (!s_ctx) {
   		ERR_print_errors_fp(stderr);
   		exit(2);
   	}

//this verify should be set to none so that server doesn't ask for certificates from client
SSL_CTX_set_verify(s_ctx,SSL_VERIFY_NONE,NULL); /* whether verify the certificate */

   	if (SSL_CTX_use_certificate_file(s_ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
   		ERR_print_errors_fp(stderr);
   		exit(3);
   	}
   	if (SSL_CTX_use_PrivateKey_file(s_ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
   		ERR_print_errors_fp(stderr);
   		exit(4);
   	}

   	if (!SSL_CTX_check_private_key(s_ctx)) {
   		fprintf(stderr,"Private key does not match the certificate public key\n");
   		exit(5);
   	}

/* ----------------------------------------------- */
/* Prepare TCP socket for receiving connections */

   	listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");

   	memset (&sa_serv, '\0', sizeof(sa_serv));
   	sa_serv.sin_family      = AF_INET;
   	sa_serv.sin_addr.s_addr = INADDR_ANY;
sa_serv.sin_port        = htons (1111);          /* Server Port number */

   	err = bind(listen_sd, (struct sockaddr*) &sa_serv,
   		sizeof (sa_serv));                   CHK_ERR(err, "bind");

/* Receive a TCP connection. */

   	err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");

   	client_len = sizeof(sa_cli);
   	s_sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
   	CHK_ERR(s_sd, "accept");
   	close (listen_sd);

   	printf ("Connection from %lx, port %x\n",
   		sa_cli.sin_addr.s_addr, sa_cli.sin_port);

/* ----------------------------------------------- */
/* TCP connection is ready. Do server side SSL. */

   	s_ssl = SSL_new (s_ctx);                           CHK_NULL(s_ssl);
   	SSL_set_fd (s_ssl, s_sd);
   	err = SSL_accept (s_ssl);                        CHK_SSL(err);

	/* We could do all sorts of certificate verification stuff here before
deallocating the certificate. */

   	X509_free (client_cert);


/* DATA EXCHANGE - Receive message and send reply. */

   	err = SSL_read (s_ssl, buf, sizeof(buf) - 1);                   CHK_SSL(err);
   	buf[err] = '\0';
   	printf ("Got %d chars:'%s'\n", err, buf);

   	err = SSL_write (s_ssl, "I hear you.", strlen("I hear you."));  CHK_SSL(err);

/* Clean up. */

   	close (s_sd);
   	SSL_free (s_ssl);
   	SSL_CTX_free (s_ctx);

   	return 0;
}
/* EOF - serv.cpp */
