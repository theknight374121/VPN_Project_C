#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <getopt.h>
#include <sys/ioctl.h>
//Hashing and encryption includes
#include <openssl/evp.h> 
#include <openssl/hmac.h>
//OpenSSL includes
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <arpa/inet.h>
#include <memory.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>

//Hashing and encryption definitions
#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

//OpenSSL definitions
#define CERTF "client.crt"
#define KEYF "client.key"
#define CACERT "ca.crt"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { printf("inside err"); perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { printf("inside ssl"); ERR_print_errors_fp(stderr); exit(2); }

/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define SCERTF  HOME "server.crt"
#define SKEYF  HOME  "server.key"
#define SCACERT HOME "ca.crt"

/*length of IV*/
#define LEN 16

char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";


void usage()
{
	fprintf(stderr, "Usage: tunproxy [-s port|-c targetip:port] [-e]\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	struct sockaddr_in sin, sout, from;
	struct ifreq ifr;
	int fd, s, fromlen, soutlen, port, PORT, l;
	char c, *p, *ip;
	char buf[4098];
	fd_set fdset;
	
	  //Encryption variables
	  unsigned char sendencoutbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	  unsigned char decoutbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	  int outlen, tmplen, decoutlen,dectmplen, i;
	  unsigned char * encoutbuf = sendencoutbuf+16;
	  unsigned char * realbufpointer;
	  unsigned char key[] = {"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"};
	  unsigned char iv[16] = "";  
	  EVP_CIPHER_CTX *ctx,*dctx;
	
	  ctx = EVP_CIPHER_CTX_new();
	  dctx = EVP_CIPHER_CTX_new();

	 //HMAC variables 
	  char printbuf[65];
	 char printbuf2[65];
	 unsigned char md_value[EVP_MAX_MD_SIZE];
	 unsigned char md_value1[EVP_MAX_MD_SIZE];
	 int md_len,md_len1, j;

	//username and password
	unsigned char username[50];
	unsigned char password[50];
	unsigned char sendcred[100];

	//client side authentication
	FILE *fp;
	int flag=0;
	unsigned char storeduser[50];
	unsigned char storedpwd[65];
	unsigned char storedsalt[10];
	unsigned char combpwd[60];

	//client side auth hash variables. SHA256	
	EVP_MD_CTX *mdctx;
	 const EVP_MD *md;
	 char storedig[64];
	 char * storeptr;
	 char * saltptr;
	 char storesalt[5];
	 unsigned char md_value2[EVP_MAX_MD_SIZE];
	 int md_len2;

	//OpenSSL variables for client
	int err;
	int sd;	//socket for client side
	struct sockaddr_in sa;
	SSL_CTX* sslctx;
	SSL*     ssl;
	X509*    server_cert;
	char*    str;
	SSL_METHOD *meth;
	SSLeay_add_ssl_algorithms();
	meth = SSLv23_client_method();
	SSL_load_error_strings();
	sslctx = SSL_CTX_new (meth);
	CHK_NULL(sslctx);
	CHK_SSL(err);	

	//OpenSSL Variables for server
	int listen_sd,s_sd;	//socket for server side listen socket, server side normal socket
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	size_t client_len;
	SSL_CTX* s_ctx;
	SSL*     s_ssl;
	X509*    client_cert;
	char*    s_str;
	SSL_METHOD *s_meth;
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	s_meth = SSLv23_server_method();
	s_ctx = SSL_CTX_new (s_meth);
	if (!s_ctx) {
	ERR_print_errors_fp(stderr);
	exit(2);
	}

	int MODE = 0, TUNMODE = IFF_TUN, DEBUG = 0;

	while ((c = getopt(argc, argv, "s:c:ehd")) != -1) {
		switch (c) {
		case 'h':
			usage();
		case 'd':
			DEBUG++;
			break;
		case 's':
			MODE = 1;
			PORT = atoi(optarg);
			break;
		case 'c':
			MODE = 2;
			p = memchr(optarg,':',16);
			if (!p) ERROR("invalid argument : [%s]\n",optarg);
			*p = 0;
			ip = optarg;
			port = atoi(p+1);
			PORT = 0;
			break;
		case 'e':
			TUNMODE = IFF_TAP;
			break;
		default:
			usage();
		}
	}
	if (MODE == 0) usage();

	if ( (fd = open("/dev/net/tun",O_RDWR)) < 0) PERROR("open");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = TUNMODE;
	strncpy(ifr.ifr_name, "toto%d", IFNAMSIZ);
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");

	printf("Allocated interface %s. Configure and use it\n", ifr.ifr_name);
	
	s = socket(PF_INET, SOCK_DGRAM, 0);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(PORT);
	if ( bind(s,(struct sockaddr *)&sin, sizeof(sin)) < 0) PERROR("bind");

	fromlen = sizeof(from);

	if (MODE == 1) {
		//while(1) {
			
		///////////////////////////////////////////////////////////////////////////
		/////////	starting SSL tunnel to authenticate client	///////////
		///////////////////////////////////////////////////////////////////////////

		//this verify should be set to none so that server doesn't ask for certificates from client
		SSL_CTX_set_verify(s_ctx,SSL_VERIFY_NONE,NULL); /* whether verify the certificate */
		SSL_CTX_load_verify_locations(s_ctx,SCACERT,NULL);

		if (SSL_CTX_use_certificate_file(s_ctx, SCERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
		}
		if (SSL_CTX_use_PrivateKey_file(s_ctx, SKEYF, SSL_FILETYPE_PEM) <= 0) {
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
		sa_serv.sin_port        = htons (PORT);          /* Server Port number */

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

		/* Get the cipher - opt */

		printf ("SSL connection using %s\n", SSL_get_cipher (s_ssl));

		/* Get client's certificate (note: beware of dynamic allocation) - opt */

		client_cert = SSL_get_peer_certificate (s_ssl);
		if (client_cert != NULL) {
		printf ("Client certificate:\n");

		s_str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
		CHK_NULL(s_str);
		printf ("\t subject: %s\n", s_str);
		OPENSSL_free (s_str);

		s_str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
		CHK_NULL(s_str);
		printf ("\t issuer: %s\n", s_str);
		OPENSSL_free (s_str);

		/* We could do all sorts of certificate verification stuff here before
		deallocating the certificate. */

		X509_free (client_cert);
		} else
		printf ("Client does not have certificate.\n");

		/* DATA EXCHANGE - Receive message and send reply. */

		err = SSL_read (s_ssl, buf, sizeof(buf) - 1);                   CHK_SSL(err);
		buf[err] = '\0';
		
		///////////////////////////////////////////////////////////////////
		/////////	client side authentication		///////////
		///////////////////////////////////////////////////////////////////
			char *p;
			p = strtok(buf, "@");
			if(p)	strcpy(username,p);
			p = strtok(NULL, "@");
			if(p)	strcpy(password,p);
			printf("username:%s\npasssword:%s\n",username,password);
			   if( (fp=fopen("userdb.txt","r")) == NULL )
			     {printf("File can not open !\n"); exit(1);}
			   
				while( !feof(fp) )                 
				   {
				      	fscanf(fp,"%s %s %s",storeduser,storedsalt,storedpwd);
					storedpwd[64]='\0';
				
				      if(strcmp(storeduser,username)==0)
				      {
					 	//compose the combined password
						for(i=0;i<10;i++){
							combpwd[i]=storedsalt[i];
						}
						for(i=0;i<strlen(password);i++){
							combpwd[i+10]=password[i];
						}
						combpwd[10+strlen(password)]='\0';

						//set value of message digest used
						 md = EVP_sha256();
						 if(!md) {
							printf("Unknown message digest %s\n", "md5");
							exit(1);
						 }

						//Hash the initial message to use the hash for further calculations
						 mdctx = EVP_MD_CTX_create();
						 EVP_DigestInit_ex(mdctx, md, NULL);
						 EVP_DigestUpdate(mdctx, combpwd, strlen(combpwd));
						 EVP_DigestFinal_ex(mdctx, md_value2, &md_len2);
						 EVP_MD_CTX_destroy(mdctx);

						//Printing the calculated hash.
						storeptr=storedig;
							 
						for(i = 0; i < md_len2; i++){
							storeptr+=sprintf(storeptr,"%02x", md_value2[i]);
						}
						storedig[64]='\0';

						if(strcmp(storedpwd,storedig)==0){
							printf("password matched!\n");
							flag=1;
						//need to put a goto here
							goto CLIENT_AUTHENTICATED;
						}
						else{
							printf("incorrect password\n");
							flag=1;
						}
				      }
				      
				   }
					if(flag==0) printf("no usr preseent\n");
	CLIENT_AUTHENTICATED:
			   fclose(fp);                         
		
		///////////////////////////////////////////////////////////////////
		/////////	client side authentication done		///////////
		///////////////////////////////////////////////////////////////////
		
		
		///////////////////////////////////////////////////////////////////////////
		/////////	Ending SSL tunnel to authenticate client	///////////
		///////////////////////////////////////////////////////////////////////////
		

		//	} 
	
		
	} else {//these are parameters to set the UDP tunnel.
		from.sin_family = AF_INET;
		from.sin_port = htons(port);
		inet_aton(ip, &from.sin_addr);

		///////////////////////////////////////////////////////////////////////////
		/////////	starting SSL tunnel to authenticate server	///////////
		///////////////////////////////////////////////////////////////////////////

		SSL_CTX_set_verify(sslctx,SSL_VERIFY_PEER,NULL);
		SSL_CTX_load_verify_locations(sslctx,CACERT,NULL);

		
		/* ----------------------------------------------- */
		/* Create a socket and connect to server using normal socket calls. */

		sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");

		memset (&sa, '\0', sizeof(sa));
		sa.sin_family      = AF_INET;
		sa.sin_addr.s_addr = inet_addr ("10.0.2.7");   /* Server IP */
		sa.sin_port        = htons     (port);          /* Server Port number */

		err = connect(sd, (struct sockaddr*) &sa,
			sizeof(sa));                   CHK_ERR(err, "connect");

		/* ----------------------------------------------- */
		/* Now we have TCP conncetion. Start SSL negotiation. */

		ssl = SSL_new (sslctx);                         CHK_NULL(ssl);    
		SSL_set_fd (ssl, sd);
		err = SSL_connect (ssl);                     CHK_SSL(err);

		/* Following two steps are optional and not required for
		data exchange to be successful. */

		/* Get the cipher - opt */

		printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

		/* Get server's certificate (note: beware of dynamic allocation) - opt */

		server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);
		printf ("Server certificate:\n");

		str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
		CHK_NULL(str);
		printf ("\t subject: %s\n", str);
		OPENSSL_free (str);

		str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
		CHK_NULL(str);
		printf ("\t issuer: %s\n", str);
		OPENSSL_free (str);

		/* We could do all sorts of certificate verification stuff here before
		deallocating the certificate. */

		X509_free (server_cert);

		/* --------------------------------------------------- */
		/* DATA EXCHANGE - Send a message and receive a reply. */

		///////////////////////////////////////////////////////////////////
		/////////	asking user for username and password	///////////
		///////////////////////////////////////////////////////////////////
		
		printf("Enter username:");
		scanf("%s",username);
		printf("Enter Password:");
		scanf("%s",password);
		printf("\n");
		for(i=0;i<strlen(username);i++){
			sendcred[i]=username[i];
		}
		sendcred[strlen(username)]='@';
		int credptr = strlen(username)+1;
		for(i=0;i<strlen(password);i++){
			sendcred[credptr+i]=password[i];
		}
		sendcred[credptr+strlen(password)]='\0';
		printf("sent:%s",sendcred);
		
		//////////////////////////////////////////////////////////////////////
		/////////	done asking user for username and password	//////
		//////////////////////////////////////////////////////////////////////

		err = SSL_write (ssl, sendcred, strlen(sendcred));  CHK_SSL(err);

		err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
		buf[err] = '\0';
		
		///////////////////////////////////////////////////////////////////////////
		/////////	SSL tunnel to authenticate server ends here	///////////
		///////////////////////////////////////////////////////////////////////////
			
		
	}
	
	//printf("Connection with %s:%i established\n",inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
	printf("Connection established:");
	while (1) {
		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);
		FD_SET(s, &fdset);
		//FD_SET(,&fdset);
		if (select(fd+s+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
		if (FD_ISSET(fd, &fdset)) {
			if (DEBUG) write(1,">", 1);
			l = read(fd, buf, sizeof(buf));
			if (l < 0) PERROR("read");
			
			////////////////////////////////////////////////////////////////
			////////////	Generation Of IV starts here	///////////////
			///////////////////////////////////////////////////////////////
				unsigned char * iv = (unsigned char *) malloc (sizeof(unsigned char)*LEN);
				FILE* random = fopen("/dev/urandom","r");
				fread(iv,sizeof(unsigned char)*LEN,1,random);
				fclose(random);

			////////////////////////////////////////////////////////////////
			////////////	Generation Of IV ends here	///////////////
			///////////////////////////////////////////////////////////////

				for(i =0;i<16;i++){
					sendencoutbuf[i]=iv[i];
				}
				//printf("IV at enc side:%s\n",iv);



			////////////////////////////////////////////////////////////////
			////////////	Encryption of data starts here	///////////////
			///////////////////////////////////////////////////////////////
				EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

				if(!EVP_EncryptUpdate(ctx, encoutbuf, &outlen, buf, l))
			       		{
					/* Error */
					EVP_CIPHER_CTX_cleanup(ctx);
					printf("Error thrown at update at enc");               		
					return 0;
			      	}
				 /* Buffer passed to EVP_EncryptFinal() must be after data just
				  * encrypted to avoid overwriting it.
				   */
				  if(!EVP_EncryptFinal_ex(ctx, encoutbuf + outlen, &tmplen))
			    	    {
			    	    /* Error */
					EVP_CIPHER_CTX_cleanup(ctx);
					printf("Error thrown at final at enc");  
			     	  	return 0;
			   	     }
				  outlen += tmplen;

			       		
				/* Need binary mode for fopen because encrypted data is
				 * binary data. Also cannot use strlen() on it because
				 * it wont be null terminated and may contain embedded
				 * nulls.
				 */
			////////////////////////////////////////////////////////////////
			////////////	Encryption of data ends here	///////////////
			///////////////////////////////////////////////////////////////

			////////////////////////////////////////////////////////////////
			////////////	Generation Of hash starts here	///////////////
			///////////////////////////////////////////////////////////////
				HMAC(EVP_sha256(), key, strlen(key), sendencoutbuf+16, outlen, md_value, &md_len );
				unsigned char * ptr = sendencoutbuf+16+outlen;
				for(i =0;i < md_len;i++){
					ptr+=sprintf(ptr,"%02x",md_value[i]);
				}

			////////////////////////////////////////////////////////////////
			////////////	Generation Of hash ends here	///////////////
			///////////////////////////////////////////////////////////////


			if (sendto(s, sendencoutbuf, outlen+16+64, 0, (struct sockaddr *)&from, fromlen) < 0) PERROR("sendto");
		} else {
			if (DEBUG) write(1,"<", 1);
			l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&sout, &soutlen);
			/*			
			if ((sout.sin_addr.s_addr != from.sin_addr.s_addr) || (sout.sin_port != from.sin_port))
				printf("Got packet from  %s:%i instead of %s:%i\n", 
				       inet_ntoa(sout.sin_addr.s_addr), ntohs(sout.sin_port),
				       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
			*/
			////////////////////////////////////////////////////////////////
			////////////	Retrieving the IV starts here	///////////////
			///////////////////////////////////////////////////////////////
				for(i =0;i<16;i++){
					iv[i]=buf[i];
				}
				//printf("IV at dec side:%s\n",iv);
			////////////////////////////////////////////////////////////////
			////////////	Retrieving the IV ends here	///////////////
			///////////////////////////////////////////////////////////////

			////////////////////////////////////////////////////////////////
			////////////	Generation Of hash starts here	///////////////
			///////////////////////////////////////////////////////////////
				unsigned char * buf_dec_ptr = buf+16;
				HMAC(EVP_sha256(), key, strlen(key), buf+16, l-16-64, md_value1, &md_len1 );
				unsigned char * dec_ptr = printbuf;
				for(i =0;i < md_len1;i++){
					dec_ptr+=sprintf(dec_ptr,"%02x",md_value1[i]);
				}
				printbuf[64]='\0';
				unsigned char * ptr = buf+(l - 64);
				for(i = l - 64, j =0 ;i < l;i++, j++){
					printbuf2[j]=buf[i];
				}
				printbuf2[64]='\0';
				/*
				if(strcmp(printbuf,printbuf2)==0){
				   printf("it matches, p:%s\np1:%s\n",printbuf,printbuf2);
				}else{
					printf("it does not matches, p:%s\np1:%s\n",printbuf,printbuf2);
				}
				*/
			////////////////////////////////////////////////////////////////
			////////////	Generation Of hash ends here	///////////////
			///////////////////////////////////////////////////////////////

			////////////////////////////////////////////////////////////////
			////////////	Decryption of data starts here	///////////////
			///////////////////////////////////////////////////////////////

				realbufpointer = buf + 16;
	
				EVP_DecryptInit_ex(dctx, EVP_aes_256_cbc(), NULL, key, iv);
				if(!EVP_DecryptUpdate(dctx, decoutbuf, &decoutlen, realbufpointer, l-16-64))
			       		{
					/* Error */
					EVP_CIPHER_CTX_cleanup(dctx);
					printf("Error thrown at update at decr");               		
					return 0;
			      	}
				 /* Buffer passed to EVP_EncryptFinal() must be after data just
				  * encrypted to avoid overwriting it.
				   */
				  if(!EVP_DecryptFinal_ex(dctx, decoutbuf + decoutlen, &dectmplen))
			    	    {
			    	    /* Error */
					EVP_CIPHER_CTX_cleanup(dctx);
					printf("Error thrown at final at decr");  
			     	  	return 0;
			   	     }
				  decoutlen += dectmplen;

			////////////////////////////////////////////////////////////////
			////////////	Decryption of data ends here	///////////////
			///////////////////////////////////////////////////////////////


			if (write(fd, decoutbuf, decoutlen) < 0) PERROR("write");
		}
	}
	/* Clean up. */

		close (s_sd);
		SSL_free (s_ssl);
		SSL_CTX_free (s_ctx);
	SSL_shutdown (ssl);  /* send SSL/TLS close_notify */

		/* Clean up. */

		close (sd);
		SSL_free (ssl);
		SSL_CTX_free (sslctx);
}
	       
	
