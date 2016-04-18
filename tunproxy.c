/*
 * tunproxy.c --- small demo program for tunneling over UDP with tun/tap
 *
 * Copyright (C) 2003  Philippe Biondi <phil@secdev.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */



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
#include <openssl/evp.h> 
#include <openssl/hmac.h>

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

/*length of key*/
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
	char buf[1800];
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

	 //hashing 
	  char printbuf[65];
	 char printbuf2[65];
	 unsigned char md_value[EVP_MAX_MD_SIZE];
	 unsigned char md_value1[EVP_MAX_MD_SIZE];
	 int md_len,md_len1, j;

	  ctx = EVP_CIPHER_CTX_new();
	  dctx = EVP_CIPHER_CTX_new();
	

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
		while(1) {
			l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
			if (l < 0) PERROR("recvfrom");
			if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD)) == 0)
				break;
			printf("Bad magic word from %s:%i\n", 
			       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
		} 
		l = sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, fromlen);
		if (l < 0) PERROR("sendto");
	} else {
		from.sin_family = AF_INET;
		from.sin_port = htons(port);
		inet_aton(ip, &from.sin_addr);
		l =sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, sizeof(from));
		if (l < 0) PERROR("sendto");
		l = recvfrom(s,buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
		if (l < 0) PERROR("recvfrom");
		if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD) != 0))
			ERROR("Bad magic word for peer\n");
	}
	printf("Connection with %s:%i established\n", 
	       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));
	while (1) {
		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);
		FD_SET(s, &fdset);
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
			if ((sout.sin_addr.s_addr != from.sin_addr.s_addr) || (sout.sin_port != from.sin_port))
				printf("Got packet from  %s:%i instead of %s:%i\n", 
				       inet_ntoa(sout.sin_addr.s_addr), ntohs(sout.sin_port),
				       inet_ntoa(from.sin_addr.s_addr), ntohs(from.sin_port));

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
}
	       
	
