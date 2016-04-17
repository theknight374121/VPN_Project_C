#include <stdio.h>
#include <openssl/hmac.h>

 main(int argc, char *argv[])
 {
 HMAC_CTX *hmacctx;
 const EVP_MD *md;
 char key[] ="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
 char mess1[] = "Test Message";
 char mess2[] = "Test Message";
 char printbuf[65];
 char printbuf2[65];
 unsigned char md_value[EVP_MAX_MD_SIZE];
 unsigned char md_value1[EVP_MAX_MD_SIZE];
 int md_len,md_len1, i;

 md = EVP_sha256();

 if(!md) {
        printf("Unknown message digest %s\n", argv[1]);
        exit(1);
 }
 
 HMAC(md, key, strlen(key), mess1, strlen(mess1), md_value, &md_len );
 HMAC(md, key, strlen(key), mess2, strlen(mess2), md_value1, &md_len1 );


 
 printf("Digest is: ");
unsigned char * decbuf_ptr;
decbuf_ptr = (printbuf);
for(i =0;i < md_len;i++){
	decbuf_ptr+=sprintf(decbuf_ptr,"%02x",md_value[i]);
}
printbuf[64]='\0';
md_value[64]='\0';
decbuf_ptr = (printbuf2);
for(i =0;i < md_len1;i++){
	decbuf_ptr+=sprintf(decbuf_ptr,"%02x",md_value1[i]);
}

if(strcmp(md_value,md_value1)==0){
   printf("it matches, p:%s\np1:%s\n",printbuf,printbuf2);
}else{
	printf("it does not matches, p:%s\np1:%s\n",printbuf,printbuf2);
}


if(strcmp(printbuf,printbuf2)==0){
   printf("it matches, p:%s\np1:%s\n",printbuf,printbuf2);
}else{
	printf("it does not matches, p:%s\np1:%s\n",printbuf,printbuf2);
}
 printf("\n");
 
 exit(0);
 }
