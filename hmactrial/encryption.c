#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h> 
int main()
        {	
	char outfile[]="ciphertext.txt";
        unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	unsigned char printbuf[1024 + EVP_MAX_BLOCK_LENGTH];
        int outlen, tmplen, i;
        /* Bogus key and IV: we'd normally set these from
         * another source.
         */
        unsigned char key[] = {"median"};
        unsigned char iv[16] = {0};
        char intext[] = "This is a top secret.";
	char ciphertext[] = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9";
        EVP_CIPHER_CTX *ctx;
        FILE *out;
	ctx = EVP_CIPHER_CTX_new();
        
	//Code to read words from the file
	FILE *words_file;
	words_file = fopen ("words.txt","r");
	if (words_file<0){
		printf("Cannot open file");
		exit(1);
	}
	char words[16];
	int counter=0;
	int size;
	while(fscanf(words_file,"%s",words)!=EOF){
		size = strlen(words);
		if (size < 16){
			while(size<16){
				words[size]=' ';
				size++;
			}
			words[size]='\0';
		}
		size=strlen(words);		
				
        	EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, words, iv);

        	if(!EVP_EncryptUpdate(ctx, outbuf, &outlen, intext, strlen(intext)))
               		{
                	/* Error */
			EVP_CIPHER_CTX_cleanup(ctx);
			printf("Error thrown at update");               		
			return 0;
              	}
		 /* Buffer passed to EVP_EncryptFinal() must be after data just
       		  * encrypted to avoid overwriting it.
      		   */
      		  if(!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen))
            	    {
            	    /* Error */
			EVP_CIPHER_CTX_cleanup(ctx);
			printf("Error thrown at final");  
             	  	return 0;
           	     }
      		  outlen += tmplen;

       		
        /* Need binary mode for fopen because encrypted data is
         * binary data. Also cannot use strlen() on it because
         * it wont be null terminated and may contain embedded
         * nulls.
         */
	int x=0;
	char * buf_ptr = (printbuf);
	for(i =0;i < outlen;i++){

		buf_ptr+=sprintf(buf_ptr,"%02x",outbuf[i]);
	}
		
	if(strcmp(ciphertext,printbuf)==0){
		printf("%s = ",words);		
		printf("%s\n",printbuf);
		printf("Ciphertext = %s\n",printbuf);		
		break;
	}
	    	
       		 
 }       
return 1;
}



