#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h> 
int main()
        {	
	char outfile[]="ciphertext.txt";
        unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	unsigned char decoutbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	unsigned char printbuf[1024 + EVP_MAX_BLOCK_LENGTH];
        int outlen, tmplen, decoutlen,dectmplen, i;
        /* Bogus key and IV: we'd normally set these from
         * another source.
         */
        unsigned char key[] = {"median"};
        unsigned char iv[16] = {0};
        char intext[] = "This is a top secret.";
	char ciphertext[] = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9";
        EVP_CIPHER_CTX *ctx,*dctx;
        
	ctx = EVP_CIPHER_CTX_new();
	dctx = EVP_CIPHER_CTX_new();
        
			
	EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

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
		
			
		
	printf("Ciphertext = %s\n",printbuf);	

	EVP_DecryptInit_ex(dctx, EVP_aes_128_cbc(), NULL, key, iv);
	if(!EVP_DecryptUpdate(dctx, decoutbuf, &decoutlen, outbuf, strlen(outbuf)))
       		{
        	/* Error */
		EVP_CIPHER_CTX_cleanup(dctx);
		printf("Error thrown at update");               		
		return 0;
      	}
	 /* Buffer passed to EVP_EncryptFinal() must be after data just
	  * encrypted to avoid overwriting it.
	   */
	  if(!EVP_DecryptFinal_ex(dctx, decoutbuf + decoutlen, &dectmplen))
    	    {
    	    /* Error */
		EVP_CIPHER_CTX_cleanup(dctx);
		printf("Error thrown at final");  
     	  	return 0;
   	     }
	  decoutlen += dectmplen;
	char * decbuf_ptr = (printbuf);
	for(i =0;i < decoutlen;i++){

		decbuf_ptr+=sprintf(decbuf_ptr,"%02x",decoutbuf[i]);
	}
      		 
       printf("DeCiphertext = %s\n",decoutbuf);	
return 1;
}



