#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
 
#define LEN 5

int main()
{
   FILE *fp;
   unsigned char storeduser[50];
   unsigned char storedpwd[50];
   unsigned char username[50];
   unsigned char password[50];
   unsigned char combpwd[60];
   

  EVP_MD_CTX *mdctx;
 const EVP_MD *md;
 char storedig[64];
 char * storeptr;
 char * saltptr;
 char storesalt[5];
 unsigned char md_value[EVP_MAX_MD_SIZE];
 int md_len, i,j;

   if( (fp=fopen("userdb.txt","w")) == NULL )
     puts("File can not open !\n"), exit(1);
   
   for (j=0;j<5;j++){
	printf("type username :"); scanf("%s",username);
   	printf("type password :"); scanf("%s",password); printf("\n");
	 
	//generate random salt
	unsigned char * salt = (unsigned char *) malloc (sizeof(unsigned char)*LEN);
	FILE* random = fopen("/dev/urandom","r");
	fread(salt,sizeof(unsigned char)*LEN,1,random);
	fclose(random);

	saltptr=storesalt;
	for(i = 0; i < 5; i++){
		saltptr+=sprintf(saltptr,"%02x", salt[i]);
	}
		
	//compose the combined password
	
	for(i=0;i<10;i++){
		combpwd[i]=storesalt[i];
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
	 EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	 EVP_MD_CTX_destroy(mdctx);

	//Printing the calculated hash.
	storeptr=storedig;
		 
	for(i = 0; i < md_len; i++){
		storeptr+=sprintf(storeptr,"%02x", md_value[i]);
	}
	
	fprintf(fp,"%s\t%s\t%s\n",username,storesalt,storedig);
    }
   
   /*
    while( !feof(fp) )                 
   {
      fscanf(fp,"%s %s",storeduser,storedpwd);
 
      if((No1==username) && (No2==password))
      {
         printf("Correct Numbers");
      }
      else
      {
         printf("Wrong Numbers");
      }
   }
 */
   fclose(fp);                         
 
 return 0;
}
