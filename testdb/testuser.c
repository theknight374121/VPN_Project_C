#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
 
#define LEN 5

int main()
{
   FILE *fp;
   int flag=0;
   unsigned char storeduser[50];
   unsigned char storedpwd[65];
   unsigned char storedsalt[10];
   char usrid[50];
   char password[50];
   unsigned char combpwd[60];
   

  EVP_MD_CTX *mdctx;
 const EVP_MD *md;
 char storedig[64];
 char * storeptr;
 char * saltptr;
 char storesalt[5];
 unsigned char md_value[EVP_MAX_MD_SIZE];
 int md_len, i,j;

	printf("type username :"); scanf("%s",usrid); 
	printf("type password :"); scanf("%s",password); printf("\n");

   if( (fp=fopen("userdb.txt","r")) == NULL )
     puts("File can not open !\n"), exit(1);
   
	while( !feof(fp) )                 
	   {
	      	fscanf(fp,"%s %s %s",storeduser,storedsalt,storedpwd);
		storedpwd[64]='\0';
				
	      if(strcmp(storeduser,usrid)==0)
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
			 EVP_DigestFinal_ex(mdctx, md_value, &md_len);
			 EVP_MD_CTX_destroy(mdctx);

			//Printing the calculated hash.
			storeptr=storedig;
				 
			for(i = 0; i < md_len; i++){
				storeptr+=sprintf(storeptr,"%02x", md_value[i]);
			}
			storedig[64]='\0';

			if(strcmp(storedpwd,storedig)==0){
				printf("password matched!\n");
				flag=1;
				break;
			}
			else{
				printf("incorrect password\n");
				flag=1;
			}
	      }
	      
	   }
		if(flag==0) printf("no usr preseent\n");
	
   fclose(fp);                         
 
 return 0;
}
