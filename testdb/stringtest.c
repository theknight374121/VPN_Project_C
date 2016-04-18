
#include<string.h>
#include<stdio.h>
int main()
{
	char input[] = {"username|password"};    
	char username[50];
	char password[50];
    char *p;
    p = strtok(input, "|");

    if(p)
    {
    strcpy(username,p);
    }
    p = strtok(NULL, "|");

    if(p)
           strcpy(password,p);

	printf("%s\n%s\n%d\n%d\n",username,password,strlen(username),strlen(password));
    return 0;
}
