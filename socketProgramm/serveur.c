#include <stdio.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

/* Use to compile : clang serveur.c -o Alice -Wall -Wextra -g */

int main(int argc, char *argv[]) 
{
	int s_ecoute,scom, lg_app, i, j, c;
	struct sockaddr_in adr;
	struct sockaddr_storage recep;
	char buf[1500], renvoi[1500], host[1024],service[20], buffer[200], texte[200];
	s_ecoute=socket(AF_INET,SOCK_STREAM,0);
	printf("Pour le menu, pour effectuer l'action que vous désirez, appuyez sur le numéro que vous souhaitez puis appuyez sur entrée. Toute autre action fermera l'application.\n");

	adr.sin_family=AF_INET;
	adr.sin_port=htons(atoi(argv[1]));
	adr.sin_addr.s_addr=INADDR_ANY;

	if (bind(s_ecoute,(struct sockaddr *)&adr,sizeof(struct sockaddr_in)) !=0) 
	{
		printf("probleme de bind sur v4\n");
		exit(1); 
	}
	if (listen(s_ecoute,5) != 0) 
	{
		printf("pb ecoute\n"); 
		exit(1);
	}
	
	bzero(texte,sizeof(texte));
	bzero(buffer,sizeof(buffer));
	i = 0;
	printf("Que voulez-vous faire ? \n1. Appeler\n2. Quitter\n");
	while((c=getchar()) != '\n')
		texte[i++]=c;
	switch (texte[0])
	{
		case '1':
			printf("En attente de connexion de Bob\n");
			break;
		case '2':
			printf("À bientôt !\n");
			return 0;
		default:
			printf("Votre demande n'est pas valide\n");
			break;
	}
	while (1) 
	{
		scom=accept(s_ecoute,(struct sockaddr *)&recep, (socklen_t *)&lg_app);
		getnameinfo((struct sockaddr *)&recep,sizeof (recep), host, sizeof(host),service,
		sizeof(service),0); //optionnelle pour info
		printf("recu de %s venant du port %s\n",host, service); //optionnnelle
		while (1) 
		{
			recv(scom,buf,sizeof(buf),0);
			printf("buf recu %s\n",buf);
			bzero(renvoi,sizeof(renvoi));
			for(i=strlen(buf)-1,j=0;i>=0;i--,j++) 
				renvoi[j]=buf[i];
			renvoi[j+1]='\0';

			send(scom,renvoi,strlen(renvoi),0);
			bzero(buf,sizeof(buf));
			if (strcmp(renvoi,"NIF") == 0) 
				break; 
		}
		close(scom); 
	}
	close(s_ecoute); 

	return 0;
}