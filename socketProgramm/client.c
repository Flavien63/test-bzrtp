#include <stdio.h>
#include <stdlib.h> 
#include <netinet/in.h> 
#include <netdb.h> 
#include <sys/socket.h> 
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* Use to compile : clang client.c -o Bob -Wall -Wextra -g */

int main(int argc, char *argv[])
{
	char buffer[200],texte[200];
	int port, rc, sock,i,c;
	struct sockaddr_in addr;
	struct hostent *entree;
	if (argc !=3) 
	{
		printf("usage : client_tcp nom_machine numero_port\n");
		exit(1); 
	}

	addr.sin_port=htons(atoi(argv[2]));
	addr.sin_family=AF_INET;
	entree=(struct hostent *)gethostbyname(argv[1]);
	bcopy((char *)entree->h_addr,(char *)&addr.sin_addr,entree->h_length);

	sock= socket(AF_INET,SOCK_STREAM,0);
	if (connect(sock, (struct sockaddr *)&addr,sizeof(struct sockaddr_in)) < 0) 
	{
		printf("L'autre personne n'est pas prête à être appelée.\n");
		exit(1); 
	}
	printf("Pour le menu, pour effectuer l'action que vous désirez, appuyez sur le numéro que vous souhaitez puis appuyez sur entrée. Toute autre action fermera l'application.\n");
	while (1) 
	{
		bzero(texte,sizeof(texte));
		bzero(buffer,sizeof(buffer));
		i = 0;
		printf("Entrez une ligne de texte : (Entrez FIN pour mettre fin à l'appel)\n");
		while((c=getchar()) != '\n')
			texte[i++]=c;
		send(sock,texte,strlen(texte)+1,0);
		recv(sock,buffer,sizeof(buffer),0);
		printf("recu %s\n",buffer);

		if (strcmp("FIN",texte) == 0) 
			break;
	}
	close(sock); 
}