#include <sys/socket.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>


int main(int argc, char** argv){
	if(argc < 4) return -1;
	struct sockaddr_in main_sockaddr;
	uint16_t port;
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	sscanf(argv[2], "%hd", &port);
	memset(&main_sockaddr, 0, sizeof(struct sockaddr_in));
	main_sockaddr.sin_family = AF_INET;
	main_sockaddr.sin_port = htons(port);
	main_sockaddr.sin_addr.s_addr = inet_addr(argv[1]);
	if(connect(sock, (struct sockaddr*)&main_sockaddr, sizeof(struct sockaddr_in))) return -2;
	send(sock, argv[3], strlen(argv[3]), 0);
    char buffer[4096];
    printf("%ld\n", recv(sock, buffer, 4096, 0));
    for(int i = 0; i < 65; i++){
        printf("%02x", *(buffer+i));
    }
    printf("\n");
    buffer[89] = 0;
    printf("%24s\n", buffer+65);
	return 0;
}
