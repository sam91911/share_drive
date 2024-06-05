#include "client.h"
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>


int main(int argc, char** argv){
	char* root_dir = ".";
	char* password = 0;
	char password_str[256];
	char instruction[1024];
	uint8_t buffer[1024];
	uint8_t buffer2[1024];
	struct stat oper_stat;
	struct termios oper_term, temp_term;
	struct sockaddr_in oper_sockaddr;
	uint8_t brk;
	pid_t client_pid = 0;
	uint64_t size_buf[4];
	int pid_state;
	memset(instruction, 0, 1024);
	for(int i = 1; i < argc; i++){
		if(argv[i][0] == '-'){
			switch(argv[i][1]){
				case 'p':
					password = password_str;
					break;
				case 'd':
					if(++i >= argc) return -1;
					root_dir = argv[i];
					break;
				default:
					fprintf(stderr, "unknown indicater\n");
					return -1;
			}
		}else{
			root_dir = argv[i];
		}
	}
	if(root_dir){
		if(access(root_dir, F_OK)){
			if(errno == ENOENT){
				if(mkdir(root_dir, 0744)){
					return -1;
				}
			}else{
				return -1;
			}
		}
		if(stat(root_dir, &oper_stat)){
			return -1;
		}
		if(!(S_IFDIR&(oper_stat.st_mode))){
			return -1;
		}
		if(chdir(root_dir)){
			return -1;
		}
	}
	if(pk_termin(password, 256)) return 0;
	while(1){
		if(printf("client:%s>", root_dir) < 0) return -1;
		if(!fgets(instruction, 1024, stdin)) continue;
		if(!strcmp(instruction, "init\n")){
			client_init(password);
		}else if(!memcmp(instruction, "fget ", 5)){
			if(sscanf(instruction+5, "%s", buffer) < 1) continue;
			size_buf[0] = strlen(buffer)+6;
			if(serverid_get_id(buffer, size_buf+1)) continue;
			if(sscanf(instruction+size_buf[0], "%s", buffer) < 1) continue;
			size_buf[0] += strlen(buffer)+1;
			if(user_name2id(size_buf[1], buffer, size_buf+2)) continue;
			if(sscanf(instruction+size_buf[0], "%s", buffer) < 1) continue;
			size_buf[0] += strlen(buffer)+1;
			if(sscanf(instruction+size_buf[0], "%s", buffer2) < 1) continue;
			if(client_pid){
				if(!kill(client_pid, 0)){
					if(!waitpid(client_pid, &pid_state, WNOHANG)){
						if(printf("client has been started\n") < 0) return -1;
						continue;
					}
				}else{
					if(errno != ESRCH) return -1;
					client_pid = 0;
				}
			}
			if((client_pid = fork()) == -1){
				return -1;
			}
			if(client_pid){
				continue;
			}else{
				client_fget(password, size_buf[1], size_buf[2], buffer, buffer2);
				return 0;
			}
		}else if(!memcmp(instruction, "fpost ", 6)){
			printf("fpost\n");
			if(sscanf(instruction+6, "%s", buffer) < 1) continue;
			size_buf[0] = strlen(buffer)+7;
			if(serverid_get_id(buffer, size_buf+1)) continue;
			if(sscanf(instruction+size_buf[0], "%s", buffer) < 1) continue;
			size_buf[0] += strlen(buffer)+1;
			if(sscanf(instruction+size_buf[0], "%s", buffer2) < 1) continue;
			if(client_pid){
				if(!kill(client_pid, 0)){
					if(!waitpid(client_pid, &pid_state, WNOHANG)){
						if(printf("client has been started\n") < 0) return -1;
						continue;
					}
				}else{
					if(errno != ESRCH) return -1;
					client_pid = 0;
				}
			}
			if((client_pid = fork()) == -1){
				return -1;
			}
			if(client_pid){
				continue;
			}else{
				client_fpost(password, size_buf[1], buffer, buffer2);
				return 0;
			}
		}else if(!strcmp(instruction, "exit\n")){
exit:
			if(client_pid){
				if(kill(client_pid, SIGKILL)) abort();
				if(wait(0) == -1) abort();
			}
			return 0;
		}else if(!strcmp(instruction, "pubkey\n")){
			size_buf[0] = 65;
			if(pk_get_pubkey(buffer, size_buf));
			printf("pubkey:\n");
			for(uint8_t i = 0; i < 65; i++){
				if(printf("%02X", buffer[i]) < 1) return -1;
			}
			printf("\n");
		}else if(!memcmp(instruction, "addServerid ", 12)){
			size_buf[0] = strtoul(instruction+12, 0, 16);
			if(instruction[28] != ' '){
				printf("usage:\naddServerid serverid name\n");
				continue;
			}
			if(sscanf(instruction+29, "%s", buffer) < 1) continue;
			if(serverid_add(buffer, size_buf[0])){
				printf("error with addServerid");
			}
			if(user_server_init(size_buf[0])) continue;
			if(log_server_init(size_buf[0])) continue;
		}else if(!memcmp(instruction, "addServer ", 10)){
			if(sscanf(instruction+10, "%s", buffer) < 1) continue;
			memset(&oper_sockaddr, 0, 16);
			if((oper_sockaddr.sin_addr.s_addr = inet_addr(buffer)) == -1) continue;
			oper_sockaddr.sin_family = AF_INET;
			size_buf[0] = strlen(buffer)+11;
			if(sscanf(instruction+size_buf[0], "%s", buffer) < 1) continue;
			size_buf[0] += strlen(buffer)+1;
			oper_sockaddr.sin_port = strtoul(buffer, 0, 10);
			oper_sockaddr.sin_port = htons(oper_sockaddr.sin_port);
			if(sscanf(instruction+size_buf[0], "%s", buffer) < 1) continue;
			size_buf[1] = strlen(buffer);
			brk = 0;
			for(uint64_t i = 0; i < size_buf[1]/2; i++){
				if(sscanf(instruction+size_buf[0]+2*i, "%2hhX", buffer+i) < 1){
					brk = 1;
					break;
				}
			}
			size_buf[0] += size_buf[1]+1;
			size_buf[1] /= 2;
			if(brk) continue;
			if(sscanf(instruction+size_buf[0], "%s", buffer+size_buf[1]) < 1) continue;
			if(serverid_get_id(buffer+size_buf[1], size_buf+2)) continue;
			if(serverid_add_server(size_buf[2], (uint8_t*)&oper_sockaddr, buffer, 16, size_buf[1], 0)) continue;
		}else if(!memcmp(instruction, "addUserid ", 10)){
			size_buf[0] = strtoul(instruction+10, 0, 16);
			if(instruction[26] != ' '){
				printf("usage:\naddServerid serverid name\n");
				continue;
			}
			if(sscanf(instruction+27, "%s %s", buffer, buffer2) < 1) continue;
			if(serverid_get_id(buffer2, size_buf+1)) continue;
			if(user_add_name(size_buf[1], buffer, size_buf[0])){
				printf("error with addServerid");
			}
		}else if(!memcmp(instruction, "id ", 3)){
			if(sscanf(instruction+3, "%s", buffer) < 1) continue;
			if(serverid_get_id(buffer, (uint64_t*) buffer2)) continue;
			size_buf[0] = 1016;
			if(pk_get_pubkey(buffer2+8, size_buf)) continue;
			if(!EVP_Digest(buffer2, 8+size_buf[0], buffer, 0, EVP_sha3_256(), 0)) continue;
			printf("Id:\n%016lX\n", *(uint64_t*)buffer);
		}else if(!memcmp(instruction, "update ", 7)){
			if(sscanf(instruction+7, "%s", buffer) < 1) continue;
			if(serverid_get_id(buffer, size_buf)) continue;
			if(client_update(password, size_buf[0])) continue;
		}
	}
}
