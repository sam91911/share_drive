#include "server.h"
#include "method.h"
#include "signreg.h"
#include "client.h"
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <openssl/rand.h>

#ifndef INSTRUCT_LEN
#define INSTRUCT_LEN 1024
#endif

#ifndef BUFFER_LEN
#define BUFFER_LEN 1024
#endif

int main(const int argc, char** argv){
	char* root_dir = 0;
	char* password = 0;
	char password_str[256];
	struct termios oper_term, temp_term;
	char instruction[INSTRUCT_LEN];
	uint8_t buffer[BUFFER_LEN];
	key_t ipc_key = IPC_PRIVATE;
	pid_t server_pid = 0;
	int oper_msg;
	int oper_fd;
	uint32_t flag = 0;
	uint8_t brk;
	struct stat oper_stat;
	uint64_t server_id;
	uint8_t init_flag = 0;
	int pid_state;
	uint64_t size_buf[4];
	if((oper_msg = msgget(ipc_key, O_CREAT)) == -1) return -1;
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
				case 'r':
					flag |= 0x80000000;
					break;
				case 'i':
					init_flag = 1;
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
	if(server_getid(&server_id)){
		if(init_flag){
			server_init(password, 0);
		}else{
			printf("server do not init\nplease init first\n");
		}
	}
	while(1){
		if(root_dir){
			if(printf("server:%s>", root_dir) < 0) return -1;
		}else{
			if(printf("server>") < 0) return -1;
		}
		if(!fgets(instruction, INSTRUCT_LEN, stdin)) continue;
		if(!strcmp(instruction, "init\n")){
			server_init(password, 0);
			server_getid(&server_id);
			continue;
		}else if(!strcmp(instruction, "start\n")){
			if(server_pid){
				if(!kill(server_pid, 0)){
					if(!waitpid(server_pid, &pid_state, WNOHANG)){
						if(printf("server has been started\n") < 0) return -1;
						continue;
					}
				}else{
					if(errno != ESRCH) return -1;
					server_pid = 0;
				}
			}
			if((server_pid = fork()) == -1){
				return -1;
			}
			if(server_pid){
				continue;
			}else{
				server_start(password, oper_msg, flag);
				return 0;
			}
		}else if(!strcmp(instruction, "exit\n")){
exit:
			if(server_pid){
				if(kill(server_pid, SIGKILL)) abort();
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
		}else if(!strcmp(instruction, "signreg\n")){
			if(RAND_bytes(buffer, 32) != 1) continue;
			if(signreg_add(buffer, 0, 0)) continue;
			printf("copy the following code to your member:\n");
			for(uint8_t i = 0; i < 32; i++){
				printf("%02X", buffer[i]);
			}
			printf("\n");
		}else if(!strcmp(instruction, "serverid\n")){
			if(server_getid(size_buf)) continue;
			printf("serverid:\n%016lX\n", size_buf[0]);
		}else if(!memcmp(instruction, "signreg ", 8)){
			if(strlen(instruction) < 139) continue;
			brk = 0;
			for(uint8_t i = 0; i < 65; i++){
				if(sscanf(instruction+8+(2*i), "%2hhX", buffer+i) < 1){
					brk = 1;
					break;
				}
			}
			if(brk) continue;
			if(user_add(server_id, buffer, 65)) return -1;
		}else if(!memcmp(instruction, "update\n", 7)){
			if(client_update(password, server_id)) continue;
		}
	}
}
