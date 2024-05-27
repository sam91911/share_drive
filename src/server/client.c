#include "client.h"

void client_err(const char* restrict error_message){
	if(!error_message){
		fprintf(stderr, "client:\nerrno:\t%02x\n", errno);
	}else{
		fprintf(stderr, "client:\t%s\nerrno:\t%02x\n", error_message, errno);
	}
	exit(-1);
}
int client_init(char* restrict password){
	struct stat oper_stat;
	int oper_fd;
	FILE* oper_file;
	uint8_t rand_buffer[1024];
	uint8_t* oper_str;
	ssize_t oper_str_len;
	if((oper_fd = open("config", O_CREAT|O_WRONLY, 0644)) == -1){
		client_err("open config");
	}
	const char* config_init =
		"capacity = 5\n"
		"socket_buffer_size = 4096\n";
	if(write(oper_fd, config_init, strlen(config_init)) == -1){
		client_err("write config");		
	}
	close(oper_fd);
	pk_init(password);
	serverid_init();
	return 0;
}

int client_fpost(char* restrict password, uint64_t server_id, const char* restrict file_name){
	struct stat oper_stat;
	int file_fd;
	if(access(file_name, F_OK|R_OK)) client_err("access file_name");
	if(stat(file_name, &oper_stat)){
		client_err("stat file_name");
	}
	if(!(S_IFREG&(oper_stat.st_mode))){
		client_err("root_dir not a regular file");
	}
	if((file_fd = open(file_name, O_RDONLY)) == -1){
		client_err("open file_name");
	}
	if(access("config", F_OK|R_OK)){
		client_err("access config");
	}
	int oper_fd;
	FILE* oper_file;
	uint8_t rand_buffer[1024];
	uint8_t key[256], value[256];
	uint64_t socket_buffer_size;
	uint64_t capacity;
	if((oper_fd = open("config", O_RDONLY)) == -1){
		client_err("open config");
	}
	if(!(oper_file = fdopen(oper_fd, "r"))){
		client_err("fdopen");
	}
	while(!feof(oper_file)){
		if(fscanf(oper_file, "%255s = %255s\n", key, value) == -1) break;
		if(!strcmp("socket_buffer_size", key)){
			socket_buffer_size = strtoul(value, 0, 10);
		}else if(!strcmp("capacity", key)){
			capacity = strtoul(value, 0, 10);
		}else{
		}
	}
	fclose(oper_file);
	close(oper_fd);
	int oper_sock;
	int list_sock[capacity];
	uint8_t server_pubkey[65];
	uint64_t server_userid;
	pid_t oper_pid;
	pid_t child_pid[capacity];
	uint64_t child_pid_len = 0;
	uint8_t oper_sockaddr[16];
	uint64_t sockaddr_len = 16;
	uint64_t pubkey_len = 65;
	uint8_t cnt = 0;
	int pid_state;
	printf("\nstart ftrans\n");
	if((oper_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) client_err("socket");
	for(uint64_t server_offset = 0;
			!serverid_get_server(server_id, server_offset, oper_sockaddr, server_pubkey, &sockaddr_len, &pubkey_len, 0, &server_userid);
			({server_offset += sockaddr_len+pubkey_len+32; sockaddr_len = 16; pubkey_len = 65;})){
		if(child_pid_len == capacity){
			for(uint64_t i = 0; i < capacity; i++){
				if(kill(child_pid[i], 0) == -1){
					if(errno == ESRCH) continue;
					client_err("kill");
				}
				if(!waitpid(child_pid[i], &pid_state, WNOHANG)){
					continue;
				}
				child_pid[i] = 0;
				child_pid_len--;
			}
		}
		while(child_pid_len == capacity){
			sleep(1);
			for(uint64_t i = 0; i < capacity; i++){
				if(kill(child_pid[i], 0) == -1){
					if(errno == ESRCH) continue;
					client_err("kill");
				}
				if(!waitpid(child_pid[i], &pid_state, WNOHANG)){
					continue;
				}
				child_pid[i] = 0;
				child_pid_len--;
			}
		}
		if(connect(oper_sock, (struct sockaddr*)oper_sockaddr, sockaddr_len) == -1){
			if(errno == ECONNREFUSED){
				printf("refused\n");
				continue;
			}else{
				client_err("connect");
			}
		}
		if((oper_pid = fork()) == -1){
			client_err("fork");
		}
		if(oper_pid){
			for(uint64_t i = 0; i < capacity; i++){
				if(!child_pid[i]){
					child_pid[i] = oper_pid;
					list_sock[i] = oper_sock;
					child_pid_len++;
					break;
				}
			}
			oper_sock = socket(AF_INET, SOCK_STREAM, 0);
		}else{
			if(client_login(server_id, oper_sock, socket_buffer_size, password, server_pubkey, pubkey_len)) return -1;
			shutdown(oper_sock, SHUT_RDWR);
			return 0;
		}
	}
	return 0;
}
