#include "server.h"
#ifndef SERVER_CLIENT_BUFFER
#define SERVER_CLIENT_BUFFER 4096
#endif

void server_err(const char* restrict error_message){	
	if(!error_message){
		fprintf(stderr, "server:\nerrno:\t%02x\n", errno);
	}else{
		fprintf(stderr, "server:\t%s\nerrno:\t%02x\n", error_message, errno);
	}
	exit(-1);
}

int server_init(char* restrict password){
	struct stat oper_stat;
	int oper_fd;
	FILE* oper_file;
	uint8_t rand_buffer[1024];
	uint8_t oper_str[65];
	uint64_t oper_str_len;
	uint64_t oper_serverid;
	if((oper_fd = open("config", O_CREAT|O_WRONLY, 0644)) == -1){
		server_err("open config");
	}
	const char* config_init =
		"server_ipv4 = 127.0.0.1\n"
		"server_main_port = 8000\n"
		"server_filetrans_port_min = 8001\n"
		"server_filetrans_port_max = 8001\n"
		"server_capacity = 5\n"
		"socket_buffer_size = 4096\n";
	if(write(oper_fd, config_init, strlen(config_init)) == -1){
		server_err("write config");		
	}
	oper_file = fdopen(oper_fd, "w");
	if(RAND_bytes((uint8_t *)&oper_serverid, 8) != 1) server_err("RAND_bytes");
	fprintf(oper_file, "serverid = %016lX\n", oper_serverid);
	fclose(oper_file);
	close(oper_fd);
	if((oper_fd = open("serverlist", O_CREAT|O_WRONLY, 0644)) == -1){
		server_err("open serverlist");
	}
	close(oper_fd);
	if(log_init()) return -1;
	if(log_server_init(oper_serverid)) return -1;
	if(pk_init(password)) return -1;
	if(pk_get_pubkey(oper_str, &oper_str_len)) return -1;
	if(user_init()) server_err("user_init");
	if(user_server_init(oper_serverid)) server_err("fsys server init");
	if(user_add(oper_serverid, oper_str, 65)) server_err("user_add");
	if(signreg_init()) server_err("signreg init");
	if(fsys_init()) server_err("fsys init");
	return 0;
}

int server_getid(uint64_t* id){
	if(access("config", F_OK|R_OK)){
		return -1;
	}
	int oper_fd;
	FILE* oper_file;
	uint8_t key[256], value[256];
	uint64_t server_id;
	if((oper_fd = open("config", O_RDONLY)) == -1){
		return -1;
	}
	if(!(oper_file = fdopen(oper_fd, "r"))){
		return -1;
	}
	while(!feof(oper_file)){
		if(fscanf(oper_file, "%255s = %255s\n", key, value) == -1) break;
		if(!strcmp("serverid", key)){
			fclose(oper_file);
			close(oper_fd);
			if(id){
				*id = strtoul(value, 0, 16);
			}
			return 0;
		}
	}
	fclose(oper_file);
	close(oper_fd);
	return 1;
}

int server_start(char* restrict password, int oper_msg, uint32_t flag){
	if(access("config", F_OK|R_OK)){
		server_err("access config");
	}
	struct stat oper_stat;
	int oper_fd;
	FILE* oper_file;
	uint8_t rand_buffer[1024];
	uint8_t key[256], value[256];
	uint8_t ipv4[16];
	uint16_t port, port_min, port_max;
	uint64_t capacity;
	uint64_t socket_buffer_size;
	uint64_t server_id;
	if((oper_fd = open("config", O_RDONLY)) == -1){
		server_err("open config");
	}
	if(!(oper_file = fdopen(oper_fd, "r"))){
		server_err("fdopen");
	}
	while(!feof(oper_file)){
		if(fscanf(oper_file, "%255s = %255s\n", key, value) == -1) break;
		if(!strcmp("server_ipv4", key)){
			memcpy(ipv4, value, 16);
		}else if(!strcmp("server_main_port", key)){
			port = strtoul(value, 0, 10);
		}else if(!strcmp("server_filetrans_port_min", key)){
			port_min = strtoul(value, 0, 10);
		}else if(!strcmp("server_filetrans_port_max", key)){
			port_max = strtoul(value, 0, 10);
		}else if(!strcmp("server_capacity", key)){
			capacity = strtoul(value, 0, 10);
		}else if(!strcmp("socket_buffer_size", key)){
			socket_buffer_size = strtoul(value, 0, 10);
		}else if(!strcmp("serverid", key)){
			server_id = strtoul(value, 0, 16);
		}else{
		}
	}
	fclose(oper_file);
	close(oper_fd);
	int main_sock;
	int sock_opt = 1;
	if((main_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		server_err("socket main_sock");
	}
	if(flag&0x80000000){
		printf("reuse\n");
		if(setsockopt(main_sock, SOL_SOCKET, SO_REUSEADDR|SO_REUSEPORT, &sock_opt, sizeof(int))) server_err("setsockopt");
	}
	struct sockaddr_in main_sockaddr;
	memset(&main_sockaddr, 0, sizeof(struct sockaddr_in));
	main_sockaddr.sin_family = AF_INET;
	main_sockaddr.sin_port = htons(port);
	main_sockaddr.sin_addr.s_addr = inet_addr(ipv4);
	if(bind(main_sock, (struct sockaddr*)&main_sockaddr, sizeof(struct sockaddr_in))){
		server_err("bind");
	}
	if(listen(main_sock, capacity)){
		server_err("listen");
	}
	struct sockaddr_in client_sockaddr;
	memset(&client_sockaddr, 0, sizeof(struct sockaddr_in));
	socklen_t addr_size = sizeof(struct sockaddr_in);
	int client_sock;
	pid_t oper_pid;
	pid_t client_pid[capacity];
	uint64_t client_pid_len = 0;
	uint8_t msg_buffer[1032];
	uint8_t secret[32];
	size_t msg_size;
	int pid_state;
	printf("\nstart listen\nipv4:\t%s\nport:\t%hd\nserverid:%016lx\n", ipv4, port, server_id);
	while(1){
		while(client_pid_len == capacity){
			for(uint64_t i = 0; i < capacity; i++){
				if(kill(client_pid[i], 0) == -1){
					if(errno == ESRCH) continue;
					server_err("kill");
				}
				if(!waitpid(client_pid[i], &pid_state, WNOHANG)){
					continue;
				}
				client_pid[i] = 0;
				client_pid_len--;
			}
		}
		if((client_sock = accept(main_sock, (struct sockaddr*)&client_sockaddr, &addr_size)) == -1){
			server_err("accept");
		}
		if((oper_pid = fork()) == -1){
			server_err("fork");
		}
		if(oper_pid){
			for(uint64_t i = 0; i < capacity; i++){
				if(!client_pid[i]){
					client_pid[i] = oper_pid;
					client_pid_len++;
					break;
				}
			}
		}else{
			uint64_t client_id;
			if(server_login(server_id, client_sock, client_sockaddr, socket_buffer_size, &client_id, password, secret)){
				shutdown(client_sock, SHUT_RDWR);
				return 0;
			}
			if(server_process(server_id, client_sock, client_sockaddr, socket_buffer_size, client_id, password, secret)){
				shutdown(client_sock, SHUT_RDWR);
				return 0;
			}
			shutdown(client_sock, SHUT_RDWR);
			return 0;
		}
	}
	return 0;
}
