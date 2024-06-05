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
	fsys_init();
	temp_init();
	user_init();
	log_init();
	return 0;
}

int client_fpost(char* restrict password, uint64_t server_id, char* restrict file_name, char* upname){
	uint64_t threshold = 2;
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
	uint8_t buffer[1024];
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
	uint64_t self_id;
	pid_t oper_pid;
	pid_t child_pid[capacity];
	uint64_t child_pid_len = 0;
	uint8_t oper_sockaddr[16];
	uint64_t sockaddr_len = 16;
	uint64_t pubkey_len = 65;
	uint8_t cnt = 0;
	uint8_t secret[32];
	int pid_state;
	uint8_t aes_key[32];
	uint8_t iv[16];
	uint64_t size_buf[4];
	uint64_t success_cnt = 0;
	uint64_t oper_keyf[threshold*4];
	EVP_MD_CTX* md_ctx;
	memset(child_pid, 0, capacity*sizeof(pid_t));
	if(!(md_ctx = EVP_MD_CTX_new())) return -1;
	if(RAND_bytes(aes_key, 32) != 1) return -1;
	if(RAND_bytes(iv, 32) != 1) return -1;
	memcpy(buffer, &server_id, 8);
	size_buf[0] = 1016;
	pk_get_pubkey(buffer+8, size_buf);
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	EVP_DigestUpdate(md_ctx, buffer, 8+size_buf[0]);
	EVP_DigestFinal(md_ctx, buffer, 0);
	memcpy(&self_id, buffer, 8);
	if(temp_encode(self_id, file_name, aes_key, iv, threshold, upname, password))return -1;
	if(share_key_gen(*(uint64_t*)(aes_key+0), threshold, oper_keyf)) return -1;
	if(share_key_gen(*(uint64_t*)(aes_key+8), threshold, oper_keyf+threshold)) return -1;
	if(share_key_gen(*(uint64_t*)(aes_key+16), threshold, oper_keyf+threshold*2)) return -1;
	if(share_key_gen(*(uint64_t*)(aes_key+24), threshold, oper_keyf+threshold*3)) return -1;
	printf("\nstart fpost\n");
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
			if(client_login(server_id, oper_sock, socket_buffer_size, password, secret, server_pubkey, pubkey_len)) return -1;
			if(client_process_fpost(server_id, server_userid, self_id, oper_keyf, threshold, oper_sock, *(struct sockaddr_in*)oper_sockaddr, socket_buffer_size, password, secret, server_pubkey, pubkey_len, upname)) return -1;
			shutdown(oper_sock, SHUT_RDWR);
			return 0;
		}
	}
	int wait_status;
	for(int i = 0; i < capacity; i++){
		if(!child_pid[i]) continue;
		if(waitpid(child_pid[i], &wait_status, 0) > 0){
			if(WIFEXITED(wait_status)){
				if(!WEXITSTATUS(wait_status)){
					success_cnt += 1;
				}
			}
		}
	}
	temp_encode_clean(upname);
	printf("success:%lu\n", success_cnt);
	EVP_MD_CTX_free(md_ctx);
	return 0;
}

int client_fget(char* restrict password, uint64_t server_id, uint64_t call_id, char* restrict file_name, char* upname){
	struct stat oper_stat;
	int file_fd;
	if(access("config", F_OK|R_OK)){
		client_err("access config");
	}
	int oper_fd;
	FILE* oper_file;
	uint8_t buffer[1024];
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
	uint8_t secret[32];
	uint64_t success_cnt = 0;
	uint8_t log_id[9];
	int pid_state;
	memset(child_pid, 0, capacity*sizeof(pid_t));
	printf("\nstart fget\n");
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
			if(client_login(server_id, oper_sock, socket_buffer_size, password, secret, server_pubkey, pubkey_len)) exit(-1);
			if(client_process_fget(server_id, server_userid, oper_sock, *(struct sockaddr_in*)oper_sockaddr, socket_buffer_size, password, secret, server_pubkey, pubkey_len, call_id, upname)) exit(-1);
			shutdown(oper_sock, SHUT_RDWR);
			exit(0);
		}
	}
	uint8_t iv[16];
	uint8_t check_hash[32];
	uint64_t threshold = 2;
	uint64_t file_size;
	int wait_status;
	for(int i = 0; i < capacity; i++){
		if(!child_pid[i]) continue;
		if(waitpid(child_pid[i], &wait_status, 0) > 0){
			if(WIFEXITED(wait_status)){
				if(!WEXITSTATUS(wait_status)){
					success_cnt += 1;
				}
			}
		}
	}
	printf("success:%lu\n", success_cnt);
	if(log_get_content(server_id, call_id, upname, log_id)){
		printf("fail fget, update first1\n");
		temp_decode_clean(upname);
		return -1;
	}
	if((oper_fd = log_content(server_id, log_id, O_RDONLY)) == -1){
		printf("fail fget, update first2\n");
		temp_decode_clean(upname);
		return -1;
	}
	if(read(oper_fd, buffer, 1024) == -1){
		printf("errno:%d\n", errno);
		close(oper_fd);
		return -1;
	}
	close(oper_fd);
	memcpy(iv, buffer+68, 16);
	memcpy(check_hash, buffer+84, 32);
	memcpy(&threshold, buffer+28, 8);
	memcpy(&file_size, buffer+20, 8);
	printf("size:%ld\n", file_size);
	if(temp_decode(file_name, 0, iv, check_hash, threshold, upname)){
		printf("decode fail\nmight update first\n");
		temp_decode_clean(upname);
		return 0;
	}
	if(truncate(file_name, file_size) == -1){
		printf("trunc fail\n");
		temp_decode_clean(upname);
		return 0;
	}
	temp_decode_clean(upname);
	return 0;
}

int client_update(char* restrict password, uint64_t server_id){
	struct stat oper_stat;
	int file_fd;
	if(access("config", F_OK|R_OK)){
		client_err("access config");
	}
	int oper_fd;
	FILE* oper_file;
	uint8_t buffer[1024];
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
	uint64_t success_cnt = 0;
	pid_t oper_pid;
	pid_t child_pid[capacity];
	uint64_t child_pid_len = 0;
	uint8_t oper_sockaddr[16];
	uint64_t sockaddr_len = 16;
	uint64_t pubkey_len = 65;
	uint8_t cnt = 0;
	uint8_t secret[32];
	int pid_state;
	memset(child_pid, 0, capacity*sizeof(pid_t));
	printf("\nstart update\n");
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
			if(client_login(server_id, oper_sock, socket_buffer_size, password, secret, server_pubkey, pubkey_len)) exit(-1);
			if(client_process_update(server_id, server_userid, oper_sock, *(struct sockaddr_in*)oper_sockaddr, socket_buffer_size, password, secret, server_pubkey, pubkey_len)) exit(-1);
			shutdown(oper_sock, SHUT_RDWR);
			exit(0);
		}
	}
	int wait_status;
	for(int i = 0; i < capacity; i++){
		if(!child_pid[i]) continue;
		if(waitpid(child_pid[i], &wait_status, 0) > 0){
			if(WIFEXITED(wait_status)){
				if(!WEXITSTATUS(wait_status)){
					success_cnt += 1;
				}
			}
		}
	}
	printf("success:%lu\n", success_cnt);
	return 0;
}

int client_clone(char* restrict password, uint64_t server_id){
	struct stat oper_stat;
	int file_fd;
	if(access("config", F_OK|R_OK)){
		client_err("access config");
	}
	int oper_fd;
	FILE* oper_file;
	uint8_t buffer[1024];
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
	uint8_t secret[32];
	int pid_state;
	printf("\nstart fget\n");
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
			if(client_login(server_id, oper_sock, socket_buffer_size, password, secret, server_pubkey, pubkey_len)) return -1;
			shutdown(oper_sock, SHUT_RDWR);
			return 0;
		}
	}
	return 0;
}
