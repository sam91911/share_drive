#include "login.h"
#ifndef LOGIN_REPLY_TIME
#define LOGIN_REPLY_TIME 60
#endif

int server_login(uint64_t server_id, int sock, struct sockaddr_in addr, uint64_t buffer_size, uint64_t* client_id, char* restrict password, uint8_t* secret){
	uint8_t buffer[buffer_size];
	uint8_t sbuffer[1024];
	int64_t read_bytes;
	uint16_t version;
	uint64_t user_id;
	uint64_t self_id;
	int oper_fd;
	uint64_t oper_str_len;
	uint8_t oper_str[256];
	FILE* oper_file;
	time_t timen;
	uint64_t size_buf[4];
	EVP_MD_CTX* md_ctx;
	if(!(md_ctx = EVP_MD_CTX_new())) return -1;
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	if((read_bytes = recv(sock, buffer, 20, MSG_WAITALL)) == -1) return -3;
	if(read_bytes < 12) return -1;
	uint8_t method;
	uint8_t pack_id;
	uint16_t plen;
	uint16_t pflag;
	uint64_t signlen;
	uint8_t log_id[9];
	version = (*(uint16_t*)(buffer+0));
	method = (*(uint8_t*)(buffer+2));
	pack_id = (*(uint8_t*)(buffer+3));
	if(version > 0) return -1;
	if((*(uint64_t*)(buffer+4)) != server_id) return -1;
	switch(method){
		case METHOD_LOGIN:
			if(pack_id != 0) return -1;
			if(read_bytes < 20) return -1;
			user_id = (*(uint64_t*)(buffer+12));
			if(user_checkid(server_id, user_id)) return -2;
			(*(uint64_t*)(oper_str+0)) = server_id;
			oper_str_len = 65;
			if(pk_get_pubkey(oper_str+8, &oper_str_len)) return -1;
			(*(uint16_t*)(sbuffer+0)) = version;
			(*(uint8_t*)(sbuffer+2)) = method;
			(*(uint8_t*)(sbuffer+3)) = 1;
			(*(uint64_t*)(sbuffer+4)) = server_id;
			(*(uint64_t*)(oper_str)) = server_id;
			if(!EVP_Digest(oper_str, oper_str_len+8, sbuffer+12, 0, EVP_sha3_256(), 0)) return -1;
			(*(uint64_t*)(sbuffer+20)) = user_id;
			(*(int64_t*)(sbuffer+28)) = time(0);
			(*(int64_t*)(sbuffer+36)) = (*(int64_t*)(sbuffer+28)) + LOGIN_REPLY_TIME;
			if(RAND_bytes(sbuffer+44, 16) != 1) return -3;
			if(send(sock, sbuffer, 60, 0) == -1) return -3;
			if((read_bytes = recv(sock, buffer, 44, MSG_WAITALL)) == -1) return -3;
			if(read_bytes < 44) return -1;
			if(*(uint16_t*)(buffer+0) != 0) return -1;
			if(*(uint8_t*)(buffer+2) != METHOD_LOGIN) return -1;
			if(*(uint8_t*)(buffer+3) != 2) return -1;
			if(*(uint64_t*)(buffer+4) != server_id) return -1;
			if(*(uint64_t*)(buffer+12) != user_id) return -1;
			memcpy(size_buf, buffer+20, 8);
			oper_str_len = 65;
			if((read_bytes = recv(sock, buffer+44, size_buf[0], MSG_WAITALL)) == -1) return -3;
			if(user_pubkey(server_id, user_id, oper_str)) return -1;
			if(pk_verify(oper_str, 65, sbuffer, 60, buffer+44, size_buf[0]) != 1) return -1;
			EVP_DigestInit(md_ctx, EVP_sha3_256());
			EVP_DigestUpdate(md_ctx, buffer, 44+size_buf[0]);
			(*(uint8_t*)(sbuffer+3)) = 3;
			(*(uint64_t*)(sbuffer+20)) = 996;
			if(pk_sign(buffer, 44, sbuffer+28, (uint64_t*)(sbuffer+20), password)) return -1;
			EVP_DigestUpdate(md_ctx, sbuffer, 28+(*(uint64_t*)(sbuffer+20)));
			EVP_DigestFinal(md_ctx, secret, 0);
			EVP_MD_CTX_free(md_ctx);
			if(send(sock, sbuffer, 28+(*(uint64_t*)(sbuffer+20)), 0) == -1) return -1;
			if(client_id){
				*client_id = user_id;
			}
			break;
		case METHOD_LOG:
			if((read_bytes = recv(sock, buffer+20, 12, MSG_WAITALL)) == -1) return -3;
			if(pack_id != 0) return -1;
			if(read_bytes < 20) return -1;
			user_id = (*(uint64_t*)(buffer+12));
			memcpy(&plen, buffer+20, 2);
			memcpy(&pflag, buffer+22, 2);
			if(user_checkid(server_id, user_id)) return -2;
			if(user_pubkey(server_id, user_id, oper_str)) return -1;
			if(pflag) return -1;
			if((read_bytes = recv(sock, buffer+24, plen+8, MSG_WAITALL)) == -1) return -3;
			memcpy(&signlen, buffer+24+plen, 8);
			if((read_bytes = recv(sock, buffer+plen+32, signlen, MSG_WAITALL)) == -1) return -3;
			if(pk_verify(oper_str, 65, buffer+32, plen, buffer+plen+32, signlen) != 1) return -1;
			if(log_add(server_id, buffer+32, plen+8+signlen, log_id)) return -1;
			switch(buffer[26]){
				case METHOD_LOG:
					printf("MSG by:%016lX\nsend at:%s\n", user_id, ctime((time_t*)(buffer+38)));
					if(write(STDOUT_FILENO, buffer+46, plen-16) == -1) break;
					printf("\n");
					break;
				case METHOD_POST:
					memcpy(size_buf, buffer+28, 8);
					size_buf[1] = buffer[152];
					memcpy(oper_str, buffer+153, size_buf[1]);
					oper_str[size_buf[1]] = '\0';
					log_add_content(server_id, size_buf[0], oper_str, log_id);
					break;
				case METHOD_SIGNREG:
					memcpy(size_buf, buffer+44, 8);
					if(user_add(server_id, buffer+52, size_buf[0])) break;
					break;
				case METHOD_CLONE:
					memcpy(size_buf, buffer+28, 8);
					memcpy(size_buf+1, buffer+44, 8);
					if(user_pubkey(server_id, size_buf[0], sbuffer)) break;
					if(serverid_add_server(server_id, buffer+52, sbuffer, 16, 65, 0)) break;
					break;
			}
			break;
		default:
			return -1;
	}
	return 0;
}

int client_login(uint64_t server_id, int sock, uint64_t buffer_size, char* restrict password, uint8_t* secret, uint8_t* server_pubkey, uint64_t pubkey_len){
	uint8_t buffer[buffer_size];
	uint8_t sbuffer[1024];
	int64_t read_bytes;
	uint16_t version;
	int oper_fd;
	uint64_t oper_str_len;
	uint64_t self_id;
	uint64_t remote_id;
	uint8_t oper_str[256];
	uint64_t size_buf[4];
	FILE* oper_file;
	time_t timen;
	version = 0;
	EVP_MD_CTX* md_ctx;
	if(!(md_ctx = EVP_MD_CTX_new())) return -1;
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	*(uint16_t*)(sbuffer+0) = version;
	*(uint8_t*)(sbuffer+2) = METHOD_LOGIN;
	*(uint8_t*)(sbuffer+3) = 0;
	*(uint64_t*)(sbuffer+4) = server_id;
	*(uint64_t*)(oper_str+0) = server_id;
	oper_str_len = 65;
	memcpy(oper_str+8, server_pubkey, pubkey_len);
	if(!EVP_Digest(oper_str, pubkey_len+8, sbuffer+12, 0, EVP_sha3_256(), 0)) return -1;
	remote_id = *(uint64_t*)(sbuffer+12);
	oper_str_len = 65;
	if(pk_get_pubkey(oper_str+8, &oper_str_len)) return -1;
	if(!EVP_Digest(oper_str, oper_str_len+8, sbuffer+12, 0, EVP_sha3_256(), 0)) return -1;
	self_id = *(uint64_t*)(sbuffer+12);
	if((read_bytes = send(sock, sbuffer, 20, 0)) == -1){
		printf("errno:%02X", errno);
		return -3;
	}
	if((read_bytes = recv(sock, buffer, 60, MSG_WAITALL)) == -1) return -3;
	if(read_bytes < 60) return -1;
	if(*((uint16_t*) buffer) != 0) return -1;
	if(buffer[2] != METHOD_LOGIN) return -1;
	if(buffer[3] != 1) return -1;
	if(*(uint64_t*)(buffer+4) != server_id) return -1;
	if(*(uint64_t*)(buffer+12) != remote_id){
		return -1;
	}
	if(*(uint64_t*)(buffer+20) != self_id) return -1;
	timen = time(0);
	if(*(time_t*)(buffer+28) > timen) return -1;
	if(*(time_t*)(buffer+36) < timen) return -1;
	*(uint8_t*)(sbuffer+3) = 2;
	if(RAND_bytes(sbuffer+28, 16) != 1) return -3;
	*(uint64_t*)(sbuffer+20) = 980;
	if(pk_sign(buffer, 60, sbuffer+44, (uint64_t*)(sbuffer+20), password)) return -1;
	EVP_DigestUpdate(md_ctx, sbuffer, 44+(*(uint64_t*)(sbuffer+20)));
	if((read_bytes = send(sock, sbuffer, 44+(*(uint64_t*)(sbuffer+20)), 0)) == -1){
		return -3;
	}
	if((read_bytes = recv(sock, buffer, 28, MSG_WAITALL)) == -1) return -3;
	if(read_bytes < 28) return -1;
	if(*(uint16_t*)(buffer+0) != 0) return -1;
	if(*(uint8_t*)(buffer+2) != METHOD_LOGIN) return -1;
	if(*(uint8_t*)(buffer+3) != 3) return -1;
	if(*(uint64_t*)(buffer+4) != server_id) return -1;
	if(*(uint64_t*)(buffer+12) != remote_id) return -1;
	memcpy(size_buf, buffer+20, 8);
	if((read_bytes = recv(sock, buffer+28, size_buf[0], MSG_WAITALL)) == -1) return -3;
	if(pk_verify(server_pubkey, pubkey_len, sbuffer, 44, buffer+28, size_buf[0]) != 1) return -1;
	EVP_DigestUpdate(md_ctx, buffer, 28+size_buf[0]);
	EVP_DigestFinal(md_ctx, secret, 0);
	EVP_MD_CTX_free(md_ctx);
	return 0;
}

int login_log(uint64_t server_id, int sock, uint64_t buffer_size, char* restrict password, uint8_t* data, uint64_t len){
	uint8_t sbuffer[len+32+256];
	int64_t read_bytes;
	uint16_t version;
	int oper_fd;
	uint64_t oper_str_len;
	uint64_t self_id;
	uint64_t remote_id;
	uint8_t oper_str[256];
	uint64_t size_buf[4];
	FILE* oper_file;
	time_t timen;
	uint16_t pflag = 0x0000;
	version = 0;
	memcpy(sbuffer, &version, 2);
	sbuffer[2] = METHOD_LOG;
	sbuffer[3] = 0x00;
	memcpy(sbuffer+4, &server_id, 8);
	memcpy(oper_str, &server_id, 8);
	if(pk_get_pubkey(oper_str+8, &oper_str_len)) return -1;
	if(!EVP_Digest(oper_str, oper_str_len+8, sbuffer+12, 0, EVP_sha3_256(), 0)) return -1;
	if(pk_sign(data, len, sbuffer+len+32, (uint64_t*)(sbuffer+24+len), password)) return -1;
	memcpy(sbuffer+32, data, len);
	memcpy(sbuffer+20, &len, 2);
	memcpy(sbuffer+22, &pflag, 2);
	if(send(sock, sbuffer, 32+len+(*(uint64_t*)(sbuffer+24+len)), 0) == -1) return -1;
	return 0;
}
int login_signreg(char* restrict password, uint64_t server_id, uint8_t* sign_pubkey, uint64_t sign_publen){
	struct stat oper_stat;
	int file_fd;
	if(access("config", F_OK|R_OK)){
		return -1;
	}
	int oper_fd;
	FILE* oper_file;
	uint8_t buffer[1024];
	uint8_t key[256], value[256];
	uint64_t socket_buffer_size;
	uint64_t capacity;
	if((oper_fd = open("config", O_RDONLY)) == -1){
		return -1;
	}
	if(!(oper_file = fdopen(oper_fd, "r"))){
		return -1;
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
	int pid_state;
	if(logfile_signreg(server_id, sign_pubkey, sign_publen, buffer)) return -1;
	memset(child_pid, 0, capacity*sizeof(pid_t));
	if((oper_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		return -1;
	}
	for(uint64_t server_offset = 0;
			!serverid_get_server(server_id, server_offset, oper_sockaddr, server_pubkey, &sockaddr_len, &pubkey_len, 0, &server_userid);
			({server_offset += sockaddr_len+pubkey_len+32; sockaddr_len = 16; pubkey_len = 65;})){
		if(child_pid_len == capacity){
			for(uint64_t i = 0; i < capacity; i++){
				if(kill(child_pid[i], 0) == -1){
					if(errno == ESRCH) continue;
					return -1;
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
					return -1;
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
				continue;
			}else{
				return -1;
			}
		}
		if((oper_pid = fork()) == -1){
			return -1;
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
			if(login_log(server_id, oper_sock, socket_buffer_size, password, buffer, 28+sign_publen)) exit(-1);
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


int login_clone(char* restrict password, uint64_t server_id, uint8_t* addr, uint64_t addr_len){
	struct stat oper_stat;
	int file_fd;
	if(access("config", F_OK|R_OK)){
		return -1;
	}
	int oper_fd;
	FILE* oper_file;
	uint8_t buffer[1024];
	uint8_t key[256], value[256];
	uint64_t socket_buffer_size;
	uint64_t capacity;
	if((oper_fd = open("config", O_RDONLY)) == -1){
		return -1;
	}
	if(!(oper_file = fdopen(oper_fd, "r"))){
		return -1;
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
	int pid_state;
	if(logfile_signreg(server_id, addr, addr_len, buffer)) return -1;
	memset(child_pid, 0, capacity*sizeof(pid_t));
	if((oper_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		return -1;
	}
	for(uint64_t server_offset = 0;
			!serverid_get_server(server_id, server_offset, oper_sockaddr, server_pubkey, &sockaddr_len, &pubkey_len, 0, &server_userid);
			({server_offset += sockaddr_len+pubkey_len+32; sockaddr_len = 16; pubkey_len = 65;})){
		if(child_pid_len == capacity){
			for(uint64_t i = 0; i < capacity; i++){
				if(kill(child_pid[i], 0) == -1){
					if(errno == ESRCH) continue;
					return -1;
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
					return -1;
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
				continue;
			}else{
				return -1;
			}
		}
		if((oper_pid = fork()) == -1){
			return -1;
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
			if(login_log(server_id, oper_sock, socket_buffer_size, password, buffer, 28+addr_len)) exit(-1);
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
