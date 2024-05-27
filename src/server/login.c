#include "login.h"

int server_login(uint64_t server_id, int sock, struct sockaddr_in addr, uint64_t buffer_size, uint64_t* client_id, const char* restrict password){
	uint8_t buffer[buffer_size];
	uint8_t sbuffer[1024];
	int64_t read_bytes;
	uint16_t version;
	uint64_t user_id;
	uint64_t self_id;
	uint8_t user_pubkey[65];
	int oper_fd;
	uint64_t oper_str_len;
	uint8_t oper_str[256];
	FILE* oper_file;
	time_t timen;
	memset(sbuffer, 0, 1024);
	printf("server login\n");
	if((read_bytes = recv(sock, buffer, buffer_size, 0)) == -1) return -3;
	if(read_bytes < 12) return -1;
	uint8_t method;
	uint8_t pack_id;
	version = (*(uint16_t*)(buffer+0));
	method = (*(uint8_t*)(buffer+2));
	pack_id = (*(uint8_t*)(buffer+3));
	if(version > 0) return -1;
	if((*(uint64_t*)(buffer+4)) != server_id) return -1;
	switch(method){
		case METHOD_LOGIN:
			printf("recv login\n");
			if(pack_id != 0) return -1;
			if(read_bytes < 20) return -1;
			user_id = (*(uint64_t*)(buffer+12));
			if(user_checkid(user_id)) return -2;
			printf("\nuser login success\n");
			(*(uint64_t*)(oper_str+0)) = server_id;
			if(pk_get_pubkey(oper_str+8, &oper_str_len)) return -1;
			(*(uint16_t*)(sbuffer+0)) = version;
			(*(uint8_t*)(sbuffer+2)) = method;
			(*(uint8_t*)(sbuffer+3)) = 1;
			(*(uint64_t*)(sbuffer+4)) = server_id;
			if(!EVP_Digest(oper_str, oper_str_len+8, sbuffer+12, 0, EVP_sha3_256(), 0)) return -1;
			(*(uint64_t*)(sbuffer+20)) = user_id;
			(*(int64_t*)(sbuffer+28)) = time(0);
			if(RAND_bytes(sbuffer+36, 16) != 1) return -3;
			if(send(sock, sbuffer, 52, 0) == -1) return -3;
			if((read_bytes = recv(sock, buffer, buffer_size, 0)) == -1) return -3;
			break;
		case METHOD_REGISTER:
			break;
		case METHOD_SIGNREG:
			break;
		default:
			return -1;
	}
	return 0;
}

int client_login(uint64_t server_id, int sock, uint64_t buffer_size, const char* restrict password, uint8_t* server_pubkey, uint64_t pubkey_len){
	uint8_t buffer[buffer_size];
	uint8_t sbuffer[1024];
	int64_t read_bytes;
	uint16_t version;
	int oper_fd;
	uint64_t oper_str_len;
	uint8_t oper_str[65];
	FILE* oper_file;
	time_t timen;
	version = 0;
	*(uint16_t*)(sbuffer+0) = version;
	*(uint8_t*)(sbuffer+2) = METHOD_LOGIN;
	*(uint8_t*)(sbuffer+3) = 0;
	*(uint64_t*)(sbuffer+4) = server_id;
	*(uint64_t*)(oper_str+0) = server_id;
	if(pk_get_pubkey(oper_str+8, &oper_str_len)) return -1;
	if(!EVP_Digest(oper_str, oper_str_len+8, sbuffer+12, 0, EVP_sha3_256(), 0)) return -1;
	if(send(sock, sbuffer, 20, 0) == -1) return -3;
	if((read_bytes = recv(sock, buffer, buffer_size, 0)) == -1) return -3;

	return 0;
}
