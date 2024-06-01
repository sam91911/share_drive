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
			if(pack_id != 0) return -1;
			if(read_bytes < 20) return -1;
			user_id = (*(uint64_t*)(buffer+12));
			if(user_checkid(user_id)) return -2;
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
			if((read_bytes = recv(sock, buffer, buffer_size, 0)) == -1) return -3;
			if(read_bytes < 44) return -1;
			if(*(uint16_t*)(buffer+0) != 0) return -1;
			if(*(uint8_t*)(buffer+2) != METHOD_LOGIN) return -1;
			if(*(uint8_t*)(buffer+3) != 2) return -1;
			if(*(uint64_t*)(buffer+4) != server_id) return -1;
			if(*(uint64_t*)(buffer+12) != user_id) return -1;
			memcpy(size_buf, buffer+20, 8);
			oper_str_len = 65;
			if(user_pubkey(user_id, oper_str)) return -1;
			if(pk_verify(oper_str, 65, sbuffer, 60, buffer+44, size_buf[0]) != 1) return -1;
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
		case METHOD_REGISTER:
			return -1;
			break;
		case METHOD_SIGNREG:
			return -1;
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
	if(send(sock, sbuffer, 20, 0) == -1) return -3;
	if((read_bytes = recv(sock, buffer, buffer_size, 0)) == -1) return -3;
	if(read_bytes < 60) return -1;
	if(*((uint16_t*) buffer) != 0) return -1;
	if(buffer[2] != METHOD_LOGIN) return -1;
	if(buffer[3] != 1) return -1;
	if(*(uint64_t*)(buffer+4) != server_id) return -1;
	if(*(uint64_t*)(buffer+12) != remote_id) return -1;
	if(*(uint64_t*)(buffer+20) != self_id) return -1;
	timen = time(0);
	if(*(time_t*)(buffer+28) > timen) return -1;
	if(*(time_t*)(buffer+36) < timen) return -1;
	*(uint8_t*)(sbuffer+3) = 2;
	if(RAND_bytes(sbuffer+28, 16) != 1) return -3;
	*(uint64_t*)(sbuffer+20) = 980;
	if(pk_sign(buffer, 60, sbuffer+44, (uint64_t*)(sbuffer+20), password)) return -1;
	EVP_DigestUpdate(md_ctx, sbuffer, 44+(*(uint64_t*)(sbuffer+20)));
	if(send(sock, sbuffer, 44+(*(uint64_t*)(sbuffer+20)), 0) == -1) return -1;
	if((read_bytes = recv(sock, buffer, buffer_size, 0)) == -1) return -3;
	if(read_bytes < 28) return -1;
	if(*(uint16_t*)(buffer+0) != 0) return -1;
	if(*(uint8_t*)(buffer+2) != METHOD_LOGIN) return -1;
	if(*(uint8_t*)(buffer+3) != 3) return -1;
	if(*(uint64_t*)(buffer+4) != server_id) return -1;
	if(*(uint64_t*)(buffer+12) != remote_id) return -1;
	memcpy(size_buf, buffer+20, 8);
	if(pk_verify(server_pubkey, pubkey_len, sbuffer, 44, buffer+28, size_buf[0]) != 1) return -1;
	EVP_DigestUpdate(md_ctx, buffer, 28+size_buf[0]);
	EVP_DigestFinal(md_ctx, secret, 0);
	EVP_MD_CTX_free(md_ctx);
	return 0;
}
