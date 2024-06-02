#include "process.h"

int server_process(uint64_t server_id, int sock, struct sockaddr_in addr, uint64_t buffer_size, uint64_t client_id, char* restrict password, uint8_t* secret){
	uint8_t buffer[2048];
	uint8_t sbuffer[2048];
	int64_t read_bytes;
	uint64_t self_id;
	int oper_fd;
	FILE* oper_file;
	time_t timen;
	uint16_t version;
	uint8_t method;
	uint8_t pflag;
	uint8_t derive_s[32];
	uint64_t size_buf[4];
	uint64_t tlen;
	uint8_t slen;
	uint8_t oper_str[256];
	uint8_t hash_r[32];
	uint8_t hash_v[32];
	uint8_t remote_pubkey[65];
	uint64_t pack_id;
	uint16_t plen;
	uint16_t flag;
	uint64_t rpt;
	EVP_MD_CTX* md_ctx;
	if(!(md_ctx = EVP_MD_CTX_new())) return -1;
	if(user_pubkey(client_id, remote_pubkey)) return -1;
	memcpy(sbuffer, secret, 32);
	size_buf[0] = 2016;
	if(pk_dh(remote_pubkey, 65, sbuffer+32, size_buf, password)) return -1;
	if(!EVP_Digest(sbuffer, 32+size_buf[0], derive_s, 0, EVP_sha3_256(), 0)) return -1;
	if((read_bytes = recv(sock, buffer, 2048, 0)) == -1) return -3;
	if(read_bytes < 12) return -1;
	memcpy(&version, buffer, 2);
	method = buffer[2];
	pflag = buffer[3];
	if(version != 0) return -1;
	if(memcmp(buffer+4, &server_id, 8)) return -1;
	switch(method){
		case METHOD_POST:
			if(pflag) return -1;
			if(read_bytes < 166) return -1;
			if(memcmp(&server_id, buffer+44, 8)) return -1;
			slen = sbuffer[44+112];
			if(read_bytes < 44+121+slen) return -1;
			memcpy(size_buf, buffer+44+113+slen, 8);
			if(pk_verify(remote_pubkey, 65, buffer+44, 113+slen, buffer+44+121+slen, size_buf[0]) != 1) return -1;
			EVP_DigestInit(md_ctx, EVP_sha3_256());
			EVP_DigestUpdate(md_ctx, derive_s, 32);
			EVP_DigestUpdate(md_ctx, buffer+44, 121+slen+size_buf[0]);
			EVP_DigestFinal(md_ctx, hash_v, 0);
			if(memcmp(hash_r, hash_v, 32)) return -1;
			memcpy(oper_str, buffer+113, slen);
			oper_str[slen] = '\0';
			while(1){
				rpt = 0;
				if((read_bytes = recv(sock, buffer, 56, MSG_WAITALL)) == -1) return -1;
				rpt = read_bytes;
				if(rpt < 56) return -1;
				memcpy(&version, buffer, 2);
				method = buffer[2];
				pflag = buffer[3];
				if(version != 0) return -1;
				if(method != METHOD_POST) return -1;
				if(!(pflag&0x01)) return -1;
				if(memcmp(buffer+4, &server_id, 8)) return -1;
				memcpy(&pack_id, buffer+12, 8);
				memcpy(&plen, buffer+20, 2);
				memcpy(&flag, buffer+22, 2);
				if(plen > 1024) return -1;
				memcpy(hash_r, buffer+24, 32);
				if((read_bytes = recv(sock, buffer+56, plen, MSG_WAITALL)) == -1) return -1;
				EVP_DigestInit(md_ctx, EVP_sha3_256());
				EVP_DigestUpdate(md_ctx, derive_s, 32);
				EVP_DigestUpdate(md_ctx, buffer+56, plen);
				EVP_DigestFinal(md_ctx, hash_v, 0);
				if(memcmp(hash_r, hash_v, 32)) return -1;
				if(fsys_store(client_id, (char*)oper_str, buffer+56, plen, pack_id*1024, SEEK_SET)) return -1;
				if(flag&0x0001) break;
			}
			break;
		case METHOD_GET:
			break;
		default:
			return -1;
	}
	return 0;
}

int client_process_fpost(uint64_t server_id, int sock, struct sockaddr_in addr, uint64_t buffer_size, char* restrict password, uint8_t* secret, uint8_t* restrict server_pubkey, uint64_t pubkey_len, char* file_name, char* upname){
	uint8_t buffer[2048];
	uint8_t sbuffer[2048];
	uint64_t size_buf[4];
	uint8_t derive_s[32];
	uint64_t hash_v[32];
	struct stat oper_stat;
	uint64_t tlen;
	uint16_t slen;
	uint16_t mlen;
	uint64_t pack_id;
	uint16_t plen;
	uint16_t flag;
	int oper_fd;
	FILE* oper_file;
	int64_t read_bytes;
	EVP_MD_CTX* md_ctx;
	if(!(md_ctx = EVP_MD_CTX_new())) return -1;
	memcpy(sbuffer, secret, 32);
	size_buf[0] = 2016;
	if(pk_dh(server_pubkey, pubkey_len, sbuffer+32, size_buf, password)) return -1;
	if(!EVP_Digest(sbuffer, 32+size_buf[0], derive_s, 0, EVP_sha3_256(), 0)) return -1;
	*(uint16_t*)(sbuffer+0) = 0;
	sbuffer[2] = METHOD_POST;
	sbuffer[3] = 0;
	memcpy(sbuffer+4, &server_id, 8);
	if(!file_name) return -1;
	if(stat(file_name, &oper_stat)) return -1;
	tlen = oper_stat.st_size;
	slen = strlen(file_name);
	mlen = 0;
	memcpy(sbuffer+44, &tlen, 8);
	memcpy(sbuffer+52, &slen, 2);
	memcpy(sbuffer+54, &mlen, 2);
	memcpy(sbuffer+88, upname, slen);
	if((oper_fd = open(file_name, O_RDONLY)) == -1) return -1;
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	while(1){
		if((read_bytes = read(oper_fd, buffer, 2048)) < 1) break;
		EVP_DigestUpdate(md_ctx, buffer, read_bytes);
	}
	EVP_DigestFinal(md_ctx, sbuffer+56, 0);
	size_buf[0] = 1952-slen-mlen*8;
	if(pk_sign(sbuffer+44, slen+mlen*8+44, sbuffer+96+slen+mlen*8, size_buf, password)) return -1;
	memcpy(sbuffer+slen+mlen*8+88, size_buf, 8);
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	EVP_DigestUpdate(md_ctx, derive_s, 32);
	EVP_DigestUpdate(md_ctx, sbuffer+44, 52+mlen*8+slen+size_buf[0]);
	EVP_DigestFinal(md_ctx, sbuffer+12, 0);
	if(send(sock, sbuffer, 96+slen+mlen*8+size_buf[0], 0) == -1) return -1;
	if(lseek(oper_fd, 0, SEEK_SET) == -1) return -1;
	pack_id = 0;
	uint8_t send_buf[buffer_size];
	//setsockopt(sock, SOL_SOCKET, SO_SNDBUF, send_buf, buffer_size);
	while(1){
		if((read_bytes = read(oper_fd, sbuffer+56, 1024)) != 1024){
			*(uint16_t*)(sbuffer+0) = 0;
			sbuffer[2] = METHOD_POST;
			sbuffer[3] = 0x01;
			plen = read_bytes;
			flag = 0x0001;
			memcpy(sbuffer+12, &pack_id, 8);
			memcpy(sbuffer+20, &plen, 2);
			memcpy(sbuffer+22, &flag, 2);
			EVP_DigestInit(md_ctx, EVP_sha3_256());
			EVP_DigestUpdate(md_ctx, derive_s, 32);
			EVP_DigestUpdate(md_ctx, sbuffer+56, plen);
			EVP_DigestFinal(md_ctx, sbuffer+24, 0);
			if(send(sock, sbuffer, 56+plen, 0) == -1) return -1;
			break;
		}else{
			*(uint16_t*)(sbuffer+0) = 0;
			sbuffer[2] = METHOD_POST;
			sbuffer[3] = 0x01;
			plen = read_bytes;
			flag = 0;
			memcpy(sbuffer+12, &pack_id, 8);
			memcpy(sbuffer+20, &plen, 2);
			memcpy(sbuffer+22, &flag, 2);
			EVP_DigestInit(md_ctx, EVP_sha3_256());
			EVP_DigestUpdate(md_ctx, derive_s, 32);
			EVP_DigestUpdate(md_ctx, sbuffer+56, plen);
			EVP_DigestFinal(md_ctx, sbuffer+24, 0);
			if(send(sock, sbuffer, 56+plen, MSG_MORE) != 56+plen) return -1;
			pack_id++;
		}
	}
	return 0;
}

int client_process_fget(uint64_t server_id, int sock, struct sockaddr_in addr, uint64_t buffer_size, char* restrict password, uint8_t* secret, uint8_t* restrict server_pubkey, uint64_t pubkey_len, char* file_name, char* upname){
	return 0;
}
