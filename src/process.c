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
	uint64_t call_id;
	EVP_MD_CTX* md_ctx;
	if(!(md_ctx = EVP_MD_CTX_new())) return -1;
	if(user_pubkey(server_id, client_id, remote_pubkey)) return -1;
	memcpy(sbuffer, secret, 32);
	size_buf[0] = 2016;
	if(pk_dh(remote_pubkey, 65, sbuffer+32, size_buf, password)) return -1;
	if(!EVP_Digest(sbuffer, 32+size_buf[0], derive_s, 0, EVP_sha3_256(), 0)) return -1;
	if((read_bytes = recv(sock, buffer, 12, MSG_WAITALL)) == -1) return -3;
	if(read_bytes < 12) return -1;
	memcpy(&version, buffer, 2);
	method = buffer[2];
	pflag = buffer[3];
	if(version != 0) return -1;
	if(memcmp(buffer+4, &server_id, 8)) return -1;
	switch(method){
		case METHOD_POST:
			if((read_bytes = recv(sock, buffer+12, 36, MSG_WAITALL)) == -1) return -3;
			if(read_bytes < 36) return -1;
			memcpy(&plen, buffer+44, 2);
			if((read_bytes = recv(sock, buffer+48, plen, MSG_WAITALL)) == -1) return -3;
			if(pflag) return -1;
			slen = buffer[160];
			memcpy(size_buf, buffer+161+slen, 8);
			if(plen != (slen+121+size_buf[0])){
				printf("slen:%u\tplen:%u\tsign:%lu\n", slen, plen, size_buf[0]);
				return -1;
			}
			EVP_DigestInit(md_ctx, EVP_sha3_256());
			EVP_DigestUpdate(md_ctx, derive_s, 32);
			EVP_DigestUpdate(md_ctx, buffer+44, plen+4);
			EVP_DigestFinal(md_ctx, hash_v, 0);
			if(memcmp(buffer+12, hash_v, 32)) return -1;
			memcpy(oper_str, buffer+161, slen);
			oper_str[slen] = '\0';
			if((oper_fd = fsys_store(client_id, oper_str)) == -1) return -1;
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
				if(write(oper_fd, buffer+56, plen) == -1) return -3;
				if(flag&0x0001) break;
			}
			close(oper_fd);
			break;
		case METHOD_GET:
			printf("get\n");
			if(pflag) return -1;
			if((read_bytes = recv(sock, buffer+12, 41, MSG_WAITALL)) == -1) return -3;
			slen = buffer[52];
			memcpy(&call_id, buffer+44, 8);
			if((read_bytes = recv(sock, buffer+53, slen, MSG_WAITALL)) == -1) return -3;
			EVP_DigestInit(md_ctx, EVP_sha3_256());
			EVP_DigestUpdate(md_ctx, derive_s, 32);
			EVP_DigestUpdate(md_ctx, buffer+44, 9+slen);
			EVP_DigestFinal(md_ctx, hash_v, 0);
			if(memcmp(buffer+12, hash_v, 32)) return -1;
			memcpy(oper_str, buffer+53, slen);
			oper_str[slen] = '\0';
			if((oper_fd = fsys_get(client_id, oper_str)) == -1) return -3;
			pack_id = 0;
			while(1){
				if((read_bytes = read(oper_fd, sbuffer+56, 1024)) != 1024){
					*(uint16_t*)(sbuffer+0) = 0;
					sbuffer[2] = METHOD_GET;
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
					sbuffer[2] = METHOD_GET;
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
			break;
		default:
			return -1;
	}
	EVP_MD_CTX_free(md_ctx);
	return 0;
}

int client_process_fpost(uint64_t server_id, uint64_t server_user_id, uint64_t self_id, uint64_t* oper_keyf, uint64_t threshold, int sock, struct sockaddr_in addr, uint64_t buffer_size, char* restrict password, uint8_t* secret, uint8_t* restrict server_pubkey, uint64_t pubkey_len, char* upname){
	uint8_t buffer[2048];
	uint8_t sbuffer[2048];
	uint64_t size_buf[4];
	uint8_t derive_s[32];
	uint8_t hash_v[32];
	struct stat oper_stat;
	uint64_t tlen;
	uint16_t slen;
	uint64_t pack_id;
	uint16_t plen;
	uint16_t flag;
	int oper_fd;
	FILE* oper_file;
	int64_t read_bytes;
	int pipefd[2];
	uint64_t en_key[4];
	uint32_t rbl;
	int pipe_flag;
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
	flag = 0x0000;
	if((oper_fd = temp_sign_file(upname)) == -1) return -1;
	if((read_bytes = read(oper_fd, sbuffer+48, 2000)) == -1) return -1;
	close(oper_fd);
	plen = read_bytes;
	memcpy(sbuffer+46, &flag, 2);
	memcpy(sbuffer+44, &plen, 2);
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	EVP_DigestUpdate(md_ctx, derive_s, 32);
	EVP_DigestUpdate(md_ctx, sbuffer+44, read_bytes+4);
	EVP_DigestFinal(md_ctx, sbuffer+12, 0);
	if(send(sock, sbuffer, 48+plen, 0) == -1) return -1;
	share_key_plug(threshold, oper_keyf, server_user_id, en_key);
	share_key_plug(threshold, oper_keyf+threshold, server_user_id, en_key+1);
	share_key_plug(threshold, oper_keyf+threshold*2, server_user_id, en_key+2);
	share_key_plug(threshold, oper_keyf+threshold*3, server_user_id, en_key+3);
	if((oper_fd = temp_temp_file(upname)) == -1) return -1;
	if(lseek(oper_fd, 0, SEEK_SET) == -1) return -1;
	pack_id = 0;
	if(pipe(pipefd) == -1) return -3;
	pipe_flag = fcntl(pipefd[0], F_GETFL, 0);
	fcntl(pipefd[0], F_SETFL, pipe_flag| O_NONBLOCK);
	pipe_flag = fcntl(pipefd[1], F_GETFL, 0);
	fcntl(pipefd[1], F_SETFL, pipe_flag| O_NONBLOCK);
	if(write(pipefd[1], en_key, 32) == -1) return -3;
	if(fork()){
		close(pipefd[1]);
		close(oper_fd);
		while(1){
			rbl = 0;
			while(rbl < 1024){
				read_bytes = read(pipefd[0], sbuffer+56+rbl, 1024-rbl);
				if(read_bytes == -1){
					if(errno == EAGAIN) continue;
					if(errno == EPIPE) break;
					return -3;
				}
				if(read_bytes == 0) break;
				rbl += read_bytes;
			}
			if(rbl != 1024){
				*(uint16_t*)(sbuffer+0) = 0;
				sbuffer[2] = METHOD_POST;
				sbuffer[3] = 0x01;
				plen = rbl;
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
				plen = rbl;
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
		close(pipefd[0]);
	}else{
		close(pipefd[0]);
		sep_data_sep(oper_fd, pipefd[1], server_user_id, threshold);
		close(pipefd[1]);
		close(oper_fd);
	}
	EVP_MD_CTX_free(md_ctx);
	return 0;
}

int client_process_fget(uint64_t server_id, uint64_t server_userid, int sock, struct sockaddr_in addr, uint64_t buffer_size, char* restrict password, uint8_t* secret, uint8_t* restrict server_pubkey, uint64_t pubkey_len, uint64_t client_id, char* upname){
	uint8_t buffer[2048];
	uint8_t sbuffer[2048];
	uint64_t size_buf[4];
	uint8_t derive_s[32];
	uint8_t hash_v[32];
	struct stat oper_stat;
	uint64_t tlen;
	uint8_t slen;
	uint64_t pack_id;
	uint16_t plen;
	uint8_t pflag;
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
	sbuffer[2] = METHOD_GET;
	sbuffer[3] = 0;
	memcpy(sbuffer+4, &server_id, 8);
	if(!upname) return -1;
	size_buf[0] = strlen(upname);
	if(size_buf[0] > 255) return -1;
	slen = size_buf[0];
	memcpy(sbuffer+44, &client_id, 8);
	sbuffer[52] = slen;
	memcpy(sbuffer+53, upname, slen);
	printf("send fget request\n");
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	EVP_DigestUpdate(md_ctx, derive_s, 32);
	EVP_DigestUpdate(md_ctx, sbuffer+44, 9+slen);
	EVP_DigestFinal(md_ctx, hash_v, 0);
	memcpy(sbuffer+12, hash_v, 32);
	if(send(sock, sbuffer, 53+slen, 0) == -1) return -3;
	if((oper_fd = temp_decode_file(server_userid, upname)) == -1) return -3;
	while(1){
		if((read_bytes = recv(sock, buffer, 56, MSG_WAITALL)) == -1) return -3;
		memcpy(&plen, buffer+20, 2);
		memcpy(&flag, buffer+22, 2);
		memcpy(&pack_id, buffer+12, 8);
		pflag = buffer[3];
		if(!(pflag&0x01)) return -1;
		if((read_bytes = recv(sock, buffer+56, plen, MSG_WAITALL)) == -1) return -3;
		EVP_DigestInit(md_ctx, EVP_sha3_256());
		EVP_DigestUpdate(md_ctx, derive_s, 32);
		EVP_DigestUpdate(md_ctx, buffer+56, plen);
		EVP_DigestFinal(md_ctx, hash_v, 0);
		if(memcmp(hash_v, buffer+24, 32)) return -1;
		if(lseek(oper_fd, pack_id*1024, SEEK_SET) == -1) return -3;
		if(write(oper_fd, buffer+56, plen) == -1) return -3;
		if(flag&0x0001) break;
	}
	close(oper_fd);
	return 0;
}
