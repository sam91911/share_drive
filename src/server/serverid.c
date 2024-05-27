#include "serverid.h"
#ifndef SERVERID_MLEN
#define SERVERID_MLEN 1024
#endif

int serverid_init(){
	if(access("serverid", F_OK)){
		if(errno == ENOENT){
			if(mkdir("serverid", 0744)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	struct stat oper_stat;
	int oper_fd;
	if(stat("serverid", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if((oper_fd = open("serverid/list", O_CREAT|O_WRONLY, 0644)) == -1){
		return -1;
	}
	close(oper_fd);
	return 0;
}

int serverid_add(const char* restrict name, uint64_t id){
	if(!name) return -1;
	if(access("serverid", F_OK)){
		return -1;
	}
	struct stat oper_stat;
	FILE* oper_file;
	int oper_fd;
	uint8_t buffer[26];
	if(stat("serverid", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(!(oper_file = fopen("serverid/list", "a"))){
		return -1;
	}
	if(fprintf(oper_file, "%016lX %s\n", id, name) == -1) return -1;
	fclose(oper_file);
	sprintf(buffer, "serverid/%016lX", id);
	if((oper_fd = open(buffer, O_CREAT|O_WRONLY, 0644)) == -1){
		return -1;
	}
	close(oper_fd);
	return 0;
}

int serverid_get_id(const char* restrict name, uint64_t* id){
	if(!name) return -1;
	if(!id) return -1;
	if(access("serverid", F_OK)){
		return -1;
	}
	struct stat oper_stat;
	FILE* oper_file;
	uint8_t buffer[SERVERID_MLEN];
	uint64_t oper_id;
	if(stat("serverid", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(!(oper_file = fopen("serverid/list", "r"))){
		return -1;
	}
	while(!feof(oper_file)){
		if(fscanf(oper_file, "%16lX %s\n", &oper_id, buffer) <= 0) break;
		if(!strcmp(name, buffer)){
			*id = oper_id;
			fclose(oper_file);
			return 0;
		}
	}
	fclose(oper_file);
	return 1;
}

int serverid_check_id(uint64_t id){
	if(access("serverid", F_OK)){
		return -1;
	}
	struct stat oper_stat;
	FILE* oper_file;
	uint8_t buffer[SERVERID_MLEN];
	uint64_t oper_id;
	if(stat("serverid", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(!(oper_file = fopen("serverid/list", "r"))){
		return -1;
	}
	while(!feof(oper_file)){
		if(fscanf(oper_file, "%16lX %s\n", &oper_id, buffer) <= 0) break;
		if(id == oper_id){
			fclose(oper_file);
			return 0;
		}
	}
	fclose(oper_file);
	return 1;
}

int serverid_list(char** name, uint64_t* nlen){
	if(access("serverid", F_OK)){
		return -1;
	}
	struct stat oper_stat;
	if(stat("serverid", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}

}
int serverid_check_server(uint64_t id, uint64_t user_id){
	if(access("serverid", F_OK)){
		return -1;
	}
	struct stat oper_stat;
	if(stat("serverid", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(serverid_check_id(id)) return 1;
	int oper_fd;
	FILE* oper_file;
	char path[26];
	uint64_t buffer[3];
	if(sprintf(path, "serverid/%016lX", id) < 1) return -1;
	if(!(oper_file = fopen(path, "rb"))) return -1;
	while(!feof(oper_file)){
		if(fread(buffer, 24, 1, oper_file) < 1) break;
		if(buffer[0] == user_id){
			fclose(oper_file);
			return 0;
		}
		if(buffer[1]+buffer[2] == 0) break;
		if(fseek(oper_file, buffer[1]+buffer[2]+8, SEEK_CUR)) break;
	}
	fclose(oper_file);
	return 1;
}

int serverid_add_server(uint64_t id, uint8_t* restrict oper_sockaddr, uint8_t* restrict pubkey, uint64_t len, uint64_t pubkey_len, uint64_t flag){
	if(access("serverid", F_OK)){
		return -1;
	}
	struct stat oper_stat;
	if(stat("serverid", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(serverid_check_id(id)) return 1;
	int oper_fd;
	FILE* oper_file;
	char path[26];
	uint64_t buffer[4];
	buffer[0] = id;
	EVP_MD_CTX* md_ctx;
	if(!(md_ctx = EVP_MD_CTX_new())) return -1;
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	EVP_DigestUpdate(md_ctx, buffer, 8);
	EVP_DigestUpdate(md_ctx, pubkey, pubkey_len);
	EVP_DigestFinal(md_ctx, (uint8_t*)buffer, 0);
	EVP_MD_CTX_free(md_ctx);
	if(!serverid_check_server(id, buffer[0])) return 0;
	buffer[1] = len;
	buffer[2] = pubkey_len;
	buffer[3] = flag;
	if(sprintf(path, "serverid/%016lX", id) < 1) return -1;
	if((oper_fd = open(path, O_WRONLY)) == -1) return -1;
	if(lseek(oper_fd, 0, SEEK_END) == -1) return -1;
	if(write(oper_fd, buffer, 32) == -1) return -1;
	if(write(oper_fd, oper_sockaddr, len) == -1) return -1;
	if(write(oper_fd, pubkey, pubkey_len) == -1) return -1;
	close(oper_fd);
	return 0;
}

int serverid_get_server(uint64_t id, uint64_t offset, uint8_t* oper_sockaddr, uint8_t* pubkey, uint64_t* len, uint64_t* pubkey_len, uint64_t* flag, uint64_t* user_id){
	if(access("serverid", F_OK)){
		return -1;
	}
	struct stat oper_stat;
	if(stat("serverid", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(serverid_check_id(id)) return 1;
	int oper_fd;
	char path[26];
	uint64_t buffer[4];
	if(sprintf(path, "serverid/%016lX", id) < 1) return -1;
	if((oper_fd = open(path, O_RDONLY)) == -1) return -1;
	if(lseek(oper_fd, offset, SEEK_SET) == -1) return -1;
	if(read(oper_fd, buffer, 32) < 32) return 1;
	if(flag){
		*flag = buffer[3];
	}
	if(user_id){
		*user_id = buffer[0];
	}
	if(oper_sockaddr&&len){
		if(buffer[1] <= *len){
			if(read(oper_fd, oper_sockaddr, buffer[1]) == -1) return -1;
			*len = buffer[1];
		}else{
			if(lseek(oper_fd, buffer[1], SEEK_CUR) == -1) return -1;
			*len = 0;
		}
	}else{
		if(lseek(oper_fd, buffer[1], SEEK_CUR) == -1) return -1;
	}
	if(pubkey&&pubkey_len){
		if(buffer[2] <= *pubkey_len){
			if(read(oper_fd, pubkey, buffer[2]) == -1) return -1;
			*pubkey_len = buffer[2];
		}else{
			*pubkey_len = 0;
		}
	}
	close(oper_fd);
	return 0;
}
