#include "user.h"

int user_pubkey(uint64_t serverid, uint64_t id, uint8_t* pubkey){
	if(!pubkey) return -2;
	FILE* oper_file;
	uint8_t buffer[64];
	if(sprintf(buffer, "user/%016lX/%016lX", serverid, id) < 0) return -1;
	if(!(oper_file = fopen(buffer, "rb"))) return -1;
	if(fread(pubkey, USER_PUBKEY_LEN, 1, oper_file) < 1) return -1;
	fclose(oper_file);
	return 0;
}

int user_checkid(uint64_t serverid, uint64_t id){
	FILE* oper_file;
	uint8_t buffer[64];
	if(sprintf(buffer, "user/%016lX/user_list", serverid) < 0) return -1;
	if(!(oper_file = fopen(buffer, "rb"))) return -1;
	int check_bool = 1;
	while(!feof(oper_file)){
		if(fread(buffer, 32, 1, oper_file) < 1) break;
		if(*(uint64_t*)buffer == id){
			check_bool = 0;
			break;
		}
	}
	fclose(oper_file);
	return check_bool;
}

int user_check(uint64_t serverid, uint8_t* restrict pubkey, uint64_t len){
	FILE* oper_file;
	uint8_t buffer[64];
	if(sprintf(buffer, "user/%016lX/user_list", serverid) < 0) return -1;
	if(!(oper_file = fopen("user/%016lX/user_list", "rb"))) return -1;
	uint8_t hash_value[32];
	uint8_t pubkey_buffer[len];
	int check_bool = 1;
	EVP_MD_CTX* md_ctx;
	if(!(md_ctx = EVP_MD_CTX_new())) return -1;
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	EVP_DigestUpdate(md_ctx, &serverid, 8);
	EVP_DigestUpdate(md_ctx, pubkey, len);
	EVP_DigestFinal(md_ctx, buffer, 0);
	EVP_MD_CTX_free(md_ctx);
	while(!feof(oper_file)){
		if(fread(buffer, 32, 1, oper_file) < 1) break;
		if(!memcmp(buffer, hash_value, 8)){
			check_bool = 0;
			break;
		}
	}
	fclose(oper_file);
	if(sprintf(buffer, "user/%016lX", *(uint64_t*)hash_value) < 0) return -1;
	if(!check_bool){
		if(!(oper_file = fopen(buffer, "rb"))) return -1;
		if(fread(pubkey_buffer, len, 1, oper_file) == 0) return -1;
		if(memcmp(pubkey, pubkey_buffer, len)) check_bool = 1;
		fclose(oper_file);
	}
	return check_bool;
}
int user_add(uint64_t serverid, uint8_t* restrict pubkey, uint64_t len){
	if(!pubkey) return 0;
	if(!user_check(serverid, pubkey, len)) return 0;
	int oper_fd;
	uint8_t buffer[64];
	uint64_t id;
	EVP_MD_CTX* md_ctx;
	if(!(md_ctx = EVP_MD_CTX_new())) return -1;
	if(sprintf(buffer, "user/%016lX/user_list", serverid) < 0) return -1;
	if((oper_fd = open(buffer, O_WRONLY)) == -1) return -1;
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	EVP_DigestUpdate(md_ctx, &serverid, 8);
	EVP_DigestUpdate(md_ctx, pubkey, len);
	EVP_DigestFinal(md_ctx, buffer, 0);
	EVP_MD_CTX_free(md_ctx);
	memset(buffer+8, 0, 24);
	if(lseek(oper_fd, 0, SEEK_END) == -1) return -1;
	if(write(oper_fd, buffer, 32) == -1) return -1;
	close(oper_fd);
	id =  *(uint64_t*)buffer;
	if(sprintf(buffer, "user/%016lX/%016lX", serverid, id) < 0) return -1;
	if((oper_fd = open(buffer, O_CREAT|O_WRONLY, 0644)) < 0) return -1;
	if(write(oper_fd, pubkey, len) == -1) return -1;
	close(oper_fd);
	return 0;
}
int user_init(){
	struct stat oper_stat;
	if(access("user", F_OK)){
		if(errno == ENOENT){
			if(mkdir("user", 0744)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	if(stat("user", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	return 0;
}
int user_server_init(uint64_t serverid){
	struct stat oper_stat;
	int oper_fd;
	char buffer[64];
	if(access("user", F_OK)){
		return -1;
	}
	if(stat("user", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(sprintf(buffer, "user/%016lX", serverid) < 0) return -1;
	if(access(buffer, F_OK)){
		if(errno == ENOENT){
			if(mkdir(buffer, 0744)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	if(stat(buffer, &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(sprintf(buffer, "user/%016lX/user_list", serverid) < 0) return -1;
	if((oper_fd = open(buffer, O_CREAT|O_WRONLY, 0644)) < 0){
		return -1;
	}
	if(sprintf(buffer, "user/%016lX/list", serverid) < 0) return -1;
	if((oper_fd = open(buffer, O_CREAT|O_WRONLY, 0644)) < 0){
		return -1;
	}
	close(oper_fd);
	return 0;
}

int user_name2id(uint64_t serverid, char* name, uint64_t* id){
	if(!name) return -1;
	if(!id) return -1;
	struct stat oper_stat;
	FILE* oper_file;
	uint64_t oper_id;
	char buffer[64];
	if(access("user", F_OK)){
		return -1;
	}
	if(stat("user", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(sprintf(buffer, "user/%016lX", serverid) < 0) return -1;
	if(access(buffer, F_OK)){
		return -1;
	}
	if(sprintf(buffer, "user/%016lX/list", serverid) < 0) return -1;
	if(!(oper_file = fopen(buffer, "r"))){
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

int user_add_name(uint64_t serverid, const char* restrict name, uint64_t id){
	if(!name) return -1;
	if(access("serverid", F_OK)){
		return -1;
	}
	struct stat oper_stat;
	FILE* oper_file;
	int oper_fd;
	uint8_t buffer[64];
	if(access("user", F_OK)){
		return -1;
	}
	if(stat("user", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(sprintf(buffer, "user/%016lX", serverid) < 0) return -1;
	if(access(buffer, F_OK)){
		return -1;
	}
	if(sprintf(buffer, "user/%016lX/list", serverid) < 0) return -1;
	if(!(oper_file = fopen(buffer, "a"))){
		return -1;
	}
	if(fprintf(oper_file, "%016lX %s\n", id, name) == -1) return -1;
	fclose(oper_file);
	return 0;
}
