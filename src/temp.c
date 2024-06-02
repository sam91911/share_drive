#include "temp.h"

int temp_init(){
	struct stat oper_stat;
	int oper_fd;
	if(access(".temp", F_OK)){
		if(errno == ENOENT){
			if(mkdir(".temp", 0744)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	if(stat(".temp", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(access(".sign", F_OK)){
		if(errno == ENOENT){
			if(mkdir(".sign", 0744)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	if(stat(".sign", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	return -1;
}

int temp_encode(uint64_t user_id, char* file_name, uint8_t* aes_key, uint8_t* iv, uint64_t treshold, char* upname, char* password){
	struct stat oper_stat;
	int file_fd, oper_fd;
	uint8_t buffer[2048];
	uint8_t sbuffer[2048+128];
	char path[256+7];
	int64_t read_bytes;
	uint64_t size_buf[4];
	uint8_t hash_v[32];
	time_t timen = time(0);
	EVP_MD_CTX* md_ctx;
	EVP_CIPHER_CTX* ctx;
	if(!(md_ctx  = EVP_MD_CTX_new())) return -1;
	if(!(ctx  = EVP_CIPHER_CTX_new())) return -1;
	if(access(".temp", F_OK)){
		return -1;
	}
	if(stat(".temp", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(access(".sign", F_OK)){
		return -1;
	}
	if(stat(".sign", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(access(file_name, F_OK|R_OK)) return -1;
	if(stat(file_name, &oper_stat)) return -1;
	if(!(S_IFREG&(oper_stat.st_mode))) return -1;
	if(!file_name) return -1;
	if(!aes_key) return -1;
	if(!upname) return -1;
	if(strlen(upname) > 255) return -1;
	if(sprintf(path, ".temp/%s", upname) < 1) return -1;
	if((oper_fd = open(path, O_CREAT|O_WRONLY|O_EXCL, 0644)) == -1) return -1;
	if((file_fd = open(file_name, O_RDONLY)) == -1) return -1;
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	EVP_EncryptInit(ctx, EVP_aes_256_cbc(), aes_key, iv);
	while(1){
		if((read_bytes = read(file_fd, buffer, 2048)) == -1) return -1;
		if(read_bytes == 0) break;
		size_buf[0] = 2048+128;
		EVP_EncryptUpdate(ctx, sbuffer, (int*)size_buf, buffer, read_bytes);
		EVP_DigestUpdate(md_ctx, buffer, read_bytes);
		if(write(oper_fd, sbuffer, size_buf[0]) == -1) return -1;
	}
	size_buf[0] = 2048+128;
	EVP_EncryptFinal(ctx, sbuffer, (int*)size_buf);
	EVP_DigestFinal(md_ctx, hash_v, 0);
	if(write(oper_fd, sbuffer, size_buf[0]) == -1) return -1;
	close(oper_fd);
	close(file_fd);
	if(sprintf(path, ".sign/%s", upname) < 1) return -1;
	if((oper_fd = open(path, O_CREAT|O_WRONLY|O_EXCL, 0644)) == -1) return -1;
	size_buf[0] = strlen(upname);
	*(uint64_t*)(sbuffer + 0) = user_id;
	*(uint64_t*)(sbuffer + 8) = timen;
	*(uint64_t*)(sbuffer + 16) = oper_stat.st_size;
	*(uint64_t*)(sbuffer + 24) = treshold;
	memcpy(sbuffer+32, hash_v, 32);
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	EVP_DigestUpdate(md_ctx, iv, 16);
	EVP_DigestUpdate(md_ctx, aes_key, 32);
	EVP_DigestFinal(md_ctx, hash_v, 0);
	memcpy(sbuffer+64, iv, 16);
	memcpy(sbuffer+80, hash_v, 32);
	size_buf[0] = strlen(upname);
	if(size_buf[0] > 255) return -1;
	sbuffer[112] = size_buf[0];
	memcpy(sbuffer+113, upname, size_buf[0]);
	size_buf[1] = (2048-113)-size_buf[0];
	if(pk_sign(sbuffer, 113+size_buf[0], sbuffer+121+size_buf[0], size_buf+1, password) == -1) return -1;
	memcpy(sbuffer+113+size_buf[0], size_buf+1, 8);
	if(write(oper_fd, sbuffer, 121+size_buf[0]+size_buf[1]) == -1) return -1;
	close(oper_fd);
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
	EVP_MD_CTX_free(md_ctx);
	return 0;
}

int temp_sign_file(char* upname){
	char path[256+7];
	int oper_fd;
	if(!upname) return -1;
	if(sprintf(path, ".sign/%s", upname) < 1) return -1;
	if((oper_fd = open(path, O_RDONLY)) == -1) return -1;
	return oper_fd;
}

int temp_temp_file(char* upname){
	char path[256+7];
	int oper_fd;
	if(!upname) return -1;
	if(sprintf(path, ".temp/%s", upname) < 1) return -1;
	if((oper_fd = open(path, O_RDONLY)) == -1) return -1;
	return oper_fd;
}

int temp_decode(char* file_name, uint64_t* secret, uint64_t threshold, char* upname){
	return 0;
}

int temp_clean(char* upname){
	char path[256+7];
	int rt = 0;
	if(sprintf(path, ".sign/%s", upname) < 1) return -1;
	if(remove(path)){
		if(errno != ENOENT) rt += -1;
	}
	if(sprintf(path, ".temp/%s", upname) < 1) return -1;
	if(remove(path)){
		if(errno != ENOENT) rt += -2;
	}
	return rt;
}
