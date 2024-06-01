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

int temp_encode(char* file_name, uint8_t* aes_key, uint8_t* iv, uint64_t* user_ids, uint64_t mlen, char* upname, char* password){
	struct stat oper_stat;
	int file_fd, oper_fd;
	uint8_t buffer[2048];
	uint8_t sbuffer[2048+128];
	char* path[256+7];
	int64_t read_bytes;
	uint64_t size_buf[4];
	uint8_t hash_v[32];
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
	if((!user_ids)&&mlen) return -1;
	if(strlen(upname) > 255) return -1;
	if(mlen > 128) return -1;
	if(sprintf(path, ".temp/%s", upname) < 1) return -1;
	if((oper_fd = open(path, O_CREAT|O_WRONLY|O_EXCL, 0644)) == -1) return -1;
	if((file_fd = open(file_name, O_RDONLY)) == -1) return -1;
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	EVP_EncryptInit(ctx, EVP_aes256_cbc(), aes_key, iv);
	while(1){
		if((read_bytes = read(file_fd, buffer, 2048)) == -1) return -1;
		if(read_bytes == 0) break;
		size_buf[0] = 2048+128;
		EVP_EncryptUpdate(ctx, sbuffer, size_buf, buffer, read_bytes);
		EVP_DigestUpdate(ctx, buffer, read_bytes);
		if(write(oper_fd, sbuffer, size_buf[0]) == -1) return -1;
	}
	size_buf[0] = 2048+128;
	EVP_EncryptFinal(ctx, sbuffer, size_buf);
	EVP_DigestFinal(ctx, hash_v, 0);
	if(write(oper_fd, sbuffer, size_buffer[0]) == -1) return -1;
	close(oper_fd);
	close(file_fd);
	if(sprintf(path, ".sign/%s", upname) < 1) return -1;
	if((oper_fd = open(path, O_CREAT|O_WRONLY|O_EXCL, 0644)) == -1) return -1;
	size_buf[0] = strlen(upname);
	*(uint64_t*)(sbuffer + 0) = oper_stat.st_size;
	*(uint16_t*)(sbuffer + 8) = size_buf[0];
	*(uint16_t*)(sbuffer + 10) = mlen;
	memcpy(sbuffer+12, hash_v, 32);
	memcpy(sbuffer+44, upname, size_buf[0]);
	if(user_ids){
		memcpy(sbuffer+44+size_buf[0], user_ids, mlen*8);
	}
	size_buf[1] = 1996-size_buf[0]-mlen*8;
	if(pk_sign(sbuffer, 44+size_buf[0]+mlen*8, sbuffer+52+size_buf[0]+mlen*8, size_buf+1, password) == -1) return -1;
	memcpy(sbuffer+44+size_buf[0]+mlen*8, size_buf+1, 8);
	if(write(oper_fd, sbuffer, 52+size_buf[0]+mlen*8+size_buf[1]) == -1) return -1;
	close(oper_fd);
	return 0;
}

int temp_decode(char* file_name, uint8_t* aes_key, char* upname){

}

int temp_clean(char* upname){
	
}
