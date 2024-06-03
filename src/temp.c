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

int temp_encode(uint64_t user_id, char* file_name, uint8_t* aes_key, uint8_t* iv, uint64_t threshold, char* upname, char* password){
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
	*(uint64_t*)(sbuffer + 24) = threshold;
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

int temp_decode_file(uint64_t user_id, char* upname){
	struct stat oper_stat;
	int oper_fd;
	char path[256+64];
	if(access(".temp", F_OK)){
		return -1;
	}
	if(stat(".temp", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(sprintf(path, ".temp/%s", upname) < 1) return -1;
	if(access(path, F_OK)){
		if(errno == ENOENT){
			if(mkdir(path, 0744)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	if(stat(path, &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(sprintf(path, ".temp/%s/%016lX", upname, user_id) < 1) return -1;
	if((oper_fd = open(path, O_WRONLY|O_CREAT, 0644)) == -1) return -1;
	return oper_fd;
}

int temp_decode(char* file_name, uint64_t* secret, uint8_t* iv, uint8_t* check_hash, uint64_t threshold, char* upname){
	struct stat oper_stat;
	int oper_fd;
	DIR* oper_dir;
	char path[256+64];
	uint64_t user_ids[threshold];
	uint64_t file_cnt;
	char* temp_str;
	struct dirent* oper_dirent;
	int up_fds[threshold];
	uint64_t key_y[threshold];
	uint8_t aes_key[32];
	uint64_t i, j;
	uint8_t hash_v[32];
	int pipefd[2];
	int pipe_flag;
	uint8_t buffer[1024];
	uint8_t sbuffer[1024+128];
	uint32_t rbl;
	int32_t read_bytes;
	int oper_pid;
	EVP_MD_CTX* md_ctx;
	EVP_CIPHER_CTX* ctx;
	if(!(md_ctx  = EVP_MD_CTX_new())) return -1;
	if(!(ctx  = EVP_CIPHER_CTX_new())) return -1;
	if(!iv) return -1;
	if(!check_hash) return -1;
	if(!file_name) return -1;
	if(!upname) return -1;
	if(access(".temp", F_OK)){
		return -1;
	}
	if(stat(".temp", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(sprintf(path, ".temp/%s", upname) < 1) return -1;
	if(!(oper_dir = opendir(path))) return -1;
	for(file_cnt = 0; file_cnt < threshold;){
		if(!(oper_dirent = readdir(oper_dir))) break;
		if(oper_dirent->d_type != DT_REG) continue;
		if(strlen(oper_dirent->d_name) != 16) continue;
		user_ids[file_cnt] = strtoul(oper_dirent->d_name, &temp_str, 16);
		if(strlen(temp_str)) continue;
		file_cnt++;
	}
	if(file_cnt != threshold) return -1;
	for(i = 0; i < threshold; i++){
		if(sprintf(path, ".temp/%s/%016lX", upname, user_ids[i]) < 1) return -1;
		if((up_fds[i] = open(path, O_RDONLY)) == -1){
			for(j = 0; j < i; j++){
				close(up_fds[j]);
			}
			return -1;
		}
	}
	for(i = 0; i < 4; i++){
		for(j = 0; j < threshold; j++){
			if(read(up_fds[j], key_y+j, 8) == -1){
				for(i = 0; i < threshold; i++){
					close(up_fds[i]);
				}
				return -1;
			}
		}
		share_key_combinen(threshold, user_ids, key_y, 0, (uint64_t*)(aes_key+i*8));
	}
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	EVP_DigestUpdate(md_ctx, iv, 16);
	EVP_DigestUpdate(md_ctx, aes_key, 32);
	EVP_DigestFinal(md_ctx, hash_v, 0);
	EVP_MD_CTX_free(md_ctx);
	EVP_DecryptInit(ctx, EVP_aes_256_cbc(), aes_key, iv);
	if(memcmp(hash_v, check_hash, 32)) return -1;
	if(pipe(pipefd) == -1) return -3;
	pipe_flag = fcntl(pipefd[0], F_GETFL, 0);
	fcntl(pipefd[0], F_SETFL, pipe_flag| O_NONBLOCK);
	pipe_flag = fcntl(pipefd[1], F_GETFL, 0);
	fcntl(pipefd[1], F_SETFL, pipe_flag| O_NONBLOCK);
	if((oper_fd = open(file_name, O_CREAT|O_WRONLY, 0666)) == -1) return -1;
	oper_pid = fork();
	if(oper_pid){
		close(pipefd[0]);
		close(oper_fd);
		if(sep_data_merge(up_fds, pipefd[1], user_ids, threshold)) return -1;
		close(pipefd[1]);
	}else{
		close(pipefd[1]);
		while(1){
			rbl = 0;
			while(rbl < 1024){
				read_bytes = read(pipefd[0], buffer+rbl, 1024-rbl);
				if(read_bytes == -1){
					if(errno == EAGAIN) continue;
					break;
				}
				if(read_bytes == 0) break;
				rbl += read_bytes;
			}
			if(read_bytes == -1) break;
			if(read_bytes == 0){
				read_bytes = 1024+128;
				if(!EVP_DecryptUpdate(ctx, sbuffer, &read_bytes, buffer, rbl)){
					read_bytes = -1;
					break;
				}
				if(write(oper_fd, sbuffer, read_bytes) == -1){
					read_bytes = -1;
					break;
				}
				read_bytes = 1024+128;
				if(!EVP_DecryptFinal(ctx, sbuffer, &read_bytes)){
					read_bytes = -1;
					break;
				}
				if(write(oper_fd, sbuffer, read_bytes) == -1){
					read_bytes = -1;
					break;
				}
			}
			read_bytes = 1024+128;
			if(!EVP_DecryptUpdate(ctx, sbuffer, &read_bytes, buffer, rbl)){
				read_bytes = -1;
				break;
			}
			if(write(oper_fd, sbuffer, read_bytes) == -1){
				read_bytes = -1;
				break;
			}
		}
		close(pipefd[0]);
		close(oper_fd);
		if(read_bytes == -1){
			kill(oper_pid, SIGKILL);
		}
		waitpid(oper_pid, 0, 0);
	}
	for(i = 0; i < threshold; i++){
		close(up_fds[i]);
	}
	EVP_MD_CTX_free(md_ctx);
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
	if(read_bytes == -1){
		return -1;
	}
	return 0;
}

int temp_encode_clean(char* upname){
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

int temp_decode_clean(char* upname){
	char path[256+256+7];
	DIR* oper_dir;
	struct dirent* oper_dirent;
	while(1){
		if(!(oper_dirent = readdir(oper_dir))) break;
		if(oper_dirent->d_type != DT_REG) continue;
		if(sprintf(path, ".temp/%s/%s", upname, oper_dirent->d_name) < 1) continue;
		if(remove(path)) continue;
	}
	if(sprintf(path, ".temp/%s", upname) < 1) return -1;
	if(rmdir(path) == -1) return -1;
	return 0;
}
