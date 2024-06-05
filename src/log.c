#include "log.h"

int log_init(){
	struct stat oper_stat;
	int oper_fd;
	uint8_t buffer[8];
	uint8_t hash_v[32];
	uint8_t hash_buf[8192];
	memset(buffer, 0, 8);
	if(access("log", F_OK)){
		if(errno == ENOENT){
			if(mkdir("log", 0744)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	if(stat("log", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if((oper_fd = open("log/default", O_CREAT|O_WRONLY|O_TRUNC, 0644)) == -1) return -1;
	if(lseek(oper_fd, 32*256, SEEK_SET) == -1){
		close(oper_fd);
		return -1;
	}
	for(uint16_t i = 0; i < (1<<8); i++){
		buffer[3] = i;
		if(EVP_Digest(buffer, 8, hash_v, 0, EVP_sha3_256(), 0) != 1){
			close(oper_fd);
			return -1;
		}
		memcpy(hash_buf+i*32, hash_v, 32);
	}
	if(write(oper_fd, hash_buf, 8192) == -1){
		close(oper_fd);
		return -1;
	}
	for(int8_t i = 7; i >= 0; i--){
		if(lseek(oper_fd, ((1<<i)-1)*32, SEEK_SET) == -1){
			close(oper_fd);
			return -1;
		}
		for(uint8_t j = 0; j < (1<<i); j++){
			if(EVP_Digest(hash_buf+j*64, 64, hash_v, 0, EVP_sha3_256(), 0) != 1){
				close(oper_fd);
				return -1;
			}
			memcpy(hash_buf+j*32, hash_v, 32);
		}
		if(write(oper_fd, hash_buf, (1<<(i+5))) == -1){
			close(oper_fd);
			return -1;
		}
	}
	close(oper_fd);
	return 0;
}

int log_hash_reset(uint64_t serverid, uint64_t pack_id){
	struct stat oper_stat;
	int oper_fd, src_fd;
	char path[64];
	uint8_t buffer[40];
	memset(buffer, 0, 32);
	if(sprintf(path, "log/%016lX/cur_hash", serverid) < 1) return -1;
	if(access(path, F_OK|R_OK)){
		if(errno != ENOENT) return -1;
		else{
			memset(buffer+32, 0, 8);
		}
	}else{
		if((oper_fd = open(path, O_RDONLY, 0644)) == -1) return -1;
		if(lseek(oper_fd, 16384, SEEK_SET) == -1){
			close(oper_fd);
			return -1;
		}
		if(read(oper_fd, buffer+32, 8) == -1){
			close(oper_fd);
			return -1;
		}
		if(pack_id){
			*(uint64_t*)(buffer+32) = pack_id;
		}else{
			*(uint64_t*)(buffer+32) += 1;
		}
		close(oper_fd);
	}
	if(stat("log/default", &oper_stat)){
		return -1;
	}
	if((oper_fd = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0644)) == -1) return -1;
	if((src_fd = open("log/default", O_RDONLY)) == -1){
		close(oper_fd);
		return -1;
	}
	if(sendfile(oper_fd, src_fd, 0, oper_stat.st_size) == -1){
		close(oper_fd);
		close(src_fd);
		return -1;
	}
	if(write(oper_fd, buffer, 33) == -1){
		close(oper_fd);
		close(src_fd);
		return -1;
	}
	close(oper_fd);
	close(src_fd);
	return 0;
}

int log_hash_nullGet(uint64_t serverid, uint8_t* hash){
	int oper_fd;
	char path[64];
	uint8_t buffer[32];
	uint8_t hash_buf[32];
	int i, j;
	if(sprintf(path, "log/%016lX/cur_hash", serverid) < 1) return -1;
	if((oper_fd = open(path, O_RDONLY)) == -1) return -1;
	if(lseek(oper_fd, 16384-32, SEEK_SET) == -1){
		close(oper_fd);
		return -1;
	}
	if(read(oper_fd, buffer, 32) == -1){
		close(oper_fd);
		return -1;
	}
	i = 0;
	j = 0;
	while(1){
		for(; i < 32; i++){
			if(buffer[i] != 0xff) break;
		}
		if(i == 32){
			i = -1;
			break;
		}
		for(; j < 8; j++){
			if(!(buffer[i]&(1<<j))){
				i = i*8+j;
				break;
			}
		}
		if(!hash) break;
		if(lseek(oper_fd, 8192-32+i*32, SEEK_SET) == -1){
			close(oper_fd);
			return -1;
		}
		if(read(oper_fd, hash_buf, 32) == -1){
			close(oper_fd);
			return -1;
		}
		if(memcmp(hash, hash_buf, 32)) break;
		i = (i/8);
		if(j >= 7){
			i++;
			j = 0;
		}else{
			j++;
		}
	}
	close(oper_fd);
	return i;
}

int log_server_init(uint64_t serverid){
	struct stat oper_stat;
	int oper_fd, src_fd;
	char path[64];
	if(access("log", F_OK)){
		if(errno == ENOENT){
			if(mkdir("log", 0744)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	if(stat("log", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(sprintf(path, "log/%016lX", serverid) < 1) return -1;
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
	log_hash_reset(serverid, 0);
	if(sprintf(path, "log/%016lX/cont", serverid) < 1) return -1;
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
	if(sprintf(path, "log/%016lX/cont/list", serverid) < 1) return -1;
	if((oper_fd = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0644)) == -1) return -1;
	close(oper_fd);
	return 0;
}

int log_file(uint64_t serverid, uint64_t pack){
	int oper_fd;
	char path[64];
	if(sprintf(path, "log/%016lX/%016lX", serverid, pack) < 1) return -1;
	oper_fd = open(path, O_RDONLY);
	return oper_fd;
}

int log_content(uint64_t serverid, uint8_t* id, int flags){
	if(!id) return -1;
	int oper_fd;
	char path[64];
	if(sprintf(path, "log/%016lX/cont/%016lX%02X", serverid, *(uint64_t*)id, id[8]) < 1) return -1;
	if(flags & O_CREAT){
		oper_fd = open(path, flags, 0644);
	}else{
		oper_fd = open(path, flags);
	}
	return oper_fd;
}

int log_get_content(uint64_t serverid, uint64_t userid, char* name, uint8_t* id){
	if(!id) return -1;
	FILE* oper_file;
	char path[64];
	uint8_t buffer[512];
	uint64_t r_id;
	int8_t brk = 1;
	uint8_t id_r[9];
	uint8_t id_c[9];
	memset(id_c, 0, 9);
	if(sprintf(path, "log/%016lX/cont/list", serverid) < 1) return -1;
	if(!(oper_file = fopen(path, "r"))) return -1;
	while(!feof(oper_file)){
		if(!fgets(buffer, 512, oper_file)){
			if(brk) brk = -1;
			break;
		}
		r_id = strtoul(buffer+20, 0, 16);
		if(r_id != userid) continue;
		if(memcmp(buffer+37, name, strlen(name))) continue;
		if(buffer[37+strlen(name)] != '\n') continue;
		*(uint64_t*)id_r = strtoul(buffer, 0, 16);
		id_r[8] = strtoul(buffer+17, 0, 16);
		if(*(uint64_t*)id_r >= *(uint64_t*)id_c){
			if(id_r[8] > id_c[8]){
				memcpy(id_c, id_r, 9);
			}
		}
		brk = 0;
	}
	if(!brk) memcpy(id, id_c, 9);
	fclose(oper_file);
	return brk;
}

int log_check_content(uint64_t serverid, uint64_t userid, char* name, uint8_t* id){
	FILE* oper_file;
	char path[64];
	uint8_t buffer[512];
	uint64_t r_id;
	int8_t brk = 0;
	uint8_t id_r[9];
	if(sprintf(path, "log/%016lX/cont/list", serverid) < 1) return -1;
	if(!(oper_file = fopen(path, "r"))) return -1;
	while(!feof(oper_file)){
		if(!fgets(buffer, 512, oper_file)){
			brk = -1;
			break;
		}
		r_id = strtoul(buffer+20, 0, 16);
		if(r_id != userid) continue;
		if(memcmp(buffer+37, name, strlen(name))) continue;
		if(buffer[37+strlen(name)] != '\n') continue;
		if(!id){
			break;
		}
		*(uint64_t*)id_r = strtoul(buffer, 0, 16);
		id_r[8] = strtoul(buffer+17, 0, 16);
		if(!memcmp(id_r, id, 9)) break;
	}
	fclose(oper_file);
	return brk;
	
}

int log_add_content(uint64_t serverid, uint64_t userid, char* name, uint8_t* id){
	if(!id) return -1;
	int oper_fd;
	FILE* oper_file;
	char path[64];
	uint8_t buffer[512];
	uint64_t size;
	if(!log_check_content(serverid, userid, name, id)) return 0;
	if(sprintf(path, "log/%016lX/cont/list", serverid) < 1) return -1;
	if((oper_fd = open(path, O_WRONLY|O_APPEND)) == -1) return -1;
	if(!(oper_file = fdopen(oper_fd, "a"))){
		close(oper_fd);
		return -1;
	}
	if(fprintf(oper_file, "%016lX %02X %016lX %s\n", *(uint64_t*)id, id[8], userid, name) < 1){
		fclose(oper_file);
		close(oper_fd);
		return -1;
	}
	fclose(oper_file);
	close(oper_fd);
	return 0;
}

int log_pack(uint64_t serverid){
	int oper_fd, src_fd;
	char path[64];
	uint8_t hash_r[64];
	uint8_t hash_v[32];
	uint64_t pack;
	if(sprintf(path, "log/%016lX/cur_hash", serverid) < 1) return -1;
	if((oper_fd = open(path, O_RDONLY)) == -1) return -1;
	if(read(oper_fd, hash_r+32, 32) == -1){
		close(oper_fd);
		return -1;
	}
	if(lseek(oper_fd, 16384, SEEK_SET) == -1){
		close(oper_fd);
		return -1;
	}
	if(read(oper_fd, &pack, 8) == -1){
		close(oper_fd);
		return -1;
	}
	close(oper_fd);
	if(sprintf(path, "log/%016lX/%016lX", serverid, pack) < 1) return -1;
	if((oper_fd = open(path, O_RDONLY)) == -1){
		memset(hash_r, 0, 32);
	}else{
		if(read(oper_fd, hash_r, 32) == -1){
			close(oper_fd);
			return -1;
		}
		close(oper_fd);
	}
	if(sprintf(path, "log/%016lX/%016lX", serverid, pack) < 1) return -1;
	pack += 1;
	if((oper_fd = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0644)) == -1) return -1;
	if(sprintf(path, "log/%016lX/cur_hash", serverid) < 1) return -1;
	if((src_fd = open(path, O_RDONLY)) == -1) return -1;
	if(EVP_Digest(hash_r, 64, hash_v, 0, EVP_sha3_256(), 0) != 1) return -1;
	if(write(oper_fd, hash_v, 32) == -1){
		close(oper_fd);
		close(src_fd);
		return -1;
	}
	if(write(oper_fd, hash_r, 64) == -1){
		close(oper_fd);
		close(src_fd);
		return -1;
	}
	if(sendfile(oper_fd, src_fd, 0, 16384-32) == -1){
		close(oper_fd);
		close(src_fd);
		return -1;
	}
	close(oper_fd);
	close(src_fd);
	log_hash_reset(serverid, 0);
	return 0;
}

int log_add(uint64_t serverid, uint8_t* log, uint64_t len, uint8_t* id){
	int oper_fd;
	FILE* oper_file;
	char path[64];
	uint8_t hash_v[32];
	int read_bytes;
	uint8_t idx;
	uint64_t pack;
	uint8_t buffer[64];
	uint8_t hash_p[256];
	uint8_t o_flag;
	if(EVP_Digest(log, len, hash_v, 0, EVP_sha3_256(), 0) != 1) return -1;
	if((read_bytes = log_hash_nullGet(serverid, hash_v)) == -1){
		log_pack(serverid);
	}
	if((read_bytes = log_hash_nullGet(serverid, hash_v)) == -1){
		return -1;
	}
	idx = read_bytes;
	if(sprintf(path, "log/%016lX/cur_hash", serverid) < 1) return -1;
	if((oper_fd = open(path, O_RDONLY)) == -1) return -1;
	for(int i = 0; i < 8; i++){
		if(lseek(oper_fd, 32*((1<<(8-i))+((idx>>i)^0x01)-1), SEEK_SET) == -1){
			close(oper_fd);
			return -1;
		}
		if(read(oper_fd, hash_p+i*32, 32) == -1){
			close(oper_fd);
			return -1;
		}
	}
	if(lseek(oper_fd, 16384-32+(idx/8), SEEK_SET) == -1){
		close(oper_fd);
		return -1;
	}
	if(read(oper_fd, &o_flag, 1) == -1){
		close(oper_fd);
		return -1;
	}
	o_flag |= (0x01<<(idx%8));
	if(lseek(oper_fd, 16384, SEEK_SET) == -1){
		close(oper_fd);
		return -1;
	}
	if(read(oper_fd, &pack, 8) == -1){
		close(oper_fd);
		return -1;
	}
	close(oper_fd);
	if((oper_fd = open(path, O_WRONLY)) == -1) return -1;
	if(lseek(oper_fd, 32*((1<<8)+idx-1), SEEK_SET) == -1){
		close(oper_fd);
		return -1;
	}
	if(write(oper_fd, hash_v, 32) == -1){
		close(oper_fd);
		return -1;
	}
	for(int i = 0; i < 8; i++){
		if((idx>>i)&0x01){
			memcpy(buffer+32, hash_v, 32);
			memcpy(buffer, hash_p+32*i, 32);
		}else{
			memcpy(buffer, hash_v, 32);
			memcpy(buffer+32, hash_p+32*i, 32);
		}
		if(EVP_Digest(buffer, 64, hash_v, 0, EVP_sha3_256(), 0) != 1){
			close(oper_fd);
			return -1;
		}
		if(lseek(oper_fd, 32*((1<<(7-i))+(idx>>(i+1))-1), SEEK_SET) == -1){
			close(oper_fd);
			return -1;
		}
		if(write(oper_fd, hash_v, 32) == -1){
			close(oper_fd);
			return -1;
		}
	}
	if(lseek(oper_fd, 16384-32+(idx/8), SEEK_SET) == -1){
		close(oper_fd);
		return -1;
	}
	if(write(oper_fd, &o_flag, 1) == -1){
		close(oper_fd);
		return -1;
	}
	close(oper_fd);
	*(uint64_t*) id = pack;
	id[8] = idx;
	if((oper_fd = log_content(serverid, id, O_CREAT|O_WRONLY|O_TRUNC)) == -1) return -1;
	if(write(oper_fd, log, len) == -1){
		close(oper_fd);
		return -1;
	}
	close(oper_fd);
	return 0;
}

int log_get(uint64_t serverid, uint8_t* log, uint64_t* len, uint8_t* id){
	int oper_fd;
	int read_bytes;
	if((oper_fd = log_content(serverid, id, O_RDONLY)) == -1) return -1;
	if(read_bytes = read(oper_fd, log, *len) == -1){
		close(oper_fd);
		return -1;
	}
	*len = read_bytes;
	close(oper_fd);
	return 0;
}

int log_cur_pack(uint64_t serverid, uint64_t* pack){
	int oper_fd;
	char path[64];
	if(sprintf(path, "log/%016lX/cur_hash", serverid) < 1) return -1;
	if((oper_fd = open(path, O_RDONLY)) == -1) return -1;
	if(lseek(oper_fd, 16384, SEEK_SET) == -1){
		close(oper_fd);
		return -1;
	}
	if(read(oper_fd, pack, 8) == -1){
		close(oper_fd);
		return -1;
	}
	close(oper_fd);
	return 0;
}

int log_content_dir(uint64_t serverid, DIR** dir){
	char path[64];
	if(sprintf(path, "log/%016lX/cont/", serverid) < 1) return -1;
	if(!(*dir = opendir(path))) return -1;
	return  0;
}

int log_add_pack(uint64_t serverid, uint8_t* pack, uint64_t len, uint64_t offset, uint64_t packid){
	int oper_fd, src_fd;
	char path[64];
	if(sprintf(path, "log/%016lX/%016lX", serverid, packid) < 1) return -1;
	if((oper_fd = open(path, O_CREAT|O_WRONLY, 0644)) == -1) return -1;
	if(lseek(oper_fd, offset, SEEK_SET) == -1){
		close(oper_fd);
		return -1;
	}
	if(write(oper_fd, pack, len) == -1){
		close(oper_fd);
		return -1;
	}
	close(oper_fd);
	return 0;

}
