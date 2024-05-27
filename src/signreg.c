#include "signreg.h"
#ifndef SIGNREG_CODE_TIME
#define SIGNREG_CODE_TIME 300
#endif

int signreg_init(){
	int oper_fd;
	uint8_t buffer[52];
	memset(buffer, 0, 52);
	if((oper_fd = open(".signreg", O_CREAT|O_WRONLY, 0600)) < 0) return -1;
	if(write(oper_fd, buffer, 52) == -1) return -1;
	close(oper_fd);
	return 0;
}

int signreg_check(uint8_t* mac, uint8_t* msg, uint64_t msg_len){
	if(access(".signreg", F_OK|R_OK|W_OK)) return -1;
	FILE* oper_file;
	int oper_fd;
	uint8_t buffer[52];
	uint8_t hash_value[32];
	EVP_MD_CTX* md_ctx;
	uint64_t end_line;
	uint64_t start_line;
	uint64_t new_start_line;
	uint8_t new_start = 1;
	time_t timenow = time(0);
	time_t timestart;
	time_t timeend;
	if(!(oper_file = fopen(".signreg", "r"))) return -1;
	if(fread(buffer, 52, 1, oper_file) < 1){
		fclose(oper_file);
		return -1;
	}
	start_line = *(uint64_t*)(buffer+0);
	end_line = *(uint64_t*)(buffer+4);
	new_start_line = start_line;
	if(start_line == end_line){
		fclose(oper_file);
		return 1;
	}
	if(start_line > end_line){
		fclose(oper_file);
		return -1;
	}
	if(start_line == 0){
		fclose(oper_file);
		return -1;
	}
	if(fseek(oper_file, start_line*52, SEEK_SET)){
		fclose(oper_file);
		return -1;
	}
	if(!(md_ctx = EVP_MD_CTX_new())) return -1;
	if(!EVP_DigestInit(md_ctx, EVP_sha3_256())) return -1;
	EVP_DigestInit(md_ctx, EVP_sha3_256());
	for(uint64_t i = start_line; i < end_line; i++){
		if(fread(buffer, 52, 1, oper_file)){
			fclose(oper_file);
			return 1;
		}
		timestart = *(time_t*)(buffer+32);
		timeend = *(time_t*)(buffer+32);
		if(timenow > timeend){
			if(new_start) new_start_line++;
			continue;
		}
		if(new_start) new_start = 0;
		if(timenow < timestart) continue;
		if(!EVP_DigestUpdate(md_ctx, buffer, 32)) return -1;
		if(!EVP_DigestUpdate(md_ctx, msg, msg_len)) return -1;
		if(!EVP_DigestFinal(md_ctx, hash_value, 0)) return -1;
		if(!memcmp(hash_value, mac, 32)){
			EVP_MD_CTX_free(md_ctx);
			fclose(oper_file);
			buffer[51] = 0x80;
			if((oper_fd = open(".signreg", O_WRONLY)) == -1) return -1;
			if(new_start_line != start_line){
				if(write(oper_fd, &new_start_line, 8) == -1) return -1;
			}
			if(lseek(oper_fd, i*52+51, SEEK_SET) == -1) return -1;
			if(write(oper_fd, buffer+51, 1) == -1) return -1;
			close(oper_fd);
			return 0;
		}
	}
	if(new_start_line != start_line){
		if((oper_fd = open(".signreg", O_WRONLY)) == -1) return -1;
		if(write(oper_fd, &new_start_line, 8) == -1) return -1;
		close(oper_fd);
	}
	EVP_MD_CTX_free(md_ctx);
	return 1;
}

int signreg_add(uint8_t* value, int64_t end, int64_t start){
	if(access(".signreg", F_OK|R_OK|W_OK)) return -1;
	int oper_fd;
	uint64_t start_line;
	uint8_t buffer[52];
	time_t timenow = time(0);
	memcpy(buffer, value, 32);
	//start time
	*(time_t*)(buffer+32) = timenow + start;
	//end time
	if(end){
		*(time_t*)(buffer+40) = *(time_t*)(buffer+32) + end;
	}else{
		*(time_t*)(buffer+40) = *(time_t*)(buffer+32) + SIGNREG_CODE_TIME;
	}
	//empty flag
	memset(buffer+48, 0, 4);
	if((oper_fd = open(".signreg", O_RDONLY)) == -1) return -1;
	if(read(oper_fd, &start_line, 8) == -1) return -1;
	close(oper_fd);
	start_line++;
	if((oper_fd = open(".signreg", O_WRONLY)) == -1) return -1;
	if(lseek(oper_fd, 0, SEEK_END) == -1) return -1;
	if(write(oper_fd, buffer, 52) == -1) return -1;
	if(lseek(oper_fd, 0, SEEK_SET) == -1) return -1;
	if(write(oper_fd, &start_line, 8) == -1) return -1;
	close(oper_fd);
	return 0;
}
