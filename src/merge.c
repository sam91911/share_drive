#include "sep_data.h"
#include "fsize.h"
#include "aes.h"
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/wait.h>
int main(int argc, char** argv){
	uint64_t threshold;
	sscanf(argv[1], "%ld", &threshold);
	uint64_t keys[threshold];
	int ifds[threshold];
	int ofd;
	int pipefd[4];
	uint8_t aes_key[32];
	uint8_t aes_iv[16];
	for(int i = 0; i < 32; i++){
		sscanf(argv[3]+2*i, "%2hhx", aes_key+i);
	}
	for(int i = 0; i < 16; i++){
		sscanf(argv[4]+2*i, "%2hhx", aes_iv+i);
	}
	if(pipe(pipefd) == -1){
		perror("pipe");
		exit(EXIT_FAILURE);
	}
	if(pipe(pipefd+2) == -1){
		perror("pipe");
		exit(EXIT_FAILURE);
	}
	int flag;
	flag = fcntl(pipefd[0], F_GETFL, 0);
	fcntl(pipefd[0], F_SETFL, flag| O_NONBLOCK);
	flag = fcntl(pipefd[1], F_GETFL, 0);
	fcntl(pipefd[1], F_SETFL, flag| O_NONBLOCK);
	flag = fcntl(pipefd[2], F_GETFL, 0);
	fcntl(pipefd[2], F_SETFL, flag| O_NONBLOCK);
	flag = fcntl(pipefd[3], F_GETFL, 0);
	fcntl(pipefd[3], F_SETFL, flag| O_NONBLOCK);
	for(uint64_t i = 0; i < threshold; i++){
		sscanf(argv[5+i], "%ld", keys+i);
	}
	for(uint64_t i = 0; i < threshold; i++){
		ifds[i] = open(argv[5+threshold+i], O_RDONLY);
	}
	ofd = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if(fork()){
		close(pipefd[0]);
		close(pipefd[2]);
		close(pipefd[3]);
		if(sep_data_merge(ifds, pipefd[1], keys, threshold)) return -2;
		close(pipefd[1]);
	}else{
		close(pipefd[1]);
		if(fork()){
			close(pipefd[2]);
			if(aes_ofb(pipefd[0], pipefd[3], aes_key, aes_iv)) return -3;
			close(pipefd[0]);
			close(pipefd[3]);
		}else{
			close(pipefd[0]);
			close(pipefd[3]);
			if(fsize_remove(pipefd[2], ofd)) return -4;
			close(pipefd[2]);
		}
	}
	for(uint64_t i = 0; i < threshold; i++){
		close(ifds[i]);
	}
	close(ofd);
	return 0;

}
