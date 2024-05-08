#include "sep_data.h"
#include "fsize.h"
#include "aes.h"
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char** argv){
	if(argc < 7) return 1;
	uint64_t threshold;
	sscanf(argv[1], "%ld", &threshold);
	uint64_t key;
	sscanf(argv[3], "%ld", &key);
	uint8_t aes_key[32];
	uint8_t aes_iv[16];
	for(int i = 0; i < 32; i++){
		sscanf(argv[5]+2*i, "%2hhx", aes_key+i);
	}
	for(int i = 0; i < 16; i++){
		sscanf(argv[6]+2*i, "%2hhx", aes_iv+i);
	}
	int ifd, ofd;
	int pipefd[4];
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
	if((ifd = open(argv[4], O_RDONLY)) <3) return -1;
	if((ofd = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, 0666)) <3) return -1;
	if(fork()){
		close(pipefd[1]);
		close(pipefd[2]);
		close(pipefd[3]);
		if(sep_data_sep(pipefd[0], ofd, key, threshold)) return -2;
		close(pipefd[0]);
	}else{
		close(pipefd[0]);
		if(fork()){
			close(pipefd[3]);
			if(aes_ofb(pipefd[2], pipefd[1], aes_key, aes_iv)) return -3;
			close(pipefd[2]);
			close(pipefd[1]);
		}else{
			close(pipefd[1]);
			close(pipefd[2]);
			if(fsize_add(ifd, pipefd[3])) return -4;
			close(pipefd[3]);
		}
	}
	close(ofd);
	close(ifd);
	return 0;

}
