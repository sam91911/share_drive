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
	for(uint64_t i = 0; i < threshold; i++){
		sscanf(argv[3+i], "%ld", keys+i);
	}
	for(uint64_t i = 0; i < threshold; i++){
		ifds[i] = open(argv[3+threshold+i], O_RDONLY);
	}
	ofd = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if(sep_data_merge(ifds, ofd, keys, threshold)) return -2;
	for(uint64_t i = 0; i < threshold; i++){
		close(ifds[i]);
	}
	close(ofd);
	return 0;

}
