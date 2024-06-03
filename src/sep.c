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
	if(argc < 4) return 1;
	uint64_t threshold;
	sscanf(argv[1], "%ld", &threshold);
	uint64_t key;
	sscanf(argv[3], "%ld", &key);
	int ifd, ofd;
	if((ifd = open(argv[4], O_RDONLY)) <3) return -1;
	if((ofd = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, 0666)) <3) return -1;
	if(sep_data_sep(ifd, ofd, key, threshold)) return -2;
	close(ofd);
	close(ifd);
	return 0;

}
