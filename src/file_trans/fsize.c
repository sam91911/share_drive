#include "fsize.h"

int fsize_add(int ifd, int ofd)
{
	uint8_t block[FSIZE_BLOCK_SIZE];
	ssize_t bytes_read;
	ssize_t bytes_write;
	ssize_t remain;
	struct stat st;
	if (fstat(ifd, &st) != 0) {
		printf("errno 0:%x\n", errno);
		return -2;
	}

	off_t file_size = st.st_size;
	if ((bytes_read = write(ofd, &file_size, sizeof(off_t))) != sizeof(off_t)) {
		printf("errno 1:%x\n", errno);
		return -2;
	}
	while((bytes_read = read(ifd, block, FSIZE_BLOCK_SIZE))){
		while(remain < bytes_read){
			bytes_write = write(ofd, block+remain, bytes_read-remain);
			if(bytes_write < 0){
				if(errno == EAGAIN) continue;
				return -2;
			}
			remain += bytes_write;
		}
		remain = 0;
		if((bytes_read < 0)&&(errno != EAGAIN)) break;
	}
	if (bytes_read < 0) {
		printf("errno 1:%x\n", errno);
		fprintf(stderr, "Error reading input file.\n");
		exit(EXIT_FAILURE);
	}
	return 0;
}

int fsize_remove(int ifd, int ofd)
{
	unsigned char block[FSIZE_BLOCK_SIZE];
	ssize_t bytes_read;
	off_t file_size;
	while(1){
		if(bytes_read = read(ifd, &file_size, sizeof(off_t)) < 0){
			if(errno == EAGAIN) continue;
			return -2;
		}
		break;
	}
	while ((bytes_read = read(ifd, block, FSIZE_BLOCK_SIZE)) != 0) {
		if(bytes_read < 0){
			if(errno == EAGAIN) continue;
			printf("errno:%x\n", errno);
			return -2;
		}
		if (write(ofd, block, (bytes_read < file_size)?bytes_read:file_size) < 0) {
			printf("errno:%x\n", errno);
			return -2;
		}
		if(file_size <= bytes_read) break;
		file_size -= bytes_read;
	}
	if (bytes_read < 0) {
		fprintf(stderr, "Error reading input file.\n");
		exit(EXIT_FAILURE);
	}
	return 0;
}

