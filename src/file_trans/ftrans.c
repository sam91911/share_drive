#include "ftrans.h"

#ifndef FTRANS_BLOCK_SIZE
#define FTRANS_BLOCK_SIZE 4096
#endif

int ftrans_send(int ifile, int sock){
	uint8_t sbuffer[FTRANS_BLOCK_SIZE];
	int64_t read_value;
	uint16_t rbl = 0;
	while(1){
		rbl = 0;
		while(rbl < FTRANS_BLOCK_SIZE){
			read_value = read(ifile, sbuffer+rbl, FTRANS_BLOCK_SIZE-rbl);
			if(read_value == 0){
				goto exit;
			}
			if(read_value < 0){
				if(errno == EAGAIN) continue;
				if(errno == EPIPE) goto exit;
				return -1;
			}
			rbl += read_value;
		}
		if(send(sock, sbuffer, FTRANS_BLOCK_SIZE, 0) < 0) return -2;
	}
exit:
	if(send(sock, sbuffer, rbl, 0) < 0) return -2;
	return 0;
}

int ftrans_recv(int ofile, int sock){
	uint8_t sbuffer[FTRANS_BLOCK_SIZE];
	int64_t read_value;
	uint16_t rbl = 0;
	while(1){
		rbl = 0;
		while(rbl < FTRANS_BLOCK_SIZE){
			read_value = recv(sock, sbuffer+rbl, FTRANS_BLOCK_SIZE-rbl, MSG_WAITALL);
			if(read_value == 0){
				goto exit;
			}
			if(read_value < 0){
				if(errno == EAGAIN) continue;
				return -1;
			}
			rbl += read_value;
		}
		if(write(ofile, sbuffer, FTRANS_BLOCK_SIZE, 0) < 0) return -2;
	}
exit:
	if(write(ofile, sbuffer, rbl, 0) < 0) return -2;
	return 0;
}
