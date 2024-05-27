#include "fpack.h"

#ifndef FPACK_BLOCK_SIZE
#define FPACK_BLOCK_SIZE 4096
#endif

int fpack_pack(int ifile, int ofile, EVP_PKEY* pkey){
	uint8_t block[32+FPACK_BLOCK_SIZE];
	uint8_t signature[72];
	int64_t remain = 0;
	int64_t read_value;
	uint16_t rbl = 0;
	uint8_t state = 0;
	uint64_t sign_len;
	while(1){
		while(rbl < FPACK_BLOCK_SIZE){
			read_value = read(ifile, block+rbl+32, FPACK_BLOCK_SIZE-rbl);
			if(read_value == 0){
				goto deal_remain;
			}
			if(read_value < 0){
				if(errno == EAGAIN) continue;
				if(errno == EPIPE) goto deal_remain;
				return -1;
			}
			rbl += read_value;
		}
		rbl = 0;
		EVP_Digest(block+32, FPACK_BLOCK_SIZE, block, 0, EVP_sha3_256(), 0);
		if(!state){
			if(PK_sign(pkey, block, 32, signature, &sign_len, 72)) return -1;
			write(ofile, signature, 72);
			state = 1;
		}
		write(ofile, block, 32+FPACK_BLOCK_SIZE);
	}
deal_remain:
	EVP_Digest(block+32, rbl, block, 0, EVP_sha3_256(), 0);
	write(ofile, block, 32+rbl);
	return 0;
}
