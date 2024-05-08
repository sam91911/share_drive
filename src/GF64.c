#include "GF64.h"

uint64_t GF64_mul(uint64_t a, uint64_t b){
	uint64_t rt = (b>>63)?a:0;
	b <<= 1;
	for(uint8_t i = 0; i < 63; i++){
		rt = (rt<<1)^((rt>>63)?0x0000000247f43cb7:0);
		if(b>>63){
			rt ^= a;
		}
		b <<= 1;
	}
	return rt;
}

uint64_t GF64_inverse(uint64_t a){
	uint64_t rt = a;
	for(uint8_t i = 0; i < 62; i++){
		rt = GF64_mul(GF64_mul(rt, rt), a);
	}
	rt = GF64_mul(rt, rt);
	return rt;
}
