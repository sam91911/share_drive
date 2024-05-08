#include "dh.h"
#include <stdio.h>
#include <stdint.h>


int main(int argc, char** argv){
	if(argc < 5) return -1;
	uint64_t len;
	sscanf(argc[1], "%ld", &len);
	uint8_t x[len], y[len], p[len], k[len];
	for(uint64_t i = 0; i < len; i++){
		sscanf(argv[2], "%2hhx", x+i);
		sscanf(argv[3], "%2hhx", y+i);
		sscanf(argv[4], "%2hhx", p+i);
	}
	DH_getKey(x, y, p, len, k);
	for(uint64_t i = 0; i < len; i++){
		printf("%02x", k[i]);
	}
	return 0;
}
