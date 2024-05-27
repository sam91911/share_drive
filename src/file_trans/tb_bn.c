#include "bn.h"
#include <stdio.h>
#include <stdint.h>
#include <openssl/bn.h>


int main(int argc, char** argv){
	if(argc < 3) return -1;
	uint64_t nlen, dlen;
	sscanf(argv[1], "%ld", &nlen);
	sscanf(argv[2], "%ld", &dlen);
	return 0;
}
