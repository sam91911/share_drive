#include "share_key.h"
#include <stdio.h>
#include <stdint.h>

inline uint64_t random64(){
	FILE* f = fopen("/dev/urandom", "rb");
	uint64_t x;
	if(!fread(&x, sizeof(uint64_t), 1, f)) return 0;
	fclose(f);
	return x;
}

int main(int argc, char** argv){
	if(argc < 3) return 0;
	uint64_t key, threshold;
	sscanf(argv[1], "%ld", &key);
	sscanf(argv[2], "%ld", &threshold);
	uint64_t y[threshold];
	uint64_t x[threshold];
	for(int i = 0; i < threshold; i++){
		x[i] = random64();
	}
	share_key_share(key, threshold, threshold, x, y);
	for(int i = 0; i < threshold; i++){
		printf("%016lx\t%016lx\n", x[i], y[i]);
	}
	return 0;
}
