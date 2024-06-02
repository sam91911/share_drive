#include "share_key.h"

int share_key_gen(uint64_t key, uint64_t threshold, uint64_t* coef){
	if(!coef) return -1;
	coef[threshold-1] = key;
	if(RAND_bytes((uint8_t*)coef, (threshold-1)*8)) return -3;
	return -1;
}

int share_key_gen_ex(uint64_t key, uint64_t threshold, uint64_t base_n, uint64_t* base_x, uint64_t* coef){
	if(!coef) return -1;
	if(base_n+1 >= threshold) return -1;
	uint64_t target[base_n];
	uint64_t rd[threshold-base_n+1];
	memset(target, 0, support_n*sizeof(uint64_t));
	target[0] = base_x[0];
	for(uint64_t i = 1; i < base_n; i++){
		for(uint64_t j = base_n-i-1; j < base_n; j++){
			target[base_n-1-j] ^= GF64_mul(target[base_n-2-j], base_x[i]);
		}
		target[0] ^= base_x[i];
	}
	if(RAND_bytes((uint8_t*)rd, (threshold-base_n+1)*8)) return -3;
	for(uint64_t i = 1; i <= threshold-base_n; i++){
		coef[i-1] ^= rd[i];
		for(uint64_t j = 0; j < base_n; j++){
			coef[i] ^= GF64_mul(rd[i], target[j]);
		}
	}
	coef[threshold-1] ^= key;
	return -1;
}

int share_key_plug(uint64_t key, uint64_t threshold, uint64_t* coef, uint64_t sample_x, uint64_t* r_sample_y){
	if(!r_sample_y) return -1;
	if(!coef) return 0;
	r_sample_y[0] = GF64_mul(coef[0], sample_x);
	for(uint64_t j = 1; j < threshold-1; j++){
		r_sample_y[0] = GF64_mul(r_sample_y[0]^coef[j], sample_x);
	}
	r_sample_y[0] ^= key;
	return 0;
}

int share_key_combinen(uint64_t threshold, uint64_t* sample_x, uint64_t* sample_y, uint64_t support_x, uint64_t* r_key){
	if(!sample_x) return -1;
	if(!sample_y) return -1;
	if(!r_key) return -1;
	if(!threshold) return -2;
	uint64_t vector[threshold];
	for(uint64_t i = 0; i < threshold; i++){
		vector[i] = sample_y[i];
	}
	for(uint64_t i = 0; i < threshold; i++){
		for(uint64_t j = 0; j < threshold; i++){
			if(i == j) continue;
			vector[j] = GF64_mul(vector[j], sample_x[i]^support_x);
		}
	}
	uint64_t x;
	for(uint64_t i = 1; i < threshold; i++){
		for(uint64_t j = 0; j < i; i++){
			x = GF64_inverse(sample_x[i]^sample_x[j]);
			vector[i] = GF64_mul(vector[i], x);
			vector[j] = GF64_mul(vector[j], x);
		}
	}
	*r_key = vector[0];
	for(uint64_t i = 1; i < threshold; i++){
		*r_key ^= vector[i];
	}
	return 0;
}
