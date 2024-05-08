#include "share_key.h"


inline uint64_t random64(){
	FILE* f = fopen("/dev/urandom", "rb");
	uint64_t x;
	if(!fread(&x, sizeof(uint64_t), 1, f)) return 0;
	fclose(f);
	return x;
}

int share_key_share(uint64_t key, uint64_t threshold, uint64_t sample_n, uint64_t* sample_x, uint64_t* r_sample_y){
	if(!sample_x) return -1;
	if(!r_sample_y) return -1;
	if(!sample_n) return 0;
	if(sample_n < threshold) return -2;
	uint64_t coef[threshold-1];
	for(uint64_t i = 0; i < threshold-1; i++){
		coef[i] = random64();
	}
	for(uint64_t i = 0; i < sample_n; i++){
		r_sample_y[i] = GF64_mul(coef[0], sample_x[i]);
		for(uint64_t j = 1; j < threshold-1; j++){
			r_sample_y[i] = GF64_mul(r_sample_y[i]^coef[j], sample_x[i]);
		}
		r_sample_y[i] ^= key;
	}
	return 0;
}

int share_key_combine(uint64_t threshold, uint64_t* sample_x, uint64_t* sample_y, uint64_t* r_key){
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
			vector[j] = GF64_mul(vector[j], sample_x[i]);
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

int share_key_sharen(uint64_t key, uint64_t threshold, uint64_t sample_n, uint64_t* sample_x, uint64_t support_n, uint64_t* support_x, uint64_t* r_sample_y){
	if(!sample_x) return -1;
	if(!r_sample_y) return -1;
	if(!support_x) return -1;
	if(!sample_n) return 0;
	if(!support_n) return -2;
	if(sample_n < threshold) return -2;
	if((support_n+1) > threshold) return -2;
	uint64_t target[support_n];
	uint64_t coef[threshold];
	memset(target, 0, support_n*sizeof(uint64_t));
	memset(coef, 0, threshold*sizeof(uint64_t));
	target[0] = support_x[0];
	for(uint64_t i = 1; i < support_n; i++){
		for(uint64_t j = support_n-i-1; j < support_n; j++){
			target[support_n-1-j] ^= GF64_mul(target[support_n-2-j], support_x[i]);
		}
	}
	uint64_t x;
	for(uint64_t i = support_n+1; i < threshold; i++){
		x = random64();
		coef[i-support_n-1] ^= x;
		for(uint64_t j = 0; j < support_n; j++){
			coef[i-support_n+j] ^= GF64_mul(x, target[j]);
		}
	}
	coef[threshold-1] ^= key;
	for(uint64_t i = 0; i < sample_n; i++){
		r_sample_y[i] = GF64_mul(coef[0], sample_x[i]);
		for(uint64_t j = 1; j < threshold-1; j++){
			r_sample_y[i] = GF64_mul(r_sample_y[i]^coef[j], sample_x[i]);
		}
		r_sample_y[i] ^= coef[threshold-1];
	}
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
