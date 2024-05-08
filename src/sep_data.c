#include "sep_data.h"
#ifndef SEP_BUFFER_SIZE
#define SEP_BUFFER_SIZE 1024
#endif

int sep_data_sep(int ipipe, int opipe, uint64_t key, uint64_t threshold){
	if(ipipe < 0) return -1;
	if(opipe < 0) return -2;
	uint64_t vector[threshold];
	vector[0] = 1;
	for(uint64_t i = 1; i < threshold; i++){
		vector[i] = GF64_mul(vector[i-1], key);
	}
	uint64_t data[threshold];
	uint64_t rt;
	int64_t remain;
	int64_t read_value;
	uint8_t rbuffer[SEP_BUFFER_SIZE];
	uint8_t wbuffer[SEP_BUFFER_SIZE];
	uint16_t rbl = 0, rpt = 0;
	uint16_t wpt = 0;
	remain = 0;
	while(1){
		if(rbl < rpt+threshold*8){
			remain = rbl-rpt;
			memcpy(data, rbuffer+rpt, remain);
			rbl = 0;
			while(rbl < (threshold*8-remain)){
				read_value = read(ipipe, rbuffer+rbl, SEP_BUFFER_SIZE-rbl);
				if(read_value == 0){
					goto deal_remain;
				}
				if(read_value < 0){
					if(errno == EAGAIN)
						continue;
					if(errno == EPIPE)
						goto deal_remain;
					return -1;
				}
				rbl += read_value;
			}
			memcpy(data+remain, rbuffer, threshold*8-remain);
			rpt = threshold*8-remain;
		}else{
			memcpy(data, rbuffer+rpt, threshold*8);
			rpt += threshold*8;
		}
		rt = data[0];
		for(uint64_t i = 1; i < threshold; i++){
			rt ^= GF64_mul(data[i], vector[i]);
		}
		if(wpt+8 > SEP_BUFFER_SIZE){
			while(1){
				read_value = write(opipe, wbuffer, wpt);
				if(read_value < 0){
					if(errno == EAGAIN)
						continue;
					if(errno == EPIPE)
						return 0;
					return -1;
				}
				break;
			}
			wpt = 0;
		}
		memcpy(wbuffer+wpt, &rt, 8);
		wpt += 8;
	}
deal_remain:
	if(!(remain+rbl)) goto deal_write;
	memcpy(((uint8_t*)data)+remain, rbuffer, rbl);
	memset(((uint8_t*)data)+remain+rbl, 0, (threshold*8-(remain+rbl)));
	rt = data[0];
	for(uint64_t i = 1; i < threshold; i++){
		rt ^= GF64_mul(data[i], vector[i]);
	}
	if(wpt+8 > SEP_BUFFER_SIZE){
		while(1){
			read_value = write(opipe, wbuffer, wpt);
			if(read_value < 0){
				if(errno == EAGAIN)
					continue;
				if(errno == EPIPE)
					return 0;
				return -1;
			}
			break;
		}
		wpt = 0;
	}
	memcpy(wbuffer+wpt, &rt, 8);
	wpt += 8;
deal_write:
	while(1){
		read_value = write(opipe, wbuffer, wpt);
		if(read_value < 0){
			if(errno == EAGAIN)
				continue;
			if(errno == EPIPE)
				return 0;
			return -1;
		}
		break;
	}
exit:
	return 0;
}                 	

int sep_data_merge(int* ipipes, int opipe, uint64_t* keys, uint64_t threshold){
	uint64_t rt[threshold];
	memset(rt, 0, threshold*sizeof(uint64_t));
	for(uint64_t i = 0; i < threshold; i++){
		for(uint64_t j = 0; j < threshold-1; j++){
			rt[j] ^= GF64_mul(rt[j+1], keys[i]);
		}
		rt[threshold-1] ^= keys[i];
	}
	uint64_t vectors[threshold*threshold];
	memset(vectors, 0, threshold*threshold*sizeof(uint64_t));
	for(uint64_t i = 0; i < threshold; i++){
		vectors[threshold*i+(threshold-1)] = 1;
		vectors[threshold*i+(threshold-2)] = rt[threshold-1]^keys[i];
		for(uint64_t j = 2; j < threshold; j++){
			vectors[threshold*i+(threshold-1-j)] = rt[threshold-j]^GF64_mul(keys[i], vectors[threshold*i+(threshold-j)]);
		}
	}
	uint64_t x;
	for(uint64_t i = 0; i < threshold; i++){
		rt[i] = vectors[threshold*i];
		x = keys[i];
		for(uint64_t j = 1; j < threshold; j++){
			rt[i] ^= GF64_mul(vectors[threshold*i+j], x);
			x = GF64_mul(x, keys[i]);
		}
		rt[i] = GF64_inverse(rt[i]);
		for(uint64_t j = 0; j < threshold; j++){
			vectors[threshold*i+j] = GF64_mul(vectors[threshold*i+j], rt[i]);
		}
	}
	uint64_t data[threshold];
	int64_t read_value;
	uint8_t remain;
	uint8_t rbuffer[threshold*SEP_BUFFER_SIZE];
	uint8_t wbuffer[SEP_BUFFER_SIZE];
	uint16_t rbl[threshold], rpt[threshold];
	uint16_t wpt = 0;
	memset(rbl, 0, threshold*2);
	memset(rpt, 0, threshold*2);
	while(1){
		memset(rt, 0, threshold*sizeof(uint64_t));
		for(uint64_t i = 0; i < threshold; i++){
			if(rpt[i]+8 > rbl[i]){
				remain = rbl[i]-rpt[i];
				memcpy(((uint8_t*)data)+(i*8), rbuffer+(i*SEP_BUFFER_SIZE+rpt[i]), remain);
				rbl[i] = 0;
				while(rbl[i]+remain < 8){
					read_value = read(ipipes[i], rbuffer+i*SEP_BUFFER_SIZE, SEP_BUFFER_SIZE-rbl[i]);
					if(read_value == 0){
						goto deal_remain;
					}
					if(read_value < 0){
						if(errno == EAGAIN)
							continue;
						if(errno == EPIPE)
							goto deal_remain;
						return -1;
					}
					rbl[i] += read_value;
				}
				memcpy(((uint8_t*)data)+(i*8)+remain, rbuffer+i*SEP_BUFFER_SIZE, 8-remain);
				rpt[i] = 8-remain;
			}else{
				memcpy(((uint8_t*)data)+(i*8), rbuffer+(i*SEP_BUFFER_SIZE+rpt[i]), 8);
				rpt[i] += 8;
			}
			for(uint64_t j = 0; j < threshold; j++){
				rt[j] ^= GF64_mul(vectors[threshold*i+j], data[i]);
			}
		}
		if(wpt+threshold*8 > SEP_BUFFER_SIZE){
			while(1){
				read_value = write(opipe, wbuffer, wpt);
				if(read_value < 0){
					if(errno == EAGAIN)
						continue;
					if(errno == EPIPE)
						return 0;
					return -1;
				}
				break;
			}
			wpt = 0;
		}
		memcpy(wbuffer+wpt, &rt, threshold*8);
		wpt += threshold*8;
	}
deal_remain:
	if(wpt+threshold*8 > SEP_BUFFER_SIZE){
		while(1){
			read_value = write(opipe, wbuffer, wpt);
			if(read_value < 0){
				if(errno == EAGAIN)
					continue;
				if(errno == EPIPE)
					return 0;
				return -1;
			}
			break;
		}
		wpt = 0;
	}
	memcpy(wbuffer+wpt, &rt, threshold*8);
	wpt += threshold*8;
	while(1){
		read_value = write(opipe, wbuffer, wpt);
		if(read_value < 0){
			if(errno == EAGAIN)
				continue;
			if(errno == EPIPE)
				return 0;
			return -1;
		}
		break;
	}
	return 0;
}
