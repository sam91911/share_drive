#include "sha3.h"

#ifndef SHA3_BUFFER_SIZE
#define SHA3_BUFFER_SIZE 1024
#endif

//ref:https://github.com/brainhub/SHA3IUF
static const uint64_t keccakf_rndc[24] = {
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008
};

static const unsigned keccakf_rotc[24] = {
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
	18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[24] = {
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
	14, 22, 9, 6, 1
};

static void keccakf(uint64_t* s){
	uint8_t k;
	uint64_t t, tt, bc[5];
	for(int round = 0; round < 24; round++){
		for(int i = 0; i<5; i++){
			bc[i] = s[i]^s[i+5]^s[i+10]^s[i+15]^s[i+20];
		}
		for(int i = 0; i < 5; i++){
			t = bc[(i+4)%5]^((bc[(i+1)%5]<<1)|(bc[(i+1)%5]>>63));
			for(int j = 0; j < 5; j++){
				s[5*j+i] ^= t;
			}
		}

		t = s[1];
		for(int i = 0; i < 24; i++){
			k = keccakf_piln[i];
			tt = s[k];
			s[k] = (t<<keccakf_rotc[i])|(t>>(64-keccakf_rotc[i]));
			t = tt;
		}

		for(int i = 0; i < 5; i++){
			for(int j = 0; j < 5; j++){
				bc[j] = s[5*i+j];
			}
			for(int j = 0; j < 5; j++){
				s[5*i+j] ^= (~bc[(j+1)%5] & bc[(j+2)%5]);
			}
		}
		s[0] ^= keccakf_rndc[round];
	}
}

int sha3_hash(int ifile, uint8_t* hash){
	uint8_t s[200];
	uint8_t r[136];
	uint8_t rbuffer[SHA3_BUFFER_SIZE];
	uint16_t rbl = 0, rpt = 0;
	int32_t read_value;
	uint8_t remain;
	if(!hash) return -1;
	memset(s, 0, 200);
	while(1){
		if(rpt+136 > rbl){
			remain = rbl - rpt;
			memcpy(r, rbuffer+rpt, remain);
			rbl = 0;
			while(rbl < (136-remain)){
				read_value = read(ifile, rbuffer+rbl, SHA3_BUFFER_SIZE-rbl);
				if(read_value == 0){
					goto deal_remain;
				}
				if(read_value < 0){
					if(errno == EAGAIN) continue;
					if(errno == EPIPE) goto deal_remain;
					return -2;
				}
				rbl += read_value;
			}
			memcpy(r+remain, rbuffer, 136-remain);
			rpt = 136-remain;
		}else{
			memcpy(r, rbuffer+rpt, 136);
			rpt += 136;
		}
		for(int i = 0; i < 136; i++){
			s[i] ^= r[i];
		}
		keccakf((uint64_t*)s);
	}
deal_remain:
	memcpy(r+remain, rbuffer, rbl);
	remain += rbl;
	r[remain] = 0x06;
	memset(r+remain+1, 0, 135-remain);
	r[135] |= 0x80;
	for(int i = 0; i < 136; i++){
		s[i] ^= r[i];
	}
	keccakf((uint64_t*)s);
	for(int i = 0; i < 32; i++){
		hash[i] = s[i];
	}
	return 0;
}

int sha3_ofb(int ifile, int ofile, uint8_t* iv){
	uint8_t rbuffer[SHA3_BUFFER_SIZE];
	uint8_t wbuffer[SHA3_BUFFER_SIZE];
	uint16_t rbl = 0, rpt = 0;
	uint16_t wpt = 0;
	uint8_t data[64];
	uint8_t s[200];
	uint8_t remain;
	int32_t read_value;
	if(!iv) return -1;
	memcpy(s, iv, 64);
	memset(s+64, 0, 136);
	while(1){
		if(rpt+64 > rbl){
			remain = rbl - rpt;
			memcpy(data, rbuffer+rpt, remain);
			rbl = 0;
			while(rbl < (64-remain)){
				read_value = read(ifile, rbuffer+rbl, SHA3_BUFFER_SIZE-rbl);
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
			memcpy(data+remain, rbuffer, 64-remain);
			rpt = 64-remain;
		}else{
			memcpy(data, rbuffer+rpt, 64);
			rpt += 64;
		}
		keccakf((uint64_t*)s);
		for(int i = 0; i < 8; i++){
			((uint64_t*)data)[i] ^= ((uint64_t*)s)[i];
		}
		if(wpt+64 > SHA3_BUFFER_SIZE){
			while(1){
				read_value = write(ofile, wbuffer, wpt);
				if(read_value < 0){
					if(errno == EAGAIN) continue;
					if(errno == EPIPE) return 0;
					return -1;
				}
				break;
			}
			wpt = 0;
		}
		memcpy(wbuffer+wpt, data, 64);
		wpt += 64;
	}
deal_remain:
	if(!(remain+rbl)) goto deal_write;
	memcpy(((uint8_t*)data)+remain, rbuffer, rbl);
	memset(((uint8_t*)data)+remain+rbl, 0, (64-(remain+rbl)));
	keccakf((uint64_t*)s);
	for(int i = 0; i < 8; i++){
		((uint64_t*)data)[i] ^= ((uint64_t*)s)[i];
	}
	if(wpt+64 > SHA3_BUFFER_SIZE){
		while(1){
			read_value = write(ofile, wbuffer, wpt);
			if(read_value < 0){
				if(errno == EAGAIN) continue;
				if(errno == EPIPE) return 0;
				return -1;
			}
			break;
		}
		wpt = 0;
	}
	memcpy(wbuffer+wpt, data, 64);
	wpt += 64;
deal_write:
	while(1){
		read_value = write(ofile, wbuffer, wpt);
		if(read_value < 0){
			if(errno == EAGAIN) continue;
			if(errno == EPIPE) return 0;
			return -1;
		}
		break;
	}
	return 0;
}
