#include "logfile.h"

int logfile_signreg(uint64_t serverid, uint8_t* pubkey, uint64_t len, uint8_t* data){
	if(!data) return -1;
	if(!pubkey) return -1;
	uint16_t version = 0;
	time_t timen = time(0);
	uint8_t buffer[256];
	uint64_t size_buf[4];
	size_buf[0] = 256-8;
	memcpy(buffer, &serverid, 8);
	if(pk_get_pubkey(buffer+8, size_buf)) return -1;
	if(!EVP_Digest(buffer, size_buf[0]+8, data+4, 0, EVP_sha3_256(), 0)) return -1;
	memcpy(data, &version, 2);
	data[2] = METHOD_SIGNREG;
	data[3] = 0x00;
	memcpy(data+12, &timen, 8);
	memcpy(data+20, &len, 8);
	memcpy(data+28, pubkey, len);
	return 0;
}

int logfile_clone(uint64_t serverid, uint8_t* addr, uint64_t len, uint8_t* data){
	if(!data) return -1;
	if(!addr) return -1;
	uint16_t version = 0;
	time_t timen = time(0);
	uint8_t buffer[256];
	uint64_t size_buf[4];
	size_buf[0] = 256-8;
	memcpy(buffer, &serverid, 8);
	if(pk_get_pubkey(buffer+8, size_buf)) return -1;
	if(!EVP_Digest(buffer, size_buf[0]+8, data+4, 0, EVP_sha3_256(), 0)) return -1;
	memcpy(data, &version, 2);
	data[2] = METHOD_CLONE;
	data[3] = 0x00;
	memcpy(data+12, &timen, 8);
	memcpy(data+20, &len, 8);
	memcpy(data+28, addr, len);
	return 0;
}
