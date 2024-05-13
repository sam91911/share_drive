#include "pk.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <errno.h>
#include <argp.h>

int main(int argc, char** argv){
	if(argc < 2) return 0;
	uint64_t msg_len = strlen(argv[1]);
	FILE* key_f;
	EVP_PKEY* pkey = EVP_PKEY_new();
	if(argc >= 3){
		if(!(key_f = fopen(argv[2], "rb"))){
			printf("%02x\n", errno);
			return -1;
		}
		PEM_read_PrivateKey(key_f, &pkey, 0, 0);
		if(!pkey) return -1;
		fclose(key_f);
	}else{
		if(!(key_f = fopen("key.pem", "wb"))) return -1;
		EVP_PKEY_CTX* ctx;
		ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, 0);
		if(!ctx) return -1;
		if(EVP_PKEY_keygen_init(ctx) <= 0) return -1;
		if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) return -1;
		if(EVP_PKEY_keygen(ctx, &pkey) <= 0) return -1;
		EVP_PKEY_CTX_free(ctx);
		if(!PEM_write_PrivateKey(key_f, pkey, 0, 0, 0, 0, 0)) return -1;
		fclose(key_f);
		if(!(key_f = fopen("pubkey.pem", "wb"))) return -1;
		if(!PEM_write_PUBKEY(key_f, pkey)) return -1;
		fclose(key_f);
	}
	uint8_t sign[2048];
	uint64_t sign_len;
	if(PK_sign(pkey, argv[1], msg_len, sign, &sign_len, 2048)) return -2;
	for(uint64_t i = 0; i < sign_len; i++){
		printf("%02x", sign[i]);
	}
	printf("\n");
	int vrf;
	//vrf = PK_verify(pubkey, uint8_t* msg, uint64_t msg_len, uint8_t* sign, uint64_t sign_len);
	EVP_PKEY_free(pkey);
	EVP_cleanup();
	return 0;
}
