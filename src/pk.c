#include "pk.h"

int PK_sign(EVP_PKEY* pkey, uint8_t* msg, uint64_t msg_len, uint8_t* sign, uint64_t* sign_len, uint64_t sign_mlen){
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx) return -1;
	if(!EVP_DigestSignInit(md_ctx, 0, EVP_sha256(), 0, pkey)) return -1;
	if(!EVP_DigestSignUpdate(md_ctx, msg, msg_len)) return -1;
	if(!EVP_DigestSignFinal(md_ctx, 0, sign_len)) return -1;
	if(*sign_len > sign_mlen) return -2;
	if(!EVP_DigestSignFinal(md_ctx, sign, sign_len)) return -1;
	EVP_MD_CTX_free(md_ctx);
	EVP_cleanup();
	return 0;
}

int PK_verify(EVP_PKEY* pubkey, uint8_t* msg, uint64_t msg_len, uint8_t* sign, uint64_t sign_len){
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	int rt;
	if(!md_ctx) return -1;
	if(!EVP_DigestVerifyInit(md_ctx, 0, EVP_sha256(), 0, pubkey)) return -1;
	if(!EVP_DigestVerifyUpdate(md_ctx, msg, msg_len)) return -1;
	rt = EVP_DigestVerifyFinal(md_ctx, sign, sign_len);
	EVP_MD_CTX_free(md_ctx);
	EVP_cleanup();
	return rt;
}

int PK_dh(EVP_PKEY* pkey, EVP_PKEY* pubkey, uint8_t* secret, uint64_t* secret_len, uint64_t secret_mlen){
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, 0);
	if(!ctx) return -1;
	if(EVP_PKEY_derive_init(ctx) <= 0) return -1;
	if(EVP_PKEY_derive_set_peer(ctx, pubkey) <= 0) return -1;
	if(EVP_PKEY_derive(ctx, 0, secret_len) <= 0) return -1;
	if(*secret_len > secret_mlen) return -2;
	if(EVP_PKEY_derive(ctx, secret, secret_len) <= 0) return -1;
	EVP_MD_CTX_free(md_ctx);
	EVP_cleanup();
	return 0;
}
