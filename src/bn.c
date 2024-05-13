#include "bn.h"


//use for DH key exchange
int BN_power(uint8_t* x, uint8_t* y, uint8_t* p, uint64_t len, uint8_t* rt){
	memset(rt, 0, len);
	BIGNUM* bx = BN_bin2bn(x, len, 0);
	BIGNUM* by = BN_bin2bn(y, len, 0);
	BIGNUM* bp = BN_bin2bn(p, len, 0);
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* bk = BN_new();
	BN_mod_exp(bk, by, bx, bp, ctx);
	BN_bn2bin(bk, rt);
	BN_free(bx);
	BN_free(by);
	BN_free(bp);
	BN_free(bk);
	BN_CTX_free(ctx);
	return 0;
}

//use for DSA
int BN_sign(uint8_t* x, uint8_t* data, uint8_t* g, uint8_t* p, uint8_t* q, uint64_t nlen, uint64_t dlen, uint8_t* r, uint8_t* s){
	memset(r, 0, nlen);
	memset(s, 0, nlen);
	BIGNUM* bx = BN_bin2bn(x, nlen, 0);
	BIGNUM* bg = BN_bin2bn(g, nlen, 0);
	BIGNUM* bp = BN_bin2bn(p, nlen, 0);
	BIGNUM* bq = BN_bin2bn(q, nlen, 0);
	BIGNUM* bd = BN_bin2bn(data, dlen, 0);
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* bk = BN_new();
	BIGNUM* br = BN_new();
	BIGNUM* bs = BN_new();
	while(1){
		BN_rand_range(bk, bq);
		BN_mod_exp(br, bg, bk, bp, ctx);
		BN_mod(br, br, bq, ctx);
		if(BN_is_zero(br)) continue;
		BN_mod_inverse(bk, bk, bq, ctx);
		BN_mod_mul(bs, bx, br, bq, ctx);
		BN_mod_add(bs, bs, bd, bq, ctx);
		if(BN_is_zero(bs)) continue;
		BN_mod_mul(bs, bs, bk, bq, ctx);
		break;
	}
	BN_bn2bin(br, r);
	BN_bn2bin(bs, s);
	BN_free(bx);
	BN_free(bg);
	BN_free(bp);
	BN_free(bq);
	BN_free(bd);
	BN_free(bk);
	BN_free(br);
	BN_free(bs);
	BN_CTX_free(ctx);
	return 0;
}
int BN_verify(uint8_t* y, uint8_t* data, uint8_t* g, uint8_t* p, uint8_t* q, uint8_t* r, uint8_t* s, uint64_t nlen, uint64_t dlen){
	BIGNUM* by = BN_bin2bn(y, nlen, 0);
	BIGNUM* bg = BN_bin2bn(g, nlen, 0);
	BIGNUM* bp = BN_bin2bn(p, nlen, 0);
	BIGNUM* bq = BN_bin2bn(q, nlen, 0);
	BIGNUM* br = BN_bin2bn(r, nlen, 0);
	BIGNUM* bs = BN_bin2bn(s, nlen, 0);
	BIGNUM* bd = BN_bin2bn(data, dlen, 0);
	BN_CTX* ctx = BN_CTX_new();
	BN_mod_inverse(bs, bs, bq, ctx);
	BN_mod_mul(bd, bd, bs, bq, ctx);
	BN_mod_exp(bd, bg, bd, bp, ctx);
	BN_mod_mul(bg, br, bs, bq, ctx);
	BN_mod_exp(bg, by, bg, bp, ctx);
	BN_mod_mul(bd, bg, bd, bp, ctx);
	BN_mod(bd, bd, bq, ctx);
	int rt = BN_cmp(bd, br);
	BN_free(by);
	BN_free(bg);
	BN_free(bp);
	BN_free(bq);
	BN_free(bd);
	BN_free(br);
	BN_free(bs);
	BN_CTX_free(ctx);
	return rt;
}
