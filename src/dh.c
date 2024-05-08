#include "dh.h"

int DH_getKey(uint8_t* x, uint8_t* gy, uint8_t* p, uint64_t len, uint8_t* key){
	DH* dh = DH_new();
	dh->p = BN_bin2bn(p, len, 0);
	dh->priv_key = BN_bin2bn(x, len, 0);
	pub_key = BN_bin2bn(gy, len, 0);
	DH_compute_key(key, pub_key, dh);
	BN_free(dh->p);
	BN_free(dh->priv_key);
	BN_free(pub_key);
	DH_free(dh);
}
