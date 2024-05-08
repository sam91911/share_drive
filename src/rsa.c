#include "rsa.h"

int rsa_sign(RSA* key, uint8_t* data, uint8_t* sign){
	if(!RSA_sign(NID_sha3_256, data, 32, sign, )
}
