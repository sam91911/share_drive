#ifndef DH_H
#define DH_H
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <stdint.h>

int DH_getKey(uint8_t* x, uint8_t* gy, uint8_t* p, uint64_t len, uint8_t* key);

#endif
