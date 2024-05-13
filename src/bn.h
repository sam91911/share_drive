#ifndef BN_H
#define BN_H
#include <openssl/bn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

int BN_power(uint8_t* x, uint8_t* gy, uint8_t* p, uint64_t len, uint8_t* key);

#endif
