#ifndef BN_H
#define BN_H
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int bn_mul(uint8_t* a, uint8_t* b, uint8_t* p, uint64_t len);
int bn_add(uint8_t* a, uint8_t* b, uint8_t* p, uint64_t len);
int bn_sub(uint8_t* a, uint8_t* b, uint8_t* p, uint64_t len);

#endif
