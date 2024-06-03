#ifndef SHARE_KEY_H
#define SHARE_KEY_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/rand.h>

#include "GF64.h"

int share_key_gen(uint64_t key, uint64_t threshold, uint64_t* coef);
int share_key_gen_ex(uint64_t key, uint64_t threshold, uint64_t base_n, uint64_t* base_x, uint64_t* coef);
int share_key_plug(uint64_t threshold, uint64_t* coef, uint64_t sample_x, uint64_t* r_sample_y);
int share_key_combinen(uint64_t threshold, uint64_t* sample_x, uint64_t* sample_y, uint64_t support_x, uint64_t* r_key);

#endif
