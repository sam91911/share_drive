#ifndef SIGNREG_H
#define SIGNREG_H
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>

int signreg_init();
int signreg_check(uint8_t* mac, uint8_t* msg, uint64_t msg_len);
int signreg_add(uint8_t* value, int64_t end, int64_t start);

#endif
