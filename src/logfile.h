#ifndef LOGFILE_H
#define LOGFILE_H
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>
#include "pk.h"
#include "method.h"

int logfile_signreg(uint64_t serverid, uint8_t* pubkey, uint64_t len, uint8_t* data);
int logfile_clone(uint64_t serverid, uint8_t* addr, uint64_t len, uint8_t* data);

#endif
