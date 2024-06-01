#ifndef TEMP_H
#define TEMP_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "pk.h"


int temp_init();
int temp_encode(char* file_name, uint8_t* aes_key, uint8_t* iv, uint64_t* user_ids, uint64_t mlen, char* upname, char* password);
int temp_decode(char* file_name, uint8_t* aes_key, char* upname);
int temp_clean(char* upname);
#endif
