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
#include <time.h>
#include "pk.h"


int temp_init();
int temp_encode(uint64_t user_id, char* file_name, uint8_t* aes_key, uint8_t* iv, uint64_t treshold, char* upname, char* password);
int temp_decode(char* file_name, uint64_t* secret, uint64_t threshold, char* upname);
int temp_clean(char* upname);
int temp_sign_file(char* upname);
int temp_temp_file(char* upname);
#endif
