#ifndef AES_H
#define AES_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int aes_ofb(int ifile, int ofile, uint8_t* key, uint8_t* iv);

#endif
