#ifndef SHA3_H
#define SHA3_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>

int sha3_hash(int ifile, uint8_t* hash);
int sha3_ofb(int ifile, int ofile, uint8_t* iv);

#endif
