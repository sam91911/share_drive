#ifndef SEP_DATA_H
#define SEP_DATA_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>

#include "GF64.h"

int sep_data_sep(int ifile, int ofile, uint64_t key, uint64_t threshold);
int sep_data_merge(int* ifiles, int ofile, uint64_t* keys, uint64_t threshold);

#endif
