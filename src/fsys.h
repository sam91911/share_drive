#ifndef FSYS_H
#define FSYS_H
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
int fsys_init();
int fsys_check(uint64_t id, char* name);
int fsys_store(uint64_t id, char* name, uint8_t* data, uint64_t len, int64_t offset, uint8_t offset_type);
int fsys_get(uint64_t id, char* name, uint8_t* data, uint64_t* len, int64_t offset, uint8_t offset_type);
uint64_t fsys_size(uint64_t id, char* name);
int fsys_del(uint64_t id, char* name);
#endif
