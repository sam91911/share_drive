#ifndef FSIZE_H
#define FSIZE_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define FSIZE_BLOCK_SIZE 4096
int fsize_add(int ifd, int ofd);
int fsize_remove(int ifd, int ofd);

#endif
