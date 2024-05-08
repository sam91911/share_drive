#include "sha3.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

int main(int argc, char** argv)
{
    if(argc < 2) return -1;
    int fd;
    uint8_t hash[32];
    if((fd=open(argv[1], O_RDONLY))<3) return -1;
    if(sha3_hash(fd, hash)) return -2;
    for(int i = 0; i < 32; i++){
    	printf("%02x", hash[i]);
    }
    printf("\n");
    return 0;
}
