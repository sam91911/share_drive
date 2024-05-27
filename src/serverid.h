#ifndef SERVERID_H
#define SERVERID_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>


int serverid_init();
int serverid_add(const char* restrict name, uint64_t id);
int serverid_get_id(const char* restrict name, uint64_t* id);
int serverid_list(char** name, uint64_t* nlen);
int serverid_check_server(uint64_t id, uint64_t user_id);
int serverid_add_server(uint64_t id, uint8_t* restrict oper_sockaddr, uint8_t* restrict pubkey, uint64_t len, uint64_t pubkey_len, uint64_t flag);
int serverid_get_server(uint64_t id, uint64_t offset, uint8_t* oper_sockaddr, uint8_t* pubkey, uint64_t* len, uint64_t* pubkey_len, uint64_t* flag, uint64_t* user_id);

#endif
