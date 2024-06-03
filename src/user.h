#ifndef USER_H
#define USER_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "method.h"
#ifndef USER_PUBKEY_LEN
#define USER_PUBKEY_LEN 65
#endif

int user_pubkey(uint64_t serveid, uint64_t id, uint8_t* pubkey);
int user_checkid(uint64_t serverid, uint64_t id);
int user_check(uint64_t serverid, uint8_t* restrict pubkey, uint64_t len);
int user_add(uint64_t serverid, uint8_t* restrict pubkey, uint64_t len);
int user_init();
int user_server_init(uint64_t serverid);
int user_name2id(uint64_t server_id, char* name, uint64_t* id);
int user_add_name(uint64_t server_id, const char* restrict name, uint64_t id);

#endif
