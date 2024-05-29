#ifndef PK_H
#define PK_H
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

int pk_init(char* restrict password);
int pk_termin(char* password, uint64_t len);
int pk_get_pubkey(uint8_t* pubkey, uint64_t* len);
int pk_dh(uint8_t* restrict pubkey, uint64_t len, uint8_t* secret, uint64_t* slen, char* restrict password);
int pk_verify(uint8_t* restrict pubkey, uint64_t len, const uint8_t* restrict msg, uint64_t msg_len, const uint8_t* restrict sign, uint64_t sign_len);
int pk_sign(const uint8_t* restrict msg, uint64_t msg_len, uint8_t* sign, uint64_t* sign_len, char* restrict password);


#endif
