#ifndef PK_H
#define PK_H
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

int PK_sign(EVP_PKEY* pkey, uint8_t* msg, uint64_t msg_len, uint8_t* sign, uint64_t* sign_len, uint64_t sign_mlen);
int PK_verify(EVP_PKEY* pubkey, uint8_t* msg, uint64_t msg_len, uint8_t* sign, uint64_t sign_len);
int PK_dh(EVP_PKEY* pkey, EVP_PKEY* pubkey, uint8_t* secret, uint64_t* secret_len, uint64_t secret_mlen);
#endif
