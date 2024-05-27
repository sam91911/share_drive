#ifndef LOGIN_H
#define LOGIN_H
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
#include "user.h"
#include "pk.h"
#include "signreg.h"

int server_login(uint64_t server_id, int sock, struct sockaddr_in addr, uint64_t buffer_size, uint64_t* client_id, const char* restrict password);
int client_login(uint64_t server_id, int sock, uint64_t buffer_size, const char* restrict password, uint8_t* server_pubkey, uint64_t pubkey_len);

#endif
