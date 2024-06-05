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
#include "serverid.h"
#include "log.h"
#include "logfile.h"

int server_login(uint64_t server_id, int sock, struct sockaddr_in addr, uint64_t buffer_size, uint64_t* client_id, char* restrict password, uint8_t* secret);
int client_login(uint64_t server_id, int sock, uint64_t buffer_size, char* restrict password, uint8_t* secret, uint8_t* server_pubkey, uint64_t pubkey_len);
int login_clone(char* restrict password, uint64_t server_id, uint8_t* addr, uint64_t addr_len);
int login_signreg(char* restrict password, uint64_t server_id, uint8_t* sign_pubkey, uint64_t sign_publen);
int login_log(uint64_t server_id, int sock, uint64_t buffer_size, char* restrict password, uint8_t* data, uint64_t len);

#endif
