#ifndef PROCESS_H
#define PROCESS_H
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
#include <dirent.h>
#include <netinet/in.h>
#include "method.h"
#include "pk.h"
#include "user.h"
#include "fsys.h"
#include "temp.h"
#include "sep_data.h"
#include "share_key.h"
#include "log.h"
#include "serverid.h"

int server_process(uint64_t server_id, int sock, struct sockaddr_in addr, uint64_t buffer_size, uint64_t client_id, char* restrict password, uint8_t* secret);
int client_process_fpost(uint64_t server_id, uint64_t server_user_id, uint64_t self_id, uint64_t* oper_keyf, uint64_t threshold, int sock, struct sockaddr_in addr, uint64_t buffer_size, char* restrict password, uint8_t* secret, uint8_t* restrict server_pubkey, uint64_t pubkey_len, char* upname);
int client_process_fget(uint64_t server_id, uint64_t server_userid, int sock, struct sockaddr_in addr, uint64_t buffer_size, char* restrict password, uint8_t* secret, uint8_t* restrict server_pubkey, uint64_t pubkey_len, uint64_t client_id, char* upname);
int client_process_update(uint64_t server_id, uint64_t server_userid, int sock, struct sockaddr_in addr, uint64_t buffer_size, char* restrict password, uint8_t* secret, uint8_t* restrict server_pubkey, uint64_t pubkey_len);

#endif
