#ifndef CLIENT_H
#define CLIENT_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "share_key.h"
#include "login.h"
#include "pk.h"
#include "serverid.h"
#include "fsys.h"
#include "process.h"
#include "temp.h"
#include "user.h"
#include "log.h"

void client_err(const char* restrict error_message);
int client_init(char* restrict passward);
int client_fpost(char* restrict passward, uint64_t server_id, char* restrict file_name, char* upname);
int client_fget(char* restrict password, uint64_t server_id, uint64_t call_id, char* restrict file_name, char* upname);
int client_update(char* restrict password, uint64_t server_id);

#endif
