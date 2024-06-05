#ifndef SERVER_H
#define SERVER_H
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
#include <sys/ipc.h>
#include <sys/msg.h>
#include "login.h"
#include "process.h"
#include "user.h"
#include "pk.h"
#include "signreg.h"
#include "fsys.h"
#include "log.h"

void server_err(const char* restrict error_message);
int server_init(char* restrict passward);
int server_start(char* restrict passward, int oper_msg, uint32_t flag);
int server_getid(uint64_t* id);

#endif
