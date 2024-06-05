#ifndef LOG_H
#define LOG_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <dirent.h>
#include <sys/sendfile.h>


int log_init();
int log_server_init(uint64_t serverid);
int log_add(uint64_t serverid, uint8_t* log, uint64_t len, uint8_t* id);
int log_get(uint64_t serverid, uint8_t* log, uint64_t* len, uint8_t* id);
int log_hash_nullGet(uint64_t serverid, uint8_t* hash);
int log_hash_reset(uint64_t serverid, uint64_t pack_id);
int log_file(uint64_t serverid, uint64_t pack);
int log_content(uint64_t serverid, uint8_t* id, int flags);
int log_get_content(uint64_t serverid, uint64_t userid, char* name, uint8_t* id);
int log_check_content(uint64_t serverid, uint64_t userid, char* name, uint8_t* id);
int log_add_content(uint64_t serverid, uint64_t userid, char* name, uint8_t* id);
int log_cur_pack(uint64_t serverid, uint64_t* pack);
int log_content_dir(uint64_t serverid, DIR** dir);
int log_add_pack(uint64_t serverid, uint8_t* pack, uint64_t len, uint64_t offset, uint64_t packid);
#endif
