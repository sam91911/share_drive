#include "process.h"

int server_process(uint64_t server_id, int sock, struct sockaddr_in addr, uint64_t buffer_size, uint64_t client_id, char* restrict password){
	uint8_t buffer[buffer_size];
	uint8_t er[1024];
	uint8_t oper_sock;
	printf("addr:%08X\nport:%hu\n", addr.sin_addr.s_addr, addr.sin_port);
	return 0;
}

int client_process_fpost(uint64_t server_id, int sock, uint64_t buffer_size, char* restrict password, uint8_t* secret, uint8_t* restrict server_pubkey, uint64_t pubkey_len){
	uint8_t buffer[buffer_size];
	uint8_t sbuffer[1024];
	uint8_t oper_sock;
	return 0;
}
