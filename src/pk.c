#include "pk.h"
#define PK_GROUP (NID_X9_62_prime256v1)
#ifndef PK_MAX_TEMP
#define PK_MAX_TEMP 3
#endif

int pk_init(char* restrict password){
	struct stat oper_stat;
	int oper_fd;
	FILE* oper_file;
	EVP_PKEY* pkey;
	EVP_PKEY_CTX* ctx;
	if(access(".private", F_OK)){
		if(errno == ENOENT){
			if(mkdir(".private", 0700)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	if(stat(".private", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(!(pkey = EVP_PKEY_new())) return -1;
	if(!(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, 0))) return -1;
	if(EVP_PKEY_keygen_init(ctx) <= 0) return -1;
	if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, PK_GROUP) <= 0) return -1;
	if(EVP_PKEY_keygen(ctx, &pkey) <= 0) return -1;
	EVP_PKEY_CTX_free(ctx);
	if((oper_fd = open(".private/.private", O_CREAT|O_WRONLY, 0600)) == -1) return -1;
	if(!(oper_file = fdopen(oper_fd, "wb"))) return -1;
	if(password){
		if(!PEM_write_PrivateKey(oper_file, pkey, EVP_aes_256_cbc(), 0, 0, 0, password));
	}else{
		if(!PEM_write_PrivateKey(oper_file, pkey, 0, 0, 0, 0, 0));
	}
	fclose(oper_file);
	close(oper_fd);
	if(access("public", F_OK)){
		if(errno == ENOENT){
			if(mkdir("public", 0744)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	if(stat("public", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if((oper_fd = open("public/public.pem", O_CREAT|O_WRONLY, 0644)) == -1) return -1;
	if(!(oper_file = fdopen(oper_fd, "wb"))) return -1;
	if(!PEM_write_PUBKEY(oper_file, pkey)) return -1;
	EVP_PKEY_free(pkey);
	fclose(oper_file);
	close(oper_fd);
	return 0;
}
int pk_termin(char* password, uint64_t len){
	struct termios oper_term;
	int oper_fd;
	uint8_t hash_v[32];
	uint8_t salt[33];
	uint8_t hash_r[32];
	EVP_MD_CTX* ctx;
	if(RAND_bytes(salt+1, 32) != 1) return -1;
	if(access(".passphrase", F_OK)){
		if(errno != ENOENT) return -1;
		if((oper_fd = open(".passphrase", O_CREAT|O_EXCL|O_WRONLY, 0600)) == -1) return -1;
		if(password){
			salt[0] = 0x80;
			tcgetattr(STDIN_FILENO, &oper_term);
			oper_term.c_lflag &= ~ECHO;
			tcsetattr(STDIN_FILENO, TCSANOW, &oper_term);
			printf("intput password:");
			if(!fgets(password, len, stdin)) return 1;
			if(!(ctx = EVP_MD_CTX_new())) return -1;
			if(!EVP_DigestInit(ctx, EVP_sha3_256())) return 1;
			if(!EVP_DigestUpdate(ctx, salt+1, 32)) return 1;
			if(!EVP_DigestUpdate(ctx, password, strlen(password))) return 1;
			if(!EVP_DigestFinal(ctx, hash_v, 0)) return 1;
			if(write(oper_fd, salt, 33) == -1) return -1;
			if(write(oper_fd, hash_v, 32) == -1) return -1;
			close(oper_fd);
			EVP_MD_CTX_free(ctx);
			oper_term.c_lflag |= ECHO;
			tcsetattr(STDIN_FILENO, TCSANOW, &oper_term);
			return 0;
		}else{
			salt[0] = 0x00;
			if(write(oper_fd, salt, 33) == -1) return -1;
			close(oper_fd);
			return 0;
		}
	}else{
		if(access(".passphrase", F_OK|R_OK)) return 1;
		if((oper_fd = open(".passphrase", O_RDONLY)) == -1) return 1;
		if(read(oper_fd, salt, 33) == -1) return -1;
		if(password){
			if(!salt[0]) return 1;
			if(read(oper_fd, hash_r, 32) == -1) return -1;
			if(!(ctx = EVP_MD_CTX_new())) return -1;
			for(uint64_t i = 0; i < PK_MAX_TEMP; i++){
				tcgetattr(STDIN_FILENO, &oper_term);
				oper_term.c_lflag &= ~ECHO;
				tcsetattr(STDIN_FILENO, TCSANOW, &oper_term);
				printf("intput password:");
				if(!fgets(password, len, stdin)) return 1;
				if(!EVP_DigestInit(ctx, EVP_sha3_256())) return 1;
				if(!EVP_DigestUpdate(ctx, salt+1, 32)) return 1;
				if(!EVP_DigestUpdate(ctx, password, strlen(password))) return 1;
				if(!EVP_DigestFinal(ctx, hash_v, 0)) return 1;
				if(!memcmp(hash_v, hash_r, 32)){
					EVP_MD_CTX_free(ctx);
					oper_term.c_lflag |= ECHO;
					tcsetattr(STDIN_FILENO, TCSANOW, &oper_term);
					return 0;
				}
				printf("worng password\n");
			}
			oper_term.c_lflag |= ECHO;
			tcsetattr(STDIN_FILENO, TCSANOW, &oper_term);
			return 1;
		}else{
			if(salt[0]) return 1;
		}
	}
	return 0;
}
int pk_get_pubkey(uint8_t* pubkey, uint64_t* len){
	struct stat oper_stat;
	int oper_fd;
	FILE* oper_file;
	EVP_PKEY* pkey = 0;
	uint8_t* oper_str;
	size_t oper_strlen;
	if(access("public", F_OK)){
		return -1;
	}
	if(stat("public", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if((oper_fd = open("public/public.pem", O_RDONLY)) == -1) return -1;
	if(!(oper_file = fdopen(oper_fd, "rb"))) return -1;
	if(!PEM_read_PUBKEY(oper_file, &pkey, 0, 0)) return -1;
	if(!(oper_strlen = EVP_PKEY_get1_encoded_public_key(pkey, &oper_str))) return -1;
	if(oper_strlen <= *len){
		memcpy(pubkey, oper_str, oper_strlen);
		*len = oper_strlen;
	}else{
		*len = 0;
	}
	free(oper_str);
	EVP_PKEY_free(pkey);
	fclose(oper_file);
	close(oper_fd);
	return 0;
}
int pk_dh(uint8_t* restrict pubkey_str, uint64_t len, uint8_t* secret, uint64_t* slen, char* restrict password){
	if(!pubkey_str) return 0;
	if(!secret) return 0;
	if(!slen) return 0;
	EVP_PKEY* pkey = 0;
	EVP_PKEY* pubkey;
	EVP_PKEY_CTX* ctx;
	int oper_fd;
	struct stat oper_stat;
	FILE* oper_file;
	if(access(".private", F_OK)){
		if(errno == ENOENT){
			if(mkdir(".private", 0700)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	if(stat(".private", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(access(".private/.private", F_OK|R_OK)) return -1;
	if((oper_fd = open(".private/.private", O_RDONLY)) == -1) return -1;
	if(!(oper_file = fdopen(oper_fd, "rb"))) return -1;
	if(!PEM_read_PrivateKey(oper_file, &pkey, 0, password)) return 1;
	if(!(pubkey = EVP_PKEY_new())) return -1;
	if(EVP_PKEY_copy_parameters(pubkey, pkey) <= 0) return -1;
	if(!EVP_PKEY_set1_encoded_public_key(pubkey, pubkey_str, len)) return 1;
	if(!(ctx = EVP_PKEY_CTX_new(pkey, 0))) return -1;
	if(EVP_PKEY_derive_init(ctx) <= 0) return -1;
	if(EVP_PKEY_derive_set_peer(ctx, pubkey) <= 0) return -1;
	if(EVP_PKEY_derive(ctx, secret, slen) <= 0) return -1;
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	EVP_PKEY_free(pubkey);
	return 0;
}
int pk_verify(uint8_t* restrict pubkey_str, uint64_t len, const uint8_t* restrict msg, uint64_t msg_len, const uint8_t* restrict sign, uint64_t sign_len){
	if(!pubkey_str) return 0;
	if(!msg) return 0;
	if(!sign) return 0;
	EVP_MD_CTX* ctx;
	EVP_PKEY* pubkey;
	EVP_PKEY* ourkey = 0;
	struct stat oper_stat;
	int oper_fd;
	FILE* oper_file;
	int rt;
	if(access("public", F_OK)){
		return -1;
	}
	if(stat("public", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if((oper_fd = open("public/public.pem", O_RDONLY)) == -1) return -1;
	if(!(oper_file = fdopen(oper_fd, "rb"))) return -1;
	if(!PEM_read_PUBKEY(oper_file, &ourkey, 0, 0)) return -1;
	fclose(oper_file);
	close(oper_fd);
	if(!(pubkey = EVP_PKEY_new())) return -1;
	if(EVP_PKEY_copy_parameters(pubkey, ourkey) <= 0) return -1;
	if(!EVP_PKEY_set1_encoded_public_key(pubkey, pubkey_str, len)) return 0;
	if(!(ctx = EVP_MD_CTX_new())) return -1;
	if(!EVP_DigestVerifyInit(ctx, 0, EVP_sha3_256(), 0, pubkey)) return -1;
	if(!EVP_DigestVerifyUpdate(ctx, msg, msg_len)) return -1;
	rt = EVP_DigestVerifyFinal(ctx, sign, sign_len);
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pubkey);
	EVP_PKEY_free(ourkey);
	return rt;
}
int pk_sign(const uint8_t* restrict msg, uint64_t msg_len, uint8_t* sign, uint64_t* sign_len, char* restrict password){
	if(!msg) return 1;
	if(!sign) return 1;
	if(!sign_len) return 1;
	EVP_PKEY* pkey = 0;
	EVP_MD_CTX* ctx;
	int oper_fd;
	struct stat oper_stat;
	FILE* oper_file;
	if(access(".private", F_OK)){
		if(errno == ENOENT){
			if(mkdir(".private", 0700)){
				return -1;
			}
		}else{
			return -1;
		}
	}
	if(stat(".private", &oper_stat)){
		return -1;
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		return -1;
	}
	if(access(".private/.private", F_OK|R_OK)) return -1;
	if((oper_fd = open(".private/.private", O_RDONLY)) == -1) return -1;
	if(!(oper_file = fdopen(oper_fd, "rb"))) return -1;
	if(!PEM_read_PrivateKey(oper_file, &pkey, 0, password)) return 1;
	if(!(ctx = EVP_MD_CTX_new())) return -1;
	if(!EVP_DigestSignInit(ctx, 0, EVP_sha3_256(), 0, pkey)) return -1;
	if(!EVP_DigestSignUpdate(ctx, msg, msg_len)) return -1;
	if(!EVP_DigestSignFinal(ctx, sign, sign_len)) return -1;
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return 0;
}
