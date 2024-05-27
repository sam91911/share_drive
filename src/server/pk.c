#include "pk.h"
#ifndef PK_PKEY_GROUP
#define PK_PKEY_GROUP (NID_X9_62_prime256v1)
#endif
#ifndef PK_MAX_TEMP
#define PK_MAX_TEMP 10
#endif

void pk_err(const char* restrict error_message){	
	if(!error_message){
		fprintf(stderr, "pk:\nerrno:\t%02x\n", errno);
	}else{
		fprintf(stderr, "pk:\t%s\nerrno:\t%02x\n", error_message, errno);
	}
	exit(-1);
}

int pk_termin(uint8_t* password, uint64_t len){
	uint8_t count;
	struct termios oper_term, temp_term;
	if(password){
		for(count = 0; count < PK_MAX_TEMP; count++){
			if(printf("input password:") < 0) return -1;
			tcgetattr(STDIN_FILENO, &oper_term);
			temp_term = oper_term;
			temp_term.c_lflag &= ~(ECHO);
			tcsetattr(STDIN_FILENO, TCSANOW, &temp_term);
			if(!fgets(password, len, stdin)) return -1;
			tcsetattr(STDIN_FILENO, TCSANOW, &oper_term);
			if(printf("\n") < 0) return -1;
			if(!pk_init_password(password)) break;
			if(pk_check_password(password)){
				sleep(1);
				printf("wrong password\n");
			}else{
				break;
			}
		}
		if(count == PK_MAX_TEMP) return 1;
	}else{
		if(pk_init_password(0)){
			if(pk_check_password(0)) return -1;
		}
	}
	return 0;
}

int pk_init(uint8_t* password){
	struct stat oper_stat;
	int oper_fd;
	FILE* oper_file;
	if(access(".private", F_OK)){
		if(errno == ENOENT){
			if(mkdir(".private", 0700)){
				pk_err("mkdir .private");
			}
		}else{
			pk_err("access .private");
		}
	}
	if(stat(".private", &oper_stat)){
		pk_err("stat .private");
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		pk_err(".private is not s dir");
	}
	if((oper_fd = open(".private/private_key", O_CREAT|O_WRONLY, 0600)) < 0){
		pk_err("open private_key");
	}
	EVP_PKEY* pkey = EVP_PKEY_new();
	if(!pkey){
		pk_err("new pkey");
	}
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, 0);
	if(!ctx){
		pk_err("new ctx");
	}
	if(EVP_PKEY_keygen_init(ctx) <= 0){
		pk_err("keygen init");
	}
	if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, PK_PKEY_GROUP) <= 0){
		pk_err("set ec curve");
	}
	if(EVP_PKEY_keygen(ctx, &pkey) <= 0){
		pk_err("keygen");
	}
	EVP_PKEY_CTX_free(ctx);
	if(!(oper_file = fdopen(oper_fd, "wb"))){
		pk_err("fdopen");
	}
	if(!password){
		if(!PEM_write_PrivateKey(oper_file, pkey, 0, 0, 0, 0, 0)){
			pk_err("write pem");
		}
	}else{
		if(!PEM_write_PrivateKey(oper_file, pkey, EVP_aes_256_cbc(), 0, 0, 0, password)){
			pk_err("write pem");
		}
	}
	fclose(oper_file);
	close(oper_fd);
	if(access("public", F_OK)){
		if(errno == ENOENT){
			if(mkdir("public", 0744)){
				pk_err("mkdir public");
			}
		}else{
			pk_err("access public");
		}
	}
	if(stat("public", &oper_stat)){
		pk_err("stat public");
	}
	if(!(S_IFDIR&(oper_stat.st_mode))){
		pk_err("public is not s dir");
	}
	if((oper_fd = open("public/public.pem", O_CREAT|O_WRONLY, 0644)) < 0){
		pk_err("open public.pem");
	}
	if(!(oper_file = fdopen(oper_fd, "wb"))){
		pk_err("fdopen");
	}
	if(!PEM_write_PUBKEY(oper_file, pkey)){
		pk_err("write pubkey");
	}
	fclose(oper_file);
	close(oper_fd);
	EVP_PKEY_free(pkey);

}
int pk_get_pubkey(uint8_t* pubkey, uint64_t* len){
	if(!pubkey) pk_err("pubkey null");
	EVP_PKEY* pkey;
	FILE* oper_file;
	uint8_t* oper_str;
	ssize_t oper_str_len;
	if(!(pkey = EVP_PKEY_new())){
		pk_err("PKEY_new");
	}
	if(!(oper_file = fopen("public/public.pem", "rb"))){
		pk_err("fopen pubkey");
	}
	if(!PEM_read_PUBKEY(oper_file, &pkey, 0, 0)){
		pk_err("PEM_read_PrivateKey");
	}
	fclose(oper_file);
	oper_str_len = EVP_PKEY_get1_encoded_public_key(pkey, &oper_str);
	memcpy(pubkey, oper_str, oper_str_len);
	if(len){
		*len = oper_str_len;
	}
	free(oper_str);
	return 0;
}
int pk_sign(uint8_t* msg, uint64_t msg_len, uint8_t* sign, uint64_t* sign_len);
int pk_verify(uint8_t* pubkey, uint8_t* msg, uint64_t msg_len, uint8_t* sign, uint64_t sign_len);
int pk_dh(uint8_t* pubkey, uint8_t* secret, uint64_t* secret_len);
int pk_init_password(uint8_t* password){
	if(!access(".passphrase", F_OK|R_OK)){
		return 1;
	}else{
		if(errno != ENOENT) pk_err("access passphrase");
	}
	int oper_fd;
	uint8_t hash_value[32];
	uint8_t salt[20];
	memset(salt, 0, 20);
	EVP_MD_CTX* md_ctx;
	if((oper_fd = open(".passphrase", O_CREAT|O_WRONLY, 0600)) < 0){
		pk_err("open passphrase");
	}
	if(password){
		if(!(md_ctx = EVP_MD_CTX_new())) pk_err("MD_CTX_new");
		if(RAND_bytes(salt+4, 16) != 1) pk_err("RAND_bytes");
		EVP_DigestInit(md_ctx, EVP_sha3_256());
		EVP_DigestUpdate(md_ctx, salt+4, 16);
		EVP_DigestUpdate(md_ctx, password, strlen(password));
		EVP_DigestFinal(md_ctx, hash_value, 0);
		EVP_MD_CTX_free(md_ctx);
		salt[0] = 0x80;
		if(write(oper_fd, salt, 20) == -1) pk_err("write passphrase");
		if(write(oper_fd, hash_value, 32) == -1) pk_err("write passphrase");
	}else{
		if(write(oper_fd, salt, 4) == -1) pk_err("write passphrase");
	}
	close(oper_fd);
	return 0;
}
int pk_check_password(uint8_t* password){
	FILE* oper_file;
	if(!(oper_file = fopen(".passphrase", "rb"))){
		pk_err("fopen passphrase");
	}
	uint8_t hash_value[32];
	uint8_t salt[20];
	uint8_t read_hash[32];
	memset(salt, 0, 20);
	EVP_MD_CTX* md_ctx;
	if(fread(salt, 4, 1, oper_file) < 1) return -1;
	if(password){
		if(!((0x80)&(salt[0]))) return 1;
		if(fread(salt+4, 16, 1, oper_file) < 1) return -1;
		if(fread(read_hash, 32, 1, oper_file) < 1) return -1;
		if(!(md_ctx = EVP_MD_CTX_new())) pk_err("MD_CTX_new");
		if(!EVP_DigestInit(md_ctx, EVP_sha3_256())) return -1;
		if(!EVP_DigestUpdate(md_ctx, salt+4, 16)) return -1;
		if(!EVP_DigestUpdate(md_ctx, password, strlen(password))) return -1;
		if(!EVP_DigestFinal(md_ctx, hash_value, 0)) return -1;
		EVP_MD_CTX_free(md_ctx);
		if(memcmp(read_hash, hash_value, 32)) return 1;
	}else{
		if(((0x80)&(salt[0]))) return 1;
	}
	fclose(oper_file);
	return 0;
}
