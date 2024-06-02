all: server client
server: server_main.o server.o login.o process.o user.o pk.o signreg.o fsys.o
	gcc $^ -o $@ -lcrypto
client: client_main.o client.o pk.o serverid.o login.o process.o user.o fsys.o temp.o
	gcc $^ -o $@ -lcrypto
sep: sep.o sep_data.o GF64.o fsize.o aes.o
	gcc $^ -o $@ -O3
merge: merge.o sep_data.o GF64.o fsize.o aes.o
	gcc $^ -o $@ -O3
tb_key: tb_key.o share_key.o GF64.o
	gcc $^ -o $@ -O3
tb_aes: tb_aes.o aes.o
	gcc $^ -o $@ -O3
tb_sha3: tb_sha3.o sha3.o
	gcc $^ -o $@ -O3
tb_pk: tb_pk.o pk.o
	gcc $^ -o $@ -O3 -lcrypto
tb_bn: tb_bn.o bn.o
	gcc $^ -o $@ -O3 -lcrypto 
%.o: %.c
	gcc -c $< -o $@ -O3
