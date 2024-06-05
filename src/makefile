all: server client
server: server_main.o server.o login.o process.o user.o pk.o signreg.o fsys.o temp.o share_key.o GF64.o sep_data.o log.o
	gcc $^ -o $@ -lcrypto
client: client_main.o client.o pk.o serverid.o login.o process.o user.o fsys.o temp.o share_key.o GF64.o sep_data.o log.o
	gcc $^ -o $@ -lcrypto
%.o: %.c
	gcc -c $< -o $@ -O3
