all: server client
server: server_main.o server.o client.o login.o process.o user.o pk.o signreg.o fsys.o temp.o share_key.o GF64.o sep_data.o log.o logfile.o serverid.o
	gcc $^ -o $@ -lcrypto -O3
client: client_main.o client.o server.o login.o pk.o serverid.o login.o process.o user.o fsys.o temp.o share_key.o GF64.o sep_data.o log.o logfile.o signreg.o
	gcc $^ -o $@ -lcrypto -O3
%.o: %.c
	gcc -c $< -o $@ -O3
