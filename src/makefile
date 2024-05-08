all: sep merge tb_sha3
sep: sep.o sep_data.o GF64.o fsize.o aes.o
	gcc $< sep_data.o GF64.o fsize.o aes.o -o $@ -O3
merge: merge.o sep_data.o GF64.o fsize.o aes.o
	gcc $< sep_data.o GF64.o fsize.o aes.o -o $@ -O3
tb_key: tb_key.o share_key.o GF64.o
	gcc $< share_key.o GF64.o -o $@ -O3
tb_aes: tb_aes.o aes.o
	gcc $< aes.o -o $@ -O3
tb_sha3: tb_sha3.o sha3.o
	gcc $< sha3.o -o $@ -O3
sep.o: sep.c sep_data.o
	gcc -c $< -o $@ -O3
merge.o: merge.c sep_data.o
	gcc -c $< -o $@ -O3
sep_data.o: sep_data.c sep_data.h GF64.o
	gcc -c $< -o $@ -O3
GF64.o: GF64.c GF64.h
	gcc -c $< -o $@ -O3
share_key.o: share_key.c share_key.h
	gcc -c $< -o $@ -O3
tb_key.o: tb_key.c share_key.h
	gcc -c $< -o $@ -O3
aes.o: aes.c aes.h
	gcc -c $< -o $@ -O3
tb_aes.o: tb_aes.c aes.h
	gcc -c $< -o $@ -O3
sha3.o: sha3.c sha3.h
	gcc -c $< -o $@ -O3
tb_sha3.o: tb_sha3.c sha3.h
	gcc -c $< -o $@ -O3
fsize.o: fsize.c fsize.h
	gcc -c $< -o $@ -O3
