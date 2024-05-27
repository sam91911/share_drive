#include "aes.h"

int main(int argc, char *argv[])
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s ifilename ofilename encfilename\n", argv[0]);
        return 1;
    }

    char *ifilename = argv[1];
    char *ofilename = argv[2];
    char *encfilename = argv[3];

    // Example key and IV (for demonstration purposes)
    unsigned char key[AES_KEY_LENGTH / 8];
    unsigned char iv[AES_BLOCK_SIZE];
    // Initialize key and IV with actual values (e.g., using RAND_bytes)

	FILE* f = fopen("/dev/urandom", "rb");
	if(!fread(key, sizeof(uint8_t), AES_KEY_LENGTH / 8, f)) return 0;
	if(!fread(iv, sizeof(uint8_t), AES_BLOCK_SIZE, f)) return 0;
	fclose(f);

    int ifile = open(ifilename, O_RDONLY);
    if (ifile < 0) {
        fprintf(stderr, "Error opening input file.\n");
        exit(EXIT_FAILURE);
    }

    int ofile = open(encfilename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (ofile < 0) {
        fprintf(stderr, "Error opening output file.\n");
        exit(EXIT_FAILURE);
    }

    aes_enc(ifile, ofile, key, iv);

    close(ifile);
    close(ofile);

    // Decrypt the encrypted file
    ifile = open(encfilename, O_RDONLY);
    if (ifile < 0) {
        fprintf(stderr, "Error opening encrypted file for decryption.\n");
        exit(EXIT_FAILURE);
    }

    ofile = open(ofilename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (ofile < 0) {
        fprintf(stderr, "Error opening output file for decryption.\n");
        exit(EXIT_FAILURE);
    }

    aes_dec(ifile, ofile, key, iv);

    close(ifile);
    close(ofile);

    return 0;
}
