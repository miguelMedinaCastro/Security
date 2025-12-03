#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cypherAES.h"

#define BUFFER_SIZE 4096

void 
handle_errors()
{
    fprintf(stderr, "An error occurred in an OpenSSL function.\n");
    abort();
}

void 
aes_encrypt_file
(const char *input_file, const char *output_file,
 const unsigned char *key, const unsigned char *iv)
{
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        perror("Failed to open input file");
        return;
    }

    FILE *out = fopen(output_file, "wb");
    if (!out) {
        perror("Failed to open output file");
        fclose(in);
        return;
    }

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char in_buf[BUFFER_SIZE];
    unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handle_errors();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handle_errors();
    }

    while ((len = fread(in_buf, 1, BUFFER_SIZE, in)) > 0) {
        if (1 != EVP_EncryptUpdate(ctx, out_buf, &ciphertext_len, in_buf, len)) {
            handle_errors();
        }
        fwrite(out_buf, 1, ciphertext_len, out);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, out_buf, &ciphertext_len)) {
        handle_errors();
    }
    fwrite(out_buf, 1, ciphertext_len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}

void 
aes_decrypt_file
(const char *input_file, const char *output_file,
 const unsigned char *key, const unsigned char *iv)
{
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        perror("Failed to open input file");
        return;
    }

    FILE *out = fopen(output_file, "wb");
    if (!out) {
        perror("Failed to open output file");
        fclose(in);
        return;
    }

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char in_buf[BUFFER_SIZE];
    unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handle_errors();
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handle_errors();
    }

    while ((len = fread(in_buf, 1, BUFFER_SIZE, in)) > 0) {
        if (1 != EVP_DecryptUpdate(ctx, out_buf, &plaintext_len, in_buf, len)) {
            handle_errors();
        }
        fwrite(out_buf, 1, plaintext_len, out);
    }

    if (1 != EVP_DecryptFinal_ex(ctx, out_buf, &plaintext_len)) {
        handle_errors();
    }
    fwrite(out_buf, 1, plaintext_len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}


long 
file_size
(const char *filename)
{
    FILE *f = fopen(filename, "rb");
    if (f == NULL) {
        perror("Failed to open file to get size");
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fclose(f);
    return size;
}

double
time_now()
{
    return (double)clock() / CLOCKS_PER_SEC;
}

double
aes_time_encrypt
(const char *input, const char *output,
 const unsigned char *key, const unsigned char *iv)
{
    double start_time = time_now();
    aes_encrypt_file(input, output, key, iv);
    double end_time = time_now();
    return end_time - start_time;
}



