#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BUFFER_SIZE 4096

static OSSL_PROVIDER *legacy_provider = NULL;
static OSSL_PROVIDER *default_provider = NULL;

void init_openssl_providers() {
    legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy_provider) 
        ERR_print_errors_fp(stderr);
    
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) 
        ERR_print_errors_fp(stderr);
}

void cleanup_openssl_providers() {
    if (legacy_provider) {
        OSSL_PROVIDER_unload(legacy_provider);
    }
    if (default_provider) {
        OSSL_PROVIDER_unload(default_provider);
    }
}

void error_bf() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

int blowfish_encrypt_file(const char *input_file, const char *output_file,  const unsigned char *key, const unsigned char *iv) {
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        perror("Failed to open input file");
        return 0;
    }

    FILE *out = fopen(output_file, "wb");
    if (!out) {
        perror("Failed to open output file");
        fclose(in);
        return 0;
    }

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char in_buf[BUFFER_SIZE];
    unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        error_bf();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), NULL, key, iv)) {
        error_bf();
    }

    while ((len = fread(in_buf, 1, BUFFER_SIZE, in)) > 0) {
        if (1 != EVP_EncryptUpdate(ctx, out_buf, &ciphertext_len, in_buf, len)) {
            error_bf();
        }
        if (fwrite(out_buf, 1, ciphertext_len, out) != (size_t)ciphertext_len) {
            perror("Failed to write to output file");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 0;
        }
    }

    if (1 != EVP_EncryptFinal_ex(ctx, out_buf, &ciphertext_len)) {
        error_bf();
    }
    if (fwrite(out_buf, 1, ciphertext_len, out) != (size_t)ciphertext_len) {
        perror("Failed to write to output file");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    return 1;
}

int blowfish_decrypt_file(const char *input_file, const char *output_file, const unsigned char *key, const unsigned char *iv) {
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        perror("Failed to open input file");
        return 0;
    }

    FILE *out = fopen(output_file, "wb");
    if (!out) {
        perror("Failed to open output file");
        fclose(in);
        return 0;
    }

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char in_buf[BUFFER_SIZE];
    unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        error_bf();
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_bf_cbc(), NULL, key, iv)) {
        error_bf();
    }

    while ((len = fread(in_buf, 1, BUFFER_SIZE, in)) > 0) {
        if (1 != EVP_DecryptUpdate(ctx, out_buf, &plaintext_len, in_buf, len)) {
            error_bf();
        }
        if (fwrite(out_buf, 1, plaintext_len, out) != (size_t)plaintext_len) {
            perror("Failed to write to output file");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 0;
        }
    }

    if (1 != EVP_DecryptFinal_ex(ctx, out_buf, &plaintext_len))
        error_bf();
    
    if (fwrite(out_buf, 1, plaintext_len, out) != (size_t)plaintext_len) {
        perror("Failed to write to output file");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    return 1;
}

double time_now_blowfish() {
    return (double)clock() / CLOCKS_PER_SEC;
}

double blowfish_time_encrypt(const char *input, const char *output, const unsigned char *key, const unsigned char *iv) {
    double start_time = time_now_blowfish();
    blowfish_encrypt_file(input, output, key, iv);
    double end_time = time_now_blowfish();
    return end_time - start_time;
}

double blowfish_time_decrypt(const char *input, const char *output, const unsigned char *key, const unsigned char *iv) {
    double start_time = time_now_blowfish();
    blowfish_decrypt_file(input, output, key, iv);
    double end_time = time_now_blowfish();
    return end_time - start_time;
}
