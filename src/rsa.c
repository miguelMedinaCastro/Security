#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>

double time_now(){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec + ts.tv_nsec / 1e9;
}

void error(){
    ERR_print_errors_fp(stderr);
    exit(1);
}

RSA *load_public_key(const char *pub_key){
    FILE *fp = fopen(pub_key, "rb");
    if (!fp){
        perror("pub_key"); 
        exit(1);
    }

    RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    
    if (!rsa) {
        ERR_clear_error();
        rewind(fp);
        rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    }

    fclose(fp);

    if (!rsa)
        error();

    return rsa;
}

RSA *load_private_key(const char *priv_key){
    FILE *fp = fopen(priv_key, "rb");
    if (!fp){
        perror("priv_key"); 
        exit(1);
    }

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!rsa)
        error();

    return rsa;
}

void encrypted_file(const char *input, const char *output, const char *pub_key){
    RSA *rsa = load_public_key(pub_key);

    int rsa_size = RSA_size(rsa);
    int max_chunk = rsa_size - 42;

    unsigned char *inbuf = malloc(max_chunk);
    unsigned char *outbuf = malloc(rsa_size);

    FILE *fin = fopen(input, "rb");
    FILE *fout = fopen(output, "wb");
    
    if (!fin || !fout){
        perror("arquivo");
        exit(1);
    }

    int n;
    while ((n = fread(inbuf, 1, max_chunk, fin)) > 0){
        int enc_len = RSA_public_encrypt(
            n, 
            inbuf,
            outbuf,
            rsa,
            RSA_PKCS1_OAEP_PADDING
        );

        if (enc_len == -1)
            error();

        if (enc_len != rsa_size)
            error();

        if (fwrite(outbuf, 1, enc_len, fout) != (size_t)enc_len){
            perror("fwrite enc");
            exit(1);
        }
    }

    free(inbuf);
    free(outbuf);
    fclose(fin);
    fclose(fout);
    RSA_free(rsa);
}

void decrypt_file(const char *input, const char *output, const char *priv_key){
    RSA *rsa = load_private_key(priv_key);

    int rsa_size = RSA_size(rsa);

    unsigned char *inbuf = malloc(rsa_size);
    unsigned char *outbuf = malloc(rsa_size);

    FILE *fin = fopen(input, "rb");
    FILE *fout = fopen(output, "wb");
    
    int n;
    while ((n = fread(inbuf, 1, rsa_size, fin)) > 0){
        if (n != rsa_size)
            error();
        
        int dec_len = RSA_private_decrypt(
            n, 
            inbuf,
            outbuf,
            rsa,
            RSA_PKCS1_OAEP_PADDING
        );

        if (dec_len == -1)
            error();

        if (fwrite(outbuf, 1, dec_len, fout) != (size_t)dec_len){
            perror("fwrite dec");
            exit(1);
        }
    }

    free(inbuf);
    free(outbuf);
    fclose(fin);
    fclose(fout);
    RSA_free(rsa);
}

double rsa_time_encrypt(const char *input, const char *output, const char *pub_key){
    double t_n;
    
    FILE *t = fopen(input, "rb");
    if (!t) { 
        perror("entrada missing"); 
        return -1.0; 
    }
    fclose(t);
    
    double t0 = time_now();

    encrypted_file(input, output, pub_key);

    double t1 = time_now();

    t_n = t1 - t0;
    return t_n;
}

double rsa_time_decrypt(const char *input, const char *output, const char *priv_key){
    double t_n;

    FILE *t = fopen(input, "rb");
    if (!t) { 
        perror("arquivo cifrado missing"); 
        return -1.0; 
    }
    fclose(t);
    
    double t0 = time_now();

    decrypt_file(input, output, priv_key);

    double t1 = time_now();

    t_n = t1 - t0;
    return t_n;
}

long size(const char *input){
    long int aux, tam;

    FILE *file = fopen(input, "rb");
    if (file == NULL)
        error();

    fseek(file, 0L, SEEK_END);

    aux = ftell(file);
    fclose(file);

    tam = (double)aux / (1024 * 1024);
    
    return tam;
}