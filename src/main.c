#include <stdio.h>
#include <stdlib.h>
#include "../include/rsa.h"
#include "../include/cypherAES.h"
#include "../include/blowfish.h"

/*
 * ============================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  Algoritmos RSA, AES e Blowfish demonstrados e seus respectivos tempos analisados
 *
 *         Authors: Milena Bueno, Miguel Medina, Bruno dos Santos 
 *
 * ============================================================================
 */

void compression_ratio(const char *algorithm, const char *operation, long file_size_bytes, double time_seconds) {
    if (time_seconds <= 0) {
        printf("%s %s: tempo muito pequeno para medir\n", algorithm, operation);
        return;
    }
    
    double bytes_per_sec = file_size_bytes / time_seconds;
    double kb_per_sec = bytes_per_sec / 1024.0;
    double mb_per_sec = kb_per_sec / 1024.0;
    
    printf("%s %s:\n", algorithm, operation);
    printf("  Tempo: %.4f s\n", time_seconds);
    printf("  Taxa: %.2f bytes/s\n", bytes_per_sec);
    printf("  Taxa: %.2f KB/s\n", kb_per_sec);
    printf("  Taxa: %.2f MB/s\n", mb_per_sec);
}

int main(int argc, char *argv[]) {

    if (argc < 8){
        printf("Uso:  %s <arquivo> <public.pem> <private.pem> <aes.key> <aes_iv.bin> <blowfish_key.bin> <blowfish_iv.bin>\n", argv[0]);
        return 1;
    }

    init_openssl_providers();

    
    const char *input = argv[1];
    const char *pub = argv[2];
    const char *priv = argv[3];
    const char *key_aes = argv[4];
    const char *iv_aes = argv[5];
    const char *key_bf = argv[6];
    const char * iv_bf = argv[7];

    long file_size = size(input);
    printf("tam arquivo original: %0.f MB\n", (double)file_size / (1024 * 1024));

    printf("=====================================\n\n");

    double t_enc_rsa = rsa_time_encrypt(input, "arquivo_RSA.enc", pub);
    double t_dec_rsa = rsa_time_decrypt("arquivo_RSA.enc", "arquivo_RSA.dec", priv);
    
    double t_enc_aes = aes_time_encrypt(input, "arquivo_AES.enc", key_aes, iv_aes);
    double t_dec_aes = aes_time_decrypt("arquivo_AES.enc", "arquivo_AES.dec", key_aes, iv_aes);

    double t_enc_bf = blowfish_time_encrypt(input, "arquivo_BF.enc", key_bf, iv_bf);
    double t_dec_bf = blowfish_time_decrypt("arquivo_BF.enc", "arquivo_BF.dec", key_bf, iv_bf);

    compression_ratio("RSA", "Encrypt", file_size, t_enc_rsa);
    printf("\n");
    compression_ratio("RSA", "Decrypt", file_size, t_dec_rsa);
    printf("\n");

    printf("=====================================\n\n");

    compression_ratio("AES", "Encrypt", file_size, t_enc_aes);
    printf("\n");
    compression_ratio("AES", "Decrypt", file_size, t_dec_aes);
    printf("\n");

    printf("=====================================\n\n");

    compression_ratio("Blowfish", "Encrypt", file_size, t_enc_bf);
    printf("\n");
    compression_ratio("Blowfish", "Decrypt", file_size, t_dec_bf);
    printf("\n");
    
    init_openssl_providers();
    return 0;
}
