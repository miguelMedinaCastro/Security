/*
 * ============================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  Main file of the project
 *
 *         Authors: Milena Bueno, Miguel Medina, Bruno dos Santos 
 *
 * ============================================================================
 */


#include <stdio.h>
#include <stdlib.h>
#include "../include/rsa.h"

int main(int argc, char *argv[]) {

    if (argc < 4){
        printf("Uso:  %s <arquivo> <public.pem> <private.pem>\n", argv[0]);
        return 1;
    }
    
    const char *input = argv[1];
    const char *pub = argv[2];
    const char *priv = argv[3];

    long file_size = size(input);
    printf("tam arquivo original: %ld MB\n", file_size);

    double t_enc = rsa_time_encrypt(input, "arquivo_RSA.enc", pub);
    double t_dec = rsa_time_decrypt("arquivo_RSA.enc", "arquivo_RSA.dec", priv);

    printf("Tempo RSA(enc): %.4f s\n", t_enc);
    printf("Tempo RSA(dec): %.4f s\n", t_dec);
    
    return 0;
}


