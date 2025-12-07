#ifndef CYPHER_AES_H
#define CYPHER_AES_H

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <time.h>

void aes_encrypt_file(const char *input, const char *output,const unsigned char *key, const unsigned char *iv);
void aes_decrypt_file(const char *input, const char *output,  const unsigned char *key, const unsigned char *iv);
double aes_time_encrypt(const char *input, const char *output, const unsigned char *key, const unsigned char *iv);
double aes_time_decrypt(const char *input, const char *output, const unsigned char *key, const unsigned char *iv);
double time_now_aes();
// long file_size(const char *input);

#endif

