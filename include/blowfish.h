#ifndef BF_H
#define BF_H

#include <openssl/evp.h>
#include <openssl/err.h>
#include <time.h>

// void error();
int blowfish_encrypt_file(const char *input_file, const char *output_file,  const unsigned char *key, const unsigned char *iv);
int blowfish_decrypt_file(const char *input_file, const char *output_file, const unsigned char *key, const unsigned char *iv);
double time_now_blowfish();
double blowfish_time_encrypt(const char *input, const char *output, const unsigned char *key, const unsigned char *iv);
double blowfish_time_decrypt(const char *input, const char *output, const unsigned char *key, const unsigned char *iv);

#endif