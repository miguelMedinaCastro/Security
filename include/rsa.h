#ifndef RSA_H
#define RSA_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <time.h>

RSA *load_public_key(const char *pub_key);
RSA *load_private_key(const char *priv_key);
void error();
void encrypted_file(const char *input, const char *output, const char *pub_key);
void decrypt_file(const char *input, const char *output, const char *priv_key);
double rsa_time_encrypt(const char *input, const char *output, const char *pub_key);
double rsa_time_decrypt(const char *input, const char *output, const char *priv_key);
long size(const char *input);
double time_now();


#endif