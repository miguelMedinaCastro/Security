#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include "cypherAES.h"

// --- TEMPORARY TEST CODE START ---
#define AES_KEY_SIZE 32 // AES-256
#define AES_IV_SIZE 16

int
main (int argc, char* argv[])
{
    const char* input_file = "input.txt";
    const char* encrypted_file = "encrypted.aes";
    const char* decrypted_file = "decrypted.txt";

    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];

    // Generate random key and IV
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "ERROR: Failed to generate random key/IV.\n");
        return EXIT_FAILURE;
    }

    printf("--- AES Functionality Test ---\n");

    // Test encryption and timing
    double time_taken = aes_time_encrypt(input_file, encrypted_file, key, iv);
    long size = file_size(input_file);

    if (size == -1 || time_taken < 0) {
        fprintf(stderr, "ERROR: Encryption test failed.\n");
        return EXIT_FAILURE;
    }

    printf("Input File: %s\n", input_file);
    printf("File Size: %ld bytes\n", size);
    printf("Encryption Time: %f seconds\n", time_taken);
    printf("Encrypted output: %s\n", encrypted_file);

    // Test decryption for verification
    printf("\nAttempting to decrypt '%s' to '%s' for verification...\n", encrypted_file, decrypted_file);
    aes_decrypt_file(encrypted_file, decrypted_file, key, iv);
    printf("Decryption complete. Please compare '%s' and '%s' to verify correctness.\n", input_file, decrypted_file);

    printf("\n--- Test Complete ---\n");

    return EXIT_SUCCESS;
}
// --- TEMPORARY TEST CODE END ---

