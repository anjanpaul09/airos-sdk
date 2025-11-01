#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Unhexlify function (similar to binascii.unhexlify in Python)
void unhexlify(const char* input, unsigned char* output, int length) 
{
    for (int i = 0; i < length / 2; ++i) {
        sscanf(input + 2 * i, "%2hhx", &output[i]);
    }
}

// PKCS7 padding removal (similar to unpad in Python)
int unpad(unsigned char* data, int length) 
{
    int padding_length = data[length - 1];
    if (padding_length > 0 && padding_length <= AES_BLOCK_SIZE) {
        for (int i = 0; i < padding_length; ++i) {
            if (data[length - 1 - i] != padding_length) {
                return -1; // Invalid padding
            }
        }
        return length - padding_length;
    }
    return -1; // Invalid padding
}

// Function to base64 decode
int base64_decode(const char* base64_input, unsigned char* decoded_output) 
{
    BIO *b64, *bmem;
    int decoded_length = 0;
    size_t input_length = strlen(base64_input);

    // Create BIO objects for base64 decoding
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(base64_input, input_length);
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);  // Ignore newlines in input

    // Decode base64
    decoded_length = BIO_read(bmem, decoded_output, input_length);
    BIO_free_all(bmem);  // Clean up

    return decoded_length;
}

void decrypt_aes(const char* encrypted_string, const char* base64_key, char* decrypted_output) 
{
    int encrypted_length = strlen(encrypted_string);
    unsigned char encrypted_bytes[encrypted_length / 2];
    
    // Convert the hex string to bytes
    unhexlify(encrypted_string, encrypted_bytes, encrypted_length);

    // Base64 decode the key
    unsigned char key[AES_BLOCK_SIZE];  // AES-128 requires a 16-byte key
    int key_length = base64_decode(base64_key, key);
    printf("Base64-decoded key length: %d bytes\n", key_length);  // Debugging output
    if (key_length != AES_BLOCK_SIZE) {
        printf("Key length is invalid. Expected 16 bytes for AES-128.\n");
        return;
    }

    // Print the key in hexadecimal format for debugging
    printf("Base64-decoded key (hex): ");
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        printf("%02x", key[i]);
    }
    printf("\n");

    // Prepare IV (Initialization Vector) - We'll use the key itself as IV for simplicity
    unsigned char iv_spec[AES_BLOCK_SIZE];
    memcpy(iv_spec, key, AES_BLOCK_SIZE);  // For this example, using key as IV

    // Create the AES decryption context
    AES_KEY decrypt_key;
    AES_set_decrypt_key((const unsigned char*)key, 128, &decrypt_key);  // 128-bit AES key

    // Decrypt the data
    unsigned char decrypted_bytes[encrypted_length];
    AES_cbc_encrypt(encrypted_bytes, decrypted_bytes, encrypted_length / 2, &decrypt_key, iv_spec, AES_DECRYPT);

    // Debug: Print decrypted bytes before unpadding
    printf("Decrypted bytes (before unpadding): ");
    for (int i = 0; i < encrypted_length / 2; ++i) {
        printf("%02x", decrypted_bytes[i]);
    }
    printf("\n");

    // Remove padding
    int unpadded_length = unpad(decrypted_bytes, encrypted_length / 2);
    if (unpadded_length < 0) {
        printf("Invalid padding\n");
        return;
    }

    // Copy the decrypted bytes to the output buffer
    strncpy(decrypted_output, (char*)decrypted_bytes, unpadded_length);
    decrypted_output[unpadded_length] = '\0';  // Null-terminate the string
    return;
}
