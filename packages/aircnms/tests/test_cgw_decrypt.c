#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

bool decrypt_aes(const char *, const char *, char *, size_t);

static void encrypt_hex(const unsigned char *key, const unsigned char *plain,
                        int plain_len, char *hex)
{
    unsigned char cipher[256];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, total = 0, i;

    assert(ctx);
    assert(EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, key) == 1);
    assert(EVP_EncryptUpdate(ctx, cipher, &n, plain, plain_len) == 1);
    total = n;
    assert(EVP_EncryptFinal_ex(ctx, cipher + total, &n) == 1);
    total += n;
    for (i = 0; i < total; i++)
        sprintf(hex + (2 * i), "%02x", cipher[i]);
    hex[2 * total] = '\0';
    EVP_CIPHER_CTX_free(ctx);
}

int main(void)
{
    unsigned char key[16] = "0123456789abcdef";
    unsigned char wrong_key[16] = "fedcba9876543210";
    unsigned char nul_plain[3] = {'a', 0, 'b'};
    char b64[64] = {0}, wrong_b64[64] = {0}, hex[600] = {0}, out[128];

    EVP_EncodeBlock((unsigned char *)b64, key, sizeof(key));
    EVP_EncodeBlock((unsigned char *)wrong_b64, wrong_key, sizeof(wrong_key));
    encrypt_hex(key, (const unsigned char *)"mqtt-password", 13, hex);

    assert(decrypt_aes(hex, b64, out, sizeof(out)));
    assert(strcmp(out, "mqtt-password") == 0);
    assert(!decrypt_aes("0", b64, out, sizeof(out)));
    assert(!decrypt_aes("zz", b64, out, sizeof(out)));
    assert(!decrypt_aes("0011", b64, out, sizeof(out)));
    assert(!decrypt_aes(hex, "bad!", out, sizeof(out)));
    assert(!decrypt_aes(hex, "MDEyMzQ1Njc4OWFiY2RlZg==AAAA", out, sizeof(out)));
    assert(!decrypt_aes(hex, "MDEyMzQ1Njc4OWFiY2RlZQ==", out, sizeof(out)));
    assert(!decrypt_aes(hex, wrong_b64, out, sizeof(out)));
    assert(!decrypt_aes(hex, b64, out, 5));
    encrypt_hex(key, nul_plain, sizeof(nul_plain), hex);
    assert(!decrypt_aes(hex, b64, out, sizeof(out)));

    puts("decrypt_aes: 10 cases PASS");
    return 0;
}
