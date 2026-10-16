/* Verify the pinned static crypto engine retains AES-GCM after the D264 cut. */
#include <openssl/err.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>

static int fail(const char *step)
{
    fprintf(stderr, "AES-GCM test failed at %s\n", step);
    ERR_print_errors_fp(stderr);
    return 1;
}

int main(void)
{
    static const unsigned char key[16] = {0};
    static const unsigned char iv[12] = {0};
    static const unsigned char plaintext[16] = {0};
    static const unsigned char expected_ciphertext[16] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
    };
    static const unsigned char expected_tag[16] = {
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
    };
    unsigned char ciphertext[32] = {0};
    unsigned char tag[16] = {0};
    unsigned char recovered[32] = {0};
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    int written = 0;
    int total = 0;
    int ok = 0;

    if (context == NULL)
        return fail("context allocation");
    if (EVP_EncryptInit_ex(context, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1 ||
        EVP_EncryptInit_ex(context, NULL, NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(context, ciphertext, &written, plaintext, sizeof(plaintext)) != 1)
        goto cleanup_encrypt;
    total = written;
    if (EVP_EncryptFinal_ex(context, ciphertext + total, &written) != 1)
        goto cleanup_encrypt;
    total += written;
    if (total != sizeof(expected_ciphertext) ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1 ||
        memcmp(ciphertext, expected_ciphertext, sizeof(expected_ciphertext)) != 0 ||
        memcmp(tag, expected_tag, sizeof(expected_tag)) != 0)
        goto cleanup_encrypt;

    EVP_CIPHER_CTX_reset(context);
    if (EVP_DecryptInit_ex(context, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1 ||
        EVP_DecryptInit_ex(context, NULL, NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(context, recovered, &written, ciphertext, total) != 1)
        goto cleanup_decrypt;
    total = written;
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag) != 1 ||
        EVP_DecryptFinal_ex(context, recovered + total, &written) != 1)
        goto cleanup_decrypt;
    total += written;
    ok = total == sizeof(plaintext) && memcmp(recovered, plaintext, sizeof(plaintext)) == 0;

    EVP_CIPHER_CTX_free(context);
    if (!ok)
        return fail("NIST vector verification");
    puts("AES-128-GCM NIST vector encrypt/decrypt passed");
    return 0;

cleanup_encrypt:
    EVP_CIPHER_CTX_free(context);
    return fail("encryption");
cleanup_decrypt:
    EVP_CIPHER_CTX_free(context);
    return fail("decryption");
}
