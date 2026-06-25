#include "cryptographic_methods.h"

#include <string.h>
#include <openssl/rsa.h>
#include <sys/syslog.h>

#include "../log_manager.h"

static const char *TAG = "crypto_methods";
#define RSA_MAX_PLAINTEXT_SIZE 318

static int
crypto_sign_message(const unsigned char *message, size_t message_len, EVP_PKEY *private_key,
                    unsigned char *signature, size_t *signature_len) {
    if (!message || !private_key || !signature || !signature_len) return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    int ok = 0;
    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestSignInit(ctx, &pctx, EVP_sha384(), NULL, private_key) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) goto cleanup;
    if (EVP_DigestSignUpdate(ctx, message, message_len) <= 0) goto cleanup;
    if (EVP_DigestSignFinal(ctx, NULL, signature_len) <= 0) goto cleanup;
    ok = (EVP_DigestSignFinal(ctx, signature, signature_len) > 0);

    cleanup:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int crypto_verify_signature(const unsigned char *message, size_t message_len,
                                   const unsigned char *signature, size_t signature_len,
                                   EVP_PKEY *public_key) {
    if (!message || !signature || !public_key) return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    int ok = 0;
    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestVerifyInit(ctx, &pctx, EVP_sha384(), NULL, public_key) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) goto cleanup;
    if (EVP_DigestVerifyUpdate(ctx, message, message_len) <= 0) goto cleanup;
    ok = (EVP_DigestVerifyFinal(ctx, signature, signature_len) == 1);

    cleanup:
    EVP_MD_CTX_free(ctx);
    return ok;
}


static int crypto_encrypt_message(const unsigned char *plaintext, size_t plaintext_len,
                           EVP_PKEY *recipient_public_key, unsigned char *ciphertext,
                           size_t *ciphertext_len) {
    if (!plaintext || !recipient_public_key || !ciphertext || !ciphertext_len) return 0;

    // Challenge payloads are fixed-size and small
    if (plaintext_len > RSA_MAX_PLAINTEXT_SIZE) {
        custom_log(LOG_ERR, TAG, "Plaintext too large for RSA OAEP: %zu > %d", plaintext_len,
                   RSA_MAX_PLAINTEXT_SIZE);
        return 0;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(recipient_public_key, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha1()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    int ok = (EVP_PKEY_encrypt(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len) > 0);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int crypto_decrypt_message(const unsigned char *ciphertext, size_t ciphertext_len,
                           EVP_PKEY *private_key, unsigned char *plaintext, size_t *plaintext_len) {
    if (!ciphertext || !private_key || !plaintext || !plaintext_len) return 0;

    int rsa_size = EVP_PKEY_size(private_key);
    if (ciphertext_len != (size_t) rsa_size) {
        custom_log(LOG_ERR, TAG, "Invalid RSA ciphertext length: got=%zu expected=%d",
                   ciphertext_len, rsa_size);
        return 0;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
        custom_log(LOG_ERR, TAG, "Failed to initialize RSA decryption");
        if (ctx) EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        custom_log(LOG_ERR, TAG, "Failed to set OAEP padding");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        custom_log(LOG_ERR, TAG, "Failed to set OAEP digest SHA-256");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha1()) <= 0) {
        custom_log(LOG_ERR, TAG, "Failed to set MGF1 digest SHA-1");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_decrypt(ctx, plaintext, plaintext_len, ciphertext, ciphertext_len) <= 0) {
        custom_log(LOG_ERR, TAG, "Failed to decrypt message");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    custom_log(LOG_DEBUG, TAG, "RSA decrypt: %zu -> %zu bytes", ciphertext_len, *plaintext_len);
    return 1;
}

static int crypto_sign_and_encrypt(const unsigned char *message, size_t message_len,
                            EVP_PKEY *sender_private_key, EVP_PKEY *recipient_public_key,
                            unsigned char *output, size_t *output_len) {
    if (!message || !sender_private_key || !recipient_public_key || !output || !output_len)
        return 0;

    unsigned char *ciphertext = malloc(message_len * 2 + 1024);
    if (!ciphertext) return 0;

    size_t ciphertext_len = message_len * 2 + 1024;
    if (!crypto_encrypt_message(message, message_len, recipient_public_key, ciphertext,
                                &ciphertext_len)) {
        free(ciphertext);
        return 0;
    }

    unsigned char signature[512];
    size_t signature_len = sizeof(signature);
    if (!crypto_sign_message(message, message_len, sender_private_key, signature, &signature_len)) {
        free(ciphertext);
        return 0;
    }

    output[0] = (signature_len >> 8) & 0xFF;
    output[1] = signature_len & 0xFF;
    output[2] = (ciphertext_len >> 8) & 0xFF;
    output[3] = ciphertext_len & 0xFF;
    memcpy(output + 4, signature, signature_len);
    memcpy(output + 4 + signature_len, ciphertext, ciphertext_len);
    *output_len = 4 + signature_len + ciphertext_len;
    free(ciphertext);
    return 1;
}

static int
crypto_decrypt_and_verify(const unsigned char *input, size_t input_len, EVP_PKEY *own_private_key,
                          EVP_PKEY *signer_public_key, unsigned char *message,
                          size_t *message_len) {
    if (!input || !own_private_key || !signer_public_key || !message || !message_len) return 0;
    if (input_len < 4) return 0;

    size_t signature_len = ((size_t) input[0] << 8) | (size_t) input[1];
    size_t ciphertext_len = ((size_t) input[2] << 8) | (size_t) input[3];

    if (4 + signature_len + ciphertext_len != input_len) return 0;
    if (signature_len == 0 || ciphertext_len == 0) return 0;

    const unsigned char *signature = input + 4;
    const unsigned char *ciphertext = signature + signature_len;

    size_t plaintext_len = *message_len;
    if (!crypto_decrypt_message(ciphertext, ciphertext_len, own_private_key, message,
                                &plaintext_len)) {
        return 0;
    }

    if (!crypto_verify_signature(message, plaintext_len, signature, signature_len,
                                 signer_public_key)) {
        custom_log(LOG_ERR, TAG, "Signature verification failed");
        return 0;
    }

    *message_len = plaintext_len;
    return 1;
}

int crypto_sign_and_encrypt_with_keys(const unsigned char *m, size_t ml, EVP_PKEY *sk, EVP_PKEY *pk,
                                      unsigned char *o, size_t *ol) {
    return crypto_sign_and_encrypt(m, ml, sk, pk, o, ol);
}

int
crypto_decrypt_and_verify_with_keys(const unsigned char *i, size_t il, EVP_PKEY *sk, EVP_PKEY *pk,
                                    unsigned char *m, size_t *ml) {
    return crypto_decrypt_and_verify(i, il, sk, pk, m, ml);
}
