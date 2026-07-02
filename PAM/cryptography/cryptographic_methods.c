#include "cryptographic_methods.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <sys/syslog.h>

#include "../log_manager.h"

static const char *TAG = "crypto_methods";
#define RSA_MAX_PLAINTEXT_SIZE 318
#define OAEP_OVERHEAD 66  // 2*SHA-256(32) + 2; OAEP-SHA256 max plaintext = keysize - 66

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

// Encrypt blob across as many RSA-OAEP blocks as needed
static int chunk_encrypt(const unsigned char *blob, size_t blob_len, EVP_PKEY *pk,
                         unsigned char *out, size_t out_cap, size_t *out_len) {
    int rsa_size = EVP_PKEY_size(pk);
    if (rsa_size <= OAEP_OVERHEAD) return 0;
    size_t max_pt = (size_t) rsa_size - OAEP_OVERHEAD;
    size_t off = 0, written = 0;

    while (off < blob_len) {
        size_t chunk = blob_len - off;
        if (chunk > max_pt) chunk = max_pt;
        if (written + (size_t) rsa_size > out_cap) return 0;
        size_t clen = out_cap - written;
        if (!crypto_encrypt_message(blob + off, chunk, pk, out + written, &clen)) return 0;
        written += clen;
        off += chunk;
    }
    *out_len = written;
    return 1;
}

// Inverse of chunk_encrypt: input must be a whole number of keysize blocks.
static int chunk_decrypt(const unsigned char *in, size_t in_len, EVP_PKEY *sk,
                         unsigned char *out, size_t out_cap, size_t *out_len) {
    int rsa_size = EVP_PKEY_size(sk);
    if (rsa_size <= 0 || in_len == 0 || (in_len % (size_t) rsa_size) != 0) return 0;
    size_t off = 0, written = 0;

    while (off < in_len) {
        if (written >= out_cap) return 0;
        size_t plen = out_cap - written;
        if (!crypto_decrypt_message(in + off, (size_t) rsa_size, sk, out + written, &plen)) return 0;
        written += plen;
        off += (size_t) rsa_size;
    }
    *out_len = written;
    return 1;
}

static int crypto_sign_and_encrypt(const unsigned char *message, size_t message_len,
                            const unsigned char *sign_extra, size_t extra_len,
                            EVP_PKEY *sender_private_key, EVP_PKEY *recipient_public_key,
                            unsigned char *output, size_t *output_len) {
    if (!message || !sender_private_key || !recipient_public_key || !output || !output_len)
        return 0;
    if (extra_len && !sign_extra) return 0;

    // S = PSS( M || sign_extra )
    size_t tosign_len = message_len + extra_len;
    unsigned char *tosign = malloc(tosign_len ? tosign_len : 1);
    if (!tosign) return 0;
    memcpy(tosign, message, message_len);
    if (extra_len) memcpy(tosign + message_len, sign_extra, extra_len);

    unsigned char signature[512];
    size_t signature_len = sizeof(signature);
    int ok = crypto_sign_message(tosign, tosign_len, sender_private_key, signature, &signature_len);
    free(tosign);
    if (!ok) return 0;

    // blob = M || S, encrypted as one or more OAEP blocks
    size_t blob_len = message_len + signature_len;
    unsigned char *blob = malloc(blob_len);
    if (!blob) return 0;
    memcpy(blob, message, message_len);
    memcpy(blob + message_len, signature, signature_len);

    size_t cap = *output_len;
    ok = chunk_encrypt(blob, blob_len, recipient_public_key, output, cap, output_len);
    free(blob);
    return ok;
}

static int
crypto_decrypt_and_verify(const unsigned char *input, size_t input_len,
                          const unsigned char *sign_extra, size_t extra_len,
                          EVP_PKEY *own_private_key, EVP_PKEY *signer_public_key,
                          unsigned char *message, size_t *message_len) {
    if (!input || !own_private_key || !signer_public_key || !message || !message_len) return 0;
    if (extra_len && !sign_extra) return 0;

    unsigned char blob[2048];
    size_t blob_len = 0;
    if (!chunk_decrypt(input, input_len, own_private_key, blob, sizeof(blob), &blob_len)) return 0;

    // PSS signature length == modulus size of the signer's key.
    size_t signature_len = (size_t) EVP_PKEY_size(signer_public_key);
    if (blob_len <= signature_len) return 0;
    size_t plaintext_len = blob_len - signature_len;
    if (plaintext_len > *message_len) return 0;
    const unsigned char *signature = blob + plaintext_len;

    // verify PSS( M || sign_extra )
    size_t tosign_len = plaintext_len + extra_len;
    unsigned char *tosign = malloc(tosign_len ? tosign_len : 1);
    if (!tosign) return 0;
    memcpy(tosign, blob, plaintext_len);
    if (extra_len) memcpy(tosign + plaintext_len, sign_extra, extra_len);
    int ok = crypto_verify_signature(tosign, tosign_len, signature, signature_len, signer_public_key);
    free(tosign);
    if (!ok) {
        custom_log(LOG_ERR, TAG, "Signature verification failed");
        return 0;
    }

    memcpy(message, blob, plaintext_len);
    *message_len = plaintext_len;
    return 1;
}

int crypto_sign_and_encrypt_with_keys(const unsigned char *m, size_t ml,
                                      const unsigned char *sign_extra, size_t extra_len,
                                      EVP_PKEY *sk, EVP_PKEY *pk, unsigned char *o, size_t *ol) {
    return crypto_sign_and_encrypt(m, ml, sign_extra, extra_len, sk, pk, o, ol);
}

int
crypto_decrypt_and_verify_with_keys(const unsigned char *i, size_t il,
                                    const unsigned char *sign_extra, size_t extra_len,
                                    EVP_PKEY *sk, EVP_PKEY *verify_pk, unsigned char *m, size_t *ml) {
    return crypto_decrypt_and_verify(i, il, sign_extra, extra_len, sk, verify_pk, m, ml);
}
