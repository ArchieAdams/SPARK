#include "cryptographic_methods.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>

int crypto_sign_ec(const unsigned char *message, size_t message_len, EVP_PKEY *private_key,
                   unsigned char *signature, size_t *signature_len) {
    if (!message || !private_key || !signature || !signature_len)
        return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return 0;
    int ok = 0;
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, private_key) > 0 &&
        EVP_DigestSignUpdate(ctx, message, message_len) > 0 &&
        EVP_DigestSignFinal(ctx, signature, signature_len) > 0) {
        ok = 1;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

int crypto_verify_ec(const unsigned char *message, size_t message_len,
                     const unsigned char *signature, size_t signature_len, EVP_PKEY *public_key) {
    if (!message || !signature || !public_key)
        return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return 0;
    int ok = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, public_key) > 0 &&
        EVP_DigestVerifyUpdate(ctx, message, message_len) > 0 &&
        EVP_DigestVerifyFinal(ctx, signature, signature_len) == 1) {
        ok = 1;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

int crypto_generate_x25519_keypair(EVP_PKEY **private_key, unsigned char public_key[32]) {
    if (!private_key || !public_key)
        return 0;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx)
        return 0;
    int ok = 0;
    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_keygen(ctx, &key) > 0) {
        size_t len = 32;
        if (EVP_PKEY_get_raw_public_key(key, public_key, &len) > 0) {
            *private_key = key;
            ok = 1;
        } else {
            EVP_PKEY_free(key);
        }
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

int crypto_derive_x25519_secret(EVP_PKEY *private_key, const unsigned char peer_public[32],
                                unsigned char shared_secret[32]) {
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_public, 32);
    if (!peer)
        return 0;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    int ok = 0;
    size_t secret_len = 32;
    if (ctx && EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_derive_set_peer(ctx, peer) > 0 &&
        EVP_PKEY_derive(ctx, shared_secret, &secret_len) > 0) {
        ok = (secret_len == 32);
    }
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    return ok;
}

static void hkdf_expand_label(const unsigned char *secret, const char *label,
                              const unsigned char *transcript, size_t transcript_len,
                              unsigned char *out, size_t out_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return;
    if (EVP_PKEY_derive_init(pctx) > 0 && EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, 32) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char *)label, (int)strlen(label)) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(pctx, transcript, (int)transcript_len) > 0) {
        EVP_PKEY_derive(pctx, out, &out_len);
    }
    EVP_PKEY_CTX_free(pctx);
}

void crypto_derive_response_key_iv(const unsigned char shared_secret[32],
                                   const unsigned char *transcript, size_t transcript_len,
                                   unsigned char key[32], unsigned char iv_req[12],
                                   unsigned char iv_resp[12]) {
    // One key, two IVs: c3 (V->A) and c4 (A->V) must never share a (key, IV) pair under GCM
    hkdf_expand_label(shared_secret, "SPARK-AUTH-v2 key", transcript, transcript_len, key, 32);
    hkdf_expand_label(shared_secret, "SPARK-AUTH-v2 nonce req", transcript, transcript_len, iv_req, 12);
    hkdf_expand_label(shared_secret, "SPARK-AUTH-v2 nonce resp", transcript, transcript_len, iv_resp, 12);
}

int crypto_aead_encrypt(const unsigned char key[32], const unsigned char iv[12],
                        const unsigned char *plaintext, size_t plaintext_len,
                        const unsigned char *aad, size_t aad_len, unsigned char *ciphertext,
                        size_t *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return 0;
    int len = 0, out_len = 0, ok = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) > 0) {
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) > 0) {
            if (aad && aad_len > 0)
                EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len);
            if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) > 0) {
                out_len = len;
                if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &len) > 0) {
                    out_len += len;
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext + out_len);
                    *ciphertext_len = (size_t)out_len + 16;
                    ok = 1;
                }
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int crypto_aead_decrypt(const unsigned char key[32], const unsigned char iv[12],
                        const unsigned char *ciphertext, size_t ciphertext_len,
                        const unsigned char *aad, size_t aad_len, unsigned char *plaintext,
                        size_t *plaintext_len) {
    if (ciphertext_len < 16)
        return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return 0;
    int len = 0, out_len = 0, ok = 0;
    size_t enc_len = ciphertext_len - 16;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) > 0) {
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) > 0) {
            if (aad && aad_len > 0)
                EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len);
            if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)enc_len) > 0) {
                out_len = len;
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)(ciphertext + enc_len));
                if (EVP_DecryptFinal_ex(ctx, plaintext + out_len, &len) > 0) {
                    *plaintext_len = (size_t)out_len + (size_t)len;
                    ok = 1;
                }
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
