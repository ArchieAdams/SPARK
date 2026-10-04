#include "unity.h"
#include "cryptography/cryptographic_methods.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

static EVP_PKEY *gen_p256(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    TEST_ASSERT_NOT_NULL(ctx);
    TEST_ASSERT_EQUAL(1, EVP_PKEY_keygen_init(ctx));
    TEST_ASSERT_EQUAL(1, EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1));
    EVP_PKEY *k = NULL;
    TEST_ASSERT_EQUAL(1, EVP_PKEY_keygen(ctx, &k));
    EVP_PKEY_CTX_free(ctx);
    TEST_ASSERT_NOT_NULL(k);
    return k;
}

static void test_ec_signature_roundtrip(void) {
    EVP_PKEY *sk = gen_p256();
    unsigned char msg[] = "spark-ec-test";
    unsigned char sig[128];
    size_t sig_len = sizeof(sig);
    TEST_ASSERT_EQUAL(1, crypto_sign_ec(msg, sizeof(msg) - 1, sk, sig, &sig_len));
    TEST_ASSERT_EQUAL(1, (int)(sig_len > 0));
    TEST_ASSERT_EQUAL(1, crypto_verify_ec(msg, sizeof(msg) - 1, sig, sig_len, sk));
    EVP_PKEY_free(sk);
}

static void test_x25519_aead_roundtrip(void) {
    EVP_PKEY *a_priv = NULL;
    EVP_PKEY *b_priv = NULL;
    unsigned char a_pub[32];
    unsigned char b_pub[32];
    TEST_ASSERT_EQUAL(1, crypto_generate_x25519_keypair(&a_priv, a_pub));
    TEST_ASSERT_EQUAL(1, crypto_generate_x25519_keypair(&b_priv, b_pub));

    unsigned char a_secret[32];
    unsigned char b_secret[32];
    TEST_ASSERT_EQUAL(1, crypto_derive_x25519_secret(a_priv, b_pub, a_secret));
    TEST_ASSERT_EQUAL(1, crypto_derive_x25519_secret(b_priv, a_pub, b_secret));
    TEST_ASSERT_EQUAL_MEMORY(a_secret, b_secret, 32);

    unsigned char key[32];
    unsigned char iv[12], iv_resp[12];
    unsigned char transcript[] = "transcript-test-data-aad";
    crypto_derive_response_key_iv(a_secret, transcript, sizeof(transcript), key, iv, iv_resp);

    unsigned char plaintext[] = "hello spark";
    unsigned char ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    TEST_ASSERT_EQUAL(1, crypto_aead_encrypt(key, iv, plaintext, sizeof(plaintext) - 1, transcript, sizeof(transcript), ciphertext, &ciphertext_len));

    unsigned char decrypted[128];
    size_t decrypted_len = sizeof(decrypted);
    TEST_ASSERT_EQUAL(1, crypto_aead_decrypt(key, iv, ciphertext, ciphertext_len, transcript, sizeof(transcript), decrypted, &decrypted_len));
    TEST_ASSERT_EQUAL(sizeof(plaintext) - 1, decrypted_len);
    TEST_ASSERT_EQUAL_MEMORY(plaintext, decrypted, decrypted_len);

    EVP_PKEY_free(a_priv);
    EVP_PKEY_free(b_priv);
}

static void test_tampered_ciphertext_fails(void) {
    EVP_PKEY *a_priv = NULL;
    EVP_PKEY *b_priv = NULL;
    unsigned char a_pub[32];
    unsigned char b_pub[32];
    TEST_ASSERT_EQUAL(1, crypto_generate_x25519_keypair(&a_priv, a_pub));
    TEST_ASSERT_EQUAL(1, crypto_generate_x25519_keypair(&b_priv, b_pub));

    unsigned char a_secret[32];
    TEST_ASSERT_EQUAL(1, crypto_derive_x25519_secret(a_priv, b_pub, a_secret));

    unsigned char key[32];
    unsigned char iv[12], iv_resp[12];
    unsigned char transcript[] = "transcript-test-data-aad";
    crypto_derive_response_key_iv(a_secret, transcript, sizeof(transcript), key, iv, iv_resp);

    unsigned char plaintext[] = "hello spark";
    unsigned char ciphertext[128];
    size_t ciphertext_len = sizeof(ciphertext);
    TEST_ASSERT_EQUAL(1, crypto_aead_encrypt(key, iv, plaintext, sizeof(plaintext) - 1, transcript, sizeof(transcript), ciphertext, &ciphertext_len));
    ciphertext[0] ^= 0xFF;

    unsigned char decrypted[128];
    size_t decrypted_len = sizeof(decrypted);
    TEST_ASSERT_EQUAL(0, crypto_aead_decrypt(key, iv, ciphertext, ciphertext_len, transcript, sizeof(transcript), decrypted, &decrypted_len));

    EVP_PKEY_free(a_priv);
    EVP_PKEY_free(b_priv);
}

static void hex_to_bytes(const char *hex, unsigned char *out) {
    for (size_t i = 0; hex[2 * i]; i++) {
        unsigned int b;
        sscanf(hex + 2 * i, "%2x", &b);
        out[i] = (unsigned char)b;
    }
}

static void test_derive_known_vector_and_iv_separation(void) {
    unsigned char secret[32];
    for (int i = 0; i < 32; i++)
        secret[i] = (unsigned char)i;
    const unsigned char *transcript = (const unsigned char *)"SPARK-AUTH-v2-test-transcript";
    size_t tlen = strlen((const char *)transcript);

    unsigned char key[32], iv_req[12], iv_resp[12];
    crypto_derive_response_key_iv(secret, transcript, tlen, key, iv_req, iv_resp);

    unsigned char exp_key[32], exp_req[12], exp_resp[12];
    hex_to_bytes("ca4e4ee73b127e36bd95ad6ed8e0be61ce0d562dba598a9c3585771f10c683b9", exp_key);
    hex_to_bytes("e46e025fd6e05368ef8ea3ea", exp_req);
    hex_to_bytes("c728509f567da7c1ee1ed86c", exp_resp);
    TEST_ASSERT_EQUAL_MEMORY(exp_key, key, 32);
    TEST_ASSERT_EQUAL_MEMORY(exp_req, iv_req, 12);
    TEST_ASSERT_EQUAL_MEMORY(exp_resp, iv_resp, 12);

    unsigned char pt[] = "hello spark";
    unsigned char ct[64], out[64];
    size_t ct_len = sizeof(ct), out_len = sizeof(out);
    TEST_ASSERT_EQUAL(1, crypto_aead_encrypt(key, iv_req, pt, sizeof(pt) - 1, transcript, tlen, ct, &ct_len));
    TEST_ASSERT_EQUAL(1, crypto_aead_decrypt(key, iv_req, ct, ct_len, transcript, tlen, out, &out_len));
    TEST_ASSERT_EQUAL(0, crypto_aead_decrypt(key, iv_resp, ct, ct_len, transcript, tlen, out, &out_len));
}

int main(void) {
    UnityBegin("crypto_envelope_tests");
    RUN_TEST(test_ec_signature_roundtrip);
    RUN_TEST(test_x25519_aead_roundtrip);
    RUN_TEST(test_tampered_ciphertext_fails);
    RUN_TEST(test_derive_known_vector_and_iv_separation);
    UnityEnd();
    return UnityTestsFailed == 0 ? 0 : 1;
}
