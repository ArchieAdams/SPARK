#include "unity.h"
#include "cryptography/cryptographic_methods.h"

#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#define M_LEN 40

static EVP_PKEY *kp_v;  // verifier keypair
static EVP_PKEY *kp_a;  // authenticator keypair

static EVP_PKEY *gen_rsa(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    TEST_ASSERT_NOT_NULL(ctx);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);
    EVP_PKEY *k = NULL;
    EVP_PKEY_keygen(ctx, &k);
    EVP_PKEY_CTX_free(ctx);
    TEST_ASSERT_NOT_NULL(k);
    return k;
}

// extra = der(first) || der(second)
static size_t build_extra(EVP_PKEY *first, EVP_PKEY *second, unsigned char *out) {
    unsigned char *d1 = NULL, *d2 = NULL;
    int l1 = i2d_PUBKEY(first, &d1);
    int l2 = i2d_PUBKEY(second, &d2);
    memcpy(out, d1, l1);
    memcpy(out + l1, d2, l2);
    OPENSSL_free(d1);
    OPENSSL_free(d2);
    return (size_t) l1 + (size_t) l2;
}

static void make_M(unsigned char m[M_LEN], uint64_t ctr) {
    RAND_bytes(m, 32);
    for (int i = 0; i < 8; i++) m[32 + i] = (unsigned char) (ctr >> (8 * (7 - i)));
}

static void test_roundtrip_recovers_M(void) {
    unsigned char m[M_LEN];
    make_M(m, 0x0102030405060708ULL);

    unsigned char extra_c[2048];  // pk_V || pk_A (challenge direction)
    size_t extra_c_len = build_extra(kp_v, kp_a, extra_c);

    unsigned char wire[4096];
    size_t wire_len = sizeof(wire);
    TEST_ASSERT_EQUAL(1, crypto_sign_and_encrypt_with_keys(m, M_LEN, extra_c, extra_c_len,
                                                           kp_v, kp_a, wire, &wire_len));
    // 424-byte blob -> two 384-byte OAEP blocks
    TEST_ASSERT_EQUAL(768, (long) wire_len);

    unsigned char out[256];
    size_t out_len = sizeof(out);
    TEST_ASSERT_EQUAL(1, crypto_decrypt_and_verify_with_keys(wire, wire_len, extra_c, extra_c_len,
                                                             kp_a, kp_v, out, &out_len));
    TEST_ASSERT_EQUAL(M_LEN, (long) out_len);
    TEST_ASSERT_EQUAL_MEMORY(m, out, M_LEN);
}

static void test_wrong_identity_order_fails(void) {
    unsigned char m[M_LEN];
    make_M(m, 1);

    unsigned char extra_c[2048], extra_swapped[2048];
    size_t extra_c_len = build_extra(kp_v, kp_a, extra_c);          // signed as pk_V||pk_A
    size_t extra_s_len = build_extra(kp_a, kp_v, extra_swapped);    // verified as pk_A||pk_V

    unsigned char wire[4096];
    size_t wire_len = sizeof(wire);
    TEST_ASSERT_EQUAL(1, crypto_sign_and_encrypt_with_keys(m, M_LEN, extra_c, extra_c_len,
                                                           kp_v, kp_a, wire, &wire_len));

    unsigned char out[256];
    size_t out_len = sizeof(out);
    // Same ciphertext, signature must not verify.
    TEST_ASSERT_EQUAL(0, crypto_decrypt_and_verify_with_keys(wire, wire_len, extra_swapped, extra_s_len,
                                                             kp_a, kp_v, out, &out_len));
}

static void test_tampered_ciphertext_fails(void) {
    unsigned char m[M_LEN];
    make_M(m, 2);

    unsigned char extra_c[2048];
    size_t extra_c_len = build_extra(kp_v, kp_a, extra_c);

    unsigned char wire[4096];
    size_t wire_len = sizeof(wire);
    TEST_ASSERT_EQUAL(1, crypto_sign_and_encrypt_with_keys(m, M_LEN, extra_c, extra_c_len,
                                                           kp_v, kp_a, wire, &wire_len));
    wire[10] ^= 0xFF;  // corrupt a byte in the first block

    unsigned char out[256];
    size_t out_len = sizeof(out);
    TEST_ASSERT_EQUAL(0, crypto_decrypt_and_verify_with_keys(wire, wire_len, extra_c, extra_c_len,
                                                             kp_a, kp_v, out, &out_len));
}

// Authenticator-side counter gate: accept iff ctr_recv > ctr_A, then adopt it.
static int counter_accept(uint64_t recv, uint64_t *stored) {
    if (recv <= *stored) return 0;
    *stored = recv;
    return 1;
}

static void test_counter_monotonic(void) {
    uint64_t stored = 0;
    TEST_ASSERT_EQUAL(1, counter_accept(1, &stored));   // first login
    TEST_ASSERT_EQUAL(1, (long) stored);
    TEST_ASSERT_EQUAL(0, counter_accept(1, &stored));   // replay of same M
    TEST_ASSERT_EQUAL(1, counter_accept(5, &stored));   // forward jump tolerated
    TEST_ASSERT_EQUAL(0, counter_accept(4, &stored));   // stale
    TEST_ASSERT_EQUAL(5, (long) stored);
}

int main(void) {
    UnityBegin("crypto_envelope_tests");
    kp_v = gen_rsa();
    kp_a = gen_rsa();
    RUN_TEST(test_roundtrip_recovers_M);
    RUN_TEST(test_wrong_identity_order_fails);
    RUN_TEST(test_tampered_ciphertext_fails);
    RUN_TEST(test_counter_monotonic);
    EVP_PKEY_free(kp_v);
    EVP_PKEY_free(kp_a);
    UnityEnd();
    return UnityTestsFailed == 0 ? 0 : 1;
}
