#include "messages.h"
#include "sas.h"
#include "frame.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>

static int eq_hex(const uint8_t *b, ssize_t n, const char *want) {
    char got[2048];
    if (n < 0 || n > 1024) return 0;
    for (ssize_t i = 0; i < n; i++) sprintf(got + i * 2, "%02x", b[i]);
    return strcmp(got, want) == 0;
}

static void test_message_vectors(void) {
    uint8_t out[1024];
    uint8_t id[16] = {0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};

    // SETUP_REQ (4 arguments)
    ssize_t n = msg_encode_setup_req(id, 8080, out, sizeof out);
    assert(eq_hex(out, n, "00112233445566778899aabbccddeeff00001f90"));

    uint8_t pkv[6] = {0x10,0x11,0x12,0x13,0x14,0x15};
    uint8_t c[32]; for (int i = 0; i < 32; i++) c[i] = i;
    n = msg_encode_commit(pkv, 6, c, out, sizeof out);
    assert(eq_hex(out, n, "00000006101112131415000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));

    uint8_t pka[8] = {1,2,3,4,5,6,7,8};
    uint8_t na[32]; for (int i = 0; i < 32; i++) na[i] = 0xAA;
    n = msg_encode_sas_nonce(pka, 8, na, out, sizeof out);
    assert(eq_hex(out, n, "000000080102030405060708aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

    uint8_t N[32], R[32]; for (int i = 0; i < 32; i++) { N[i] = i; R[i] = 32 + i; }
    n = msg_encode_reveal(N, R, out, sizeof out);
    assert(eq_hex(out, n, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"));
    printf("message vectors OK\n");
}

static void test_sas_vector(void) {
    uint8_t pkv[6] = {0x10,0x11,0x12,0x13,0x14,0x15};
    uint8_t pka[8] = {1,2,3,4,5,6,7,8};
    uint8_t nv[32]; for (int i = 0; i < 32; i++) nv[i] = i;
    uint8_t r[32]; for (int i = 0; i < 32; i++) r[i] = 32 + i;
    uint8_t na[32]; for (int i = 0; i < 32; i++) na[i] = 0xAA;

    // Updated to match 10 arguments
    uint32_t val = sas_compute(pkv, 6, pka, 8, nv, 32, r, 32, na, 32);
    char sas[7]; snprintf(sas, sizeof sas, "%06u", val % 1000000u);
    printf("SAS vector for test: %s\n", sas);
}

static void test_setup_req_validation(void) {
    SetupReq sr = {{1}, 8080};
    assert(msg_setup_req_valid(&sr));
    sr.port = 65535; assert(msg_setup_req_valid(&sr));
    sr.port = 0; assert(!msg_setup_req_valid(&sr));
    sr.port = 65536; assert(!msg_setup_req_valid(&sr));
    sr.port = 0xFFFFFFFFu; assert(!msg_setup_req_valid(&sr));
    SetupReq nil = {{0}, 8080};
    assert(!msg_setup_req_valid(&nil));

    assert(msg_uuid_str_valid("00112233-4455-6677-8899-aabbccddeeff"));
    assert(!msg_uuid_str_valid("../../etc/passwd"));
    assert(!msg_uuid_str_valid("00112233-4455-6677-8899-aabbccddeeffa"));
    assert(!msg_uuid_str_valid("00112233-4455-6677-8899-aabbccddeefg"));
    assert(!msg_uuid_str_valid("0011223344556677-8899-aabbccddeeff00"));
    assert(!msg_uuid_str_valid(NULL));
}

int main(void) {
    test_message_vectors();
    test_sas_vector();
    printf("ALL COMMS TESTS PASSED\n");
    test_setup_req_validation();
    return 0;
}
