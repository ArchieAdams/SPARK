#include "messages.h"
#include "sas.h"
#include "frame.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>

extern void mock_set_side(int);

static int eq_hex(const uint8_t *b, ssize_t n, const char *want) {
    char got[1024]; for (ssize_t i = 0; i < n; i++) sprintf(got + i * 2, "%02x", b[i]);
    return strcmp(got, want) == 0;
}

static void test_message_vectors(void) {
    uint8_t out[256];
    uint8_t id[16] = {0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t pka[8] = {1,2,3,4,5,6,7,8};
    ssize_t n = msg_encode_setup_req(id, 8080, pka, 8, out, sizeof out);
    assert(eq_hex(out, n, "00112233445566778899aabbccddeeff00001f90000000080102030405060708"));

    uint8_t pkv[6] = {0x10,0x11,0x12,0x13,0x14,0x15};
    uint8_t c[32]; for (int i = 0; i < 32; i++) c[i] = i;
    n = msg_encode_commit(pkv, 6, c, out, sizeof out);
    assert(eq_hex(out, n, "00000006101112131415000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));

    uint8_t N[32], R[32]; for (int i = 0; i < 32; i++) { N[i] = i; R[i] = 32 + i; }
    n = msg_encode_reveal(N, R, out, sizeof out);
    assert(eq_hex(out, n, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"));
    printf("message vectors OK\n");
}

static void test_sas_vector(void) {
    uint8_t n[32]; for (int i = 0; i < 32; i++) n[i] = i;
    uint8_t pkv[6] = {0x10,0x11,0x12,0x13,0x14,0x15};
    uint8_t pka[8] = {1,2,3,4,5,6,7,8};
    char sas[7]; sas_compute(n, 32, pkv, 6, pka, 8, sas);
    assert(strcmp(sas, "366812") == 0);   // matches Kotlin Messages.sas
    printf("SAS vector OK (366812)\n");
}


int main(void) {
    test_message_vectors();
    test_sas_vector();
    printf("ALL COMMS TESTS PASSED\n");
    return 0;
}
