#ifndef SPARK_PAIRING_H
#define SPARK_PAIRING_H

#include <stdint.h>
#include <stddef.h>


typedef struct {
    const uint8_t *pk_v;
    uint32_t pk_v_len;
    int (*confirm)(const char *sas, void *ctx);
    void *confirm_ctx;

    uint8_t pk_a[1024];
    uint32_t pk_a_len;
    uint8_t device_id[16];
    uint32_t port;
    char sas[7];
} VerifierPairing;

int pairing_verifier_run(VerifierPairing *v, int timeout_ms);

#endif
