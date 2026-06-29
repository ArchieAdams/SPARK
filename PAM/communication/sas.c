#include "sas.h"
#include <openssl/evp.h>
#include <stdio.h>

static void upd_lp(EVP_MD_CTX *c, const uint8_t *b, size_t n) {
    uint8_t len[4] = { (uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n };
    EVP_DigestUpdate(c, len, 4);
    EVP_DigestUpdate(c, b, n);
}

void sas_compute(const uint8_t *n, size_t nlen,
                 const uint8_t *pkv, size_t pkvlen,
                 const uint8_t *pka, size_t pkalen,
                 char out[7]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    upd_lp(ctx, n, nlen);
    upd_lp(ctx, pkv, pkvlen);
    upd_lp(ctx, pka, pkalen);
    unsigned char h[32];
    unsigned int hl = 0;
    EVP_DigestFinal_ex(ctx, h, &hl);
    EVP_MD_CTX_free(ctx);

    uint32_t code = (((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) |
                     ((uint32_t)h[2] << 8) | (uint32_t)h[3]) & 0x7FFFFFFFu;
    snprintf(out, 7, "%06u", code % 1000000u);
}
