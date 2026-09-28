#include "sas.h"
#include <openssl/evp.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static const char *const EMOJI[] = {
    "🎉", "🎱", "🤖", "👻", "🐶", "📱", "🦊", "🐼",
    "🦁", "🐸", "🐙", "🦄", "🌵", "🌳", "🍎", "🍌",
    "🍕", "🚗", "🚀", "🌈", "🧲", "🔥", "❄️", "🐷",
    "🌙", "☀️", "🎈", "🎁", "🔑", "🍄", "💎", "🎯",
};

static void upd_lp(EVP_MD_CTX *c, const uint8_t *b, size_t n) {
    uint8_t len[4] = { (uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n };
    EVP_DigestUpdate(c, len, 4);
    EVP_DigestUpdate(c, b, n);
}

uint32_t sas_compute(const uint8_t *pkv, size_t pkvlen,
                     const uint8_t *pka, size_t pkalen,
                     const uint8_t *nv, size_t nvlen,
                     const uint8_t *r, size_t rlen,
                     const uint8_t *na, size_t nalen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    // Hash order to match diagram: pkV, pkA, nV, r, nA
    upd_lp(ctx, pkv, pkvlen);
    upd_lp(ctx, pka, pkalen);
    upd_lp(ctx, nv, nvlen);
    upd_lp(ctx, r, rlen);
    upd_lp(ctx, na, nalen);

    unsigned char h[32];
    unsigned int hl = 0;
    EVP_DigestFinal_ex(ctx, h, &hl);
    EVP_MD_CTX_free(ctx);

    uint32_t code = (((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) |
                     ((uint32_t)h[2] << 8) | (uint32_t)h[3]) & 0x7FFFFFFFu;
    return code;
}

void sas_emoji(uint32_t val, char *out, size_t outlen) {
    size_t off = 0;
    for (int shift = 25; shift >= 0 && off < outlen; shift -= 5) {
        off += snprintf(out + off, outlen - off, "%s%s",
                        shift == 25 ? "" : " ", EMOJI[(val >> shift) & 0x1F]);
    }
}
