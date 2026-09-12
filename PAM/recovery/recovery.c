#include "recovery.h"
#include "eff_wordlist.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

// rejection sampling so the index is uniform
static int random_index(uint32_t *out) {
    const uint32_t limit = UINT32_MAX - (UINT32_MAX % EFF_WORDS_COUNT);
    for (;;) {
        uint32_t r;
        if (getrandom(&r, sizeof r, 0) != (ssize_t)sizeof r) return -1;
        if (r < limit) { *out = r % EFF_WORDS_COUNT; return 0; }
    }
}

int recovery_generate_code(char *out, size_t outlen) {
    if (!out || outlen == 0) return -1;
    out[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < RECOVERY_WORDS; i++) {
        uint32_t idx;
        if (random_index(&idx) != 0) return -1;
        int n = snprintf(out + used, outlen - used, "%s%s", i ? " " : "", EFF_WORDS[idx]);
        if (n < 0 || (size_t)n >= outlen - used) return -1;
        used += (size_t)n;
    }
    return 0;
}

// lowercase, '-' and whitespace collapse to one space (some EFF words have hyphens)
static void normalise(const char *in, char *out, size_t outlen) {
    size_t n = 0;
    int pending_space = 0;
    for (; *in && n + 1 < outlen; in++) {
        unsigned char c = (unsigned char)*in;
        if (isspace(c) || c == '-') { pending_space = n > 0; continue; }
        if (pending_space) { out[n++] = ' '; pending_space = 0; if (n + 1 >= outlen) break; }
        out[n++] = (char)tolower(c);
    }
    out[n] = '\0';
}

int recovery_hash(const char *code, char *out, size_t outlen) {
    if (!code || !out || outlen < RECOVERY_HASH_MAX) return -1;
    char norm[RECOVERY_CODE_MAX * 2];
    normalise(code, norm, sizeof norm);
    struct crypt_data *cd = calloc(1, sizeof *cd);
    if (!cd) return -1;
    int rc = -1;
    char *salt = crypt_gensalt_ra("$y$", 0, NULL, 0);
    if (salt) {
        const char *h = crypt_r(norm, salt, cd);
        if (h && h[0] == '$') { snprintf(out, outlen, "%s", h); rc = 0; }
        free(salt);
    }
    explicit_bzero(norm, sizeof norm);
    explicit_bzero(cd, sizeof *cd);
    free(cd);
    return rc;
}

static int ct_equal(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return 0;
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < la; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

int recovery_verify(const char *input, const char *hash) {
    if (!input || !hash || hash[0] != '$') return 0;
    char norm[RECOVERY_CODE_MAX * 2];
    normalise(input, norm, sizeof norm);
    if (norm[0] == '\0') return 0;
    struct crypt_data *cd = calloc(1, sizeof *cd);
    if (!cd) return 0;
    const char *h = crypt_r(norm, hash, cd);
    int ok = h && ct_equal(h, hash);
    explicit_bzero(norm, sizeof norm);
    explicit_bzero(cd, sizeof *cd);
    free(cd);
    return ok;
}
