#include "pairing.h"
#include "channel.h"
#include "messages.h"
#include "sas.h"
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define PAIRING_BUF_MAX 4096

static void sha256_concat(const uint8_t *a, size_t al, const uint8_t *b, size_t bl, uint8_t out[32]) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, a, al);
    EVP_DigestUpdate(c, b, bl);
    unsigned int l = 0;
    EVP_DigestFinal_ex(c, out, &l);
    EVP_MD_CTX_free(c);
}

int pairing_verifier_run(VerifierPairing *v, int timeout_ms) {
    uint8_t pbuf[PAIRING_BUF_MAX];
    uint8_t out[PAIRING_BUF_MAX];
    Message m;
    ssize_t n;

    // 1. SETUP_REQ <- A
    if (channel_recv(&m, pbuf, sizeof pbuf, timeout_ms) != 0) return -1;
    if (m.type != MSG_SETUP_REQ) return -2;
    SetupReq sr;
    if (msg_parse_setup_req(m.payload, m.payload_len, &sr) < 0) return -3;
    if (sr.pk_a_len > sizeof v->pk_a) return -4;
    memcpy(v->pk_a, sr.pk_a, sr.pk_a_len);
    v->pk_a_len = sr.pk_a_len;
    memcpy(v->device_id, sr.device_id, sizeof v->device_id);
    v->port = sr.port;

    // 2. commit to a fresh nonce
    uint8_t N[MSG_NONCE_LEN], r[MSG_R_LEN], c[MSG_COMMIT_HASH_LEN];
    if (RAND_bytes(N, sizeof N) != 1 || RAND_bytes(r, sizeof r) != 1) return -5;
    sha256_concat(N, sizeof N, r, sizeof r, c);

    n = msg_encode_commit(v->pk_v, v->pk_v_len, c, out, sizeof out);
    if (n < 0 || !channel_send(MSG_COMMIT, out, (uint32_t)n)) return -6;

    // 3. reveal
    n = msg_encode_reveal(N, r, out, sizeof out);
    if (n < 0 || !channel_send(MSG_REVEAL, out, (uint32_t)n)) return -7;

    // 4. SAS + local human confirm
    sas_compute(N, sizeof N, v->pk_v, v->pk_v_len, v->pk_a, v->pk_a_len, v->sas);
    int accept = v->confirm ? v->confirm(v->sas, v->confirm_ctx) : 1;

    n = msg_encode_sas_confirm(accept, out, sizeof out);
    channel_send(MSG_SAS_CONFIRM, out, (uint32_t)n);
    if (!accept) return -8;

    // 5. peer's SAS_CONFIRM
    do {
        if (channel_recv(&m, pbuf, sizeof pbuf, timeout_ms) != 0) return -9;
    } while (m.type == MSG_PING);

    if (m.type == MSG_ABORT) return -10;
    if (m.type != MSG_SAS_CONFIRM) return -11;
    if (msg_parse_sas_confirm(m.payload, m.payload_len) != 1) return -12;

    return 0;
}
