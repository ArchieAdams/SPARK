#include "messages.h"
#include <string.h>

static void put_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static uint32_t get_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

typedef struct { const uint8_t *buf; size_t len; size_t pos; } Reader;

static int rd_bytes(Reader *r, size_t n, const uint8_t **out) {
    if (n > r->len - r->pos) return -1;
    *out = r->buf + r->pos;
    r->pos += n;
    return 0;
}
static int rd_u32(Reader *r, uint32_t *out) {
    const uint8_t *p;
    if (rd_bytes(r, 4, &p) < 0) return -1;
    *out = get_u32_be(p);
    return 0;
}

// ---- SETUP_REQ: deviceId[16] ‖ port[4] ‖ len(pkA) ‖ pkA ----

ssize_t msg_encode_setup_req(const uint8_t device_id[MSG_DEVICE_ID_LEN], uint32_t port,
                             const uint8_t *pk_a, uint32_t pk_a_len,
                             uint8_t *out, size_t out_cap) {
    size_t need = MSG_DEVICE_ID_LEN + 4 + 4 + pk_a_len;
    if (out_cap < need) return -1;
    size_t o = 0;
    memcpy(out + o, device_id, MSG_DEVICE_ID_LEN); o += MSG_DEVICE_ID_LEN;
    put_u32_be(out + o, port); o += 4;
    put_u32_be(out + o, pk_a_len); o += 4;
    memcpy(out + o, pk_a, pk_a_len); o += pk_a_len;
    return (ssize_t)o;
}

int msg_parse_setup_req(const uint8_t *p, size_t len, SetupReq *out) {
    Reader r = { p, len, 0 };
    const uint8_t *id;
    if (rd_bytes(&r, MSG_DEVICE_ID_LEN, &id) < 0) return -1;
    memcpy(out->device_id, id, MSG_DEVICE_ID_LEN);
    if (rd_u32(&r, &out->port) < 0) return -1;
    if (rd_u32(&r, &out->pk_a_len) < 0) return -1;
    if (rd_bytes(&r, out->pk_a_len, &out->pk_a) < 0) return -1;
    return 0;
}

// ---- COMMIT: len(pkV) ‖ pkV ‖ c[32] ----

ssize_t msg_encode_commit(const uint8_t *pk_v, uint32_t pk_v_len,
                          const uint8_t c[MSG_COMMIT_HASH_LEN],
                          uint8_t *out, size_t out_cap) {
    size_t need = 4 + pk_v_len + MSG_COMMIT_HASH_LEN;
    if (out_cap < need) return -1;
    size_t o = 0;
    put_u32_be(out + o, pk_v_len); o += 4;
    memcpy(out + o, pk_v, pk_v_len); o += pk_v_len;
    memcpy(out + o, c, MSG_COMMIT_HASH_LEN); o += MSG_COMMIT_HASH_LEN;
    return (ssize_t)o;
}

int msg_parse_commit(const uint8_t *p, size_t len, Commit *out) {
    Reader r = { p, len, 0 };
    if (rd_u32(&r, &out->pk_v_len) < 0) return -1;
    if (rd_bytes(&r, out->pk_v_len, &out->pk_v) < 0) return -1;
    const uint8_t *c;
    if (rd_bytes(&r, MSG_COMMIT_HASH_LEN, &c) < 0) return -1;
    memcpy(out->c, c, MSG_COMMIT_HASH_LEN);
    return 0;
}

// ---- REVEAL: N[32] ‖ r[32] ----

ssize_t msg_encode_reveal(const uint8_t n[MSG_NONCE_LEN], const uint8_t r[MSG_R_LEN],
                          uint8_t *out, size_t out_cap) {
    if (out_cap < MSG_NONCE_LEN + MSG_R_LEN) return -1;
    memcpy(out, n, MSG_NONCE_LEN);
    memcpy(out + MSG_NONCE_LEN, r, MSG_R_LEN);
    return MSG_NONCE_LEN + MSG_R_LEN;
}

int msg_parse_reveal(const uint8_t *p, size_t len, Reveal *out) {
    Reader r = { p, len, 0 };
    const uint8_t *n, *rr;
    if (rd_bytes(&r, MSG_NONCE_LEN, &n) < 0) return -1;
    if (rd_bytes(&r, MSG_R_LEN, &rr) < 0) return -1;
    memcpy(out->n, n, MSG_NONCE_LEN);
    memcpy(out->r, rr, MSG_R_LEN);
    return 0;
}

// ---- SAS_CONFIRM / ABORT: single byte ----

ssize_t msg_encode_sas_confirm(int accept, uint8_t *out, size_t out_cap) {
    if (out_cap < 1) return -1;
    out[0] = accept ? 1 : 0;
    return 1;
}
int msg_parse_sas_confirm(const uint8_t *p, size_t len) {
    if (len < 1) return -1;
    return p[0] == 1 ? 1 : 0;
}

ssize_t msg_encode_abort(AbortReason reason, uint8_t *out, size_t out_cap) {
    if (out_cap < 1) return -1;
    out[0] = (uint8_t)reason;
    return 1;
}
AbortReason msg_parse_abort(const uint8_t *p, size_t len) {
    if (len < 1) return ABORT_UNKNOWN;
    switch (p[0]) {
        case 0: return ABORT_USER_REJECTED;
        case 1: return ABORT_COMMITMENT_MISMATCH;
        case 2: return ABORT_TIMEOUT;
        case 3: return ABORT_PROTOCOL_ERROR;
        default: return ABORT_UNKNOWN;
    }
}
