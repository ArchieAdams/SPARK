#ifndef SPARK_MESSAGES_H
#define SPARK_MESSAGES_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define MSG_DEVICE_ID_LEN 16
#define MSG_NONCE_LEN     32
#define MSG_R_LEN         32
#define MSG_COMMIT_HASH_LEN 32

typedef enum {
    ABORT_USER_REJECTED = 0,
    ABORT_COMMITMENT_MISMATCH = 1,
    ABORT_TIMEOUT = 2,
    ABORT_PROTOCOL_ERROR = 3,
    ABORT_UNKNOWN = -1
} AbortReason;

// Parsed views alias into the input buffer (no copy / no malloc).
typedef struct {
    uint8_t device_id[MSG_DEVICE_ID_LEN];
    uint32_t port;
    const uint8_t *pk_a;
    uint32_t pk_a_len;
} SetupReq;

typedef struct {
    const uint8_t *pk_v;
    uint32_t pk_v_len;
    uint8_t c[MSG_COMMIT_HASH_LEN];
} Commit;

typedef struct {
    uint8_t n[MSG_NONCE_LEN];
    uint8_t r[MSG_R_LEN];
} Reveal;

// encode_* return payload length written, or -1 if out_cap too small.
// parse_*  return 0 on success, -1 on malformed/underrun input.

ssize_t msg_encode_setup_req(const uint8_t device_id[MSG_DEVICE_ID_LEN], uint32_t port,
                             const uint8_t *pk_a, uint32_t pk_a_len,
                             uint8_t *out, size_t out_cap);
int msg_parse_setup_req(const uint8_t *p, size_t len, SetupReq *out);

ssize_t msg_encode_commit(const uint8_t *pk_v, uint32_t pk_v_len,
                          const uint8_t c[MSG_COMMIT_HASH_LEN],
                          uint8_t *out, size_t out_cap);
int msg_parse_commit(const uint8_t *p, size_t len, Commit *out);

ssize_t msg_encode_reveal(const uint8_t n[MSG_NONCE_LEN], const uint8_t r[MSG_R_LEN],
                          uint8_t *out, size_t out_cap);
int msg_parse_reveal(const uint8_t *p, size_t len, Reveal *out);

ssize_t msg_encode_sas_confirm(int accept, uint8_t *out, size_t out_cap);
int msg_parse_sas_confirm(const uint8_t *p, size_t len);   // 1 accept, 0 reject, -1 err

ssize_t msg_encode_abort(AbortReason reason, uint8_t *out, size_t out_cap);
AbortReason msg_parse_abort(const uint8_t *p, size_t len);

#endif
