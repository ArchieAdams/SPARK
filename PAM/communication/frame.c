#include <stddef.h>
#include <sys/types.h>

#include "frame.h"

static void put_u32_be(uint8_t *dst, uint32_t value) {
    dst[0] = (uint8_t) (value >> 24);
    dst[1] = (uint8_t) (value >> 16);
    dst[2] = (uint8_t) (value >> 8);
    dst[3] = (uint8_t) value;
}

static uint32_t get_u32_be(const uint8_t *src) {
    return ((uint32_t) src[0] << 24) |
           ((uint32_t) src[1] << 16) |
           ((uint32_t) src[2] << 8) |
           (uint32_t) src[3];
}

ssize_t frame_encode(Message message, uint8_t *out, size_t out_cap) {
    size_t payload_len = (size_t) message.payload_len;
    size_t frame_length = FRAME_HEADER_LEN + payload_len;

    if (out_cap < frame_length) return -1;

    out[0] = FRAME_MAGIC0;
    out[1] = FRAME_MAGIC1;
    out[2] = FRAME_VERSION;
    out[3] = (uint8_t) message.type;
    put_u32_be(out + 4, message.seq);
    put_u32_be(out + 8, message.payload_len);

    for (size_t i = 0; i < payload_len; i++) {
        out[FRAME_HEADER_LEN + i] = message.payload[i];
    }

    return (ssize_t) frame_length;
}

int frame_decode(const uint8_t *in, size_t in_len, Message *out, size_t payload_cap) {
    if (in_len < FRAME_HEADER_LEN) return FRAME_TOO_SMALL;
    if (in[0] != FRAME_MAGIC0 || in[1] != FRAME_MAGIC1) return INVALID_MAGIC_BITS;
    if (in[2] != FRAME_VERSION) return VERSION_MISMATCH;

    size_t payload_len = (size_t) get_u32_be(in + 8);
    if (payload_len > in_len - FRAME_HEADER_LEN) return OUT_TOO_SMALL;
    if (payload_len > payload_cap) return PAYLOAD_TOO_BIG;

    out->type = (MsgType) in[3];
    out->seq = get_u32_be(in + 4);
    out->payload_len = (uint32_t) payload_len;
    out->payload = in + FRAME_HEADER_LEN;
    return 0;
}