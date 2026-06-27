#include <stdio.h>
#include <string.h>

#include "communication/frame.h"

static int check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        return 0;
    }
    return 1;
}

int main(void) {
    const uint8_t payload[] = {0x10, 0x20, 0x30, 0x40};
    uint8_t encoded[FRAME_HEADER_LEN + sizeof(payload)];
    Message message = {
        .type = MSG_COMMIT,
        .seq = 0x01020304,
        .payload = payload,
        .payload_len = (uint32_t) sizeof(payload),
    };

    ssize_t encoded_len = frame_encode(message, encoded, sizeof(encoded));
    if (!check(encoded_len == (ssize_t) sizeof(encoded), "encode length")) return 1;
    if (!check(encoded[0] == FRAME_MAGIC0 && encoded[1] == FRAME_MAGIC1, "magic bytes")) return 1;
    if (!check(encoded[2] == FRAME_VERSION, "version byte")) return 1;
    if (!check(encoded[3] == MSG_COMMIT, "message type byte")) return 1;

    Message decoded = {0};
    int decode_result = frame_decode(encoded, (size_t) encoded_len, &decoded, sizeof(payload));
    if (!check(decode_result == 0, "decode result")) return 1;
    if (!check(decoded.type == MSG_COMMIT, "decoded type")) return 1;
    if (!check(decoded.seq == 0x01020304, "decoded sequence")) return 1;
    if (!check(decoded.payload_len == sizeof(payload), "decoded payload length")) return 1;
    if (!check(memcmp(decoded.payload, payload, sizeof(payload)) == 0, "decoded payload bytes")) return 1;
    if (!check(decoded.payload == encoded + FRAME_HEADER_LEN, "decoded payload view")) return 1;

    uint8_t bad_frame[sizeof(encoded)];
    memcpy(bad_frame, encoded, sizeof(bad_frame));
    bad_frame[0] = 0x00;
    if (!check(frame_decode(bad_frame, sizeof(bad_frame), &decoded, sizeof(payload)) == INVALID_MAGIC_BITS,
               "invalid magic check")) return 1;

    puts("frame codec test passed");
    return 0;
}
