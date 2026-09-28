#include "channel.h"
#include "transport.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define CHANNEL_FRAME_MAX 4096

static uint32_t seq_ctr = 0;

bool channel_send(MsgType type, const uint8_t *payload, uint32_t len) {
    uint8_t *frame = malloc(CHANNEL_FRAME_MAX);
    if (!frame) return false;

    Message m = { .type = type, .seq = seq_ctr++, .payload = payload, .payload_len = len };
    ssize_t n = frame_encode(m, frame, CHANNEL_FRAME_MAX);
    if (n < 0) {
        free(frame);
        return false;
    }
    bool ok = transport_send(frame, (size_t)n);
    free(frame);
    return ok;
}

int channel_recv(Message *out, uint8_t *pbuf, size_t cap, int timeout_ms) {
    uint8_t *frame = malloc(CHANNEL_FRAME_MAX);
    if (!frame) return -1;

    int waited = 0;
    int result = 1; // timeout

    for (;;) {
        int n = transport_recv(frame, CHANNEL_FRAME_MAX);
        if (n > 0) {
            Message d;
            int rc = frame_decode(frame, (size_t)n, &d, cap);
            if (rc != 0) {
                result = rc;
                break;
            }
            if (d.type == MSG_PING) continue;

            if (d.payload_len <= cap) {
                memcpy(pbuf, d.payload, d.payload_len);
                d.payload = pbuf;
                *out = d;
                result = 0;
            } else {
                result = -5; // PAYLOAD_TOO_BIG
            }
            break;
        }
        if (waited >= timeout_ms) {
            result = 1;
            break;
        }
        usleep(2000);
        waited += 2;
    }
    free(frame);
    return result;
}
