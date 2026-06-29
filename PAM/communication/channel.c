#include "channel.h"
#include "transport.h"
#include <string.h>
#include <unistd.h>

#define CHANNEL_FRAME_MAX 4096

static uint32_t seq_ctr = 0;

bool channel_send(MsgType type, const uint8_t *payload, uint32_t len) {
    uint8_t frame[CHANNEL_FRAME_MAX];
    Message m = { .type = type, .seq = seq_ctr++, .payload = payload, .payload_len = len };
    ssize_t n = frame_encode(m, frame, sizeof frame);
    if (n < 0) return false;
    return transport_send(frame, (size_t)n);
}

int channel_recv(Message *out, uint8_t *pbuf, size_t cap, int timeout_ms) {
    uint8_t frame[CHANNEL_FRAME_MAX];
    int waited = 0;
    for (;;) {
        int n = transport_recv(frame, sizeof frame);
        if (n > 0) {
            Message d;
            int rc = frame_decode(frame, (size_t)n, &d, cap);
            if (rc != 0) return rc;
            if (d.type == MSG_PING) continue;
            memcpy(pbuf, d.payload, d.payload_len);
            d.payload = pbuf;
            *out = d;
            return 0;
        }
        if (waited >= timeout_ms) return 1;
        usleep(2000);
        waited += 2;
    }
}
