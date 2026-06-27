//
// Created by archiea on 26/06/2026.
//

#ifndef SPARK_CHANNEL_CODEC_H
#define SPARK_CHANNEL_CODEC_H

#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>

#define FRAME_HEADER_LEN 12
#define FRAME_MAGIC0 0x53  // 'S'
#define FRAME_MAGIC1 0x50  // 'P'
#define FRAME_VERSION 0x01


typedef enum {
    MSG_SETUP_REQ=0x01,
    MSG_COMMIT=0x02,
    MSG_REVEAL=0x03,
    MSG_SAS_CONFIRM=0x04,
    MSG_CHALLENGE=0x05,
    MSG_RESPONSE=0x06,
    MSG_PING=0x07,
    MSG_ABORT=0x08,
} MsgType;

typedef enum {
    FRAME_TOO_SMALL=-1,
    INVALID_MAGIC_BITS=-2,
    VERSION_MISMATCH=-3,
    OUT_TOO_SMALL=-4,
    PAYLOAD_TOO_BIG=-5
} DecodeErrors;

typedef struct {
    MsgType type;
    uint32_t seq;
    const uint8_t *payload;
    uint32_t payload_len;
} Message;

ssize_t frame_encode(Message message, uint8_t *out, size_t out_cap);
int frame_decode(const uint8_t *in, size_t in_len, Message *out, size_t payload_cap);

#endif //SPARK_CHANNEL_CODEC_H
