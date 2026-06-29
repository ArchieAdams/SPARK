#ifndef SPARK_CHANNEL_H
#define SPARK_CHANNEL_H

#include "frame.h"
#include <stdbool.h>

bool channel_send(MsgType type, const uint8_t *payload, uint32_t len);
int  channel_recv(Message *out, uint8_t *pbuf, size_t cap, int timeout_ms);

#endif
