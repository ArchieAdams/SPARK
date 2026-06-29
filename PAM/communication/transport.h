#ifndef SPARK_TRANSPORT_H
#define SPARK_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool transport_send(const uint8_t *data, size_t len);
int  transport_recv(uint8_t *buf, size_t cap);

#endif
