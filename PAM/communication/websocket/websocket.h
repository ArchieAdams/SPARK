#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <libwebsockets.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct ws_client {
    struct lws *wsi;
};

typedef struct ws_client ws_client_t;

int ws_init(int port);
void ws_poll(int timeout_ms);
int ws_send(const char *msg);
int ws_receive(char *buf, size_t buf_size);
int ws_send_bytes(const uint8_t *data, size_t len);
int ws_receive_bytes(uint8_t *buf, size_t buf_size);
void ws_shutdown(void);
bool ws_is_client_connected(void);

#endif