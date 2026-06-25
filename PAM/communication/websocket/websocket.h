#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <libwebsockets.h>
#include <stdbool.h>

struct ws_client {
    struct lws *wsi;
};

typedef struct ws_client ws_client_t;

int ws_init(int port);
void ws_poll(int timeout_ms);
int ws_send(const char *msg);
int ws_receive(char *buf, size_t buf_size);
void ws_shutdown(void);
bool ws_is_client_connected(void);

#endif