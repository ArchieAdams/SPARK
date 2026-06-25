#ifndef WEBSOCEKT_SERVICE_H
#define WEBSOCEKT_SERVICE_H

#include <stdbool.h>
#include <stddef.h>

void *websocket_connect();
void websocket_disconnect();
void websocket_stop_advertising();
bool websocket_send(const char *msg);
bool websocket_receive(char *buf, size_t buf_size);
bool websocket_service_is_running();
bool websocket_has_client();

#endif //WEBSOCEKT_SERVICE_H
