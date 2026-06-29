#ifndef WEBSOCEKT_SERVICE_H
#define WEBSOCEKT_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void *websocket_connect();
void websocket_disconnect();
void websocket_stop_advertising();
bool websocket_send(const char *msg);
bool websocket_receive(char *buf, size_t buf_size);
bool websocket_send_bytes(const uint8_t *data, size_t len);
int  websocket_receive_bytes(uint8_t *buf, size_t buf_size);
bool websocket_service_is_running();
bool websocket_has_client();

#endif //WEBSOCEKT_SERVICE_H
