#ifndef BT_CLIENT_H
#define BT_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool bluetooth_connect();
bool bluetooth_send(const char *msg);
bool bluetooth_receive(char *buf, size_t buf_size);
bool bluetooth_send_bytes(const uint8_t *data, size_t len);
int  bluetooth_receive_bytes(uint8_t *buf, size_t buf_size);
void bluetooth_disconnect();
bool bluetooth_is_connected();
void bluetooth_request_stop();
void bluetooth_clear_stop_request();

#endif // BLUETOOTH_H
