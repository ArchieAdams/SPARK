#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include <stdbool.h>
#include <stdlib.h>

typedef enum {
    CONN_NONE,
    CONN_BLUETOOTH,
    CONN_WEBSOCKET
} ConnectionType;


bool connection_manager_start_dual(const char *uuid);
ConnectionType connection_manager_get_active();
bool connection_manager_send(const char *msg);
bool connection_manager_receive(char *buf, size_t buf_size);
void connection_manager_disconnect();


#endif // CONNECTION_MANAGER_H


