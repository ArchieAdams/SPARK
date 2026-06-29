#include "transport.h"
#include "websocket/websocket_service.h"
#include "connection_manager.h"

// Route to whichever is active.
bool transport_send(const uint8_t *data, size_t len) {
    if (connection_manager_get_active() != CONN_NONE)
        return connection_manager_send_bytes(data, len);
    return websocket_send_bytes(data, len);
}

int transport_recv(uint8_t *buf, size_t cap) {
    if (connection_manager_get_active() != CONN_NONE)
        return connection_manager_receive_bytes(buf, cap);
    return websocket_receive_bytes(buf, cap);
}
