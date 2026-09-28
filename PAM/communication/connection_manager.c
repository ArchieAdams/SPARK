#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>

#include "connection_manager.h"
#include "log_manager.h"
#include "bluetooth/bluetooth_service.h"
#include "bluetooth/bt_client.h"
#include "websocket/websocket_service.h"
#include "../config_manager.h"
#include "time_utils.h"

static const char* TAG = "connection_manager";
static ConnectionType active_connection = CONN_NONE;
static pthread_mutex_t connection_lock = PTHREAD_MUTEX_INITIALIZER;
static bool is_connecting = false;
static pthread_t bt_tid, ws_tid;

static void stop_inactive_transports(ConnectionType winner) {
    if (winner == CONN_WEBSOCKET) {
        bluetooth_service_stop();
    } else if (winner == CONN_BLUETOOTH) {
        websocket_disconnect();
    }
}

static void *attempt_bt(void *arg) {
    bluetooth_service_start();
    pthread_mutex_lock(&connection_lock);
    if (is_connecting && active_connection == CONN_NONE && bluetooth_service_is_connected()) {
        active_connection = CONN_BLUETOOTH;
        is_connecting = false;
        custom_log(LOG_INFO, TAG, "Bluetooth link ready");
    }
    pthread_mutex_unlock(&connection_lock);
    return NULL;
}

static void *attempt_ws(void *arg) {
    websocket_connect();
    int waited = 0;
    while (waited < CONFIG_AUTH_TIMEOUT_MS) {
        pthread_mutex_lock(&connection_lock);
        bool stop = !is_connecting || active_connection != CONN_NONE;
        pthread_mutex_unlock(&connection_lock);

        if (stop) break;

        if (websocket_has_client() && websocket_service_is_running()) {
            pthread_mutex_lock(&connection_lock);
            if (is_connecting && active_connection == CONN_NONE) {
                active_connection = CONN_WEBSOCKET;
                is_connecting = false;
                custom_log(LOG_INFO, TAG, "WebSocket link ready");
            }
            pthread_mutex_unlock(&connection_lock);
            break;
        }
        sleep_ms(50);
        waited += 50;
    }
    return NULL;
}

bool connection_manager_start_dual(const char *uuid) {
    pthread_mutex_lock(&connection_lock);
    if (is_connecting) {
        pthread_mutex_unlock(&connection_lock);
        return false;
    }
    is_connecting = true;
    active_connection = CONN_NONE;
    pthread_mutex_unlock(&connection_lock);

    if (pthread_create(&bt_tid, NULL, attempt_bt, NULL) != 0 ||
        pthread_create(&ws_tid, NULL, attempt_ws, NULL) != 0) {
        pthread_mutex_lock(&connection_lock);
        is_connecting = false;
        pthread_mutex_unlock(&connection_lock);
        return false;
    }

    int waited = 0;
    bool success = false;
    while (waited < CONFIG_AUTH_TIMEOUT_MS) {
        pthread_mutex_lock(&connection_lock);
        if (active_connection != CONN_NONE) success = true;
        pthread_mutex_unlock(&connection_lock);

        if (success) break;
        sleep_ms(100);
        waited += 100;
    }

    pthread_mutex_lock(&connection_lock);
    if (success) {
        stop_inactive_transports(active_connection);
    } else {
        is_connecting = false;
        bluetooth_service_stop();
        websocket_disconnect();
    }
    pthread_mutex_unlock(&connection_lock);

    pthread_detach(bt_tid);
    pthread_detach(ws_tid);

    return success;
}

ConnectionType connection_manager_get_active() {
    pthread_mutex_lock(&connection_lock);
    ConnectionType conn = active_connection;
    pthread_mutex_unlock(&connection_lock);
    return conn;
}

bool connection_manager_send_bytes(const uint8_t *data, size_t len) {
    ConnectionType conn = connection_manager_get_active();
    if (conn == CONN_BLUETOOTH) return bluetooth_send_bytes(data, len);
    if (conn == CONN_WEBSOCKET) return websocket_send_bytes(data, len);
    return false;
}

int connection_manager_receive_bytes(uint8_t *buf, size_t cap) {
    ConnectionType conn = connection_manager_get_active();
    if (conn == CONN_BLUETOOTH) return bluetooth_receive_bytes(buf, cap);
    if (conn == CONN_WEBSOCKET) return websocket_receive_bytes(buf, cap);
    return -1;
}

void connection_manager_disconnect() {
    pthread_mutex_lock(&connection_lock);
    ConnectionType conn = active_connection;
    active_connection = CONN_NONE;
    is_connecting = false;
    pthread_mutex_unlock(&connection_lock);

    if (conn == CONN_BLUETOOTH) bluetooth_service_stop();
    else if (conn == CONN_WEBSOCKET) websocket_disconnect();
}
