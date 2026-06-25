#include "connection_manager.h"
#include <log_manager.h>
#include "bluetooth/bluetooth_service.h"
#include "bluetooth/bt_client.h"
#include "websocket/websocket_service.h"
#include "../config_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include <syslog.h>
#include "time_utils.h"

static const char* TAG = "connection_manager";
static ConnectionType active_connection = CONN_NONE;
static pthread_mutex_t connection_lock = PTHREAD_MUTEX_INITIALIZER;
static bool is_connecting = false;

static void stop_inactive_transports(ConnectionType winner) {
    if (winner == CONN_WEBSOCKET) {
        bluetooth_service_stop();
    } else if (winner == CONN_BLUETOOTH) {
        websocket_disconnect();
    }
}

static void *attempt_bt(void *arg) {
    bluetooth_service_start();
    if (bluetooth_service_is_connected()) {
        pthread_mutex_lock(&connection_lock);
        if (active_connection == CONN_NONE && is_connecting) {
            active_connection = CONN_BLUETOOTH;
            is_connecting = false;
            custom_log(LOG_INFO, TAG, "Bluetooth established");
        }
        pthread_mutex_unlock(&connection_lock);
        stop_inactive_transports(active_connection);
    }
    return NULL;
}

static void *attempt_ws(void *arg) {
    websocket_connect();
    int waited = 0;
    while (waited < CONFIG_AUTH_TIMEOUT_MS) {
        pthread_mutex_lock(&connection_lock);
        bool still_trying = is_connecting;
        ConnectionType current = active_connection;
        pthread_mutex_unlock(&connection_lock);

        if (current == CONN_BLUETOOTH || !still_trying) break;

        if (websocket_has_client() && websocket_service_is_running()) {
            pthread_mutex_lock(&connection_lock);
            if (active_connection == CONN_NONE && is_connecting) {
                active_connection = CONN_WEBSOCKET;
                is_connecting = false;
                custom_log(LOG_INFO, TAG, "WebSocket established");
            }
            pthread_mutex_unlock(&connection_lock);
            stop_inactive_transports(active_connection);
            return NULL;
        }
        sleep_ms(100);
        waited += 100;
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

    pthread_t bt_thread, ws_thread;
    pthread_create(&bt_thread, NULL, attempt_bt, NULL);
    pthread_create(&ws_thread, NULL, attempt_ws, (void *)uuid);

    int waited = 0;
    while (waited < CONFIG_AUTH_TIMEOUT_MS) {
        pthread_mutex_lock(&connection_lock);
        ConnectionType current = active_connection;
        pthread_mutex_unlock(&connection_lock);

        if (current != CONN_NONE) return true;
        sleep_ms(100);
        waited += 100;
    }

    pthread_mutex_lock(&connection_lock);
    is_connecting = false;
    pthread_mutex_unlock(&connection_lock);

    bluetooth_service_stop();
    websocket_disconnect();
    return false;
}

ConnectionType connection_manager_get_active() {
    pthread_mutex_lock(&connection_lock);
    ConnectionType conn = active_connection;
    pthread_mutex_unlock(&connection_lock);
    return conn;
}

bool connection_manager_send(const char *msg) {
    ConnectionType conn = connection_manager_get_active();
    if (conn == CONN_BLUETOOTH) return bluetooth_send(msg);
    if (conn == CONN_WEBSOCKET) return websocket_send(msg);
    return false;
}

bool connection_manager_receive(char *buf, size_t buf_size) {
    ConnectionType conn = connection_manager_get_active();
    if (conn == CONN_BLUETOOTH) return bluetooth_receive(buf, buf_size);
    if (conn == CONN_WEBSOCKET) return websocket_receive(buf, buf_size);
    return false;
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
