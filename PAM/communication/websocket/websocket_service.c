#include <log_manager.h>

#include "udp_broadcast.h"
#include "websocket.h"
#include "../../config_manager.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/syslog.h>

#include "time_utils.h"

#define WS_SERVER_PORT 8080

static const char* TAG = "websocket_service";

static pthread_t *advertising_thread_ptr = NULL;
static bool ws_running = false;
static pthread_t ws_service_thread;
static bool ws_thread_created = false;
static unsigned int ws_session_id = 0; // Session tracking for idempotency
static unsigned int ws_active_session = 0; // Active session ID guard
static pthread_mutex_t ws_session_lock = PTHREAD_MUTEX_INITIALIZER;

static void stop_advertising_if_running(void) {
    if (advertising_thread_ptr) {
        stop_advertising(*advertising_thread_ptr);
        advertising_thread_ptr = NULL;
    }
}

void websocket_disconnect() {
    // Stop the WebSocket service loop
    printf("[WS_DISCONNECT] Stopping WebSocket service\n");
    ws_running = false;

    if (ws_thread_created) {
        pthread_join(ws_service_thread, NULL);
        ws_thread_created = false;
    }

    // Stop advertising
    stop_advertising_if_running();

    // Shutdown WebSocket server
    ws_shutdown();

    pthread_mutex_lock(&ws_session_lock);
    ws_active_session = 0;
    pthread_mutex_unlock(&ws_session_lock);

    printf("[WS_DISCONNECT] WebSocket service disconnected\n");
}


static void start_websocket_service() {
    // Start WebSocket server first
    if (ws_init(WS_SERVER_PORT) < 0) {
        printf("Failed to start WebSocket server on port %d\n", WS_SERVER_PORT);
        return;
    }

    printf("WebSocket server started on port %d\n", WS_SERVER_PORT);
}

static void *ws_service_loop() {
    printf("WebSocket service loop started\n");
    while (ws_running) {
        ws_poll(50); // lws_service blocks up to 50ms
    }
    printf("WebSocket service loop ended\n");
    return NULL;
}

void *websocket_connect() {
    pthread_mutex_lock(&ws_session_lock);
    // Generate new session ID for this connection attempt
    ws_session_id++;
    unsigned int new_session = ws_session_id;
    pthread_mutex_unlock(&ws_session_lock);

    custom_log(LOG_INFO, TAG, " Starting new WebSocket session #%u\n", new_session);

    if (ws_running) {
        custom_log(LOG_INFO, TAG, " Previous session still active, tearing down old session...\n");
        websocket_disconnect();
    }

    // Start advertising
    advertising_thread_ptr = start_advertising();

    // Start WebSocket server
    start_websocket_service();
    custom_log(LOG_INFO, TAG, " UDP broadcast sent, waiting for phone to connect...\n");

    // Start WebSocket service loop in a separate thread
    ws_running = true;
    ws_thread_created = false;

    pthread_mutex_lock(&ws_session_lock);
    ws_active_session = new_session;
    pthread_mutex_unlock(&ws_session_lock);

    if (pthread_create(&ws_service_thread, NULL, ws_service_loop, NULL) != 0) {
        custom_log(LOG_INFO, TAG, " Failed to create WebSocket service thread\n");
        ws_running = false;

        pthread_mutex_lock(&ws_session_lock);
        ws_active_session = 0;
        pthread_mutex_unlock(&ws_session_lock);

        stop_advertising_if_running();
        return NULL;
    }
    ws_thread_created = true;

    custom_log(LOG_INFO, TAG, " WebSocket service is running (session #%u)\n", new_session);
    return NULL;
}


void websocket_stop_advertising() {
    stop_advertising_if_running();
}

bool websocket_send(const char *msg) {
    if (!ws_running) {
        printf("WebSocket service is not running, cannot send message\n");
        return false;
    }
    if (ws_send(msg) < 0) {
        printf("Failed to send message over WebSocket\n");
        return false;
    }
    // Don't print entire message if it's too large
    size_t msg_len = strlen(msg);
    if (msg_len > 200) {
        printf("WebSocket send: [%zu bytes] %.100s...\n", msg_len, msg);
    } else {
        printf("WebSocket send: %s\n", msg);
    }
    return true;
}

bool websocket_receive(char *buf, size_t buf_size) {
    if (!buf || buf_size == 0) {
        printf("Invalid buffer for websocket_receive\n");
        return false;
    }

    if (!ws_running) {
        printf("WebSocket service is not running, cannot receive message\n");
        return false;
    }

    fprintf(stderr, "[WS_SERVICE] Calling ws_receive...\n");
    fflush(stderr);

    int received = ws_receive(buf, buf_size);

    fprintf(stderr, "[WS_SERVICE] ws_receive returned: %d\n", received);
    fflush(stderr);

    if (received <= 0) {
        return false; // No message available or error
    }

    // Don't print entire message if it's too large
    if ((size_t) received > 200) {
        printf("WebSocket received: [%d bytes] %.100s...\n", received, buf);
    } else {
        printf("WebSocket received: %s\n", buf);
    }
    fflush(stdout);
    return true;
}

bool websocket_send_bytes(const uint8_t *data, size_t len) {
    if (!ws_running) return false;
    return ws_send_bytes(data, len) >= 0;
}

int websocket_receive_bytes(uint8_t *buf, size_t buf_size) {
    if (!ws_running) return -1;
    return ws_receive_bytes(buf, buf_size);
}

bool websocket_service_is_running() {
    return ws_running;
}

bool websocket_has_client() {
    if (!ws_running) {
        return false;
    }
    bool connected = ws_is_client_connected();
    if (connected) {
        stop_advertising_if_running();
    }
    return connected;
}
