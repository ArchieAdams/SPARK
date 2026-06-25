#include "bt_client.h"
#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>

#define BT_SERVICE_POLL_MS 50
static bool bt_running = false;
static pthread_t bt_service_thread;
static bool thread_created = false;

void bluetooth_service_start() {
    printf("[BT_CONNECT] Starting Bluetooth service\n");
    bluetooth_clear_stop_request();

    if (!bluetooth_connect()) {
        printf("[BT_CONNECT] Failed to connect to Bluetooth device\n");
        bt_running = false;
        return;
    }

    if (!bluetooth_is_connected()) {
        printf("[BT_CONNECT] Socket not connected after connect\n");
        bt_running = false;
        bluetooth_disconnect();
        return;
    }

    bt_running = true;
    thread_created = false;
    printf("[BT_CONNECT] Bluetooth service is running\n");
}

void bluetooth_service_stop() {
    // Stop the Bluetooth service loop
    printf("[BT_DISCONNECT] Stopping Bluetooth service\n");
    bt_running = false;
    bluetooth_request_stop();

    // Cancellation-safe: only join if thread was successfully created
    if (thread_created) {
        pthread_join(bt_service_thread, NULL);
        thread_created = false;
    }

    // Disconnect from Bluetooth device
    bluetooth_disconnect();
    printf("[BT_DISCONNECT] Bluetooth service disconnected\n");
}

bool bluetooth_service_is_running() {
    return bt_running;
}

bool bluetooth_service_is_connected() {
    return bt_running && bluetooth_is_connected();
}
