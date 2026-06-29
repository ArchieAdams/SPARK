#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libwebsockets.h>
#include "../../config_manager.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <sys/syslog.h>

#include "log_manager.h"

static char* TAG = "udp_broadcast";
static int sock;
static pthread_t advertising_thread_id;
static atomic_bool advertising_running = false;
static atomic_bool advertising_stop = false;

static int socket_create_udp() {
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
    if (sock < 0) {
        return 1;
    }
    return 0;
}

static int send_udp_broadcast() {
    if (socket_create_udp()) {
        custom_log(LOG_ERR,TAG,"Could not create UDP socket for broadcasting: %s\n", strerror(errno));
        return -1;
    }

    // Get device port from config manager, or use default if not configured
    int port = config_manager_get_device_port();
    if (port <= 0) {
       custom_log(LOG_ERR,TAG, "UDP broadcast skipped: invalid device port from config (%d)\n", port);
        return -1;
    }
    custom_log(LOG_INFO,TAG,"Sending UDP broadcast on port %d\n", port);

    // Send broadcast
    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = INADDR_BROADCAST;

    static const char msg[] = "AUTHAPP_FIND";
    ssize_t sent = sendto(sock, msg, sizeof(msg) - 1, 0,
                          (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        custom_log(LOG_ERR, TAG, "UDP broadcast send failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

// Broadcast presence ~1/sec so the phone discovers the server fast Checks stop every 100ms.
static void *advertising_thread() {
    while (!atomic_load(&advertising_stop)) {
        send_udp_broadcast();
        for (int i = 0; i < 10 && !atomic_load(&advertising_stop); i++)
            usleep(100000);
    }
    atomic_store(&advertising_running, false);
    return NULL;
}

pthread_t *start_advertising() {
    if (atomic_load(&advertising_running)) {
        return &advertising_thread_id;
    }
    if (sock < 0) {
        sock = socket_create_udp();
        if (sock < 0) {
           custom_log(LOG_ERR,TAG, "Failed to create UDP socket\n");
            return NULL;
        }
    }
    atomic_store(&advertising_stop, false);
    atomic_store(&advertising_running, true);
    pthread_create(&advertising_thread_id, NULL, advertising_thread, NULL);
    return &advertising_thread_id;
}

void stop_advertising(pthread_t thread_id) {
    if (!atomic_load(&advertising_running) && thread_id == advertising_thread_id) {
        return;
    }
    atomic_store(&advertising_stop, true);
    pthread_join(advertising_thread_id, NULL);
    if (sock >= 0) {
        close(sock);
        sock = -1;
    }
}
