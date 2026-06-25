#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include "websocket.h"
#include "../../config_manager.h"

#define MAX_MESSAGES 10
#define MAX_MESSAGE_SIZE 16384

typedef struct {
    char data[MAX_MESSAGE_SIZE];
    size_t len;
} message_t;

typedef struct {
    message_t messages[MAX_MESSAGES];
    int head;
    int tail;
    int count;
    pthread_mutex_t lock;
} message_queue_t;

static char fragment_buffer[MAX_MESSAGE_SIZE] = {0};
static size_t fragment_len = 0;
static pthread_mutex_t fragment_lock = PTHREAD_MUTEX_INITIALIZER;

static struct lws_context *context = NULL;
static struct lws *connected_client = NULL;
static int connected_client_count = 0;
static pthread_mutex_t connection_lock = PTHREAD_MUTEX_INITIALIZER;
static message_queue_t msg_queue = {0};

static bool is_control_message(const char *msg, size_t len) {
    if (len == 4 && (strncmp(msg, "PING", 4) == 0 || strncmp(msg, "PONG", 4) == 0)) return true;
    if (len == 12 && strncmp(msg, "ACK_RECEIVED", 12) == 0) return true;
    return false;
}

static void connection_established(struct lws *wsi) {
    pthread_mutex_lock(&connection_lock);
    if (!connected_client) {
        connected_client = wsi;
        connected_client_count++;
        pthread_mutex_unlock(&connection_lock);

        unsigned char buf[LWS_PRE + 4];
        memcpy(&buf[LWS_PRE], "ACK", 3);
        lws_write(wsi, &buf[LWS_PRE], 3, LWS_WRITE_TEXT);
    } else {
        pthread_mutex_unlock(&connection_lock);
        unsigned char buf[LWS_PRE + 5];
        memcpy(&buf[LWS_PRE], "BUSY", 4);
        lws_write(wsi, &buf[LWS_PRE], 4, LWS_WRITE_TEXT);
        lws_set_timeout(wsi, PENDING_TIMEOUT_CLOSE_ACK, 1);
    }
}

static void message_received(struct lws *wsi, const char *msg, size_t len) {
    if (len == 4 && strncmp(msg, "PING", 4) == 0) {
        unsigned char buf[LWS_PRE + 4];
        memcpy(&buf[LWS_PRE], "PONG", 4);
        lws_write(wsi, &buf[LWS_PRE], 4, LWS_WRITE_TEXT);
        return;
    }

    if (is_control_message(msg, len)) return;

    pthread_mutex_lock(&fragment_lock);
    if (fragment_len + len < MAX_MESSAGE_SIZE) {
        memcpy(&fragment_buffer[fragment_len], msg, len);
        fragment_len += len;

        if (lws_is_final_fragment(wsi)) {
            pthread_mutex_lock(&msg_queue.lock);
            if (msg_queue.count < MAX_MESSAGES) {
                memcpy(msg_queue.messages[msg_queue.tail].data, fragment_buffer, fragment_len);
                msg_queue.messages[msg_queue.tail].len = fragment_len;
                msg_queue.tail = (msg_queue.tail + 1) % MAX_MESSAGES;
                msg_queue.count++;
            }
            pthread_mutex_unlock(&msg_queue.lock);
            fragment_len = 0;
        }
    } else {
        fragment_len = 0;
    }
    pthread_mutex_unlock(&fragment_lock);
}

static void connection_closed(struct lws *wsi) {
    pthread_mutex_lock(&connection_lock);
    if (connected_client == wsi) {
        connected_client = NULL;
        connected_client_count = 0;
    }
    pthread_mutex_unlock(&connection_lock);
}

static int callback_ws(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED: connection_established(wsi); break;
        case LWS_CALLBACK_RECEIVE:     message_received(wsi, (const char *)in, len); break;
        case LWS_CALLBACK_CLOSED:      connection_closed(wsi); break;
        default: break;
    }
    return 0;
}

static struct lws_protocols protocols[] = {
    { "authapp", callback_ws, 0, MAX_MESSAGE_SIZE },
    { NULL, NULL, 0, 0 }
};

int ws_init(int port) {
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    memset(&msg_queue, 0, sizeof(message_queue_t));
    pthread_mutex_init(&msg_queue.lock, NULL);

    info.port = port;
    info.protocols = protocols;
    info.options |= LWS_SERVER_OPTION_ALLOW_LISTEN_SHARE | LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

    // Corrected paths to match your project root
    info.ssl_cert_filepath = "/home/archiea/AndroidStudioProjects/Autenticator/PAM/certs/server.crt";
    info.ssl_private_key_filepath = "/home/archiea/AndroidStudioProjects/Autenticator/PAM/certs/server.key";

    context = lws_create_context(&info);
    return context ? 0 : -1;
}

void ws_poll(int timeout_ms) {
    if (context) lws_service(context, timeout_ms);
}

int ws_send(const char *msg) {
    pthread_mutex_lock(&connection_lock);
    struct lws *client = connected_client;
    pthread_mutex_unlock(&connection_lock);

    if (!client) return -1;
    size_t len = strlen(msg);
    unsigned char *buf = malloc(LWS_PRE + len);
    if (!buf) return -1;

    memcpy(&buf[LWS_PRE], msg, len);
    int res = lws_write(client, &buf[LWS_PRE], len, LWS_WRITE_TEXT);
    free(buf);
    return res;
}

int ws_receive(char *buf, size_t buf_size) {
    if (!buf || buf_size == 0) return -1;

    int elapsed = 0;
    while (elapsed < CONFIG_AUTH_TIMEOUT_MS) {
        pthread_mutex_lock(&msg_queue.lock);
        if (msg_queue.count > 0) {
            message_t *msg = &msg_queue.messages[msg_queue.head];
            size_t copy_len = (msg->len < buf_size) ? msg->len : buf_size - 1;
            memcpy(buf, msg->data, copy_len);
            buf[copy_len] = '\0';

            msg_queue.head = (msg_queue.head + 1) % MAX_MESSAGES;
            msg_queue.count--;
            pthread_mutex_unlock(&msg_queue.lock);
            return (int)copy_len;
        }
        pthread_mutex_unlock(&msg_queue.lock);
        usleep(10000);
        elapsed += 10;
    }
    return -1;
}

bool ws_is_client_connected(void) {
    pthread_mutex_lock(&connection_lock);
    bool res = connected_client != NULL;
    pthread_mutex_unlock(&connection_lock);
    return res;
}

void ws_shutdown(void) {
    pthread_mutex_lock(&connection_lock);
    connected_client = NULL;
    connected_client_count = 0;
    pthread_mutex_unlock(&connection_lock);
    if (context) {
        lws_context_destroy(context);
        context = NULL;
    }
}
