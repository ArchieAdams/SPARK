#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include "sdp_manager.h"
#include "time_utils.h"
#include "../../config_manager.h"

#define RETRY_DELAY_SEC   1


static int sock = -1;
static atomic_bool stop_requested = false;

static void set_socket_config(int s) {
    int keepalive = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
}

static bool get_target_service_uuid(char *uuid_buf, size_t uuid_buf_size) {
    return config_manager_get_device_uuid(uuid_buf, uuid_buf_size) == 0
           && uuid_buf[0] != '\0';
}

static bool get_target_device_mac(char *mac_buf, size_t mac_buf_size) {
    return config_manager_get_device_mac(mac_buf, mac_buf_size) == 0
           && mac_buf[0] != '\0';
}

static bool resolve_channel_for_known_mac_and_uuid(const char *target_uuid, const char *mac,
                                                   bdaddr_t *out_addr, int *out_channel) {
    if (!target_uuid || !mac || !out_addr || !out_channel) return false;
    if (str2ba(mac, out_addr) != 0) return false;

    sdp_session_t *session = create_sdp_session(mac);
    if (!session) return false;

    sdp_list_t *response_list = get_sdp_response_with_uuid(session, target_uuid);
    sdp_close(session);

    int channel = -1;
    if (response_list) {
        extract_RFCOMM_channel(&channel, response_list);
        free_sdp_response(response_list);
    }

    if (channel > 0) {
        *out_channel = channel;
        printf("[BT_CLIENT] Known MAC %s matched UUID on RFCOMM channel %d\n", mac, channel);
        return true;
    }
    return false;
}

static bool connect_to_socket_by_addr(const bdaddr_t *addr, int channel, int *out_sock) {
    *out_sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
    if (*out_sock < 0) {
        perror("Failed to create RFCOMM socket");
        return false;
    }

    struct sockaddr_rc addr_rc = {0};
    addr_rc.rc_family  = AF_BLUETOOTH;
    addr_rc.rc_channel = (uint8_t)channel;
    bacpy(&addr_rc.rc_bdaddr, addr);

    char addr_str[19] = {0};
    ba2str(addr, addr_str);
    printf("[BT_CLIENT] Connecting to %s on channel %d...\n", addr_str, channel);

    if (connect(*out_sock, (struct sockaddr *)&addr_rc, sizeof(addr_rc)) == 0) {
        set_socket_config(*out_sock);
        return true;
    }

    printf("[BT_CLIENT] connect() failed for %s ch %d: %s\n",
           addr_str, channel, strerror(errno));
    close(*out_sock);
    *out_sock = -1;
    return false;
}

static bool read_message(int s, char *buf, size_t buf_size) {
    fd_set readfds;
    struct timeval tv = {1, 0};
    FD_ZERO(&readfds);
    FD_SET(s, &readfds);

    int ready = select(s + 1, &readfds, NULL, NULL, &tv);
    if (ready < 0) {
        printf("[BT_CLIENT] select error: %s\n", strerror(errno));
        return false;
    }
    if (ready == 0) {
        buf[0] = '\0';
        return true;
    }

    uint32_t msg_len_net = 0;
    ssize_t header_bytes = recv(s, &msg_len_net, 4, MSG_WAITALL);
    if (header_bytes != 4) {
        if (header_bytes == 0) {
            printf("[BT_CLIENT] Connection closed by remote\n");
        } else {
            printf("[BT_CLIENT] recv header error: %s\n", strerror(errno));
        }
        if (s == sock) {
            close(sock);
            sock = -1;
        }
        return false;
    }

    uint32_t msg_len = ntohl(msg_len_net);
    if (msg_len == 0 || msg_len >= buf_size) {
        printf("[BT_CLIENT] Invalid message length: %u\n", msg_len);
        if (s == sock) {
            close(sock);
            sock = -1;
        }
        return false;
    }

    ssize_t bytes = recv(s, buf, msg_len, MSG_WAITALL);
    if (bytes != (ssize_t)msg_len) {
        printf("[BT_CLIENT] recv data error: expected %u, got %zd\n", msg_len, bytes);
        if (s == sock) {
            close(sock);
            sock = -1;
        }
        return false;
    }

    buf[msg_len] = '\0';
    printf("[BT_CLIENT] Received: %s\n", buf);
    return true;
}

static bool write_message(int s, const char *msg) {
    size_t msg_len = strlen(msg);

    uint32_t len_net = htonl((uint32_t)msg_len);

    char *buf = malloc(4 + msg_len);
    if (!buf) {
        printf("[BT_CLIENT] malloc failed\n");
        return false;
    }

    memcpy(buf, &len_net, 4);
    memcpy(buf + 4, msg, msg_len);

    ssize_t sent = send(s, buf, 4 + msg_len, MSG_NOSIGNAL);
    free(buf);

    if (sent < 0) {
        printf("[BT_CLIENT] send failed: %s\n", strerror(errno));
        if (s == sock && (errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET || errno == EBADF)) {
            close(sock);
            sock = -1;
        }
        return false;
    }
    printf("[BT_CLIENT] Sent %zd byte(s)\n", sent);
    return true;
}

static void ensure_adapter_up(void) {
    system("hciconfig hci0 up 2>/dev/null");
}

static void wait_with_stop_check(int interval_ms) {
    int total_checks = (RETRY_DELAY_SEC * 1000) / interval_ms;
    for (int i = 0; i <  total_checks && !atomic_load(&stop_requested); i++) {
        sleep_ms(interval_ms);
    }
}

bool bluetooth_connect(void) {
    char target_uuid[256] = {0};
    char target_mac[18] = {0};

    printf("[BT_CLIENT] Bluetooth Auto-Connect (MAC-only)\n");

    if (!get_target_service_uuid(target_uuid, sizeof(target_uuid))) {
        printf("[BT_CLIENT] No device UUID in config\n");
        return false;
    }
    if (!get_target_device_mac(target_mac, sizeof(target_mac))) {
        printf("[BT_CLIENT] No device MAC in config\n");
        return false;
    }

    printf("[BT_CLIENT] Target UUID: %s\n", target_uuid);
    printf("[BT_CLIENT] Target MAC: %s\n", target_mac);

    ensure_adapter_up();   // once per connect, not per retry

    bdaddr_t target_addr = {0};
    if (str2ba(target_mac, &target_addr) != 0) {
        printf("[BT_CLIENT] Invalid MAC %s\n", target_mac);
        return false;
    }

    // Fast path: connect straight to the cached RFCOMM channel, skipping the SDP
    int cached = config_manager_get_device_channel();
    if (cached > 0 && !atomic_load(&stop_requested)) {
        if (connect_to_socket_by_addr(&target_addr, cached, &sock)) {
            printf("[BT_CLIENT] Connected via cached channel %d\n", cached);
            return true;
        }
        printf("[BT_CLIENT] Cached channel %d stale, resolving via SDP...\n", cached);
    }

    // Slow path: SDP-resolve the channel, then cache it for next time.
    while (!atomic_load(&stop_requested)) {
        int channel = -1;
        if (!resolve_channel_for_known_mac_and_uuid(target_uuid, target_mac, &target_addr, &channel)) {
            printf("[BT_CLIENT] SDP resolution failed for %s, retrying in %ds...\n", target_mac, RETRY_DELAY_SEC);
            wait_with_stop_check(100);
            continue;
        }
        if (channel <= 0) {
            continue;
        }

        if (connect_to_socket_by_addr(&target_addr, channel, &sock)) {
            config_manager_set_device_channel(channel);
            printf("[BT_CLIENT] Connected (SDP channel %d, cached)\n", channel);
            return true;
        }

        printf("[BT_CLIENT] Connection failed, retrying in %ds...\n", RETRY_DELAY_SEC);
        wait_with_stop_check(100);
    }

    printf("[BT_CLIENT] Bluetooth connection attempt cancelled\n");
    return false;
}

void bluetooth_clear_stop_request(void) {
    atomic_store(&stop_requested, false);
}

void bluetooth_request_stop(void) {
    atomic_store(&stop_requested, true);
}

void bluetooth_disconnect(void) {
    if (sock >= 0) {
        close(sock);
        sock = -1;
    }
}

bool bluetooth_is_connected(void) {
    if (sock < 0) return false;

    struct sockaddr_rc peer = {0};
    socklen_t len = sizeof(peer);
    if (getpeername(sock, (struct sockaddr *)&peer, &len) == 0) {
        return true;
    }

    if (errno == ENOTCONN || errno == EBADF) {
        close(sock);
        sock = -1;
    }
    return false;
}

bool bluetooth_send(const char *msg) {
    if (sock < 0 || !msg) return false;
    return write_message(sock, msg);
}

bool bluetooth_receive(char *buf, size_t buf_size) {
    if (sock < 0 || !buf || buf_size == 0) return false;
    return read_message(sock, buf, buf_size);
}

static bool write_message_bytes(int s, const uint8_t *data, size_t len) {
    uint32_t len_net = htonl((uint32_t)len);
    char *buf = malloc(4 + len);
    if (!buf) return false;
    memcpy(buf, &len_net, 4);
    memcpy(buf + 4, data, len);
    ssize_t sent = send(s, buf, 4 + len, MSG_NOSIGNAL);
    free(buf);
    if (sent < 0) {
        if (s == sock && (errno == ENOTCONN || errno == EPIPE || errno == ECONNRESET || errno == EBADF)) {
            close(sock); sock = -1;
        }
        return false;
    }
    return true;
}

// Returns payload length, 0 on no-data (timeout), -1 on error/closed.
static int read_message_bytes(int s, uint8_t *buf, size_t buf_size) {
    fd_set readfds;
    struct timeval tv = {1, 0};
    FD_ZERO(&readfds);
    FD_SET(s, &readfds);

    int ready = select(s + 1, &readfds, NULL, NULL, &tv);
    if (ready < 0) return -1;
    if (ready == 0) return 0;

    uint32_t msg_len_net = 0;
    if (recv(s, &msg_len_net, 4, MSG_WAITALL) != 4) {
        if (s == sock) { close(sock); sock = -1; }
        return -1;
    }
    uint32_t msg_len = ntohl(msg_len_net);
    if (msg_len == 0 || msg_len > buf_size) {
        if (s == sock) { close(sock); sock = -1; }
        return -1;
    }
    if (recv(s, buf, msg_len, MSG_WAITALL) != (ssize_t)msg_len) {
        if (s == sock) { close(sock); sock = -1; }
        return -1;
    }
    return (int)msg_len;
}

bool bluetooth_send_bytes(const uint8_t *data, size_t len) {
    if (sock < 0 || !data) return false;
    return write_message_bytes(sock, data, len);
}

int bluetooth_receive_bytes(uint8_t *buf, size_t buf_size) {
    if (sock < 0 || !buf || buf_size == 0) return -1;
    return read_message_bytes(sock, buf, buf_size);
}