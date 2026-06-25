#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <log_manager.h>
#include <sys/syslog.h>

#include "authenticator.h"
#include "setup_server.h"
#include "config_manager.h"

static const char* TAG = "main";

int main(int argc, char *argv[]) {
    // Check for setup mode
    if (argc > 1 && strcmp(argv[1], "--setup") == 0) {
        if (argc < 3 || argv[2][0] == '\0') {
            custom_log(LOG_ERR, TAG, "Usage: %s --setup <username>\n", argv[0]);
            return 1;
        }

        const char *setup_username = argv[2];
        custom_log(LOG_INFO, TAG, "Starting setup server for user '%s' (WebSocket: 8080, UDP: 5555)\n", setup_username);

        if (setup_server_start_for_user(setup_username) != 0) {
            custom_log(LOG_ERR, TAG, "Failed to start setup server\n");
            return 1;
        }

        custom_log(LOG_INFO, TAG, "Setup server running. Waiting for device pairing...\n");
        custom_log(LOG_INFO, TAG, "Device will send: device_id, public_key, and device listening port\n");
        custom_log(LOG_INFO, TAG, "Open the mobile emrys and start pairing now.\n");

        int waited = 0;
        while (!setup_server_is_done()) {
            sleep(1);
            waited++;
            if (waited % 10 == 0) {
                custom_log(LOG_INFO, TAG, "Still waiting for pairing... (%ds)\n", waited);
            }
            if (waited >= 300) {
                custom_log(LOG_ERR, TAG, "Setup timed out waiting for completion.\n");
                return 1;
            }
        }

        if (setup_server_result() == 0) {
            custom_log(LOG_INFO, TAG, "Setup completed successfully.\n");
        } else {
            custom_log(LOG_ERR, TAG, "Setup failed.\n");
        }
        return setup_server_result() == 0 ? 0 : 1;
    }

    const char *username = (argc > 1) ? argv[1] : "archiea";

    if (config_manager_init() != 0) {
        custom_log(LOG_ERR,TAG, "Failed to initialize config manager\n");
        return 1;
    }

    cache_username(username);
    if (load_config() != 0) {
        custom_log(LOG_ERR,TAG, "Failed to load config for user %s\n", username);
        return 1;
    }

    AuthDetails details = {0};

    const AuthResult result = authenticator_authenticate(&details);
    if (result != AUTH_SUCCESS) {
        custom_log(LOG_ERR,TAG, "Authentication failed: %s\n", authenticator_result_to_string(result));
        return 1;
    }

    if (details.response_len == 0 || details.response_len > sizeof(details.response)) {
        custom_log(LOG_ERR,TAG, "Authentication failed: invalid response length (%zu)\n", details.response_len);
        return 1;
    }

    // Authentication successful
    custom_log(LOG_INFO,TAG,"Authentication succeeded\n");
    custom_log(LOG_INFO,TAG,"Response (%zu bytes): ", details.response_len);
    for (size_t i = 0; i < details.response_len; i++) {
        custom_log(LOG_INFO,TAG,"%02x", details.response[i]);
    }
    custom_log(LOG_INFO,TAG,"\n");

    // Try to print as text if printable
    int printable = 1;
    for (size_t i = 0; i < details.response_len; i++) {
        unsigned char c = (unsigned char)details.response[i];
        if (!isprint(c) && !isspace(c)) {
            printable = 0;
            break;
        }
    }
    if (printable) {
        custom_log(LOG_INFO,TAG,"Response (text): %.*s\n", (int)details.response_len, details.response);
    }

    return 0;
}