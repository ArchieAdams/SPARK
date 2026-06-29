#include "phone_connection.h"

#include <log_manager.h>

#include "connection_manager.h"
#include "channel.h"
#include "message_manager.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syslog.h>

#include "time_utils.h"

#define AUTH_RESPONSE_TIMEOUT_SEC 30
#define AUTH_RESPONSE_POLL_MS 100

char*TAG = "phone_connection";

static unsigned char last_expected_response[CHALLENGE_RESPONSE_SIZE];
static size_t last_expected_response_len = 0;
static int has_pending_challenge = 0;

static void clear_pending_challenge(void) {
    memset(last_expected_response, 0, sizeof(last_expected_response));
    last_expected_response_len = 0;
    has_pending_challenge = 0;
}

static void init_outcome(PhoneAuthOutcome *outcome) {
    if (!outcome) {
        return;
    }
    outcome->result = PHONE_AUTH_INVALID_ARGUMENT;
    outcome->transport = CONN_NONE;
}

static int phone_connect(const char *device_uuid) {
    if (connection_manager_start_dual("authenticator-uuid")) {
        const ConnectionType active = connection_manager_get_active(device_uuid);
        custom_log(LOG_INFO,TAG,"Phone connected via: %s\n",
               active == CONN_BLUETOOTH ? "Bluetooth" : "WebSocket");
        return 1;
    } else {
        custom_log(LOG_INFO,TAG,"Failed to connect to phone\n");
        return 0;
    }
}

static void phone_disconnect() {
    connection_manager_disconnect();
    clear_pending_challenge();
}


static int phone_send_auth_challenge() {
    custom_log(LOG_INFO,TAG,"[PHONE] Generating authentication challenge...\n");

    // Generate signed and encrypted challenge message
    unsigned char challenge_message[2048];
    size_t challenge_len = sizeof(challenge_message);
    unsigned char expected_response[CHALLENGE_RESPONSE_SIZE];
    size_t expected_response_len = CHALLENGE_RESPONSE_SIZE;

    if (!generate_signed_and_encrypted_message(
            challenge_message,
            &challenge_len,
            expected_response,
            &expected_response_len
            )) {
        custom_log(LOG_ERR,TAG," Failed to generate challenge message\n");
        return 0;
    }
    memcpy(last_expected_response, expected_response, expected_response_len);
    last_expected_response_len = CHALLENGE_RESPONSE_SIZE;
    has_pending_challenge = 1;

    custom_log(LOG_INFO,TAG,"[PHONE] Challenge generated (%zu bytes), sending...\n", challenge_len);

    if (!channel_send(MSG_CHALLENGE, challenge_message, (uint32_t)challenge_len)) {
        custom_log(LOG_ERR,TAG," Failed to send challenge message\n");
        clear_pending_challenge();
        return 0;
    }

    custom_log(LOG_INFO,TAG,"[PHONE] Authentication challenge sent successfully\n");
    return 1;
}


static int phone_receive_verified_response(unsigned char *response, size_t *response_len) {
    if (!response || !response_len || *response_len == 0) {
        custom_log(LOG_ERR,TAG," Invalid response buffer for verified receive\n");
        return 0;
    }

    if (!has_pending_challenge || last_expected_response_len != CHALLENGE_RESPONSE_SIZE) {
        custom_log(LOG_ERR,TAG," No pending challenge available for response validation\n");
        return 0;
    }

    time_t deadline = time(NULL) + AUTH_RESPONSE_TIMEOUT_SEC;
    uint8_t pbuf[8192];
    Message m;
    while (time(NULL) < deadline) {
        int rc = channel_recv(&m, pbuf, sizeof(pbuf), AUTH_RESPONSE_POLL_MS);
        if (rc != 0) continue;
        if (m.type == MSG_PING) continue;
        if (m.type != MSG_RESPONSE) continue;

        custom_log(LOG_INFO,TAG,"[PHONE] Received device response (%u bytes), verifying...\n", m.payload_len);

        if (!process_signed_and_encrypted_response_bytes(m.payload, m.payload_len, response, response_len)) {
            custom_log(LOG_ERR,TAG," Device response failed verification\n");
            return 0;
        }

        if (!validate_challenge_response(
                last_expected_response,
                last_expected_response_len,
                response,
                *response_len)) {
            custom_log(LOG_ERR,TAG," Device response failed challenge validation\n");
            return 0;
        }

        clear_pending_challenge();
        custom_log(LOG_INFO,TAG,"[PHONE] Device response verified successfully\n");
        return 1;
    }

    custom_log(LOG_ERR,TAG," Timed out waiting for device response\n");
    return 0;
}

PhoneAuthResult phone_authenticate(const char *device_uuid, PhoneAuthOutcome *outcome) {
    init_outcome(outcome);

    clear_pending_challenge();
    custom_log(LOG_INFO,TAG," Attempting to connect to device...\n");
    if (!phone_connect(device_uuid)) {
        custom_log(LOG_ERR,TAG," Failed to establish connection via either method\n");
        if (outcome) {
            outcome->result = PHONE_AUTH_CONNECT_FAILED;
        }
        return PHONE_AUTH_CONNECT_FAILED;
    }

    ConnectionType transport = connection_manager_get_active();
    if (outcome) {
        outcome->transport = transport;
    }
    custom_log(LOG_INFO,TAG," Connected to device via: %s\n",
            transport == CONN_BLUETOOTH ? "Bluetooth" : "WebSocket");
    if (!phone_send_auth_challenge()) {
        custom_log(LOG_ERR,TAG," Authentication challenge send failed\n");
        connection_manager_disconnect();
        clear_pending_challenge();
        if (outcome) {
            outcome->result = PHONE_AUTH_CHALLENGE_SEND_FAILED;
        }
        return PHONE_AUTH_CHALLENGE_SEND_FAILED;
    }
    custom_log(LOG_INFO,TAG," Authentication challenge sent, waiting for response...\n");
    unsigned char verified_response[2048];
    size_t verified_response_len = sizeof(verified_response);
    if (!phone_receive_verified_response(verified_response, &verified_response_len)) {
        custom_log(LOG_ERR,TAG," Authentication response verification failed\n");
        connection_manager_disconnect();
        clear_pending_challenge();
        if (outcome) {
            outcome->result = PHONE_AUTH_RESPONSE_FAILED;
        }
        return PHONE_AUTH_RESPONSE_FAILED;
    }
    if (outcome) {
        memcpy(outcome->response, verified_response, verified_response_len);
        outcome->response_len = verified_response_len;
        outcome->result = PHONE_AUTH_OK;
    }

    phone_disconnect();
    return PHONE_AUTH_OK;
}

