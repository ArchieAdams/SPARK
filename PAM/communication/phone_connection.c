#include "phone_connection.h"
#include <log_manager.h>
#include "connection_manager.h"
#include "channel.h"
#include "message_manager.h"
#include "../cryptography/cryptographic_methods.h"
#include "../cryptography/key_manager.h"
#include "../config_manager.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syslog.h>
#include <pthread.h>

#define AUTH_RESPONSE_TIMEOUT_SEC 60
#define AUTH_RESPONSE_POLL_MS 100

static const char* TAG = "phone_connection";

static void init_outcome(PhoneAuthOutcome *outcome) {
    if (!outcome) return;
    outcome->result = PHONE_AUTH_INVALID_ARGUMENT;
    outcome->transport = CONN_NONE;
}

static int phone_connect(const char *device_uuid) {
    if (connection_manager_start_dual(device_uuid)) {
        const ConnectionType active = connection_manager_get_active();
        custom_log(LOG_INFO, TAG, "Phone connected via: %s",
               active == CONN_BLUETOOTH ? "Bluetooth" : "WebSocket");
        return 1;
    } else {
        custom_log(LOG_INFO, TAG, "Failed to connect to phone");
        return 0;
    }
}

static void *phone_disconnect_thread(void *arg) {
    (void)arg;
    connection_manager_disconnect();
    auth_verifier_cleanup();
    return NULL;
}

static void phone_disconnect(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, phone_disconnect_thread, NULL) != 0) {
        phone_disconnect_thread(NULL);
        return;
    }
    pthread_detach(tid);
}

PhoneAuthResult phone_authenticate(const char *device_uuid, PhoneAuthOutcome *outcome) {
    init_outcome(outcome);
    custom_log(LOG_INFO, TAG, "Cleaning up previous auth state");
    auth_verifier_cleanup();

    custom_log(LOG_INFO, TAG, "Attempting to connect to device...");
    if (!phone_connect(device_uuid)) {
        if (outcome) outcome->result = PHONE_AUTH_CONNECT_FAILED;
        return PHONE_AUTH_CONNECT_FAILED;
    }

    if (outcome) outcome->transport = connection_manager_get_active();

    // 1. V -> A : eph_V
    uint8_t ephV[32];
    custom_log(LOG_INFO, TAG, "Initiating Mutual Auth Step 1");
    if (!auth_verifier_step1(ephV)) {
        custom_log(LOG_ERR, TAG, "Step 1 failed locally");
        phone_disconnect();
        return PHONE_AUTH_CHALLENGE_SEND_FAILED;
    }
    custom_log(LOG_INFO, TAG, "Sending ephV to phone");
    if (!channel_send(MSG_AUTH_EPH_V, ephV, 32)) {
        custom_log(LOG_ERR, TAG, "Failed to send ephV");
        phone_disconnect();
        return PHONE_AUTH_CHALLENGE_SEND_FAILED;
    }

    // 2. A -> V : eph_A
    uint8_t *pbuf = malloc(4096);
    if (!pbuf) {
        phone_disconnect();
        return PHONE_AUTH_RESPONSE_FAILED;
    }
    Message m;
    uint8_t ephA[32];
    time_t deadline = time(NULL) + AUTH_RESPONSE_TIMEOUT_SEC;
    int step2_ok = 0;
    custom_log(LOG_INFO, TAG, "Waiting for ephA from phone...");
    while (time(NULL) < deadline) {
        if (channel_recv(&m, pbuf, 4096, AUTH_RESPONSE_POLL_MS) == 0) {
            if (m.type == MSG_AUTH_EPH_A && m.payload_len == 32) {
                custom_log(LOG_INFO, TAG, "Received ephA from phone");
                memcpy(ephA, m.payload, 32);
                step2_ok = 1;
                break;
            }
            if (m.type == MSG_ABORT) {
                custom_log(LOG_ERR, TAG, "Phone aborted pairing/auth");
                break;
            }
        }
    }
    if (!step2_ok) {
        custom_log(LOG_ERR, TAG, "Failed to receive ephA from phone (timeout or error)");
        free(pbuf);
        phone_disconnect();
        return PHONE_AUTH_RESPONSE_FAILED;
    }

    // 3. V -> A : aead_K( sign_skV( "req" || eph_V || eph_A || pk_V || pk_A ) )
    uint8_t *c3 = malloc(2048);
    if (!c3) { free(pbuf); phone_disconnect(); return PHONE_AUTH_RESPONSE_FAILED; }
    size_t c3_len = 2048;
    custom_log(LOG_INFO, TAG, "Performing Auth Step 3 (Signing & Encrypting Request)");
    if (!auth_verifier_step3(ephA, c3, &c3_len)) {
        custom_log(LOG_ERR, TAG, "Step 3 failed locally");
        free(pbuf); free(c3);
        phone_disconnect();
        return PHONE_AUTH_CHALLENGE_SEND_FAILED;
    }
    custom_log(LOG_INFO, TAG, "Sending C3 to phone");
    if (!channel_send(MSG_AUTH_STEP3, c3, (uint32_t)c3_len)) {
        custom_log(LOG_ERR, TAG, "Failed to send C3");
        free(pbuf); free(c3);
        phone_disconnect();
        return PHONE_AUTH_CHALLENGE_SEND_FAILED;
    }
    free(c3);

    // 4. A -> V : aead_K( sign_skA( "resp" || eph_V || eph_A || pk_A || pk_V ) )
    int step4_ok = 0;
    deadline = time(NULL) + AUTH_RESPONSE_TIMEOUT_SEC;
    custom_log(LOG_INFO, TAG, "Waiting for Step 4 response from phone (User Approval)...");
    while (time(NULL) < deadline) {
        if (channel_recv(&m, pbuf, 4096, AUTH_RESPONSE_POLL_MS) == 0) {
            if (m.type == MSG_AUTH_STEP4) {
                custom_log(LOG_INFO, TAG, "Received C4 response from phone, verifying...");
                if (auth_verifier_step5(m.payload, m.payload_len)) {
                    step4_ok = 1;
                } else {
                    custom_log(LOG_ERR, TAG, "Step 5 verification failed");
                }
                break;
            }
            if (m.type == MSG_ABORT) {
                custom_log(LOG_ERR, TAG, "Phone sent ABORT in step 4");
                break;
            }
        }
    }

    free(pbuf);
    if (!step4_ok) {
        custom_log(LOG_ERR, TAG, "Authentication sequence failed or rejected by user");
        phone_disconnect();
        if (outcome) outcome->result = PHONE_AUTH_RESPONSE_FAILED;
        return PHONE_AUTH_RESPONSE_FAILED;
    }

    custom_log(LOG_INFO, TAG, "Authentication complete and verified.");
    if (outcome) {
        memcpy(outcome->response, "SUCCESS", 7);
        outcome->response_len = 7;
        outcome->result = PHONE_AUTH_OK;
    }

    phone_disconnect();
    return PHONE_AUTH_OK;
}
