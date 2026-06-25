#include <bluetooth/bluetooth.h>
#include "sdp_manager.h"
#include "../../config_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

/* Forward declarations */
static uint8_t *uuid_to_bytes(const char *uuid_string);

static bool is_valid_uuid_string(const char *uuid_string) {
    if (!uuid_string) return false;

    size_t hex_count = 0;
    for (size_t i = 0; uuid_string[i] != '\0'; i++) {
        unsigned char c = (unsigned char)uuid_string[i];
        if (c == '-') continue;
        if (!isxdigit(c)) return false;
        hex_count++;
    }
    return hex_count == 32;
}

sdp_session_t *create_sdp_session(const char *mac) {
    bdaddr_t target, local;

    if (!mac || str2ba(mac, &target) != 0) {
        printf("[SDP] Invalid MAC address: %s\n", mac ? mac : "(null)");
        return NULL;
    }
    bacpy(&local, BDADDR_ANY);

    sdp_session_t *session = NULL;
    for (int i = 0; i < 3; i++) {
        session = sdp_connect(&local, &target, SDP_RETRY_IF_BUSY);
        if (session) break;
        printf("[SDP] Connect attempt %d failed (%s), retrying...\n", i + 1, strerror(errno));
        sleep(2);
    }

    if (!session) {
        printf("[SDP] Discovery unavailable for %s (emrys may need to be open)\n", mac);
    }
    return session;
}

/* Parse UUID string and convert to 16-byte array. Caller must free(). */
static uint8_t *uuid_to_bytes(const char *uuid_string) {
    if (!is_valid_uuid_string(uuid_string)) return NULL;

    uint8_t *uuid_bytes = malloc(16);
    if (!uuid_bytes) return NULL;

    char uuid_clean[33];
    int j = 0;
    for (int i = 0; uuid_string[i] != '\0' && j < 32; i++) {
        if (uuid_string[i] != '-') {
            uuid_clean[j++] = uuid_string[i];
        }
    }
    uuid_clean[j] = '\0';

    if (j != 32) {
        free(uuid_bytes);
        return NULL;
    }

    for (int i = 0; i < 16; i++) {
        const char byte_str[3] = { uuid_clean[i * 2], uuid_clean[i * 2 + 1], '\0' };
        uuid_bytes[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    return uuid_bytes;
}

sdp_list_t *get_sdp_response_with_uuid(sdp_session_t *session, const char *uuid_string) {
    if (!session || !uuid_string || uuid_string[0] == '\0') return NULL;

    uint8_t *uuid_bytes = uuid_to_bytes(uuid_string);
    if (!uuid_bytes) {
        printf("[SDP] Invalid UUID string: %s\n", uuid_string);
        return NULL;
    }

    uuid_t svc_uuid;
    sdp_uuid128_create(&svc_uuid, uuid_bytes);
    free(uuid_bytes);

    uint32_t range = 0x0000ffff;
    sdp_list_t *search_list = sdp_list_append(NULL, &svc_uuid);
    sdp_list_t *attrid_list = sdp_list_append(NULL, &range);
    if (!search_list || !attrid_list) {
        sdp_list_free(search_list, NULL);
        sdp_list_free(attrid_list, NULL);
        return NULL;
    }

    sdp_list_t *response_list = NULL;
    if (sdp_service_search_attr_req(session, search_list,
                                    SDP_ATTR_REQ_RANGE, attrid_list,
                                    &response_list) < 0) {
        printf("[SDP] service_search_attr_req failed (%s)\n", strerror(errno));
        response_list = NULL;
    }

    sdp_list_free(search_list, NULL);
    sdp_list_free(attrid_list, NULL);
    return response_list;
}

/*
 * FIX: Removed the response_list free from here.
 * The caller owns response_list and must free it after this call.
 * Previously this caused a double-free / use-after-free.
 */
void extract_RFCOMM_channel(int *channel, sdp_list_t *response_list) {
    if (!channel || !response_list) return;

    for (sdp_list_t *r = response_list; r; r = r->next) {
        sdp_record_t *rec = (sdp_record_t *)r->data;
        if (!rec) continue;

        sdp_list_t *proto_list = NULL;
        if (sdp_get_access_protos(rec, &proto_list) == 0 && proto_list) {
            int port = sdp_get_proto_port(proto_list, RFCOMM_UUID);
            sdp_list_free(proto_list, NULL);

            if (port > 0) {
                printf("[SDP] Found SPP on RFCOMM channel %d\n", port);
                *channel = port;
                break;
            }
        }
    }
}

/* Helper: free an SDP response list returned by get_sdp_response_with_uuid. */
void free_sdp_response(sdp_list_t *response_list) {
    for (sdp_list_t *r = response_list; r; ) {
        sdp_list_t *next = r->next;
        if (r->data) sdp_record_free((sdp_record_t *)r->data);
        free(r);
        r = next;
    }
}
