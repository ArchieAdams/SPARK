#include "pairing_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <log_manager.h>

#include "communication/websocket/websocket_service.h"
#include "communication/pairing.h"
#include "config_manager.h"
#include "cryptography/key_manager.h"

static const char *TAG = "pairing_server";

#define PKI_DIR  "/etc/AuthApp/pki"
#define PC_PRIV  PKI_DIR "/pc.key"
#define PC_PUB   PKI_DIR "/pc.pub"

static int load_or_gen_pkv_der(uint8_t **der_out, int *der_len) {
    if (access(PC_PRIV, F_OK) != 0) {
        mkdir("/etc/AuthApp", 0755);
        mkdir(PKI_DIR, 0700);
        if (!key_manager_generate_rsa_keypair(PC_PRIV, PC_PUB)) return -1;
    }
    EVP_PKEY *k = NULL;
    key_manager_load_public_key(PC_PUB, &k);
    if (!k) return -1;

    int len = i2d_PUBKEY(k, NULL);
    if (len <= 0) { key_manager_free_key(k); return -1; }
    uint8_t *buf = malloc(len);
    if (!buf) { key_manager_free_key(k); return -1; }
    uint8_t *p = buf;
    i2d_PUBKEY(k, &p);
    key_manager_free_key(k);
    *der_out = buf;
    *der_len = len;
    return 0;
}

static void uuid16_to_str(const uint8_t id[16], char out[37]) {
    snprintf(out, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7],
             id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]);
}

static int store_phone_pubkey(const char *uuid_str, const uint8_t *der, uint32_t len) {
    const uint8_t *p = der;
    EVP_PKEY *k = d2i_PUBKEY(NULL, &p, (long)len);
    if (!k) return -1;
    char path[512];
    snprintf(path, sizeof path, PKI_DIR "/%s.pub", uuid_str);
    FILE *f = fopen(path, "wb");
    if (!f) { EVP_PKEY_free(k); return -1; }
    int ok = PEM_write_PUBKEY(f, k);
    fclose(f);
    EVP_PKEY_free(k);
    return ok ? 0 : -1;
}

static int terminal_confirm(const char *sas, void *ctx) {
    (void)ctx;
    printf("\nPairing Code: %s\n", sas);
    const char *env = getenv("AUTHAPP_SAS_APPROVE");
    if (env && (strcasecmp(env, "Y") == 0 || strcmp(env, "1") == 0)) return 1;
    printf("Confirm match? (y/n): ");
    fflush(stdout);
    int ch = getchar();
    return (ch == 'y' || ch == 'Y') ? 1 : 0;
}

// Inquiry + SDP scan to find the phone's BT MAC by its advertised service UUID.
static int discover_bt_mac(const char *uuid_str, char *out_mac) {
    int dev_id = hci_get_route(NULL);
    int sock = hci_open_dev(dev_id);
    if (sock < 0) return -1;

    inquiry_info *ii = NULL;
    int n = hci_inquiry(dev_id, 8, 32, NULL, &ii, IREQ_CACHE_FLUSH);
    if (n < 0) { close(sock); return -1; }

    int found = -1;
    for (int i = 0; i < n; i++) {
        char addr_str[19];
        ba2str(&ii[i].bdaddr, addr_str);

        sdp_session_t *s = sdp_connect(BDADDR_ANY, &ii[i].bdaddr, SDP_RETRY_IF_BUSY);
        if (!s) continue;

        uint8_t u[16];
        unsigned int b[16];
        if (sscanf(uuid_str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7],
                   &b[8], &b[9], &b[10], &b[11], &b[12], &b[13], &b[14], &b[15]) == 16) {
            for (int j = 0; j < 16; j++) u[j] = (uint8_t)b[j];
            uuid_t svc; sdp_uuid128_create(&svc, u);
            sdp_list_t *search = sdp_list_append(NULL, &svc);
            uint32_t range = 0x0000ffff;
            sdp_list_t *attrid = sdp_list_append(NULL, &range);
            sdp_list_t *resp = NULL;

            if (sdp_service_search_attr_req(s, search, SDP_ATTR_REQ_RANGE, attrid, &resp) == 0 && resp) {
                strcpy(out_mac, addr_str);
                found = 0;
                sdp_list_free(resp, (sdp_free_func_t)sdp_record_free);
            }
            sdp_list_free(search, NULL);
            sdp_list_free(attrid, NULL);
        }
        sdp_close(s);
        if (found == 0) break;
    }
    free(ii);
    close(sock);
    return found;
}

int pairing_server_run(const char *username) {
    cache_setup(username, 5555);

    uint8_t *pkv = NULL;
    int pkv_len = 0;
    if (load_or_gen_pkv_der(&pkv, &pkv_len) != 0) {
        custom_log(LOG_ERR, TAG, "Failed to load/generate verifier key");
        return -1;
    }

    websocket_connect();

    int i;
    for (i = 0; i < 600 && !websocket_has_client(); i++) usleep(100000);
    if (!websocket_has_client()) {
        custom_log(LOG_ERR, TAG, "Pairing timed out waiting for phone");
        free(pkv);
        websocket_disconnect();
        return -1;
    }

    VerifierPairing v;
    memset(&v, 0, sizeof v);
    v.pk_v = pkv;
    v.pk_v_len = (uint32_t)pkv_len;
    v.confirm = terminal_confirm;

    int rc = pairing_verifier_run(&v, CONFIG_AUTH_TIMEOUT_MS);

    if (rc == 0) {
        char uuid_str[37];
        uuid16_to_str(v.device_id, uuid_str);
        config_manager_write_device(uuid_str, (int)v.port);
        if (store_phone_pubkey(uuid_str, v.pk_a, v.pk_a_len) != 0) {
            custom_log(LOG_ERR, TAG, "Failed to store phone public key");
            rc = -1;
        } else {
            custom_log(LOG_INFO, TAG, "Paired device %s on port %u", uuid_str, v.port);
            char mac[19];
            if (discover_bt_mac(uuid_str, mac) == 0) {
                config_manager_set_device_mac(mac);
                custom_log(LOG_INFO, TAG, "Discovered phone BT MAC: %s", mac);
            } else {
                custom_log(LOG_WARNING, TAG, "Could not discover phone BT MAC (Bluetooth auth may be unavailable)");
            }
        }
    } else {
        custom_log(LOG_ERR, TAG, "Pairing failed (rc=%d)", rc);
    }

    free(pkv);
    websocket_disconnect();
    return rc;
}
