#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <log_manager.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <cJSON.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "communication/websocket/websocket_service.h"
#include "config_manager.h"
#include "cryptography/key_manager.h"

static const char *TAG = "setup_server";
static volatile int setup_done = 0;
static int setup_result = -1;

static void finish(int rc, const char *msg) {
    if (rc != 0 && msg) custom_log(LOG_ERR, TAG, "Setup error: %s", msg);
    setup_result = rc;
    setup_done = 1;
}

static void compute_sas(const char *nonce, const char *pc_pub, const char *phone_pub, char *out) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned char d[EVP_MAX_MD_SIZE];
    unsigned int d_len;

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    uint32_t len;
    const char *inputs[] = {nonce, pc_pub, phone_pub};
    for(int i=0; i<3; i++) {
        len = htonl((uint32_t)strlen(inputs[i]));
        EVP_DigestUpdate(mdctx, &len, 4);
        EVP_DigestUpdate(mdctx, inputs[i], strlen(inputs[i]));
    }

    EVP_DigestFinal_ex(mdctx, d, &d_len);
    EVP_MD_CTX_free(mdctx);

    uint32_t val = ((uint32_t)d[0] << 24 | (uint32_t)d[1] << 16 | (uint32_t)d[2] << 8 | (uint32_t)d[3]) & 0x7FFFFFFF;
    sprintf(out, "%06u", val % 1000000u);
}

static int discover_bt_mac(const char *uuid_str, char *out_mac) {
    custom_log(LOG_INFO, TAG, "Starting Bluetooth MAC discovery for UUID: %s", uuid_str);
    int dev_id = hci_get_route(NULL);
    int sock = hci_open_dev(dev_id);
    if (sock < 0) {
        custom_log(LOG_ERR, TAG, "Could not open HCI device");
        return -1;
    }

    inquiry_info *ii = NULL;
    custom_log(LOG_INFO, TAG, "Performing HCI inquiry...");
    int n = hci_inquiry(dev_id, 8, 32, NULL, &ii, IREQ_CACHE_FLUSH);
    if (n < 0) {
        custom_log(LOG_ERR, TAG, "HCI inquiry failed");
        close(sock);
        return -1;
    }

    custom_log(LOG_INFO, TAG, "Found %d discoverable devices. Checking services...", n);
    int found = -1;
    for (int i = 0; i < n; i++) {
        char addr_str[19];
        ba2str(&ii[i].bdaddr, addr_str);

        sdp_session_t *s = sdp_connect(BDADDR_ANY, &ii[i].bdaddr, SDP_RETRY_IF_BUSY);
        if (!s) {
            custom_log(LOG_INFO, TAG, "  [%s] SDP connect failed", addr_str);
            continue;
        }

        uint8_t u[16];
        unsigned int b[16];
        if (sscanf(uuid_str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7], &b[8], &b[9], &b[10], &b[11], &b[12], &b[13], &b[14], &b[15]) == 16) {
            for(int j=0; j<16; j++) u[j] = (uint8_t)b[j];
            uuid_t svc; sdp_uuid128_create(&svc, u);
            sdp_list_t *search = sdp_list_append(NULL, &svc);

            uint32_t range = 0x0000ffff;
            sdp_list_t *attrid = sdp_list_append(NULL, &range);
            sdp_list_t *resp = NULL;

            if (sdp_service_search_attr_req(s, search, SDP_ATTR_REQ_RANGE, attrid, &resp) == 0 && resp) {
                custom_log(LOG_INFO, TAG, "  [%s] Match found!", addr_str);
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
    free(ii); close(sock);
    if (found != 0) custom_log(LOG_WARNING, TAG, "Could not find device with the specified UUID");
    return found;
}

static int get_pc_public_key(char *out, size_t sz) {
    const char *priv = "/etc/AuthApp/pki/pc.key", *pub = "/etc/AuthApp/pki/pc.pub";
    if (access(priv, F_OK) != 0) {
        mkdir("/etc/AuthApp", 0755); mkdir("/etc/AuthApp/pki", 0700);
        if (!key_manager_generate_rsa_keypair(priv, pub)) return 0;
    }
    FILE *f = fopen(pub, "rb");
    if (!f) return 0;
    size_t n = fread(out, 1, sz - 1, f);
    out[n] = '\0'; fclose(f);
    return n > 0;
}

static void *setup_worker(void *arg) {
    websocket_connect();
    char rx[8192], nonce[33], sas[7], pc_pub[4096], phone_pub[4096], id[256];
    int port, i;

    for (i = 0; i < 600 && !websocket_has_client(); i++) usleep(100000);
    if (!websocket_has_client()) { finish(-1, "Connection timeout"); return NULL; }

    if (!websocket_receive(rx, sizeof(rx))) { finish(-1, "Receive failed"); return NULL; }
    cJSON *req = cJSON_Parse(rx);
    if (!req) { finish(-1, "Invalid request"); return NULL; }

    strncpy(id, cJSON_GetObjectItem(req, "device_id")->valuestring, 255);
    strncpy(phone_pub, cJSON_GetObjectItem(req, "public_key")->valuestring, 4095);
    port = cJSON_GetObjectItem(req, "port")->valueint;
    cJSON_Delete(req);

    if (!get_pc_public_key(pc_pub, sizeof(pc_pub))) { finish(-1, "Key error"); return NULL; }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "pc_public_key");
    cJSON_AddStringToObject(resp, "pc_public_key", pc_pub);
    char *js = cJSON_PrintUnformatted(resp); websocket_send(js); free(js); cJSON_Delete(resp);

    unsigned char n_raw[16]; RAND_bytes(n_raw, 16);
    for(i=0; i<16; i++) sprintf(&nonce[i*2], "%02x", n_raw[i]);
    resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "nonce_challenge");
    cJSON_AddStringToObject(resp, "server_nonce", nonce);
    js = cJSON_PrintUnformatted(resp); websocket_send(js); free(js); cJSON_Delete(resp);

    if (!websocket_receive(rx, sizeof(rx))) { finish(-1, "Nonce timeout"); return NULL; }

    compute_sas(nonce, pc_pub, phone_pub, sas);
    printf("\nPairing Code: %s\n", sas);

    const char *env = getenv("AUTHAPP_SAS_APPROVE");
    if (!(env && (strcasecmp(env, "Y") == 0 || strcmp(env, "1") == 0))) {
        printf("Confirm match? (y/n): "); fflush(stdout);
        int choice = getchar();
        if (choice != 'y' && choice != 'Y') { finish(-1, "User rejected"); return NULL; }
    }

    config_manager_write_device(id, port);

    // Save phone public key
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "/etc/AuthApp/pki/%s.pub", id);
    FILE *kf = fopen(key_path, "wb");
    if (kf) { fputs(phone_pub, kf); fclose(kf); }

    char m[19]; if (discover_bt_mac(id, m) == 0) config_manager_set_device_mac(m);

    websocket_send("{\"status\":\"ok\"}");
    finish(0, NULL);
    return NULL;
}

int setup_server_start_for_user(const char *user) {
    pthread_t tid;
    setup_done = 0;
    cache_setup(user, 5555);
    return pthread_create(&tid, NULL, setup_worker, NULL);
}

int setup_server_is_done() { return setup_done; }
int setup_server_result() { return setup_result; }
