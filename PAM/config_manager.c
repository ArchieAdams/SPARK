#include "config_manager.h"
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syslog.h>

#include "log_manager.h"
#include "tpm_counter.h"

#define CONFIG_DIR "/etc/AuthApp"

static char *TAG = "config_manager";

typedef struct {
    char username[256];
    char uuid[256];
    long port;
    char mac[18];
    int channel;
    uint64_t counter;
} ConfigData;

static char cached_uuid[256] = {0};
static int cached_port = -2;
static char cached_username[256] = {0};
static char cached_mac[18] = {0};
static int cached_channel = -1;
static uint64_t cached_counter = 0;

static int copy_value(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0 || !src) return -1;
    size_t len = strlen(src);
    if (len >= dst_size) return -1;
    memcpy(dst, src, len + 1);
    return 0;
}

static int build_user_config_path(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0 || cached_username[0] == '\0') return -1;
    int written = snprintf(buffer, buffer_size, "%s/%s.conf", CONFIG_DIR, cached_username);
    return (written > 0 && (size_t) written < buffer_size) ? 0 : -1;
}

static int open_config_file(const char *mode, FILE **out_file) {
    char path[512];
    if (!mode || !out_file) return -1;
    if (build_user_config_path(path, sizeof(path)) != 0) return -1;
    FILE *f = fopen(path, mode);
    if (!f) return -1;
    *out_file = f;
    return 0;
}

static int load_config_from_file(FILE *f, ConfigData *cfg) {
    char line[1024];
    if (!f || !cfg) return -1;
    memset(cfg, 0, sizeof(*cfg));
    cfg->port = -1;
    cfg->channel = -1;

    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *key = line;
        char *value = eq + 1;
        value[strcspn(value, "\r\n")] = '\0';

        if (strcmp(key, "device_username") == 0) copy_value(cfg->username, sizeof(cfg->username), value);
        else if (strcmp(key, "device_uuid") == 0) copy_value(cfg->uuid, sizeof(cfg->uuid), value);
        else if (strcmp(key, "device_port") == 0) cfg->port = strtol(value, NULL, 10);
        else if (strcmp(key, "device_mac") == 0) copy_value(cfg->mac, sizeof(cfg->mac), value);
        else if (strcmp(key, "device_channel") == 0) cfg->channel = (int)strtol(value, NULL, 10);
        else if (strcmp(key, "device_counter") == 0) cfg->counter = strtoull(value, NULL, 10);
    }
    return (cfg->uuid[0] != '\0') ? 0 : -1;
}

int load_config(void) {
    FILE *f = NULL;
    ConfigData cfg;
    if (open_config_file("r", &f) != 0) return -1;
    int rc = load_config_from_file(f, &cfg);
    fclose(f);
    if (rc == 0) {
        copy_value(cached_uuid, sizeof(cached_uuid), cfg.uuid);
        cached_port = (int)cfg.port;
        copy_value(cached_mac, sizeof(cached_mac), cfg.mac);
        cached_channel = cfg.channel;
        cached_counter = cfg.counter;
        if (cfg.username[0]) copy_value(cached_username, sizeof(cached_username), cfg.username);
    }
    return rc;
}

int config_manager_init(void) {
    if (mkdir(CONFIG_DIR, 0700) == -1 && errno != EEXIST) return -1;
    return 0;
}

int config_manager_write_full(const char *username, const char *uuid, int port, const char *mac) {
    if (username) copy_value(cached_username, sizeof(cached_username), username);
    if (cached_username[0] == '\0') return -1;

    FILE *f = NULL;
    if (open_config_file("w", &f) != 0) return -1;

    fprintf(f, "device_username=%s\n", cached_username);
    fprintf(f, "device_uuid=%s\n", uuid ? uuid : cached_uuid);
    fprintf(f, "device_port=%d\n", port > 0 ? port : cached_port);
    if (mac && mac[0]) fprintf(f, "device_mac=%s\n", mac);
    else if (cached_mac[0]) fprintf(f, "device_mac=%s\n", cached_mac);
    if (cached_channel > 0) fprintf(f, "device_channel=%d\n", cached_channel);
    fprintf(f, "device_counter=%llu\n", (unsigned long long) cached_counter);

    fclose(f);
    if (uuid) copy_value(cached_uuid, sizeof(cached_uuid), uuid);
    if (port > 0) cached_port = port;
    if (mac) copy_value(cached_mac, sizeof(cached_mac), mac);
    return 0;
}

int config_manager_write_device(const char *uuid, int port) {
    return config_manager_write_full(NULL, uuid, port, NULL);
}

int config_manager_set_device_mac(const char *mac) {
    return config_manager_write_full(NULL, NULL, -1, mac);
}

int config_manager_get_device_uuid(char *out, size_t out_size) {
    if (cached_uuid[0] == '\0' && load_config() != 0) return -1;
    return copy_value(out, out_size, cached_uuid);
}

int config_manager_get_device_port(void) {
    if (cached_port == -2 && load_config() != 0) return -2;
    return cached_port;
}

int config_manager_get_device_mac(char *out, size_t out_size) {
    if (cached_mac[0] == '\0' && load_config() != 0) return -1;
    if (cached_mac[0] == '\0') return -1;
    return copy_value(out, out_size, cached_mac);
}

int config_manager_set_device_channel(int channel) {
    cached_channel = channel;
    return config_manager_write_full(NULL, NULL, -1, NULL);
}

int config_manager_get_device_channel(void) {
    if (cached_channel <= 0 && load_config() != 0) return -1;
    return cached_channel;
}

uint64_t config_manager_get_counter(void) {
    uint64_t v = 0;
    if (tpm_counter_read(&v) == 0) return v;  // TPM is source of truth when present
    if (cached_counter == 0 && cached_uuid[0] == '\0') load_config();
    return cached_counter;
}

int config_manager_bump_counter(uint64_t *out) {
    // Prefer the rollback-resistant TPM NV counter.
    uint64_t v = 0;
    if (tpm_counter_bump(&v) == 0) {
        if (out) *out = v;
        return 0;
    }

    // Fallback: software counter in the user's config (TPM absent/unprovisioned).
    // ponytail: don't mix TPM and file on one machine across a pairing — the two
    // counters are independent, so a TPM<->file flip can break the phone's > check.
    custom_log(LOG_WARNING, TAG, "TPM counter unavailable; using software counter");
    if (cached_uuid[0] == '\0' && load_config() != 0) return -1;
    cached_counter += 1;
    if (config_manager_write_full(NULL, NULL, -1, NULL) != 0) {
        cached_counter -= 1;  // roll back if we couldn't persist
        return -1;
    }
    if (out) *out = cached_counter;
    return 0;
}

void cache_username(const char *username) {
    if (username) copy_value(cached_username, sizeof(cached_username), username);
}

void cache_setup(const char *username, int port) {
    if (username) copy_value(cached_username, sizeof(cached_username), username);
    cached_port = port;
}
