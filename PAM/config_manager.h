#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <stddef.h>
#include <stdint.h>

#define CONFIG_AUTH_TIMEOUT_MS 30000

int config_manager_init(void);
int load_config(void);

int config_manager_write_device(const char *uuid, int port);
int config_manager_set_device_mac(const char *mac);
int config_manager_write_full(const char *username, const char *uuid, int port, const char *mac);

int config_manager_get_device_uuid(char *out, size_t out_size);
int config_manager_get_device_port(void);
int config_manager_get_device_mac(char *out, size_t out_size);
int config_manager_set_device_channel(int channel);
int config_manager_get_device_channel(void);

uint64_t config_manager_get_counter(void);
int config_manager_bump_counter(uint64_t *out);

#define CONFIG_RECOVERY_MAX 3
#define CONFIG_RECOVERY_HASH_LEN 192
int config_manager_set_recovery(const char *const *hashes, int n, const char *repair_hash);
int config_manager_recovery_count(void);
const char *config_manager_recovery_hash(int i);
int config_manager_recovery_consume(int i);
const char *config_manager_repair_hash(void);   // NULL if none
long config_manager_recovery_used(void);  // epoch, 0 if never

void cache_username(const char *username);
void cache_setup(const char *username, int port);

#endif // CONFIG_MANAGER_H
