#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <stddef.h>

#define CONFIG_AUTH_TIMEOUT_MS 30000

int config_manager_init(void);
int load_config(void);

int config_manager_write_device(const char *uuid, int port);
int config_manager_set_device_mac(const char *mac);
int config_manager_write_full(const char *username, const char *uuid, int port, const char *mac);

int config_manager_get_device_uuid(char *out, size_t out_size);
int config_manager_get_device_port(void);
int config_manager_get_device_mac(char *out, size_t out_size);

void cache_username(const char *username);
void cache_setup(const char *username, int port);

#endif // CONFIG_MANAGER_H
