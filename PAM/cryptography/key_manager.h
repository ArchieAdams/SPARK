#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include <openssl/evp.h>

int key_manager_generate_rsa_keypair(const char *private_key_file, const char *public_key_file);
int key_manager_load_private_key(const char *filepath, EVP_PKEY **out_key);
int key_manager_load_public_key(const char *filepath, EVP_PKEY **out_key);
void key_manager_free_key(EVP_PKEY *key);

#endif // KEY_MANAGER_H
