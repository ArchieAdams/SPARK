#include "key_manager.h"
#include "../log_manager.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <sys/syslog.h>
#include <sys/stat.h>

static const char *TAG = "key_manager";
#define KEY_SIZE 3072

int key_manager_generate_rsa_keypair(const char *private_key_file, const char *public_key_file) {
    if (!private_key_file || !public_key_file) return 0;

    int ok = 0;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;

    if (!ctx) return 0;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_SIZE) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto cleanup;

    FILE *fpriv = fopen(private_key_file, "wb");
    if (!fpriv) goto cleanup;
    if (!PEM_write_PrivateKey(fpriv, pkey, NULL, NULL, 0, NULL, NULL)) {
        fclose(fpriv);
        goto cleanup;
    }
    if (fchmod(fileno(fpriv), S_IRUSR | S_IWUSR) != 0) { // Chmod 600
        fclose(fpriv);
        goto cleanup;
    }
    fclose(fpriv);

    FILE *fpub = fopen(public_key_file, "wb");
    if (!fpub) goto cleanup;
    if (!PEM_write_PUBKEY(fpub, pkey)) {
        fclose(fpub);
        goto cleanup;
    }
    fclose(fpub);

    ok = 1;
    custom_log(LOG_INFO, TAG, "Generated RSA keypair (%d bits)");

cleanup:
    if (!ok) custom_log(LOG_ERR, TAG, "Failed to generate RSA keypair");
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ok;
}

int key_manager_load_private_key(const char *filepath, EVP_PKEY **out_key) {
    if (!filepath || !out_key) return 0;
    *out_key = NULL;

    FILE *f = fopen(filepath, "rb");
    if (!f) return 0;

    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!k) return 0;

    *out_key = k;
    return 1;
}

int key_manager_load_public_key(const char *filepath, EVP_PKEY **out_key) {
    if (!filepath || !out_key) return 0;
    *out_key = NULL;

    FILE *f = fopen(filepath, "rb");
    if (!f) return 0;

    EVP_PKEY *k = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!k) return 0;

    *out_key = k;
    return 1;
}

void key_manager_free_key(EVP_PKEY *key) {
    if (key) EVP_PKEY_free(key);
}
