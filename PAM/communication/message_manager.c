#include "message_manager.h"
#include "../cryptography/cryptographic_methods.h"
#include "../config_manager.h"
#include "../log_manager.h"
#include "../cryptography/key_manager.h"
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <sys/syslog.h>

#define PROTOCOL_ID "SPARK-AUTH-v2"
#define PC_HANDLE_PATH "/etc/AuthApp/pki/pc.handle"
#define PC_PUB_PATH "/etc/AuthApp/pki/pc.pub"

static const char *TAG = "message_manager";

typedef struct {
    EVP_PKEY *ephV_sk;
    uint8_t ephV_pk[32];
    uint8_t ephA_pk[32];
    uint8_t *pkV_der;
    size_t pkV_der_len;
    uint8_t *pkA_der;
    size_t pkA_der_len;
    uint8_t K_GCM[32];
    uint8_t IV_GCM[12];
    uint8_t *T;
    size_t T_len;
    int active;
    int initialized;
} SessionState;

static SessionState session = {0};

void auth_verifier_cleanup(void) {
    if (!session.initialized) {
        memset(&session, 0, sizeof(session));
        session.initialized = 1;
        return;
    }
    if (session.ephV_sk) {
        EVP_PKEY_free(session.ephV_sk);
        session.ephV_sk = NULL;
    }
    if (session.pkV_der) { free(session.pkV_der); session.pkV_der = NULL; }
    if (session.pkA_der) { free(session.pkA_der); session.pkA_der = NULL; }
    if (session.T) { free(session.T); session.T = NULL; }

    int init_val = session.initialized;
    memset(&session, 0, sizeof(session));
    session.initialized = init_val;
}

static void put_be32(unsigned char *buf, uint32_t value) {
    buf[0] = (unsigned char)((value >> 24) & 0xFF);
    buf[1] = (unsigned char)((value >> 16) & 0xFF);
    buf[2] = (unsigned char)((value >> 8) & 0xFF);
    buf[3] = (unsigned char)(value & 0xFF);
}

static int get_der_public_key(EVP_PKEY *pkey, uint8_t **out, size_t *out_len) {
    int len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0) return 0;
    *out = malloc((size_t)len);
    if (!*out) return 0;
    uint8_t *p = *out;
    i2d_PUBKEY(pkey, &p);
    *out_len = (size_t)len;
    return 1;
}

static int load_identities(void) {
    EVP_PKEY *pkV = NULL;
    if (!key_manager_load_public_key(PC_PUB_PATH, &pkV)) {
        custom_log(LOG_ERR, TAG, "Failed to load PC public key");
        return 0;
    }
    int okV = get_der_public_key(pkV, &session.pkV_der, &session.pkV_der_len);
    EVP_PKEY_free(pkV);
    if (!okV) return 0;

    char device_id[128] = {0};
    if (config_manager_get_device_uuid(device_id, sizeof(device_id)) != 0 || device_id[0] == '\0') {
        custom_log(LOG_ERR, TAG, "No paired device UUID found");
        return 0;
    }
    char pub_path[512];
    snprintf(pub_path, sizeof(pub_path), "/etc/AuthApp/pki/%s.pub", device_id);

    EVP_PKEY *pkA = NULL;
    if (!key_manager_load_public_key(pub_path, &pkA)) {
        custom_log(LOG_ERR, TAG, "Failed to load Phone key from %s", pub_path);
        return 0;
    }
    int okA = get_der_public_key(pkA, &session.pkA_der, &session.pkA_der_len);
    EVP_PKEY_free(pkA);
    return okA;
}

int auth_verifier_step1(uint8_t ephV[32]) {
    auth_verifier_cleanup();
    custom_log(LOG_INFO, TAG, "Auth Step 1: Generating ephV");
    if (!crypto_generate_x25519_keypair(&session.ephV_sk, session.ephV_pk)) {
        custom_log(LOG_ERR, TAG, "X25519 keygen failed");
        return 0;
    }
    memcpy(ephV, session.ephV_pk, 32);
    session.active = 1;
    return 1;
}

static int build_transcript(void) {
    session.T_len = strlen(PROTOCOL_ID) + 32 + 32 + 4 + session.pkV_der_len + 4 + session.pkA_der_len;
    session.T = malloc(session.T_len);
    if (!session.T) return 0;

    size_t off = 0;
    memcpy(session.T + off, PROTOCOL_ID, strlen(PROTOCOL_ID)); off += strlen(PROTOCOL_ID);
    memcpy(session.T + off, session.ephV_pk, 32); off += 32;
    memcpy(session.T + off, session.ephA_pk, 32); off += 32;
    put_be32(session.T + off, (uint32_t)session.pkV_der_len); off += 4;
    memcpy(session.T + off, session.pkV_der, session.pkV_der_len); off += session.pkV_der_len;
    put_be32(session.T + off, (uint32_t)session.pkA_der_len); off += 4;
    memcpy(session.T + off, session.pkA_der, session.pkA_der_len); off += session.pkA_der_len;

    return 1;
}

int auth_verifier_step3(const uint8_t ephA[32], uint8_t *c3, size_t *c3_len) {
    if (!session.active) return 0;
    memcpy(session.ephA_pk, ephA, 32);

    if (!load_identities()) return 0;
    if (!build_transcript()) return 0;

    uint8_t Z[32];
    if (!crypto_derive_x25519_secret(session.ephV_sk, session.ephA_pk, Z)) {
        custom_log(LOG_ERR, TAG, "ECDH secret derivation failed");
        return 0;
    }

    crypto_derive_response_key_iv(Z, session.T, session.T_len, session.K_GCM, session.IV_GCM);

    size_t m_v_len = 3 + session.T_len;
    uint8_t *m_v = malloc(m_v_len);
    if (!m_v) return 0;
    memcpy(m_v, "req", 3);
    memcpy(m_v + 3, session.T, session.T_len);

    uint8_t *sigV = NULL;
    size_t sigV_len = 0;
    if (!key_manager_tpm_sign_p256(PC_HANDLE_PATH, m_v, m_v_len, &sigV, &sigV_len)) {
        custom_log(LOG_ERR, TAG, "TPM signature failed");
        free(m_v);
        return 0;
    }
    free(m_v);

    if (!crypto_aead_encrypt(session.K_GCM, session.IV_GCM, sigV, sigV_len, session.T, session.T_len, c3, c3_len)) {
        custom_log(LOG_ERR, TAG, "AEAD encryption of Step 3 failed");
        free(sigV);
        return 0;
    }

    free(sigV);
    return 1;
}

int auth_verifier_step5(const uint8_t *c4, size_t c4_len) {
    if (!session.active || !session.T) return 0;

    uint8_t *sigmaA = malloc(1024);
    if (!sigmaA) return 0;
    size_t sigmaA_len = 1024;

    if (!crypto_aead_decrypt(session.K_GCM, session.IV_GCM, c4, c4_len, session.T, session.T_len, sigmaA, &sigmaA_len)) {
        custom_log(LOG_ERR, TAG, "AEAD decryption of phone response failed");
        free(sigmaA);
        return 0;
    }

    size_t m_a_len = 4 + 32 + 32 + 4 + session.pkA_der_len + 4 + session.pkV_der_len;
    uint8_t *m_a = malloc(m_a_len);
    if (!m_a) { free(sigmaA); return 0; }

    size_t off = 0;
    memcpy(m_a + off, "resp", 4); off += 4;
    memcpy(m_a + off, session.ephV_pk, 32); off += 32;
    memcpy(m_a + off, session.ephA_pk, 32); off += 32;
    put_be32(m_a + off, (uint32_t)session.pkA_der_len); off += 4;
    memcpy(m_a + off, session.pkA_der, session.pkA_der_len); off += session.pkA_der_len;
    put_be32(m_a + off, (uint32_t)session.pkV_der_len); off += 4;
    memcpy(m_a + off, session.pkV_der, session.pkV_der_len); off += session.pkV_der_len;

    char device_id[128] = {0};
    config_manager_get_device_uuid(device_id, sizeof(device_id));
    char pub_path[512];
    snprintf(pub_path, sizeof(pub_path), "/etc/AuthApp/pki/%s.pub", device_id);
    EVP_PKEY *pkA = NULL;
    if (!key_manager_load_public_key(pub_path, &pkA)) {
        free(m_a);
        free(sigmaA);
        return 0;
    }

    int ok = crypto_verify_ec(m_a, off, sigmaA, sigmaA_len, pkA);
    EVP_PKEY_free(pkA);
    free(m_a);
    free(sigmaA);

    if (ok) custom_log(LOG_INFO, TAG, "Mutual authentication successful");
    else custom_log(LOG_ERR, TAG, "Phone signature verification failed");

    return ok;
}
