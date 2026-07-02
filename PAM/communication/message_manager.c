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

#define PC_KEY_PATH "/etc/AuthApp/pki/pc.key"
#define MIN_SIGN_ENCRYPT_BUFFER 1024

static const char *TAG = "message_manager";

static void put_be64(unsigned char *buf, uint64_t value) {
    for (size_t i = 0; i < CHALLENGE_COUNTER_SIZE; i++) {
        buf[i] = (unsigned char) ((value >> (8 * (CHALLENGE_COUNTER_SIZE - 1 - i))) & 0xFF);
    }
}

static int pubkey_der(EVP_PKEY *key, unsigned char **out, int *out_len) {
    unsigned char *buf = NULL;
    int len = i2d_PUBKEY(key, &buf);
    if (len <= 0 || !buf) return 0;
    *out = buf;
    *out_len = len;
    return 1;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}


static int decode_hex_string(const char *hex_input, unsigned char **output, size_t *output_len) {
    if (!hex_input || !output || !output_len) {
        custom_log(LOG_ERR, TAG, "Invalid parameters for hex decode");
        return 0;
    }

    size_t hex_len = strlen(hex_input);
    if (hex_len == 0 || (hex_len % 2) != 0) {
        custom_log(LOG_ERR, TAG, "Invalid hex input length: %zu", hex_len);
        return 0;
    }

    unsigned char *decoded = malloc(hex_len / 2);
    if (!decoded) {
        custom_log(LOG_ERR, TAG, "Failed to allocate %zu bytes for decoded response", hex_len / 2);
        return 0;
    }

    for (size_t i = 0; i < hex_len; i += 2) {
        int high = hex_nibble(hex_input[i]);
        int low = hex_nibble(hex_input[i + 1]);
        if (high < 0 || low < 0) {
            custom_log(LOG_ERR, TAG, "Invalid hex character at positions %zu/%zu", i, i + 1);
            free(decoded);
            return 0;
        }
        decoded[i / 2] = (unsigned char) ((high << 4) | low);
    }

    *output = decoded;
    *output_len = hex_len / 2;
    return 1;
}

static int load_device_public_key(EVP_PKEY **out_key) {
    char device_id[128] = {0};
    if (config_manager_get_device_uuid(device_id, sizeof(device_id)) != 0 || device_id[0] == '\0') {
        custom_log(LOG_ERR, TAG, "Failed to get paired device UUID");
        return 0;
    }

    char pub_path[512];
    snprintf(pub_path, sizeof(pub_path), "/etc/AuthApp/pki/%s.pub", device_id);

    if (!key_manager_load_public_key(pub_path, out_key)) {
        custom_log(LOG_ERR, TAG, "Failed to load device public key from %s", pub_path);
        return 0;
    }
    return 1;
}


static int generate_challenge(unsigned char *buf, size_t len) {
    if (!buf && len > 0) return -1;
    if (len == 0) return 0;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;

    ssize_t result = read(fd, buf, len);
    close(fd);

    return (result == (ssize_t) len) ? 0 : -1;
}

int generate_signed_and_encrypted_message(
    unsigned char *message,
    size_t *message_len,
    unsigned char *expected_response,
    size_t *expected_response_len
) {
    if (!expected_response || !expected_response_len || *expected_response_len < CHALLENGE_RESPONSE_SIZE) {
        custom_log(LOG_ERR, TAG, "Buffer too small. Need at least %d bytes", CHALLENGE_RESPONSE_SIZE);
        return 0;
    }

    if (!message || !message_len || *message_len < MIN_SIGN_ENCRYPT_BUFFER) {
        custom_log(LOG_ERR, TAG, "Buffer too small. Need at least %d bytes", MIN_SIGN_ENCRYPT_BUFFER);
        return 0;
    }

    unsigned char m[CHALLENGE_M_SIZE];
    EVP_PKEY *device_public_key = NULL;  // pk_A
    EVP_PKEY *pc_key = NULL;             // sk_V
    unsigned char *der_v = NULL, *der_a = NULL, *sign_extra = NULL;
    int der_v_len = 0, der_a_len = 0;
    int result = 0;

    // M = N || ctr
    uint64_t ctr = 0;
    if (config_manager_bump_counter(&ctr) != 0) {
        custom_log(LOG_ERR, TAG, "Failed to bump auth counter");
        goto cleanup;
    }
    if (generate_challenge(m, CHALLENGE_RANDOM_SIZE) != 0) {
        custom_log(LOG_ERR, TAG, "Failed to generate challenge nonce");
        goto cleanup;
    }
    put_be64(m + CHALLENGE_RANDOM_SIZE, ctr);

    memcpy(expected_response, m, CHALLENGE_M_SIZE);
    *expected_response_len = CHALLENGE_M_SIZE;

    if (!load_device_public_key(&device_public_key)) goto cleanup;
    if (!key_manager_load_private_key(PC_KEY_PATH, &pc_key)) goto cleanup;

    // sign_extra = pk_V || pk_A (bound into the signature, not transmitted)
    if (!pubkey_der(pc_key, &der_v, &der_v_len)) goto cleanup;
    if (!pubkey_der(device_public_key, &der_a, &der_a_len)) goto cleanup;
    sign_extra = malloc((size_t) der_v_len + (size_t) der_a_len);
    if (!sign_extra) goto cleanup;
    memcpy(sign_extra, der_v, der_v_len);
    memcpy(sign_extra + der_v_len, der_a, der_a_len);

    size_t output_len = *message_len;
    if (!crypto_sign_and_encrypt_with_keys(m, sizeof m, sign_extra,
                                           (size_t) der_v_len + (size_t) der_a_len,
                                           pc_key, device_public_key, message, &output_len)) {
        custom_log(LOG_ERR, TAG, "Failed to sign and encrypt challenge message");
        goto cleanup;
    }

    *message_len = output_len;
    custom_log(LOG_INFO, TAG, "Challenge (ctr=%llu) signed and encrypted (%zu bytes)",
               (unsigned long long) ctr, output_len);
    result = 1;

cleanup:
    OPENSSL_free(der_v);
    OPENSSL_free(der_a);
    free(sign_extra);
    key_manager_free_key(device_public_key);
    key_manager_free_key(pc_key);
    return result;
}

int process_signed_and_encrypted_response_bytes(
    const unsigned char *input,
    size_t input_len,
    unsigned char *output_message,
    size_t *output_len
) {
    if (!input || !output_message || !output_len || *output_len == 0) {
        custom_log(LOG_ERR, TAG, "Invalid parameters for response processing");
        return 0;
    }

    EVP_PKEY *device_public_key = NULL;  // pk_A (verify)
    EVP_PKEY *pc_key = NULL;             // sk_V (decrypt)
    unsigned char *der_v = NULL, *der_a = NULL, *sign_extra = NULL;
    int der_v_len = 0, der_a_len = 0;
    int result = 0;

    if (!load_device_public_key(&device_public_key)) goto cleanup;
    if (!key_manager_load_private_key(PC_KEY_PATH, &pc_key)) goto cleanup;

    // response signed input = M || pk_A || pk_V (swapped vs the challenge)
    if (!pubkey_der(pc_key, &der_v, &der_v_len)) goto cleanup;
    if (!pubkey_der(device_public_key, &der_a, &der_a_len)) goto cleanup;
    sign_extra = malloc((size_t) der_a_len + (size_t) der_v_len);
    if (!sign_extra) goto cleanup;
    memcpy(sign_extra, der_a, der_a_len);
    memcpy(sign_extra + der_a_len, der_v, der_v_len);

    if (!crypto_decrypt_and_verify_with_keys(input, input_len, sign_extra,
                                             (size_t) der_a_len + (size_t) der_v_len,
                                             pc_key, device_public_key, output_message, output_len)) {
        custom_log(LOG_ERR, TAG, "Failed to decrypt and verify device response");
        goto cleanup;
    }

    custom_log(LOG_INFO, TAG, "Device response processed successfully (%zu plaintext bytes)", *output_len);
    result = 1;

cleanup:
    OPENSSL_free(der_v);
    OPENSSL_free(der_a);
    free(sign_extra);
    key_manager_free_key(pc_key);
    key_manager_free_key(device_public_key);
    return result;
}

int process_signed_and_encrypted_response(
    const char *hex_input,
    unsigned char *output_message,
    size_t *output_len
) {
    unsigned char *input = NULL;
    size_t input_len = 0;
    if (!decode_hex_string(hex_input, &input, &input_len)) return 0;
    int result = process_signed_and_encrypted_response_bytes(input, input_len, output_message, output_len);
    free(input);
    return result;
}

int validate_challenge_response(
    const unsigned char *expected_response,
    size_t expected_response_len,
    const unsigned char *actual_response,
    size_t actual_response_len
) {
    if (!expected_response || !actual_response) {
        custom_log(LOG_ERR, TAG, "Challenge validation received null input");
        return 0;
    }

    if (expected_response_len != CHALLENGE_RESPONSE_SIZE || actual_response_len != CHALLENGE_RESPONSE_SIZE) {
        custom_log(LOG_ERR, TAG, "Invalid challenge response size: expected=%zu actual=%zu required=%d",
                   expected_response_len, actual_response_len, CHALLENGE_RESPONSE_SIZE);
        return 0;
    }

    if (memcmp(expected_response, actual_response, CHALLENGE_RESPONSE_SIZE) != 0) {
        custom_log(LOG_ERR, TAG, "Challenge response mismatch");
        return 0;
    }

    custom_log(LOG_INFO, TAG, "Challenge response matched (N||ctr echo verified)");
    return 1;
}
