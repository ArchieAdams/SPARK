#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include <stddef.h>

typedef enum {
    AUTH_SUCCESS = 0,
    AUTH_CONFIG_ERROR,
    AUTH_CONNECTION_FAILED,
    AUTH_CHALLENGE_FAILED,
    AUTH_RESPONSE_FAILED,
    AUTH_TIMEOUT,
    AUTH_VERIFICATION_FAILED
} AuthResult;

typedef struct {
    unsigned char response[2048];
    size_t response_len;
    int transport_is_bluetooth;
} AuthDetails;

AuthResult authenticator_authenticate(AuthDetails *details);
const char *authenticator_result_to_string(AuthResult result);

#endif // AUTHENTICATOR_H
