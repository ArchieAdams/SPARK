#pragma once

#include "connection_manager.h"

typedef enum {
    PHONE_AUTH_OK = 0,
    PHONE_AUTH_INVALID_ARGUMENT,
    PHONE_AUTH_CONNECT_FAILED,
    PHONE_AUTH_CHALLENGE_SEND_FAILED,
    PHONE_AUTH_RESPONSE_FAILED
} PhoneAuthResult;

typedef struct {
    PhoneAuthResult result;
    ConnectionType transport;
    unsigned char response[2048];
    size_t response_len;
} PhoneAuthOutcome;


PhoneAuthResult phone_authenticate(const char *device_uuid, PhoneAuthOutcome *outcome);

