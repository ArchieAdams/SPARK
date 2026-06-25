#include "authenticator.h"
#include "config_manager.h"
#include "communication/phone_connection.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

AuthResult authenticator_authenticate(AuthDetails *details) {
    char device_uuid[256];
    if (config_manager_get_device_uuid(device_uuid, sizeof(device_uuid)) == -1) {
        return AUTH_CONFIG_ERROR;
    }

    PhoneAuthOutcome outcome = {0};
    const PhoneAuthResult result = phone_authenticate(device_uuid, &outcome);

    AuthResult auth_result;
    switch (result) {
        case PHONE_AUTH_OK:
            auth_result = AUTH_SUCCESS;
            break;
        case PHONE_AUTH_INVALID_ARGUMENT:
            auth_result = AUTH_CONFIG_ERROR;
            break;
        case PHONE_AUTH_CONNECT_FAILED:
            auth_result = AUTH_CONNECTION_FAILED;
            break;
        case PHONE_AUTH_CHALLENGE_SEND_FAILED:
            auth_result = AUTH_CHALLENGE_FAILED;
            break;
        case PHONE_AUTH_RESPONSE_FAILED:
            auth_result = AUTH_RESPONSE_FAILED;
            break;
        default:
            auth_result = AUTH_RESPONSE_FAILED;
            break;
    }

    if (auth_result == AUTH_SUCCESS) {
        if (outcome.response_len == 0 || outcome.response_len > sizeof(details->response)) {
            return AUTH_RESPONSE_FAILED;
        }

        if (details) {
            memset(details, 0, sizeof(*details));
            memcpy(details->response, outcome.response, outcome.response_len);
            details->response_len = outcome.response_len;
            details->transport_is_bluetooth = (outcome.transport == CONN_BLUETOOTH);
        }
    }

    return auth_result;
}

const char *authenticator_result_to_string(AuthResult result) {
    switch (result) {
        case AUTH_SUCCESS:            return "Authentication successful";
        case AUTH_CONFIG_ERROR:       return "Configuration error (device not registered)";
        case AUTH_CONNECTION_FAILED:  return "Failed to connect to device";
        case AUTH_CHALLENGE_FAILED:   return "Failed to send challenge";
        case AUTH_RESPONSE_FAILED:    return "Device response verification failed";
        case AUTH_TIMEOUT:            return "Timeout waiting for device";
        case AUTH_VERIFICATION_FAILED: return "Signature verification failed";
        default:                      return "Unknown error";
    }
}
