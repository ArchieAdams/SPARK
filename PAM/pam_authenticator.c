#define PAM_SM_AUTH
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "authenticator.h"
#include "config_manager.h"
#include "log_manager.h"

static const char* TAG = "pam_authenticator";

static int authenticate_user(const char *username) {
    AuthDetails details;
    cache_username(username);

    if (load_config() != 0) {
        custom_log(LOG_ERR, TAG, "No config for user %s", username);
        return PAM_AUTHINFO_UNAVAIL;
    }

    memset(&details, 0, sizeof(details));
    AuthResult result = authenticator_authenticate(&details);

    if (result == AUTH_SUCCESS) {
        if (details.response_len > 0 && details.response_len <= sizeof(details.response)) {
            syslog(LOG_NOTICE, "pam_authenticator: Success for user %s", username);
            return PAM_SUCCESS;
        }
        syslog(LOG_ERR, "pam_authenticator: Invalid response from device for %s", username);
    } else {
        syslog(LOG_WARNING, "pam_authenticator: Failure for %s: %s",
               username, authenticator_result_to_string(result));
    }

    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username = NULL;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username) {
        return PAM_AUTH_ERR;
    }

    if (!getpwnam(username)) {
        return PAM_USER_UNKNOWN;
    }

    return authenticate_user(username);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
