#define PAM_SM_AUTH
#include <fcntl.h>
#include <pwd.h>
#include <sys/file.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "authenticator.h"
#include "config_manager.h"
#include "log_manager.h"
#include "recovery/recovery.h"

static const char* TAG = "pam_authenticator";

// flock so two logins can't burn the same code
static int try_recovery(pam_handle_t *pamh, const char *username, const char *code) {
    if (!code || !*code) return PAM_AUTH_ERR;
    int rc = PAM_AUTH_ERR;
    int lock = open("/etc/AuthApp/.recovery.lock", O_RDONLY | O_CREAT | O_CLOEXEC, 0600);
    if (lock < 0 || flock(lock, LOCK_EX) != 0 || load_config() != 0) {
        syslog(LOG_ERR, "pam_authenticator: could not lock/reload config for %s", username);
        if (lock >= 0) close(lock);
        return PAM_AUTH_ERR;
    }
    for (int i = 0; i < config_manager_recovery_count(); i++) {
        if (!recovery_verify(code, config_manager_recovery_hash(i))) continue;
        if (config_manager_recovery_consume(i) != 0) {
            syslog(LOG_ERR, "pam_authenticator: recovery code matched for %s but could not be consumed; refusing", username);
            break;
        }
        int left = config_manager_recovery_count();
        syslog(LOG_NOTICE, "pam_authenticator: recovery code used for %s (%d left)", username, left);
        pam_info(pamh, "SPARK: recovery code accepted, %d left. Re-pair your phone to issue new codes.", left);
        rc = PAM_SUCCESS;
        break;
    }
    if (rc != PAM_SUCCESS) syslog(LOG_WARNING, "pam_authenticator: recovery code rejected for %s", username);
    close(lock);
    return rc;
}

static void warn_if_recovery_used(pam_handle_t *pamh) {
    long used = config_manager_recovery_used();
    if (!used) return;
    char when[32];
    time_t t = (time_t)used;
    struct tm tm;
    if (!localtime_r(&t, &tm) || strftime(when, sizeof when, "%Y-%m-%d %H:%M", &tm) == 0)
        snprintf(when, sizeof when, "%ld", used);
    pam_info(pamh, "SPARK: a recovery code was used on %s. If that was not you, re-pair now.", when);
}

static int authenticate_user(pam_handle_t *pamh, const char *username) {
    AuthDetails details;
    cache_username(username);

    if (load_config() != 0) {
        custom_log(LOG_ERR, TAG, "No config for user %s", username);
        return PAM_AUTHINFO_UNAVAIL;
    }

    // token already set by the app or an earlier module = recovery code, skip the phone
    const char *tok = NULL;
    if (config_manager_recovery_count() > 0 &&
        pam_get_item(pamh, PAM_AUTHTOK, (const void **)&tok) == PAM_SUCCESS && tok && *tok) {
        return try_recovery(pamh, username, tok);
    }

    memset(&details, 0, sizeof(details));
    AuthResult result = authenticator_authenticate(&details);

    if (result == AUTH_SUCCESS) {
        if (details.response_len > 0 && details.response_len <= sizeof(details.response)) {
            syslog(LOG_NOTICE, "pam_authenticator: Success for user %s", username);
            warn_if_recovery_used(pamh);
            return PAM_SUCCESS;
        }
        syslog(LOG_ERR, "pam_authenticator: Invalid response from device for %s", username);
        return PAM_AUTH_ERR;
    }

    syslog(LOG_WARNING, "pam_authenticator: Failure for %s: %s",
           username, authenticator_result_to_string(result));

    // phone failed, ask for a recovery code (SDDM answers this with its password field)
    if (config_manager_recovery_count() > 0) {
        pam_info(pamh, "SPARK: phone unavailable. Enter a recovery code (five words), or press Enter to cancel.");
        if (pam_get_authtok(pamh, PAM_AUTHTOK, &tok, "Recovery code: ") == PAM_SUCCESS)
            return try_recovery(pamh, username, tok);
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

    return authenticate_user(pamh, username);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
