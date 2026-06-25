#include "log_manager.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/syslog.h>

static void create_message(const char *tag, const char *text, char *message, size_t message_size) {
    if (tag != NULL && tag[0] != '\0') {
        snprintf(message, message_size, "[%s] %s", tag, text);
    } else {
        snprintf(message, message_size, "%s", text);
    }
}

static void log_with_level(int level, const char *label, const char *tag, const char *text) {
    if (text == NULL || text[0] == '\0') {
        return;
    }

    size_t message_length = strlen(text) + ((tag != NULL && tag[0] != '\0') ? strlen(tag) + 3 : 0) + 1;
    char message[message_length];
    create_message(tag, text, message, sizeof(message));

    syslog(level, "%s", message);
    fprintf(stdout, "%s: %s\n", label, message);
}

static void log_error(const char *tag, const char *text) {
    log_with_level(LOG_ERR, "ERROR", tag, text);
}

static void log_info(const char *tag, const char *text) {
    log_with_level(LOG_INFO, "INFO", tag, text);
}

static void log_debug(const char *tag, const char *text) {
    log_with_level(LOG_DEBUG, "DEBUG", tag, text);
}

static void log_warning(const char *tag, const char *text) {
    log_with_level(LOG_WARNING, "WARNING", tag, text);
}

void custom_log(const int level, const char *tag, const char *text, ...) {
    if (text == NULL) {
        return;
    }

    // Handle variable arguments to format the log message
    va_list args;
    va_start(args, text);

    va_list args_copy;
    va_copy(args_copy, args);
    int text_len = vsnprintf(NULL, 0, text, args_copy);
    va_end(args_copy);
    if (text_len < 0) {
        va_end(args);
        return;
    }

    size_t formatted_size = (size_t) text_len + 1;
    char formatted_text[formatted_size];
    if (vsnprintf(formatted_text, formatted_size, text, args) < 0) {
        va_end(args);
        return;
    }
    va_end(args);
    if (level == LOG_ERR) {
        log_error(tag, formatted_text);
    } else if (level == LOG_DEBUG) {
        log_debug(tag, formatted_text);
    } else if (level == LOG_WARNING) {
        log_warning(tag, formatted_text);
    } else {
        log_info(tag, formatted_text);
    }
}
