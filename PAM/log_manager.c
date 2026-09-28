#include "log_manager.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/syslog.h>

#define MAX_LOG_LINE 1024

bool debug = false;

void set_debug(bool enable) { debug = enable; }

void custom_log(const int level, const char *tag, const char *text, ...) {
    if (text == NULL)
        return;

    char formatted_text[MAX_LOG_LINE];
    va_list args;
    va_start(args, text);
    vsnprintf(formatted_text, sizeof(formatted_text), text, args);
    va_end(args);

    // 1. Log to Syslog
    if (tag && tag[0]) {
        syslog(level, "[%s] %s", tag, formatted_text);
    } else {
        syslog(level, "%s", formatted_text);
    }

    // 2. Log to Stdout for user visibility
    if (debug || level == LOG_ERR || level == LOG_WARNING || level == LOG_INFO) {
        const char *label = "INFO";
        if (level == LOG_ERR)
            label = "ERROR";
        else if (level == LOG_DEBUG)
            label = "DEBUG";
        else if (level == LOG_WARNING)
            label = "WARNING";

        if (tag && tag[0]) {
            fprintf(stdout, "%s: [%s] %s\n", label, tag, formatted_text);
        } else {
            fprintf(stdout, "%s: %s\n", label, formatted_text);
        }
        fflush(stdout);
    }
}
