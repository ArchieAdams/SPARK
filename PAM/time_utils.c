#include "time_utils.h"

#include <errno.h>
#include <time.h>

void sleep_ms(long ms) {
    if (ms <= 0) return;

    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;

    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
        // resume remaining time
    }
}
