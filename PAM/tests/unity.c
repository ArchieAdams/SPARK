#include "unity.h"

#include <stdio.h>
#include <string.h>

unsigned int UnityTestsRun = 0;
unsigned int UnityTestsFailed = 0;

static const char *UnityCurrentTestName = NULL;
static int UnityCurrentTestFailed = 0;

void UnityBegin(const char *name) {
    printf("Running %s\n", name);
}

void UnityEnd(void) {
    printf("%u tests, %u failures\n", UnityTestsRun, UnityTestsFailed);
}

void UnityDefaultTestRun(void (*func)(void), const char *name, const int line_num) {
    (void)line_num;
    UnityCurrentTestName = name;
    UnityCurrentTestFailed = 0;
    UnityTestsRun++;
    func();
    if (UnityCurrentTestFailed) {
        UnityTestsFailed++;
        printf("[FAIL] %s\n", UnityCurrentTestName);
    } else {
        printf("[PASS] %s\n", UnityCurrentTestName);
    }
}

void UnityFail(const char *msg, const int line_num) {
    UnityCurrentTestFailed = 1;
    if (msg) {
        printf("  line %d: %s\n", line_num, msg);
    } else {
        printf("  line %d: failure\n", line_num);
    }
}

void UnityAssertEqualInt(long expected, long actual, const char *msg, const int line_num) {
    if (expected != actual) {
        UnityCurrentTestFailed = 1;
        printf("  line %d: expected %ld but was %ld", line_num, expected, actual);
        if (msg) {
            printf(" (%s)", msg);
        }
        printf("\n");
    }
}

void UnityAssertNotNull(const void *ptr, const char *msg, const int line_num) {
    if (ptr == NULL) {
        UnityCurrentTestFailed = 1;
        printf("  line %d: pointer was NULL", line_num);
        if (msg) {
            printf(" (%s)", msg);
        }
        printf("\n");
    }
}

void UnityAssertEqualMemory(const void *expected, const void *actual, size_t length, const char *msg, const int line_num) {
    if (memcmp(expected, actual, length) != 0) {
        UnityCurrentTestFailed = 1;
        printf("  line %d: memory differed", line_num);
        if (msg) {
            printf(" (%s)", msg);
        }
        printf("\n");
    }
}

