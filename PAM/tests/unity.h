#ifndef UNITY_H
#define UNITY_H

#include <setjmp.h>
#include <stddef.h>

extern unsigned int UnityTestsRun;
extern unsigned int UnityTestsFailed;

void UnityBegin(const char *name);
void UnityEnd(void);
void UnityDefaultTestRun(void (*func)(void), const char *name, const int line_num);
void UnityFail(const char *msg, const int line_num);
void UnityAssertEqualInt(long expected, long actual, const char *msg, const int line_num);
void UnityAssertNotNull(const void *ptr, const char *msg, const int line_num);
void UnityAssertEqualMemory(const void *expected, const void *actual, size_t length, const char *msg, const int line_num);

#define RUN_TEST(func) UnityDefaultTestRun(func, #func, __LINE__)
#define TEST_ASSERT_EQUAL(expected, actual) UnityAssertEqualInt((long)(expected), (long)(actual), NULL, __LINE__)
#define TEST_ASSERT_NOT_NULL(ptr) UnityAssertNotNull((ptr), NULL, __LINE__)
#define TEST_ASSERT_EQUAL_MEMORY(expected, actual, length) UnityAssertEqualMemory((expected), (actual), (length), NULL, __LINE__)
#define TEST_FAIL_MESSAGE(msg) UnityFail((msg), __LINE__)

#endif

