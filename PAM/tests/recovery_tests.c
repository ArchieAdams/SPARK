#include "unity.h"
#include "recovery/recovery.h"
#include "recovery/eff_wordlist.h"

#include <string.h>

static int in_wordlist(const char *w) {
    for (int i = 0; i < EFF_WORDS_COUNT; i++) if (strcmp(EFF_WORDS[i], w) == 0) return 1;
    return 0;
}

static void test_generate_has_five_wordlist_words(void) {
    char code[RECOVERY_CODE_MAX];
    TEST_ASSERT_EQUAL(0, recovery_generate_code(code, sizeof code));
    char copy[RECOVERY_CODE_MAX]; strcpy(copy, code);
    int n = 0;
    for (char *w = strtok(copy, " "); w; w = strtok(NULL, " "), n++) TEST_ASSERT_EQUAL(1, !!in_wordlist(w));
    TEST_ASSERT_EQUAL(RECOVERY_WORDS, n);
}

static void test_two_codes_differ(void) {
    char a[RECOVERY_CODE_MAX], b[RECOVERY_CODE_MAX];
    TEST_ASSERT_EQUAL(0, recovery_generate_code(a, sizeof a));
    TEST_ASSERT_EQUAL(0, recovery_generate_code(b, sizeof b));
    TEST_ASSERT_EQUAL(1, strcmp(a, b) != 0);
}

static void test_hash_is_yescrypt_and_verifies(void) {
    char code[RECOVERY_CODE_MAX], hash[RECOVERY_HASH_MAX];
    TEST_ASSERT_EQUAL(0, recovery_generate_code(code, sizeof code));
    TEST_ASSERT_EQUAL(0, recovery_hash(code, hash, sizeof hash));
    TEST_ASSERT_EQUAL_MEMORY("$y$", hash, 3);
    TEST_ASSERT_EQUAL(1, !!recovery_verify(code, hash));
}

static void test_verify_normalises_case_and_spacing(void) {
    char hash[RECOVERY_HASH_MAX];
    TEST_ASSERT_EQUAL(0, recovery_hash("abacus zoom zit zone zippy", hash, sizeof hash));
    TEST_ASSERT_EQUAL(1, !!recovery_verify("  Abacus   ZOOM zit-zone\tzippy \n", hash));
}

static void test_hyphenated_words_round_trip(void) {
    char hash[RECOVERY_HASH_MAX];
    TEST_ASSERT_EQUAL(0, recovery_hash("yo-yo t-shirt abacus drop-down zoom", hash, sizeof hash));
    TEST_ASSERT_EQUAL(1, !!recovery_verify("yo-yo t-shirt abacus drop-down zoom", hash));
    TEST_ASSERT_EQUAL(1, !!recovery_verify("yo yo t shirt abacus drop down zoom", hash));
}

static void test_verify_rejects_wrong_and_garbage(void) {
    char hash[RECOVERY_HASH_MAX];
    TEST_ASSERT_EQUAL(0, recovery_hash("abacus zoom zit zone zippy", hash, sizeof hash));
    TEST_ASSERT_EQUAL(0, !!recovery_verify("abacus zoom zit zone zip", hash));
    TEST_ASSERT_EQUAL(0, !!recovery_verify("", hash));
    TEST_ASSERT_EQUAL(0, !!recovery_verify("   ", hash));
    TEST_ASSERT_EQUAL(0, !!recovery_verify("abacus zoom zit zone zippy", "not-a-hash"));
    TEST_ASSERT_EQUAL(0, !!recovery_verify(NULL, hash));
}

int main(void) {
    UnityBegin("recovery_tests");
    RUN_TEST(test_generate_has_five_wordlist_words);
    RUN_TEST(test_two_codes_differ);
    RUN_TEST(test_hash_is_yescrypt_and_verifies);
    RUN_TEST(test_verify_normalises_case_and_spacing);
    RUN_TEST(test_hyphenated_words_round_trip);
    RUN_TEST(test_verify_rejects_wrong_and_garbage);
    UnityEnd();
    return UnityTestsFailed ? 1 : 0;
}
