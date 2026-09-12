#ifndef SPARK_RECOVERY_H
#define SPARK_RECOVERY_H

#include <stddef.h>
#include <crypt.h>

#define RECOVERY_CODES     3
#define RECOVERY_WORDS     5
#define RECOVERY_CODE_MAX  64
#define RECOVERY_HASH_MAX  CRYPT_OUTPUT_SIZE

int recovery_generate_code(char *out, size_t outlen);
int recovery_hash(const char *code, char *out, size_t outlen);
int recovery_verify(const char *input, const char *hash);  // 1 = match

#endif
