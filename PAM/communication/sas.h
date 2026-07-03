#ifndef SPARK_SAS_H
#define SPARK_SAS_H

#include <stddef.h>
#include <stdint.h>

uint32_t sas_compute(const uint8_t *n, size_t nlen,
                     const uint8_t *pkv, size_t pkvlen,
                     const uint8_t *pka, size_t pkalen);

void sas_emoji(uint32_t val, char *out, size_t outlen);

#endif
