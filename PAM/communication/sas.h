#ifndef SPARK_SAS_H
#define SPARK_SAS_H

#include <stddef.h>
#include <stdint.h>

uint32_t sas_compute(const uint8_t *pkv, size_t pkvlen,
                     const uint8_t *pka, size_t pkalen,
                     const uint8_t *nv, size_t nvlen,
                     const uint8_t *r, size_t rlen,
                     const uint8_t *na, size_t nalen);

void sas_emoji(uint32_t val, char *out, size_t outlen);

#endif
