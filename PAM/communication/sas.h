#ifndef SPARK_SAS_H
#define SPARK_SAS_H

#include <stddef.h>
#include <stdint.h>

void sas_compute(const uint8_t *n, size_t nlen,
                 const uint8_t *pkv, size_t pkvlen,
                 const uint8_t *pka, size_t pkalen,
                 char out[7]);

#endif
