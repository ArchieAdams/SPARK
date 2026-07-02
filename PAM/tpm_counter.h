#ifndef TPM_COUNTER_H
#define TPM_COUNTER_H

#include <stdint.h>

int tpm_counter_bump(uint64_t *out);

int tpm_counter_read(uint64_t *out);

#endif // TPM_COUNTER_H
