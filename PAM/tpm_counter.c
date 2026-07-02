#include "tpm_counter.h"
#include "log_manager.h"

#include <sys/syslog.h>
#include <tss2/tss2_esys.h>

static const char *TAG = "tpm_counter";

// TPM2_NT_COUNTER type
#define SPARK_TPM_NV_INDEX 0x01800020

static ESYS_CONTEXT *tpm_open(void) {
    ESYS_CONTEXT *esys = NULL;
    if (Esys_Initialize(&esys, NULL, NULL) != TSS2_RC_SUCCESS) {
        custom_log(LOG_WARNING, TAG, "Esys_Initialize failed (no TPM?)");
        return NULL;
    }
    return esys;
}

static int nv_get_or_define(ESYS_CONTEXT *esys, ESYS_TR *nv) {
    if (Esys_TR_FromTPMPublic(esys, SPARK_TPM_NV_INDEX,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, nv) == TSS2_RC_SUCCESS) {
        return 1;
    }

    TPMA_NV attrs = TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA |
                    (((TPMA_NV) TPM2_NT_COUNTER << 4) & TPMA_NV_TPM2_NT_MASK);

    TPM2B_NV_PUBLIC pub = {0};
    pub.nvPublic.nvIndex = SPARK_TPM_NV_INDEX;
    pub.nvPublic.nameAlg = TPM2_ALG_SHA256;
    pub.nvPublic.attributes = attrs;
    pub.nvPublic.dataSize = 8;  // 64-bit counter

    TPM2B_AUTH empty = {0};
    // Defining in the owner hierarchy needs owner auth (empty on a typical TPM).
    TSS2_RC rc = Esys_NV_DefineSpace(esys, ESYS_TR_RH_OWNER,
                                     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                     &empty, &pub, nv);
    if (rc != TSS2_RC_SUCCESS) {
        custom_log(LOG_WARNING, TAG, "NV_DefineSpace failed: 0x%x", rc);
        return 0;
    }
    return 1;
}

static int read_value(ESYS_CONTEXT *esys, ESYS_TR nv, uint64_t *out) {
    TPM2B_MAX_NV_BUFFER *data = NULL;
    TSS2_RC rc = Esys_NV_Read(esys, nv, nv, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              8, 0, &data);
    if (rc != TSS2_RC_SUCCESS) {
        // A freshly defined counter reads as uninitialised until first increment.
        custom_log(LOG_INFO, TAG, "NV_Read rc=0x%x (treating as 0)", rc);
        return 0;
    }
    uint64_t v = 0;
    for (UINT16 i = 0; i < data->size && i < 8; i++) {
        v = (v << 8) | data->buffer[i];
    }
    Esys_Free(data);
    *out = v;
    return 1;
}

int tpm_counter_bump(uint64_t *out) {
    ESYS_CONTEXT *esys = tpm_open();
    if (!esys) return -1;

    int result = -1;
    ESYS_TR nv = ESYS_TR_NONE;
    if (!nv_get_or_define(esys, &nv)) goto cleanup;

    if (Esys_NV_Increment(esys, nv, nv, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE)
        != TSS2_RC_SUCCESS) {
        custom_log(LOG_WARNING, TAG, "NV_Increment failed");
        goto cleanup;
    }

    uint64_t v = 0;
    if (!read_value(esys, nv, &v)) goto cleanup;
    if (out) *out = v;
    result = 0;

cleanup:
    Esys_Finalize(&esys);
    return result;
}

int tpm_counter_read(uint64_t *out) {
    ESYS_CONTEXT *esys = tpm_open();
    if (!esys) return -1;

    int result = -1;
    ESYS_TR nv = ESYS_TR_NONE;
    if (!nv_get_or_define(esys, &nv)) goto cleanup;

    uint64_t v = 0;
    read_value(esys, nv, &v);
    if (out) *out = v;
    result = 0;

cleanup:
    Esys_Finalize(&esys);
    return result;
}
