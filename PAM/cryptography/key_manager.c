#include "key_manager.h"
#include "../log_manager.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <tss2/tss2_esys.h>

static const char *TAG = "key_manager";
static const char *HANDLE_FILE_DEFAULT = "/etc/AuthApp/pki/pc.handle";
static const char *PUBLIC_FILE_DEFAULT = "/etc/AuthApp/pki/pc.pub";
static const ESYS_TR TPM_KEY_HANDLE = 0x81010001;

static ESYS_CONTEXT *tpm_open(void) {
    ESYS_CONTEXT *esys = NULL;
    if (Esys_Initialize(&esys, NULL, NULL) != TSS2_RC_SUCCESS) {
        custom_log(LOG_WARNING, TAG, "Esys_Initialize failed (no TPM?)");
        return NULL;
    }
    return esys;
}

static int write_text_file(const char *path, const char *text) {
    FILE *f = fopen(path, "wb");
    if (!f)
        return 0;
    int ok = fputs(text, f) >= 0;
    fclose(f);
    return ok;
}

static int read_persistent_handle(const char *path, ESYS_TR *handle) {
    if (!handle)
        return 0;
    *handle = TPM_KEY_HANDLE;
    FILE *f = fopen(path, "rb");
    if (!f)
        return 1;
    unsigned int h = 0;
    int rc = fscanf(f, "%x", &h);
    fclose(f);
    if (rc == 1 && h != 0) {
        *handle = (ESYS_TR)h;
    }
    return 1;
}

static int write_public_pem_from_tpm_pub(const TPM2B_PUBLIC *pub, const char *public_key_file) {
    if (!pub || !public_key_file)
        return 0;
    if (pub->publicArea.type != TPM2_ALG_ECC ||
        pub->publicArea.parameters.eccDetail.curveID != TPM2_ECC_NIST_P256) {
        return 0;
    }

    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec)
        return 0;
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    EC_POINT *point = EC_POINT_new(group);
    BIGNUM *x =
        BN_bin2bn(pub->publicArea.unique.ecc.x.buffer, pub->publicArea.unique.ecc.x.size, NULL);
    BIGNUM *y =
        BN_bin2bn(pub->publicArea.unique.ecc.y.buffer, pub->publicArea.unique.ecc.y.size, NULL);
    int ok = 0;
    if (!point || !x || !y)
        goto cleanup;
    if (EC_POINT_set_affine_coordinates(group, point, x, y, NULL) != 1)
        goto cleanup;
    if (EC_KEY_set_public_key(ec, point) != 1)
        goto cleanup;

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey)
        goto cleanup;
    if (EVP_PKEY_set1_EC_KEY(pkey, ec) == 1) {
        FILE *f = fopen(public_key_file, "wb");
        if (f) {
            ok = PEM_write_PUBKEY(f, pkey) == 1;
            fclose(f);
        }
    }
    EVP_PKEY_free(pkey);

cleanup:
    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);
    EC_KEY_free(ec);
    return ok;
}

static int read_public_from_tpm(ESYS_CONTEXT *esys, ESYS_TR handle, const char *public_key_file) {
    TPM2B_PUBLIC *pub = NULL;
    TPM2B_NAME *name = NULL;
    TPM2B_NAME *qname = NULL;
    TSS2_RC rc = Esys_ReadPublic(esys, handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &pub,
                                 &name, &qname);
    if (rc != TSS2_RC_SUCCESS || !pub) {
        custom_log(LOG_ERR, TAG, "Esys_ReadPublic failed: 0x%x", rc);
        Esys_Free(name);
        Esys_Free(qname);
        return 0;
    }
    int ok = write_public_pem_from_tpm_pub(pub, public_key_file);
    Esys_Free(pub);
    Esys_Free(name);
    Esys_Free(qname);
    return ok;
}

static int create_persistent_p256_key(ESYS_CONTEXT *esys, ESYS_TR *persistent_handle) {
    TPM2B_SENSITIVE_CREATE in_sensitive = {0};
    TPM2B_PUBLIC in_public = {0};
    TPM2B_DATA outside = {0};
    TPML_PCR_SELECTION creation_pcr = {0};
    ESYS_TR primary = ESYS_TR_NONE;
    TPM2B_PUBLIC *out_public = NULL;
    TPM2B_PRIVATE *out_private = NULL;
    TPM2B_CREATION_DATA *creation_data = NULL;
    TPM2B_DIGEST *creation_hash = NULL;
    TPMT_TK_CREATION *creation_ticket = NULL;

    in_public.publicArea.type = TPM2_ALG_ECC;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public.publicArea.objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH |
                                            TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_FIXEDTPM |
                                            TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_NODA;
    in_public.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
    in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
    in_public.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
    in_public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    in_public.publicArea.unique.ecc.x.size = 0;
    in_public.publicArea.unique.ecc.y.size = 0;

    TSS2_RC rc =
        Esys_CreatePrimary(esys, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &in_sensitive, &in_public, &outside, &creation_pcr, &primary,
                           &out_public, &creation_data, &creation_hash, &creation_ticket);
    if (rc != TSS2_RC_SUCCESS) {
        custom_log(LOG_ERR, TAG, "Esys_CreatePrimary failed: 0x%x", rc);
        goto cleanup;
    }

    rc = Esys_EvictControl(esys, ESYS_TR_RH_OWNER, primary, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, TPM_KEY_HANDLE, persistent_handle);
    if (rc != TSS2_RC_SUCCESS) {
        custom_log(LOG_ERR, TAG, "Esys_EvictControl failed: 0x%x", rc);
        goto cleanup;
    }

    if (!read_public_from_tpm(esys, *persistent_handle, PUBLIC_FILE_DEFAULT))
        goto cleanup;

cleanup:
    Esys_Free(out_public);
    Esys_Free(out_private);
    Esys_Free(creation_data);
    Esys_Free(creation_hash);
    Esys_Free(creation_ticket);
    if (primary != ESYS_TR_NONE)
        Esys_TR_Close(esys, &primary);
    return (*persistent_handle != ESYS_TR_NONE);
}

static int encode_ecdsa_der(const TPMT_SIGNATURE *sig, unsigned char **out, size_t *out_len) {
    if (!sig || !out || !out_len)
        return 0;
    ECDSA_SIG *ecdsa = ECDSA_SIG_new();
    if (!ecdsa)
        return 0;
    BIGNUM *r = BN_bin2bn(sig->signature.ecdsa.signatureR.buffer,
                          sig->signature.ecdsa.signatureR.size, NULL);
    BIGNUM *s = BN_bin2bn(sig->signature.ecdsa.signatureS.buffer,
                          sig->signature.ecdsa.signatureS.size, NULL);
    if (!r || !s || ECDSA_SIG_set0(ecdsa, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(ecdsa);
        return 0;
    }
    int len = i2d_ECDSA_SIG(ecdsa, NULL);
    if (len <= 0) {
        ECDSA_SIG_free(ecdsa);
        return 0;
    }
    unsigned char *buf = OPENSSL_malloc((size_t)len);
    unsigned char *p = buf;
    if (!buf || i2d_ECDSA_SIG(ecdsa, &p) != len) {
        OPENSSL_free(buf);
        ECDSA_SIG_free(ecdsa);
        return 0;
    }
    *out = buf;
    *out_len = (size_t)len;
    ECDSA_SIG_free(ecdsa);
    return 1;
}

static int hash_sha256(const unsigned char *message, size_t message_len,
                       unsigned char digest[SHA256_DIGEST_LENGTH]) {
    unsigned int out_len = 0;
    return EVP_Digest(message, message_len, digest, &out_len, EVP_sha256(), NULL) == 1 &&
           out_len == SHA256_DIGEST_LENGTH;
}

int key_manager_generate_ec_keypair(const char *private_key_file, const char *public_key_file) {
    if (!private_key_file || !public_key_file)
        return 0;

    mkdir("/etc/AuthApp", 0755);
    mkdir("/etc/AuthApp/pki", 0700);

    ESYS_TR handle = ESYS_TR_NONE;
    if (!read_persistent_handle(private_key_file, &handle))
        return 0;

    ESYS_CONTEXT *esys = tpm_open();
    if (!esys)
        return 0;

    int ok = 0;
    ESYS_TR obj = ESYS_TR_NONE;
    bool flush_obj = true;
    if (Esys_TR_FromTPMPublic(esys, handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &obj) ==
        TSS2_RC_SUCCESS) {
        ok = read_public_from_tpm(esys, obj, public_key_file) &&
             write_text_file(private_key_file, "81010001\n");
    } else {
        if (!create_persistent_p256_key(esys, &obj))
            goto cleanup;
        ok = write_text_file(private_key_file, "81010001\n");
        flush_obj = false;
    }

cleanup:
    if (flush_obj && obj != ESYS_TR_NONE)
        Esys_TR_Close(esys, &obj);
    Esys_Finalize(&esys);
    return ok;
}

int key_manager_tpm_sign_p256(const char *handle_file, const unsigned char *message,
                              size_t message_len, unsigned char **signature_der,
                              size_t *signature_der_len) {
    if (!message || !signature_der || !signature_der_len)
        return 0;
    *signature_der = NULL;
    *signature_der_len = 0;

    ESYS_TR handle = ESYS_TR_NONE;
    if (!read_persistent_handle(handle_file ? handle_file : HANDLE_FILE_DEFAULT, &handle))
        return 0;

    ESYS_CONTEXT *esys = tpm_open();
    if (!esys)
        return 0;

    ESYS_TR obj = ESYS_TR_NONE;
    if (Esys_TR_FromTPMPublic(esys, handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &obj) !=
        TSS2_RC_SUCCESS) {
        Esys_Finalize(&esys);
        return 0;
    }

    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (!hash_sha256(message, message_len, digest)) {
        Esys_TR_Close(esys, &obj);
        Esys_Finalize(&esys);
        return 0;
    }

    TPM2B_DIGEST in_digest = {.size = SHA256_DIGEST_LENGTH};
    memcpy(in_digest.buffer, digest, SHA256_DIGEST_LENGTH);

    TPMT_SIG_SCHEME scheme = {0};
    scheme.scheme = TPM2_ALG_ECDSA;
    scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;

    TPMT_TK_HASHCHECK validation = {0};
    validation.tag = TPM2_ST_HASHCHECK;
    validation.hierarchy = TPM2_RH_NULL;

    TPMT_SIGNATURE *sig = NULL;
    TSS2_RC rc = Esys_Sign(esys, obj, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &in_digest,
                           &scheme, &validation, &sig);
    int ok = 0;
    if (rc == TSS2_RC_SUCCESS && sig && sig->sigAlg == TPM2_ALG_ECDSA) {
        ok = encode_ecdsa_der(sig, signature_der, signature_der_len);
    }

    Esys_Free(sig);
    Esys_TR_Close(esys, &obj);
    Esys_Finalize(&esys);
    return ok;
}

int key_manager_load_private_key(const char *filepath, EVP_PKEY **out_key) {
    if (!filepath || !out_key)
        return 0;
    *out_key = NULL;

    FILE *f = fopen(filepath, "rb");
    if (!f)
        return 0;

    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!k)
        return 0;

    *out_key = k;
    return 1;
}

int key_manager_load_public_key(const char *filepath, EVP_PKEY **out_key) {
    if (!filepath || !out_key)
        return 0;
    *out_key = NULL;

    FILE *f = fopen(filepath, "rb");
    if (!f)
        return 0;

    EVP_PKEY *k = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!k)
        return 0;

    *out_key = k;
    return 1;
}

void key_manager_free_key(EVP_PKEY *key) {
    if (key)
        EVP_PKEY_free(key);
}
