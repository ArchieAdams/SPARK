//
// Created by archiea on 05/03/26.
//

#ifndef CRYPTOGRAPHIC_METHODS_H
#define CRYPTOGRAPHIC_METHODS_H

#include <stddef.h>
#include <openssl/evp.h>


int crypto_sign_and_encrypt_with_keys(
    const unsigned char *m,
    size_t ml,
    const unsigned char *sign_extra,
    size_t extra_len,
    EVP_PKEY *sk,
    EVP_PKEY *pk,
    unsigned char *o,
    size_t *ol
);

int crypto_decrypt_and_verify_with_keys(
    const unsigned char *i,
    size_t il,
    const unsigned char *sign_extra,
    size_t extra_len,
    EVP_PKEY *sk,
    EVP_PKEY *verify_pk,
    unsigned char *m,
    size_t *ml
);

#endif // CRYPTOGRAPHIC_METHODS_H
