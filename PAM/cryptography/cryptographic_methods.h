#ifndef CRYPTOGRAPHIC_METHODS_H
#define CRYPTOGRAPHIC_METHODS_H

#include <stddef.h>
#include <openssl/evp.h>



int crypto_sign_ec(const unsigned char *message, size_t message_len, EVP_PKEY *private_key,
                   unsigned char *signature, size_t *signature_len);

int crypto_verify_ec(const unsigned char *message, size_t message_len,
                     const unsigned char *signature, size_t signature_len,
                     EVP_PKEY *public_key);

int crypto_generate_x25519_keypair(EVP_PKEY **private_key, unsigned char public_key[32]);

int crypto_derive_x25519_secret(EVP_PKEY *private_key, const unsigned char peer_public[32],
                                unsigned char shared_secret[32]);


void crypto_derive_response_key_iv(const unsigned char shared_secret[32],
                                   const unsigned char *transcript,
                                   size_t transcript_len,
                                   unsigned char key[32],
                                   unsigned char iv_req[12],
                                   unsigned char iv_resp[12]);

int crypto_aead_encrypt(const unsigned char key[32], const unsigned char iv[12],
                        const unsigned char *plaintext, size_t plaintext_len,
                        const unsigned char *aad, size_t aad_len,
                        unsigned char *ciphertext, size_t *ciphertext_len);

int crypto_aead_decrypt(const unsigned char key[32], const unsigned char iv[12],
                        const unsigned char *ciphertext, size_t ciphertext_len,
                        const unsigned char *aad, size_t aad_len,
                        unsigned char *plaintext, size_t *plaintext_len);

#endif // CRYPTOGRAPHIC_METHODS_H
