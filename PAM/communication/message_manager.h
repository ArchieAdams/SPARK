#ifndef MESSAGE_MANAGER_H
#define MESSAGE_MANAGER_H

#include <stddef.h>
#include <stdint.h>

#define CHALLENGE_X25519_PUBLIC_SIZE 32

/* Verifier (PC) steps for the SPARK-AUTH-v2 protocol */

/**
 * Step 1: Generate a fresh X25519 ephemeral key pair for the verifier.
 * @param ephV Output buffer for the 32-byte X25519 public key.
 * @return 1 on success, 0 on failure.
 */
int auth_verifier_step1(uint8_t ephV[32]);

/**
 * Step 3: Receive phone's ephemeral key, derive session key K, and prepare C3.
 * C3 contains the verifier's signature (sigmaV) over the transcript, encrypted with K.
 * @param ephA The 32-byte X25519 public key received from the phone.
 * @param c3 Output buffer for the AEAD ciphertext C3.
 * @param c3_len In/out parameter for C3 buffer capacity and actual ciphertext length.
 * @return 1 on success, 0 on failure.
 */
int auth_verifier_step3(const uint8_t ephA[32], uint8_t *c3, size_t *c3_len);

/**
 * Step 5: Receive C4 from phone, decrypt it to recover sigmaA, and verify phone's signature.
 * @param c4 The AEAD ciphertext C4 received from the phone.
 * @param c4_len Length of C4.
 * @return 1 on successful verification, 0 on failure.
 */
int auth_verifier_step5(const uint8_t *c4, size_t c4_len);

/**
 * Clean up all ephemeral session state and zeroize keys where appropriate.
 */
void auth_verifier_cleanup(void);

#endif // MESSAGE_MANAGER_H
