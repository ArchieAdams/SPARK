//
// Created by archiea on 05/03/26.
//

#ifndef MESSAGE_MANAGER_H
#define MESSAGE_MANAGER_H

#include <stddef.h>

#define CHALLENGE_RANDOM_SIZE 32
#define CHALLENGE_TIMESTAMP_SIZE 8
#define CHALLENGE_RESPONSE_SIZE (CHALLENGE_RANDOM_SIZE + CHALLENGE_TIMESTAMP_SIZE)
#define CHALLENGE_MESSAGE_SIZE 48


int generate_signed_and_encrypted_message(
    unsigned char *message,
    size_t *message_len,
    unsigned char *expected_response,
    size_t *expected_response_len
);

int process_signed_and_encrypted_response(
    const char *hex_input,
    unsigned char *output_message,
    size_t *output_len
);

int validate_challenge_response(
    const unsigned char *expected_response,
    size_t expected_response_len,
    const unsigned char *actual_response,
    size_t actual_response_len
);

#endif //MESSAGE_MANAGER_H
