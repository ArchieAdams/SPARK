#include "unity.h"
#include "communication/frame.h"

static void test_encode_writes_header_bytes(void) {
    const uint8_t payload[] = {0x10, 0x20, 0x30, 0x40};
    uint8_t out[FRAME_HEADER_LEN + sizeof(payload)] = {0};
    Message message;

    message.type = MSG_COMMIT;
    message.seq = 0x01020304;
    message.payload = payload;
    message.payload_len = (uint32_t)sizeof(payload);

    TEST_ASSERT_EQUAL((ssize_t)sizeof(out), frame_encode(message, out, sizeof(out)));
    TEST_ASSERT_EQUAL(FRAME_MAGIC0, out[0]);
    TEST_ASSERT_EQUAL(FRAME_MAGIC1, out[1]);
    TEST_ASSERT_EQUAL(FRAME_VERSION, out[2]);
    TEST_ASSERT_EQUAL(MSG_COMMIT, out[3]);
}

static void test_encode_writes_payload_bytes(void) {
    const uint8_t payload[] = {0x10, 0x20, 0x30, 0x40};
    uint8_t out[FRAME_HEADER_LEN + sizeof(payload)] = {0};
    Message message;

    message.type = MSG_COMMIT;
    message.seq = 0x01020304;
    message.payload = payload;
    message.payload_len = (uint32_t)sizeof(payload);

    TEST_ASSERT_EQUAL((ssize_t)sizeof(out), frame_encode(message, out, sizeof(out)));
    TEST_ASSERT_EQUAL_MEMORY(payload, out + FRAME_HEADER_LEN, sizeof(payload));
}

static void test_decode_reads_fields(void) {
    const uint8_t payload[] = {0x10, 0x20, 0x30, 0x40};
    uint8_t out[FRAME_HEADER_LEN + sizeof(payload)] = {0};
    Message message;
    Message decoded;

    message.type = MSG_COMMIT;
    message.seq = 0x01020304;
    message.payload = payload;
    message.payload_len = (uint32_t)sizeof(payload);

    TEST_ASSERT_EQUAL((ssize_t)sizeof(out), frame_encode(message, out, sizeof(out)));
    TEST_ASSERT_EQUAL(0, frame_decode(out, sizeof(out), &decoded, sizeof(payload)));
    TEST_ASSERT_EQUAL(MSG_COMMIT, decoded.type);
    TEST_ASSERT_EQUAL(0x01020304, decoded.seq);
    TEST_ASSERT_EQUAL((uint32_t)sizeof(payload), decoded.payload_len);
    TEST_ASSERT_NOT_NULL(decoded.payload);
    TEST_ASSERT_EQUAL_MEMORY(payload, decoded.payload, sizeof(payload));
}

static void test_decode_rejects_small_frame(void) {
    uint8_t frame[FRAME_HEADER_LEN - 1] = {0};
    Message decoded;

    TEST_ASSERT_EQUAL(FRAME_TOO_SMALL, frame_decode(frame, sizeof(frame), &decoded, 4));
}

static void test_decode_rejects_magic(void) {
    const uint8_t payload[] = {0x10, 0x20, 0x30, 0x40};
    uint8_t out[FRAME_HEADER_LEN + sizeof(payload)] = {0};
    Message message;
    Message decoded;

    message.type = MSG_COMMIT;
    message.seq = 0x01020304;
    message.payload = payload;
    message.payload_len = (uint32_t)sizeof(payload);

    TEST_ASSERT_EQUAL((ssize_t)sizeof(out), frame_encode(message, out, sizeof(out)));
    out[0] = 0x00;

    TEST_ASSERT_EQUAL(INVALID_MAGIC_BITS, frame_decode(out, sizeof(out), &decoded, sizeof(payload)));
}

int main(void) {
    UnityBegin("frame_codec_tests");
    RUN_TEST(test_encode_writes_header_bytes);
    RUN_TEST(test_encode_writes_payload_bytes);
    RUN_TEST(test_decode_reads_fields);
    RUN_TEST(test_decode_rejects_small_frame);
    RUN_TEST(test_decode_rejects_magic);
    UnityEnd();
    return UnityTestsFailed == 0 ? 0 : 1;
}

