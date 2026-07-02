cmake_minimum_required(VERSION 3.29)
project(Authenticator C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -Wall")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(PkgConfig REQUIRED)
pkg_check_modules(BLUEZ REQUIRED bluez)
pkg_check_modules(WEBSOCKETS REQUIRED libwebsockets)
pkg_check_modules(CJSON REQUIRED IMPORTED_TARGET libcjson)
pkg_check_modules(TSS2_ESYS REQUIRED tss2-esys)  # TPM 2.0 NV monotonic counter

enable_testing()

set(COMMON_SOURCES
        config_manager.c
        tpm_counter.c
        communication/connection_manager.c
        communication/message_manager.c
        communication/phone_connection.c
        communication/websocket/websocket.c
        communication/websocket/websocket_service.c
        communication/websocket/udp_broadcast.c
        communication/bluetooth/bt_client.c
        communication/bluetooth/bluetooth_service.c
        communication/bluetooth/sdp_manager.c
        cryptography/key_manager.c
        cryptography/cryptographic_methods.c
        authenticator.c
        log_manager.c
        time_utils.c
        time_utils.h
        communication/frame.c
        communication/messages.c
        communication/sas.c
        communication/channel.c
        communication/pairing.c
        communication/transport.c
)

add_executable(Authenticator
        main.c
        pairing_server.c
        setup_server.c
        ${COMMON_SOURCES}
)

add_executable(frame_codec_tests
        tests/frame_codec_tests.c
        tests/unity.c
        communication/frame.c
)

set_source_files_properties(communication/frame.c PROPERTIES LANGUAGE C)

target_include_directories(Authenticator PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/communication
        ${CMAKE_SOURCE_DIR}/cryptography
        ${BLUEZ_INCLUDE_DIRS}
        ${WEBSOCKETS_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${TSS2_ESYS_INCLUDE_DIRS}
        PkgConfig::CJSON
)

target_include_directories(frame_codec_tests PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/communication
        ${CMAKE_SOURCE_DIR}/tests
)

add_test(NAME frame_codec_tests COMMAND frame_codec_tests)

add_executable(comms_tests
        communication/frame.c
        communication/messages.c
        communication/sas.c
        communication/channel.c
        communication/pairing.c
)

target_include_directories(comms_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/communication
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(comms_tests PRIVATE ${OPENSSL_LIBRARIES} pthread)

add_test(NAME comms_tests COMMAND comms_tests)

add_executable(crypto_envelope_tests
        tests/crypto_envelope_tests.c
        tests/unity.c
        cryptography/cryptographic_methods.c
        log_manager.c
)

target_include_directories(crypto_envelope_tests PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/cryptography
        ${CMAKE_SOURCE_DIR}/tests
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(crypto_envelope_tests PRIVATE ${OPENSSL_LIBRARIES})

add_test(NAME crypto_envelope_tests COMMAND crypto_envelope_tests)

find_library(WEBSOCKETS_LIB websockets)
target_link_libraries(Authenticator PRIVATE
    bluetooth pthread ${WEBSOCKETS_LIB} ${OPENSSL_LIBRARIES} ${TSS2_ESYS_LIBRARIES} PkgConfig::CJSON)

add_library(pam_authenticator SHARED
        pam_authenticator.c
        ${COMMON_SOURCES}
)

target_include_directories(pam_authenticator PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/communication
        ${CMAKE_SOURCE_DIR}/cryptography
        ${BLUEZ_INCLUDE_DIRS}
        ${WEBSOCKETS_INCLUDE_DIRS}
        ${TSS2_ESYS_INCLUDE_DIRS}
        PkgConfig::CJSON
)

target_link_libraries(pam_authenticator PRIVATE
        pam
        bluetooth
        pthread
        ${TSS2_ESYS_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        ${WEBSOCKETS_LIBRARIES}
        ${BLUEZ_LIBRARIES}
        PkgConfig::CJSON
)

set_target_properties(pam_authenticator PROPERTIES PREFIX "")
set_target_properties(pam_authenticator PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/pam"
)

