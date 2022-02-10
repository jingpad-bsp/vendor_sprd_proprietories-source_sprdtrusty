/*
 *  faceid_ca_ta.h
 *
 *  Copyright (C) 2018 Unisoc Inc.
 *  History:
 *      <Date> 2018/09/29
 *      <Name>
 *  Description: faceid ca ta shared data struct
 */

#pragma once

#include <hardware/hw_auth_token.h>

#define FACEID_PORT "com.android.trusty.faceid"

#define DEFAULT_FACEID 0x00AB

// Commands
enum faceid_command {
    FACEID_RESP_BIT                      = 1,
    FACEID_REQ_SHIFT                     = 1,

    FACEID_PRE_ENROLL                    = (0 << FACEID_REQ_SHIFT),
    FACEID_ENROLL                        = (1 << FACEID_REQ_SHIFT),
    FACEID_DO_ENROLL_PROCESS             = (2 << FACEID_REQ_SHIFT),
    FACEID_POST_ENROLL                   = (3 << FACEID_REQ_SHIFT),
    FACEID_GET_AUTHENTICATOR_ID          = (4 << FACEID_REQ_SHIFT),
    FACEID_CANCEL                        = (5 << FACEID_REQ_SHIFT),
    FACEID_REMOVE                        = (6 << FACEID_REQ_SHIFT),
    FACEID_SET_ACTIVE_GROUP              = (7 << FACEID_REQ_SHIFT),
    FACEID_AUTHENTICATE                  = (8 << FACEID_REQ_SHIFT),
    FACEID_DO_AUTHENTICATE_PROCESS       = (9 << FACEID_REQ_SHIFT),
    FACEID_UPDATE_PROP                   = (10 << FACEID_REQ_SHIFT),
    FACEID_DUMP                          = (11 << FACEID_REQ_SHIFT),
    FACEID_VERIFY_TOKEN                  = (12 << FACEID_REQ_SHIFT),
};

/**
 * faceid_message - Serial header for communicating with face server
 * @cmd: the command, one of faceid_command.
 * @payload: start of the serialized command specific payload
 */
typedef struct faceid_message {
    uint32_t cmd;
    uint8_t payload[0];
} faceid_message_t;

/*
 * messages used in specific transmission
 */

struct face_pre_enroll_rsp {
    int32_t error;
    uint64_t challenge;
} __attribute__((__packed__));

struct face_hat_req {
    hw_auth_token_t hat;
} __attribute__((__packed__));

struct face_enroll_req {
    uint32_t gid;
    uint32_t timeout_sec;
    int32_t width;
    int32_t height;
} __attribute__((__packed__));

struct face_do_enroll_process_req {
    int64_t addr;
    int64_t lm_addr;
    int32_t count;
    int32_t byteCount;
    int32_t timestamp;
} __attribute__((__packed__));

struct face_do_enroll_process_rsp {
    int32_t help;
    uint32_t progress;
    uint32_t fid;
    int32_t error;
} __attribute__((__packed__));

struct face_get_authenticator_id_rsp {
    int32_t error;
    uint64_t authenticator_id;
} __attribute__((__packed__));

struct face_remove_req {
    uint32_t gid;
    uint32_t fid;
} __attribute__((__packed__));

struct face_authenticate_req {
    uint32_t gid;
    int32_t width;
    int32_t height;
    uint64_t operation_id;
} __attribute__((__packed__));

struct face_do_authenticate_process_req {
    int64_t main;
    int64_t sub;
    int64_t otp;
    int64_t lm_addr;
    int32_t count;
    int32_t byteCount;
    int32_t help;
    int32_t timestamp;
} __attribute__((__packed__));

struct face_do_authenticate_process_rsp {
    int32_t help;
    uint32_t fid;
    int32_t error;
    hw_auth_token_t hat;
} __attribute__((__packed__));

struct face_common_rsp {
    int32_t error;
} __attribute__((__packed__));

typedef enum faceid_prop_bit {
    CAMERA_TYPE_BIT          = 0,
    ENROLL_DUMP_BIT          = 2,
    AUTH_DUMP_BIT            = 4,
    LIVENESS_MODE_BIT        = 6,
    ENROLL_DUMP_FEATURE_BIT = 7,
    IS_DEBUGGABLE_BIT = 8,
} faceid_prop_bit_t;
