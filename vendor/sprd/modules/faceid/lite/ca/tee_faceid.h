/*
 * Copyright (C) 2018 Spreadtrum Communications Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once
#include <hardware/hw_auth_token.h>

#define FACEID_PORT "com.android.trusty.faceid"

//typedef int16_t ff_type;
typedef float ff_type;
#define DEF_FACEID_FEATURE_COUNT  512
#define DEF_FACEID_FEATURE_LENGTH (DEF_FACEID_FEATURE_COUNT*sizeof(ff_type))

// Commands
enum faceid_command {
    FACEID_RESP_BIT              = 1,
    FACEID_REQ_SHIFT             = 1,

    FACEID_SAVE_TEMPLATE         = (0 << FACEID_REQ_SHIFT),
    FACEID_REMOVE_TEMPLATE       = (1 << FACEID_REQ_SHIFT),
    FACEID_INIT_AUTH             = (2 << FACEID_REQ_SHIFT),
    FACEID_DO_COMPARE            = (3 << FACEID_REQ_SHIFT),
    FACEID_DO_COMPARE2           = (4 << FACEID_REQ_SHIFT),
    FACEID_PRE_ENROLL            = (5 << FACEID_REQ_SHIFT),
    FACEID_ENROLL                = (6 << FACEID_REQ_SHIFT),
    FACEID_POST_ENROLL           = (7 << FACEID_REQ_SHIFT),
    FACEID_GET_AUTH_TOKEN        = (8 << FACEID_REQ_SHIFT),
    FACEID_GET_AUTHENTICATOR_ID  = (9 << FACEID_REQ_SHIFT),
    FACEID_GET_TEMPLATE_COUNT    = (10 << FACEID_REQ_SHIFT),
};

/**
 * faceid_message - Serial header for communicating with face server
 * @cmd: the command, one of faceid_command.
 * @payload: start of the serialized command specific payload
 */
struct faceid_message {
    uint32_t cmd;
    uint8_t payload[0];
};

/*
 * messages used in specific transmission
 */
struct face_save_req {
    uint32_t gid;
    uint32_t index;
    uint32_t count;
    uint8_t feature[DEF_FACEID_FEATURE_LENGTH];
} __attribute__((__packed__));

struct face_remove_req {
    uint32_t gid;
} __attribute__((__packed__));

struct face_auth_init_req {
    uint32_t gid;
    uint64_t operation_id;
} __attribute__((__packed__));

struct face_common_rsp {
    int32_t error;
} __attribute__((__packed__));

struct face_compare_req {
    uint32_t count;
    uint8_t feature[DEF_FACEID_FEATURE_LENGTH];
} __attribute__((__packed__));

struct face_compare_rsp {
    int32_t error;
    float max_score;
    float mean_score;
} __attribute__((__packed__));

//
struct face_preenroll_rsp {
    int32_t error;
    uint64_t challenge;
} __attribute__((__packed__));

struct face_enroll_req {
    hw_auth_token_t token;
}  __attribute__((__packed__));

struct face_get_token_rsp {
    int32_t error;
    hw_auth_token_t token;
} __attribute__((__packed__));

/* newly added: for get_template_count() */
struct face_get_tplcnt_req {
    uint32_t gid;
} __attribute__((__packed__));

