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

#define SOTER_PORT "com.android.trusty.soter"

// Commands
enum soter_command {
    SOTER_RESP_BIT              = 1,
    SOTER_REQ_SHIFT             = 1,

    SOTER_GENERATE_ATTK    = (1 << SOTER_REQ_SHIFT),
    SOTER_VERIFY_ATTK      = (2 << SOTER_REQ_SHIFT),
    SOTER_EXPORT_ATTK      = (3 << SOTER_REQ_SHIFT),
    SOTER_SET_DEVICE_ID    = (4 << SOTER_REQ_SHIFT),
    SOTER_GET_DEVICE_ID    = (5 << SOTER_REQ_SHIFT),

    SOTER_GENERATE_ASK     = (6 << SOTER_REQ_SHIFT),
    SOTER_EXPORT_ASK       = (7 << SOTER_REQ_SHIFT),
    SOTER_REMOVE_ALL_KEY   = (8 << SOTER_REQ_SHIFT),
    SOTER_CHECK_ASK        = (9 << SOTER_REQ_SHIFT),

    SOTER_GENERATE_AUTH_KEY= (10 << SOTER_REQ_SHIFT),
    SOTER_EXPORT_AUTH_KEY  = (11 << SOTER_REQ_SHIFT),
    SOTER_REMOVE_AUTH_KEY  = (12 << SOTER_REQ_SHIFT),
    SOTER_CHECK_AUTH_KEY   = (13 << SOTER_REQ_SHIFT),

    SOTER_INIT_SIGN        = (14 << SOTER_REQ_SHIFT),
    SOTER_FINISH_SIGN      = (15 << SOTER_REQ_SHIFT),
};

/**
 * soter_message - Serial header for communicating with face server
 * @cmd: the command, one of soter_command.
 * @payload: start of the serialized command specific payload
 */
struct soter_message {
    uint32_t cmd;
    uint8_t payload[0];
};

/*
 * messages used in specific transmission
 */
struct soter_ta_rlt {
    int32_t error;
    uint8_t data[0];
} __attribute__((__packed__));

struct soter_ak_req {
    uint32_t uid;
    char name[128];
} __attribute__((__packed__));

typedef struct soter_init_req {
    uint32_t uid;
    char name[128];
    char challenge[256];
} soter_init_req_t;

typedef struct soter_finish_req {
    uint64_t session;
} soter_finish_req_t;
