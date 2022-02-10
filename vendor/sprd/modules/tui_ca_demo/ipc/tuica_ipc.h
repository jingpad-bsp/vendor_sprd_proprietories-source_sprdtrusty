/*
 * Copyright (C) 2015 The Android Open Source Project
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

__BEGIN_DECLS

#define TADEMO_PORT "com.android.trusty.tui"

#define TADEMO_MAX_BUFFER_LENGTH 1024

enum tademo_command {
    TUITA_REQ_SHIFT = 1,
    TUITA_RESP_BIT  = 1,

    TUITA_DISP       = (0 << TUITA_REQ_SHIFT),
    TUITA_CALL_FROME_OTHER_TA     = (1 << TUITA_REQ_SHIFT),
    TUITA_FONT_PREPARE    = (2 << TUITA_REQ_SHIFT),

};

typedef enum {
    ERROR_NONE = 0,
    ERROR_FIRST = 1,
    ERROR_UNKNOWN = 2,
} tademo_error_t;


/**
 * tademo_message - Serial header for communicating with ta server
 * @cmd: the command, one of xx, xx. Payload must be a serialized
 *       buffer of the corresponding request object.
 * @payload: start of the serialized command specific payload
 */
struct tademo_message {
    uint32_t cmd;
    uint8_t payload[0];
};


int trusty_cademo_connect();
int trusty_cademo_call(uint32_t cmd, uint8_t* in, uint32_t in_size, uint8_t* out,
                       uint32_t* out_size);
void trusty_cademo_disconnect();

__END_DECLS
