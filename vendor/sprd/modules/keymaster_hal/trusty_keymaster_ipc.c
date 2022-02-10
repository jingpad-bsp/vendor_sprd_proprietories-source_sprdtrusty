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

// TODO: make this generic in libtrusty

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "TrustyKeymaster"
#include <cutils/log.h>

#include <trusty/tipc.h>

#include "trusty_keymaster_ipc.h"
#include "keymaster_ipc.h"

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"

static int handle_ = -1;

int trusty_keymaster_connect() {
    int rc = tipc_connect(TRUSTY_DEVICE_NAME, KEYMASTER_PORT);
    if (rc < 0) {
        return rc;
    }

    handle_ = rc;
    return 0;
}

int trusty_keymaster_call(uint32_t cmd, void *in, uint32_t in_size, uint8_t *out,
                          uint32_t *out_size)  {
    if (handle_ < 0) {
        ALOGE("not connected\n");
        return -EINVAL;
    }

    size_t msg_size = in_size + sizeof(struct keymaster_message);
    struct keymaster_message *msg = malloc(msg_size);
    msg->cmd = cmd;
    memcpy(msg->payload, in, in_size);

    ssize_t rc = write(handle_, msg, msg_size);
    uint8_t* send_msg_buf = (uint8_t *)msg;
    size_t send_msg_size = msg_size;
    while ((rc < 0 && errno  == ENOMEM) || (rc > 0 && rc != send_msg_size )) {
        if (rc > 0) {
            send_msg_buf += rc;
            send_msg_size -= rc;
        }
        rc = write(handle_, send_msg_buf, send_msg_size);
    }
    free(msg);

    if (rc < 0) {
        ALOGE("failed to send cmd (%d) to %s: %s with rc(%d)\n", cmd,
                KEYMASTER_PORT, strerror(errno), rc);
        return -errno;
    }
    size_t out_max_size = *out_size;
    *out_size = 0;
    struct iovec iov[2];
    struct keymaster_message header;
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(struct keymaster_message);
    for(;;){
        iov[1].iov_base = out + *out_size;
        iov[1].iov_len =(KEYMASTER_MAX_BUFFER_LENGTH > out_max_size - *out_size)? \
            (out_max_size - *out_size):(KEYMASTER_MAX_BUFFER_LENGTH);
        rc = readv(handle_, iov, 2);
        if (rc < 0) {
            ALOGE("failed to retrieve response for cmd (%d) to %s: %s\n", cmd, KEYMASTER_PORT,
                  strerror(errno));
            return -errno;
        }

        if ((size_t)rc < sizeof(struct keymaster_message)) {
            ALOGE("invalid response size (%d)\n", (int)rc);
            return -EINVAL;
        }
        /*lint -e527*/
        if ((cmd | KEYMASTER_RESP_BIT) == header.cmd){
            *out_size += ((size_t)rc - sizeof(struct keymaster_message));
            break;
        }else if(header.cmd & KEYMASTER_CONT_BIT){
            *out_size += ((size_t)rc - sizeof(struct keymaster_message));
            continue;
        }else{
            ALOGE("invalid command (%d)", header.cmd);
            return -EINVAL;
        }
    }

    return *out_size;
}

void trusty_keymaster_disconnect() {
    if (handle_ >= 0) {
        tipc_close(handle_);
    }
    handle_ = -1;
}

