/*
 * Copyright (c) 2018, Spreadtrum Communications Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <log/log.h>
#include <trusty/tipc.h>
#include "tee_faceid.h"
#include "trusty_faceid_ipc.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "Face-CA"
#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"
#define DEFAULT_RECV_BUF_SIZE 128

static int handle_ = 0;

int trusty_faceid_connect(void)
{
    int rc = tipc_connect(TRUSTY_DEVICE_NAME, FACEID_PORT);
    if (rc < 0)
    {
        ALOGE("tipc_connect() failed! \n");
        return rc;
    }
    handle_ = rc;
    ALOGD("handle = %d \n", handle_);
    return 0;
}

int trusty_faceid_call(uint32_t cmd, void *in, uint32_t in_size,
        uint8_t *out, uint32_t *out_size)
{
    ALOGD("Enter %s, cmd is %02x, in_size = %d \n", __func__, cmd, in_size);
    uint8_t ipc_buf[DEFAULT_RECV_BUF_SIZE] = { 0 };
    if (handle_ == 0)
    {
        ALOGE("faceid ta not connected.\n");
        return -EINVAL;
    }

    size_t msg_size = in_size + sizeof(struct faceid_message);
    struct faceid_message *msg = malloc(msg_size);
    msg->cmd = cmd;
    if (in_size > 0) {
        memcpy(msg->payload, in, in_size);
    }

    ssize_t rc = write(handle_, msg, msg_size);
    free(msg);

    if (rc < 0) {
        ALOGD("failed to send cmd (%d) to %s: %s\n", cmd,
                FACEID_PORT, strerror(errno));
        return -errno;
    }

//    rc = read(handle_, out, *out_size);
    rc = read(handle_, ipc_buf, DEFAULT_RECV_BUF_SIZE);
    if (rc < 0) {
        ALOGD("failed to retrieve response for cmd (%d) to %s: %s\n",
                cmd, FACEID_PORT, strerror(errno));
        return -errno;
    }
    if ((size_t) rc < sizeof(struct faceid_message)) {
        ALOGD("invalid response size (%d)\n", (int) rc);
        return -EINVAL;
    }

    msg = (struct faceid_message*) ipc_buf;
    if ((cmd | FACEID_RESP_BIT) != msg->cmd) {
        ALOGD("invalid command (%d)", msg->cmd);
        return -EINVAL;
    }

    memset(out, 0, *out_size); // *out_size now means the length of |out|
    *out_size = ((size_t) rc) - sizeof(struct faceid_message);
    memcpy(out, msg->payload, *out_size);
    ALOGD("CA read response(%x) from TA, out_size is %d.\n", msg->cmd, *out_size);
    return 0;
}

void trusty_faceid_disconnect()
{
    if (handle_ > 0)
    {
        tipc_close(handle_);
    }
    handle_ = 0;
}
