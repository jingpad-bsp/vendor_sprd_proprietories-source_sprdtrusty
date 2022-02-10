/*
 *  trusty_faceid_ipc.c
 *
 *  Copyright (C) 2018 Unisoc Inc.
 *  History:
 *      <Date> 2018/09/27
 *      <Name>
 *      Description
 */

#define LOG_TAG "Face-CA"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <log/log.h>
#include <trusty/tipc.h>
#include <pthread.h>
#include "faceid_ca_ta.h"
#include "trusty_faceid_ipc.h"

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"
#define DEFAULT_RECV_BUF_SIZE 128

static int handle_ = 0;
static pthread_mutex_t mutex;

int trusty_faceid_connect(void)
{
    int rc = tipc_connect(TRUSTY_DEVICE_NAME, FACEID_PORT);
    if (rc < 0)
    {
        ALOGE("tipc_connect() failed! \n");
        return rc;
    }
    handle_ = rc;
    pthread_mutex_init(&mutex, NULL);
    ALOGD("handle = %d \n", handle_);
    return 0;
}

int trusty_faceid_call(uint32_t cmd, void *in, uint32_t in_size,
        uint8_t *out, uint32_t *out_size)
{
    ALOGD("Enter %s, cmd is %02x, in_size = %d \n", __func__, cmd, in_size);
    uint8_t ipc_buf[DEFAULT_RECV_BUF_SIZE];
    if (handle_ == 0)
    {
        ALOGE("faceid ta not connected.\n");
        return -EINVAL;
    }

    size_t msg_size = in_size + sizeof(struct faceid_message);
    struct faceid_message *msg = malloc(msg_size) ;
    msg->cmd = cmd;
    if(in)
        memcpy(msg->payload, in, in_size);

    pthread_mutex_lock(&mutex);
    ssize_t rc = write(handle_, msg, msg_size);
    free(msg);

    if (rc < 0) {
        ALOGD("failed to send cmd (%d) to %s: %s\n", cmd,
                FACEID_PORT, strerror(errno));
        return -errno;
    }

    rc = read(handle_, ipc_buf, DEFAULT_RECV_BUF_SIZE);
    pthread_mutex_unlock(&mutex);
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

    memset(out, 0, *out_size);
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
    pthread_mutex_destroy(&mutex);
}
