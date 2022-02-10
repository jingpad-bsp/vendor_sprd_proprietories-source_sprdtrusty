#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <trusty/tipc.h>
#include <log/log.h>

#include "confirmationui_ipc.h"


#undef LOG_TAG
#define LOG_TAG "confirmationui_ipc"


static int handle_ = 0;

int trusty_confirmationui_connect()
{

    int rc = tipc_connect(TRUSTY_DEVICE_NAME, CONFIRMATIONUI_PORT);

    if (rc < 0) {
        return rc;
    }

    handle_ = rc;
    return 0;
}

int trusty_confirmationui_call(uint32_t cmd, uint8_t* in, uint32_t in_size, uint8_t* out,
                               uint32_t* out_size)
{
    if (handle_ == 0) {
        ALOGE("not connected\n");
        return -EINVAL;
    }

    size_t msg_size = in_size + sizeof(struct confirmationui_message);
    struct confirmationui_message* msg = (struct confirmationui_message*)malloc(msg_size);
    msg->cmd = cmd;
    memcpy(msg->payload, in, in_size);

    ssize_t rc = write(handle_, msg, msg_size);
    free(msg);

    if (rc < 0) {
        ALOGE("failed to send cmd (%d) to %s: %s\n", cmd, CONFIRMATIONUI_PORT, strerror(errno));
        return -errno;
    }

    rc = read(handle_, out, *out_size);

    if (rc < 0) {
        ALOGE("failed to retrieve response for cmd (%d) to %s: %s\n", cmd, CONFIRMATIONUI_PORT,
              strerror(errno));
        return -errno;
    }

    if ((size_t) rc < sizeof(struct confirmationui_message)) {
        ALOGE("invalid response size (%d)\n", (int) rc);
        return -EINVAL;
    }

    struct confirmationui_message* resp_msg = (struct confirmationui_message*) out;

    if ((cmd | CONFIRMATIONUI_TA_RESP_BIT) != resp_msg->cmd) {
        ALOGE("invalid command (%d)\n", resp_msg->cmd);
        return -EINVAL;
    }

    *out_size = ((size_t) rc) - sizeof(struct confirmationui_message);
    ALOGD("trusty_confirmationui_call ...end ... rc=%d\n", (int)rc);
    return rc;
}

void trusty_confirmationui_disconnect()
{
    if (handle_ != 0) {
        ALOGD("trusty confirmationui disconnecting...\n");
        tipc_close(handle_);
        handle_ = 0;
    }
}

