#include <trusty/tipc.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <log/log.h>
#include "vecfont_ipc.h"

#undef LOG_TAG
#define LOG_TAG "vecfont_ipc"


#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"


vecft_session* trusty_vecfont_ta_connect(const char* port)
{
    if (port != NULL && strlen(port) > 0) {
        vecft_session* session = NULL;

        int handle = tipc_connect(TRUSTY_DEVICE_NAME, port);
        ALOGI("trusty vecfont ta(%s) connect. rc:%d\n", port, handle);

        if (handle > 0) {
            session = (vecft_session*)malloc(sizeof(vecft_session));

            if (session) {
                memset(session, 0, sizeof(vecft_session));

                session->handle = handle;
                memcpy(session->portStr, port, strlen(port));

                return session;
            }
        }
    }

    return NULL;
}


int trusty_vecfont_ta_call(vecft_session* s, uint32_t cmd, uint8_t* in, uint32_t in_size,
                           uint8_t* out, uint32_t* out_size)
{
    if (s == NULL) {
        ALOGE("session NULL!\n");
        return -EINVAL;
    }

    if (s->handle <= 0) {
        ALOGE("ta not connected\n");
        return -EINVAL;
    }

    size_t msg_size = in_size + sizeof(struct vecft_message);
    struct vecft_message* msg = (struct vecft_message*)malloc(msg_size);
    msg->cmd = cmd;
    memcpy(msg->payload, in, in_size);

    ssize_t rc = write(s->handle, msg, msg_size);
    free(msg);

    if (rc < 0) {
        ALOGE("failed to send cmd (%d) to %s: %s\n", cmd, s->portStr, strerror(errno));
        return -errno;
    }

    rc = read(s->handle, out, *out_size);

    if (rc < 0) {
        ALOGE("failed to retrieve response for cmd (%d) to %s: %s\n", cmd, s->portStr, strerror(errno));
        return -errno;
    }

    if ((size_t) rc < sizeof(struct vecft_message)) {
        ALOGE("invalid response size (%d)\n", (int)rc);
        return -EINVAL;
    }

    struct vecft_message* resp_msg = (struct vecft_message*) out;

    if ((cmd | VECFT_TA_RESP_BIT) != resp_msg->cmd) {
        ALOGE("invalid command (%d)\n", resp_msg->cmd);
        return -EINVAL;
    }

    *out_size = ((size_t)rc) - sizeof(struct vecft_message);
    ALOGE("trusty_vecfont_ta_call. rc=%d\n", (int)rc);

    return rc;
}


void trusty_vecfont_ta_disconnect(vecft_session* session)
{
    if (session != NULL) {
        if (session->handle > 0) {
            int rc = tipc_close(session->handle);
            ALOGI("trusty vecfont ta(%s) disconnect(%d).\n", session->portStr, rc);
        }

        free(session);
    }
}

