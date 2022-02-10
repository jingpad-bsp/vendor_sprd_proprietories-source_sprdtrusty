#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <trusty/tipc.h>

#include "tuimon_ipc.h"



static int handle_ = 0;

int trusty_tuimon_connect()
{
    int rc = tipc_connect(TRUSTY_DEVICE, TUI_MONITOR_PORT);

    if (rc < 0) {
        return rc;
    }

    handle_ = rc;
    return 0;
}

int trusty_tuimon_call(uint32_t cmd, void* in, uint32_t in_size, uint8_t* out,
                       uint32_t* out_size)
{

    if (handle_ == 0) {
        printf("tui mon session not ready.\n");
        return -1;
    }

    size_t msg_size = in_size + sizeof(tuimonitor_message);
    tuimonitor_message* msg = malloc(msg_size);
    msg->cmd = cmd;
    memcpy(msg->payload, in, in_size);

    ssize_t rc = write(handle_, msg, msg_size);
    free(msg);

    if (rc < 0) {
        printf("failed to send cmd (%d) to %s: %s\n", cmd, TUI_MONITOR_PORT, strerror(errno));
        return -errno;
    }

    rc = read(handle_, out, *out_size);

    if (rc < 0) {
        printf("failed to retrieve response for cmd (%d) to %s: %s\n", cmd, TUI_MONITOR_PORT,
               strerror(errno));
        return -errno;
    }

    if ((size_t) rc < sizeof(tuimonitor_message)) {
        printf("invalid response size (%d)\n", (int) rc);
        return -2;
    }

    tuimonitor_message* resp_msg = (tuimonitor_message*) out;

    if ((cmd | TUIMON_RESP_BIT) != resp_msg->cmd) {
        printf("invalid command (%d)\n", resp_msg->cmd);
        return -3;
    }

    *out_size = ((size_t) rc) - sizeof(tuimonitor_message);

    return rc;
}


void trusty_tuimon_disconnect()
{
    if (handle_ != 0) {
        printf("trusty tui mon disconnecting...\n");
        tipc_close(handle_);
        handle_ = 0;
    }
}

