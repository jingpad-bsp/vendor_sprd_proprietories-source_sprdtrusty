/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/major.h>
#include <linux/mmc/ioctl.h>

#include "ipc.h"
#include "log.h"
#include "rpmb.h"
#include "storage.h"


#define RPMB_F_READ      (0UL)
#define RPMB_F_WRITE     (1UL << 0)
#define RPMB_F_REL_WRITE (1UL << 1)

/**
 * struct rpmb_cmd - rpmb access command
 *
 * @flags: command flags
 *      0 - read command
 *      1 - write commnad RPMB_F_WRITE
 *      2 - reliable write RPMB_F_REL_WRITE
 * @nframes: number of rpmb frames in the command
 * @frames_ptr:  a pointer to the list of rpmb frames
 */
struct rpmb_ioc_cmd {
    __u32 flags;
    __u32 nframes;
    __aligned_u64 frames_ptr;
};


#define rpmb_ioc_cmd_set(_cmd, _flags, _ptr, _n) do {    \
    struct rpmb_ioc_cmd *icmd = (_cmd);                 \
    icmd->flags = (_flags);                              \
    icmd->nframes = (_n);                                \
    icmd->frames_ptr = (intptr_t)(_ptr);                 \
} while (0)

/**
 * struct rpmb_ioc_seq_cmd - rpmb command sequence
 *
 * @num_of_cmds: number of commands
 * @cmds: list of rpmb commands
 */
struct rpmb_ioc_seq_cmd {
	__u64 num_of_cmds;
	struct rpmb_ioc_cmd cmds[0];
};

#define RPMB_IOC_SEQ_CMD _IOWR(0xB5, 1, struct rpmb_ioc_seq_cmd)


#define MMC_BLOCK_SIZE 512

static int rpmb_fd = -1;
static uint8_t read_buf[4096];

//#define RPMB_DEBUG 1
#ifdef RPMB_DEBUG
static void print_buf(const char *prefix, const uint8_t *buf, size_t size)
{
    size_t i = 0,j = 0;
    uint8_t  tmp[2048];

    ALOGW("%s @%p [%zu]", prefix, buf, size);
    for (i = 0; i < size; i++, j++) {
        if (i && i % 32 == 0) {
            tmp[j*3] = '\0';
            ALOGW("%s : %d, %d", tmp, i, j);
            j = 0;
        }
        sprintf(tmp + j*3, " %02x", buf[i]);
    }
    if (j !=0 ) {
        tmp[j*3] = '\0';
        ALOGW("%s", tmp);
    }
    ALOGW("\n");
}

#endif


int rpmb_send(struct storage_msg *msg, const void *r, size_t req_len)
{
    int rc;
    struct {
        struct rpmb_ioc_seq_cmd h;
        struct rpmb_ioc_cmd cmd[3];
    } mmc = {};
    struct rpmb_ioc_cmd *cmd = mmc.cmd;

    const struct storage_rpmb_send_req *req = r;

    if (req_len < sizeof(*req)) {
        ALOGW("malformed rpmb request: invalid length (%zu < %zu)\n",
              req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    size_t expected_len =
            sizeof(*req) + req->reliable_write_size + req->write_size;
    if (req_len != expected_len) {
        ALOGW("malformed rpmb request: invalid length (%zu != %zu)\n",
              req_len, expected_len);
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    memset(&mmc, 0, sizeof(mmc));
    const uint8_t *write_buf = req->payload;
    if (req->reliable_write_size) {
        if ((req->reliable_write_size % MMC_BLOCK_SIZE) != 0) {
            ALOGW("invalid reliable write size %u\n", req->reliable_write_size);
            msg->result = STORAGE_ERR_NOT_VALID;
            goto err_response;
        }


       rpmb_ioc_cmd_set(cmd, (RPMB_F_WRITE | RPMB_F_REL_WRITE), write_buf, req->reliable_write_size / MMC_BLOCK_SIZE);

#ifdef RPMB_DEBUG
        print_buf("request reliable write: ", write_buf, req->reliable_write_size);
#endif
        write_buf += req->reliable_write_size;
        mmc.h.num_of_cmds++;
        cmd++;
    }

    if (req->write_size) {
        if ((req->write_size % MMC_BLOCK_SIZE) != 0) {
            ALOGW("invalid write size %u\n", req->write_size);
            msg->result = STORAGE_ERR_NOT_VALID;
            goto err_response;
        }

        rpmb_ioc_cmd_set(cmd, RPMB_F_WRITE, write_buf, req->write_size / MMC_BLOCK_SIZE);

#ifdef RPMB_DEBUG
        print_buf("request write: ", write_buf, req->write_size);
#endif
        write_buf += req->write_size;
        mmc.h.num_of_cmds++;
        cmd++;
    }

    if (req->read_size) {
        if (req->read_size % MMC_BLOCK_SIZE != 0 ||
            req->read_size > sizeof(read_buf)) {
            ALOGE("%s: invalid read size %u\n", __func__, req->read_size);
            msg->result = STORAGE_ERR_NOT_VALID;
            goto err_response;
        }

        rpmb_ioc_cmd_set(cmd, RPMB_F_READ, read_buf, req->read_size / MMC_BLOCK_SIZE);
#ifdef RPMB_DEBUG
        ALOGI("request read size 0x%u\n", req->read_size);
#endif

        mmc.h.num_of_cmds++;
        cmd++;
    }

    rc = ioctl(rpmb_fd, RPMB_IOC_SEQ_CMD, &mmc);
    if (rc < 0) {
        ALOGE("%s: mmc ioctl (RPMB_IOC_SEQ_CMD) failed: %d, %s\n", __func__, rc, strerror(errno));
        msg->result = STORAGE_ERR_GENERIC;
        goto err_response;
    }

#ifdef RPMB_DEBUG
    if (req->read_size)
        print_buf("response: ", read_buf, req->read_size);
#endif

    if (msg->flags & STORAGE_MSG_FLAG_POST_COMMIT) {
        /*
         * Nothing todo for post msg commit request as MMC_IOC_MULTI_CMD
         * is fully synchronous in this implementation.
         */
    }

    msg->result = STORAGE_NO_ERROR;
    return ipc_respond(msg, read_buf, req->read_size);

err_response:
    return ipc_respond(msg, NULL, 0);
}


int rpmb_open(const char *rpmb_devname)
{
    int rc;

    rc = open(rpmb_devname, O_RDWR, 0);
    if (rc < 0) {
        ALOGE("unable (%d) to open rpmb device '%s': %s\n",
              errno, rpmb_devname, strerror(errno));
        return rc;
    }
    rpmb_fd = rc;
    return 0;
}

void rpmb_close(void)
{
    close(rpmb_fd);
    rpmb_fd = -1;
}
