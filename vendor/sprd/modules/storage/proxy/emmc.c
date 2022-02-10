/*
 * Copyright (C) 2018 spreadtrum
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
#include "storage.h"
#include "emmc.h"



static int emmc_fd = -1;
static uint64_t emmc_base_offset;
static uint64_t emmc_max_offset;


static struct {
   struct storage_file_read_resp hdr;
   uint8_t data[MAX_READ_SIZE];
}  emmc_read_rsp;


int emmc_write(struct storage_msg *msg, const void *r, size_t req_len)
{
    int rc;
    const struct storage_file_write_req *req = r;
    uint64_t offset = 0;
    size_t write_size = 0;

    if (req_len < sizeof(*req)) {
        ALOGE("%s: invalid request length (%zd < %zd)\n",
              __func__, req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto error_response;
    }

    offset = req->offset + emmc_base_offset;
    write_size = req_len - sizeof(*req);
    if (offset + write_size > emmc_max_offset) {
        ALOGE("%s: request write too large: offset (%zd + %zd) + size %zd > %zd\n",
              __func__, emmc_base_offset, req->offset, write_size, emmc_max_offset);
        msg->result = STORAGE_ERR_NOT_VALID;
        goto error_response;
    }

    if (write_with_retry(emmc_fd, &req->data[0], write_size, (off_t)offset) < 0) {
        rc = errno;
        ALOGE("%s: error writing file (fd=%d) size %zd offset %zd: %s\n",
              __func__, emmc_fd, write_size, offset, strerror(errno));
        msg->result = translate_errno(rc);
        goto error_response;
    }

    msg->result = STORAGE_NO_ERROR;

error_response:
    return ipc_respond(msg, NULL, 0);
}


int emmc_read(struct storage_msg *msg, const void *r, size_t req_len)
{
    int rc;
    const struct storage_file_read_req *req = r;
    uint64_t offset = 0;
    ssize_t read_size = 0;



    if (req_len != sizeof(*req)) {
        ALOGE("%s: invalid request length (%zd != %zd)\n",
              __func__, req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto error_rsp;
    }

    if (req->size > MAX_READ_SIZE) {
        ALOGE("%s: request is too large (%zd > %zd) - refusing\n",
              __func__, req->size, MAX_READ_SIZE);
        msg->result = STORAGE_ERR_NOT_VALID;
        goto error_rsp;
    }

    offset = req->offset + emmc_base_offset;
    if (offset > emmc_max_offset) {
        ALOGE("%s: request offset too large (%zd + %zd) > %zd - refusing\n",
              __func__, emmc_base_offset, req->offset, emmc_max_offset);
        msg->result = STORAGE_ERR_NOT_VALID;
        goto error_rsp;
    }


    read_size = read_with_retry(emmc_fd, emmc_read_rsp.hdr.data, req->size, (off_t)offset);
    if (read_size < 0) {
        rc = errno;
        ALOGE("%s: error reading file (fd=%d) size %zd offset %zd: %s\n",
              __func__, emmc_fd, req->size, offset, strerror(errno));
        msg->result = translate_errno(rc);
        goto error_rsp;
    }

    msg->result = STORAGE_NO_ERROR;
    return ipc_respond(msg, &emmc_read_rsp, read_size + sizeof(emmc_read_rsp.hdr));

error_rsp:
    return ipc_respond(msg, NULL, 0);
}

//Calculate the available emmc block device 's spaces
int emmc_cal(void)
{
    FILE* fp;
    int rc = 0;
    int64_t block_count = 0;

    fp = fopen(EMMC_BLOCK_COUNT_FILE, "r");
    if (NULL != fp) {
        if (fscanf(fp, "%ld*[^0-9]", &block_count) > 0) {
            emmc_max_offset = block_count * EMMC_BLOCK_SIZE;
            if (emmc_max_offset <= EMMC_BLOCK_USE_SIZE) {
                ALOGW("%s: emmc's space not enough (%zd < %zd)\n",
                    __func__, emmc_max_offset, EMMC_BLOCK_USE_SIZE);
                rc = -1;
            } else {
                emmc_base_offset = emmc_max_offset - EMMC_BLOCK_USE_SIZE;
                ALOGW("%s: emmc's space (%zd - %zd)\n",
                    __func__, emmc_base_offset, emmc_max_offset);
                rc = 0;
            }
        } else {
            ALOGE("%s: read %s errror: %s\n", __func__,
                EMMC_BLOCK_COUNT_FILE, strerror(errno));
            rc = -1;
        }
        fclose(fp);
    } else {
        ALOGE("%s: open(%s) errror: %s\n", __func__,
            EMMC_BLOCK_COUNT_FILE, strerror(errno));
        rc = -1;
    }
    return rc;
}

int emmc_open()
{
    int rc;

    rc = open(EMMC_BLOCK_DEV_NAME, O_RDWR, 0);
    if (rc < 0) {
        ALOGE("unable (%d) to open emmc device '%s': %s\n",
              errno, EMMC_BLOCK_DEV_NAME, strerror(errno));
        return rc;
    }
    emmc_fd = rc;
    return 0;
}

void emmc_close(void)
{
    close(emmc_fd);
    emmc_fd = -1;
}

