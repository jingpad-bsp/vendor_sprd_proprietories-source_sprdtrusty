/*
 * Copyright (c) 2015, Spreadtrum.
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

#include <ctype.h>
#include <log/log.h>
#include <cutils/sockets.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/select.h>

#include <linux/major.h>
#include <linux/mmc/ioctl.h>

#include <cutils/properties.h>
#include "rpmb_server.h"

#define PRO_VALUE_MAX 128

#define MMC_READ_MULTIPLE_BLOCK  18
#define MMC_WRITE_MULTIPLE_BLOCK 25
#define MMC_RELIABLE_WRITE_FLAG (1 << 31)

#define MMC_RSP_PRESENT         (1 << 0)
#define MMC_RSP_CRC             (1 << 2)
#define MMC_RSP_OPCODE          (1 << 4)
#define MMC_CMD_ADTC            (1 << 5)
#define MMC_RSP_SPI_S1          (1 << 7)
#define MMC_RSP_R1              (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_RSP_SPI_R1          (MMC_RSP_SPI_S1)

#define MMC_WRITE_FLAG_R 0
#define MMC_WRITE_FLAG_W 1
#define MMC_WRITE_FLAG_RELW (MMC_WRITE_FLAG_W | MMC_RELIABLE_WRITE_FLAG)

#define MMC_BLOCK_SIZE 512
#define RPMB_DATA_SIZE 256

#ifdef USE_UFS
#define RPMB_DEV_PATH         "/dev/rpmb0"
#else
#define RPMB_DEV_PATH         "/dev/block/mmcblk0rpmb"
#endif


struct rpmb_nonce {
    uint8_t     byte[16];
};

struct rpmb_u16 {
    uint8_t     byte[2];
};

struct rpmb_u32 {
    uint8_t     byte[4];
};

struct rpmb_key {
    uint8_t     byte[32];
};


struct rpmb_packet {
    uint8_t              pad[196];
    struct rpmb_key      key_mac;
    uint8_t              data[256];
    struct rpmb_nonce    nonce;
    struct rpmb_u32      write_counter;
    struct rpmb_u16      address;
    struct rpmb_u16      block_count;
    struct rpmb_u16      result;
    struct rpmb_u16      req_resp;
};

enum rpmb_request {
    RPMB_REQ_PROGRAM_KEY                = 0x0001,
    RPMB_REQ_GET_COUNTER                = 0x0002,
    RPMB_REQ_DATA_WRITE                 = 0x0003,
    RPMB_REQ_DATA_READ                  = 0x0004,
    RPMB_REQ_RESULT_READ                = 0x0005,
};

enum rpmb_response {
    RPMB_RESP_PROGRAM_KEY               = 0x0100,
    RPMB_RESP_GET_COUNTER               = 0x0200,
    RPMB_RESP_DATA_WRITE                = 0x0300,
    RPMB_RESP_DATA_READ                 = 0x0400,
};

enum rpmb_result {
    RPMB_RES_OK                         = 0x0000,
    RPMB_RES_GENERAL_FAILURE            = 0x0001,
    RPMB_RES_AUTH_FAILURE               = 0x0002,
    RPMB_RES_COUNT_FAILURE              = 0x0003,
    RPMB_RES_ADDR_FAILURE               = 0x0004,
    RPMB_RES_WRITE_FAILURE              = 0x0005,
    RPMB_RES_READ_FAILURE               = 0x0006,
    RPMB_RES_NO_AUTH_KEY                = 0x0007,

    RPMB_RES_WRITE_COUNTER_EXPIRED      = 0x0080,
};


static struct rpmb_u16 rpmb_u16(uint16_t val)
{
    struct rpmb_u16 ret = {{
        val >> 8,
        val >> 0,
    }};
    return ret;
}



static uint16_t rpmb_get_u16(struct rpmb_u16 u16)
{
    size_t i;
    uint16_t val;

    val = 0;
    for (i = 0; i < sizeof(u16.byte); i++)
        val = val << 8 | u16.byte[i];

    return val;
}

#define LOG_TAG "RPMB_SERVER"

//#define RPMB_DEBUG 1
#if RPMB_DEBUG
#define rpmb_dprintf(fmt, ...) ALOGD(fmt, ##__VA_ARGS__)
#else
#define rpmb_dprintf(fmt, ...) do { } while (0)
#endif
#define dprintf(fmt, ...) ALOGD(fmt, ##__VA_ARGS__)

#define msleep(ms) usleep((ms) * (1000))


static void rpmb_dprint_buf(const char *prefix, const uint8_t *buf, size_t size)
{
    size_t i = 0, j = 0;
    uint8_t tmp[2048];

    rpmb_dprintf("%s %d", prefix, size);
    for (i = 0; i < size; i++,j++) {
        if (i && i % 32 == 0) {
            tmp[j*3] = '\0';
            rpmb_dprintf("%s : %d, %d", tmp, i, j);
            j = 0;
        }
        sprintf(tmp + j*3, " %02x", buf[i]);
    }
    if (j !=0 ) {
        tmp[j*3] = '\0';
        rpmb_dprintf("%s", tmp);
    }
    rpmb_dprintf("\n");
}

static void rpmb_dprint_u16(const char *prefix, const struct rpmb_u16 u16)
{
    rpmb_dprint_buf(prefix, u16.byte, sizeof(u16.byte));
}

#ifdef USE_UFS

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

/**
 * struct rpmb_ioc_req_cmd - rpmb operation request command
 *
 * @req_type: request type:  must match the in frame req_resp
 *            program key
 *            get write counter
 *            write data
 *            read data
 * @icmd: input command
 * @ocmd: output/result command
 */
struct rpmb_ioc_req_cmd {
	__u64 req_type;
	struct rpmb_ioc_cmd icmd;
	struct rpmb_ioc_cmd ocmd;
};

#define RPMB_IOC_REQ_CMD _IOWR(0xB5, 0, struct rpmb_ioc_req_cmd)


static int is_rpmb_program_key()
{
    int rc,rpmb_fd;
    struct rpmb_key mac;
    struct rpmb_nonce nonce = {.byte = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf,0x0}};
    struct rpmb_packet rpmb_pac = {
        .nonce = nonce,
        .req_resp = rpmb_u16(RPMB_REQ_GET_COUNTER),
    };
    struct rpmb_packet res;
    struct rpmb_ioc_req_cmd ireq;


    memset(&ireq, 0, sizeof(ireq));
    memset(&res, 0, sizeof(res));

    rpmb_fd = open(RPMB_DEV_PATH, O_RDWR);
    if (rpmb_fd < 0 ) {
        ALOGE("open rpmb device %s failed\n", RPMB_DEV_PATH);
        return -1 ;
    }

    ireq.req_type = RPMB_REQ_GET_COUNTER;


    ireq.icmd.flags = RPMB_F_WRITE;
    ireq.icmd.nframes = 1;
    ireq.icmd.frames_ptr = (intptr_t)(&rpmb_pac);


    ireq.ocmd.flags = RPMB_F_READ;
    ireq.ocmd.nframes = 1;
    ireq.ocmd.frames_ptr = (intptr_t)(&res);


    rc = ioctl(rpmb_fd, RPMB_IOC_REQ_CMD, &ireq);

    if (rc < 0) {
        ALOGE("%s: ufs ioctl(RPMB_IOC_REQ_CMD) failed: %d, %s\n", __func__, rc, strerror(errno));
        goto error;
    }

    rpmb_dprintf("rpmb: read counter response:");
    rpmb_dprint_u16("  result        ", res.result);
    rpmb_dprint_u16("  req/resp      ", res.req_resp);

    if (RPMB_RES_NO_AUTH_KEY == rpmb_get_u16(res.result)) {
        ALOGW("%s: rpmb key don't written\n", __func__);
        rc = 0;
    } else {
        ALOGW("%s: rpmb key has written\n", __func__);
        rc = -1;
    }

error:
    close(rpmb_fd);
    return rc;
}

int program_rpmb_key(uint8_t *key_byte, size_t key_len)
{
    struct rpmb_packet req;
    struct rpmb_packet res;
    struct rpmb_ioc_req_cmd ireq;
    int rpmb_fd = -1;
    int rc;


    ALOGW("rpmb_program_key() start \n");

    rpmb_fd = open(RPMB_DEV_PATH, O_RDWR);
    if (rpmb_fd < 0 ) {
        ALOGE("open rpmb device %s failed\n", RPMB_DEV_PATH);
        return -1 ;
    }

    if (NULL == key_byte || key_len <= 0) {
        ALOGE(" rpmb_program_key()  fail, key_byte is NULL or key_len is %d !\n", key_len);
        rc = -1;
        goto error;

    }

    memset(&ireq, 0, sizeof(ireq));
    memset(&req, 0, sizeof(req));
    memset(&res, 0, sizeof(res));

    ireq.req_type = RPMB_REQ_PROGRAM_KEY;

    req.req_resp = rpmb_u16(RPMB_REQ_PROGRAM_KEY);
    memcpy(req.key_mac.byte, key_byte, key_len);


    ireq.icmd.flags = RPMB_F_WRITE;
    ireq.icmd.nframes = 1;
    ireq.icmd.frames_ptr = (intptr_t)(&req);


    ireq.ocmd.flags = RPMB_F_READ;
    ireq.ocmd.nframes = 1;
    ireq.ocmd.frames_ptr = (intptr_t)(&res);


    rc = ioctl(rpmb_fd, RPMB_IOC_REQ_CMD, &ireq);
    if (0 > rc) {
        ALOGE("%s: ufs ioctl (RPMB_IOC_REQ_CMD) failed: %d, %s\n", __func__, rc, strerror(errno));
        rc = -1;
        goto error;

    }


#ifdef RPMB_DEBUG
    rpmb_dprint_buf("rpmb response:", (uint8_t *)&res, sizeof(res));
#endif

//result check
    if (RPMB_RESP_PROGRAM_KEY != rpmb_get_u16(res.req_resp)) {
        ALOGE("rpmb_program_key: Bad response type, 0x%x, expected 0x%x\n",
            rpmb_get_u16(res.req_resp), RPMB_RESP_PROGRAM_KEY);
        rc = -1;
        goto error;
    }

    if (RPMB_RES_OK != rpmb_get_u16(res.result)) {
        ALOGE("rpmb_program_key: Bad result, 0x%x\n", rpmb_get_u16(res.result));
        rc = -1;
        goto error;
    }

    ALOGW("rpmb_program_key() successed \n");

    rc = 0;

error:
    close(rpmb_fd);

    return rc;
}

#else

static int is_rpmb_program_key()
{
    int rc,rpmb_fd;
    struct rpmb_key mac;
    struct rpmb_nonce nonce = {.byte = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf,0x0}};
    struct rpmb_packet rpmb_pac = {
        .nonce = nonce,
        .req_resp = rpmb_u16(RPMB_REQ_GET_COUNTER),
    };
    struct rpmb_packet res;
    struct mmc_ioc_cmd cmds[3];
    struct mmc_ioc_cmd *cmd;

    memset(cmds, 0, sizeof(cmds));

    rpmb_fd = open(RPMB_DEV_PATH, O_RDWR);
    if (rpmb_fd < 0 ) {
        ALOGE("open rpmb device %s failed\n", RPMB_DEV_PATH);
        return -1 ;
    }

    cmd = &cmds[1];
    cmd->write_flag = MMC_WRITE_FLAG_W;
    cmd->opcode = MMC_WRITE_MULTIPLE_BLOCK;
    cmd->flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;
    //cmd->flags = MMC_RSP_R1;
    cmd->blksz = MMC_BLOCK_SIZE;
    cmd->data_timeout_ns = 1000000000;
    cmd->is_acmd = 0;
    cmd->blocks = sizeof(rpmb_pac) / MMC_BLOCK_SIZE;
    mmc_ioc_cmd_set_data((*cmd), &rpmb_pac);
#ifdef RPMB_DEBUG
    rpmb_dprintf("opcode: 0x%x, write_flag: 0x%x, write_buf[511] = 0x%02x\n",
        cmd->opcode, cmd->write_flag, ((uint8_t *)&rpmb_pac)[511]);
#endif

    rc = ioctl(rpmb_fd, MMC_IOC_CMD, cmd);

    if (rc < 0) {
        ALOGE("%s: mmc ioctl failed: %d, %s\n", __func__, rc, strerror(errno));
        goto error;
    }

    cmd = &cmds[2];
    cmd->write_flag = MMC_WRITE_FLAG_R;
    cmd->opcode = MMC_READ_MULTIPLE_BLOCK;
    cmd->flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC,
    cmd->blksz = MMC_BLOCK_SIZE;
    cmd->data_timeout_ns = 1000000000;
    cmd->is_acmd = 0;
    cmd->blocks = sizeof(res) / MMC_BLOCK_SIZE;
    mmc_ioc_cmd_set_data((*cmd), &res);
#ifdef RPMB_DEBUG
    rpmb_dprintf("opcode: 0x%x, write_flag: 0x%x, read_buf[511] = 0x%02x\n",
        cmd->opcode, cmd->write_flag, ((uint8_t *)&res)[511]);
#endif

    rc = ioctl(rpmb_fd, MMC_IOC_CMD, cmd);
    if (rc < 0) {
        ALOGE("%s: mmc ioctl failed: %d, %s\n", __func__, rc, strerror(errno));
        goto error;
    }

    rpmb_dprintf("rpmb: read counter response:");
    rpmb_dprint_u16("  result        ", res.result);
    rpmb_dprint_u16("  req/resp      ", res.req_resp);

    if (RPMB_RES_NO_AUTH_KEY == rpmb_get_u16(res.result)) {
        ALOGW("%s: rpmb key don't written\n", __func__);
        rc = 0;
    } else {
        ALOGW("%s: rpmb key has written\n", __func__);
        rc = -1;
    }

error:
    close(rpmb_fd);
    return rc;
}

int program_rpmb_key(uint8_t *key_byte, size_t key_len)
{
    struct mmc_ioc_cmd cmds[3];
    struct mmc_ioc_cmd *cmd;

    struct rpmb_packet req;
    struct rpmb_packet res;
    int rpmb_fd = -1;
    int rc;

    ALOGW("rpmb_program_key() start \n");

    rpmb_fd = open(RPMB_DEV_PATH, O_RDWR);
    if (rpmb_fd < 0 ) {
        ALOGE("open rpmb device %s failed\n", RPMB_DEV_PATH);
        return -1 ;
    }

    if (NULL == key_byte || key_len <= 0) {
        ALOGE(" rpmb_program_key()  fail, key_byte is NULL or key_len is %d !\n", key_len);
        rc = -1;
        goto error;

    }

    memset(cmds, 0, sizeof(cmds));
//for write rpmb key req
    cmd = &cmds[0];
    cmd->write_flag = MMC_WRITE_FLAG_RELW;
    cmd->opcode = MMC_WRITE_MULTIPLE_BLOCK;
    cmd->flags = MMC_RSP_R1;
    cmd->blksz = MMC_BLOCK_SIZE;
    cmd->data_timeout_ns = 1000000000;
    cmd->is_acmd = 0;
    cmd->blocks = 1;  //must set 1

    memset(&req, 0, sizeof(req));
    req.req_resp = rpmb_u16(RPMB_REQ_PROGRAM_KEY);
    memcpy(req.key_mac.byte, key_byte, key_len);

    mmc_ioc_cmd_set_data((*cmd), &req);
#ifdef RPMB_DEBUG
    rpmb_dprintf("opcode: 0x%x, write_flag: 0x%x\n", cmd->opcode, cmd->write_flag);
#endif
    rc = ioctl(rpmb_fd, MMC_IOC_CMD, cmd);
    if (0 > rc) {
        ALOGE("%s: mmc ioctl failed: %d, %s\n", __func__, rc, strerror(errno));
        rc = -1;
        goto error;

    }


//for read result req
    cmd = &cmds[1];
    cmd->write_flag = MMC_WRITE_FLAG_W;
    //the result read sequence is initiated by write Multiple Block command CMD25.
    cmd->opcode = MMC_WRITE_MULTIPLE_BLOCK;
    cmd->flags = MMC_RSP_R1;
    cmd->blksz = MMC_BLOCK_SIZE;
    cmd->data_timeout_ns = 1000000000;
    cmd->is_acmd = 0;
    cmd->blocks = 1;  //must set 1
    memset(&req, 0, sizeof(req));
    req.req_resp = rpmb_u16(RPMB_REQ_RESULT_READ);
    mmc_ioc_cmd_set_data((*cmd), &req);

#ifdef RPMB_DEBUG
    rpmb_dprintf("opcode: 0x%x, write_flag: 0x%x\n", cmd->opcode, cmd->write_flag);
    rpmb_dprint_buf("rpmb request:", (uint8_t *)&req, sizeof(req));
#endif

    rc = ioctl(rpmb_fd, MMC_IOC_CMD, cmd);
    if (0 > rc) {
        ALOGE("%s: mmc ioctl failed: %d, %s\n", __func__, rc, strerror(errno));
        rc = -1;
        goto error;

    }


    cmd = &cmds[2];
    cmd->write_flag = MMC_WRITE_FLAG_R;
    //read the result
    cmd->opcode = MMC_READ_MULTIPLE_BLOCK;
    cmd->flags = MMC_RSP_R1;
    cmd->blksz = MMC_BLOCK_SIZE;
    cmd->blocks = 1;
    cmd->data_timeout_ns = 1000000000;
    cmd->is_acmd = 0;

    memset(&res, 0, sizeof(res));
    mmc_ioc_cmd_set_data((*cmd), &res);


#ifdef RPMB_DEBUG
    rpmb_dprintf("opcode: 0x%x, write_flag: 0x%x\n", cmd->opcode, cmd->write_flag);
#endif

    rc = ioctl(rpmb_fd, MMC_IOC_CMD, cmd);
    if (rc < 0) {
        ALOGE("%s: mmc ioctl failed: %d, %s\n", __func__, rc, strerror(errno));
        rc = -1;
        goto error;
    }

#ifdef RPMB_DEBUG
    rpmb_dprint_buf("rpmb response:", (uint8_t *)&res, sizeof(res));
#endif

//result check
    if (RPMB_RESP_PROGRAM_KEY != rpmb_get_u16(res.req_resp)) {
        ALOGE("rpmb_program_key: Bad response type, 0x%x, expected 0x%x\n",
            rpmb_get_u16(res.req_resp), RPMB_RESP_PROGRAM_KEY);
        rc = -1;
        goto error;
    }

    if (RPMB_RES_OK != rpmb_get_u16(res.result)) {
        ALOGE("rpmb_program_key: Bad result, 0x%x\n", rpmb_get_u16(res.result));
        rc = -1;
        goto error;
    }

    ALOGW("rpmb_program_key() successed \n");

    rc = 0;

error:
    close(rpmb_fd);

    return rc;
}
#endif

#define EN_STORAGEPROXYD_PRO "vendor.sprd.storageproxyd.enabled"

static int start_storageproxyd(void)
{
    char is_ok[PRO_VALUE_MAX] = {'\0'};
    char is_running_rpmb[PRO_VALUE_MAX] = {'\0'};
    char is_running_ns[PRO_VALUE_MAX] = {'\0'};
    int count = 0;
    int result = 0;

    result = property_get(EN_STORAGEPROXYD_PRO, is_ok, "");
    ALOGW("property:%s:%s, ret %d, %s\n", EN_STORAGEPROXYD_PRO, is_ok, result, strerror(errno));
    if(strncmp(is_ok, "1",1)) {
        result = property_set(EN_STORAGEPROXYD_PRO, "1");
        if(result != 0){
            ALOGE("set %s error,result: %d, %s\n", EN_STORAGEPROXYD_PRO, result, strerror(errno));
            return -1;
        }
        ALOGW("set %s ok,result: %d\n", EN_STORAGEPROXYD_PRO, result);
    }

    for(count = 0; count < 1000; count++){
        msleep(10);
        property_get("init.svc.vendor.rpmbproxy", is_running_rpmb, "");
        property_get("init.svc.vendor.nsproxy", is_running_ns, "");
        if((0 == strncmp(is_running_rpmb, "running", 7)) && (0 == strncmp(is_running_ns, "running", 7))){
            ALOGW("property:init.svc.vendor.rpmbproxy:%s\n",is_running_rpmb);
            ALOGW("property:init.svc.vendor.nsproxy:%s\n",is_running_ns);
            return 0;
        }
    }
    return -1;
}


#define LISTEN_BACKLOG 4

int main(void)
{
    int srv_fd, lis_fd, cfd, ret;
    enum rpmb_socket_cmd command;
    uint8_t rpmb_key[RPMB_KEY_LEN];
    fd_set rfds;
    struct timeval tv;

    srv_fd = socket_local_server(RPMB_SERVER_NAME, ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    if (srv_fd < 0) {
        ALOGE("%s rpmb server socket_local_server error: %s\n", __func__, strerror(errno));
        return -1;
    }

    lis_fd = listen(srv_fd, LISTEN_BACKLOG);
    if(lis_fd != 0){
        ALOGE("%s rpmb server listen error: %s\n", __func__, strerror(errno));
        return -1;
    }

    ALOGW("%s rpmb server started\n", __func__);


    while (1) {

        cfd = accept(srv_fd, NULL, NULL);
        if (cfd < 0) {
            ALOGE("%s rpmb server accept error: %s\n", __func__, strerror(errno));
            continue;
        }

        ret = read(cfd, &command, sizeof(enum rpmb_socket_cmd));

        if (ret != sizeof(enum rpmb_socket_cmd)) {
            ALOGE("%s rpmb server read commad error: %s\n", __func__, strerror(errno));
            close(cfd);
            continue;
        }

        if (WR_RPMB_KEY == command) {
            ret = read(cfd, rpmb_key, RPMB_KEY_LEN);
            if (RPMB_KEY_LEN != ret) {
                ALOGE("%s rpmb server second read error: %s\n", __func__, strerror(errno));
                close(cfd);
                continue;
            }

            ret = program_rpmb_key(rpmb_key, RPMB_KEY_LEN);
            write(cfd, &ret, sizeof(ret));
        } else if (IS_WR_RPMB_KEY == command){
            ret = is_rpmb_program_key();
            write(cfd, &ret, sizeof(ret));
        } else if (RUN_STORAGEPROXY == command){
            ret = start_storageproxyd();
            write(cfd, &ret, sizeof(ret));
        } else {
            ALOGE("%s rpmb server unsuport commad (%d): %s, close %d\n",
                        __func__, command, strerror(errno), cfd);
            close(cfd);
            continue;
        }

        //wait client close event
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        FD_ZERO(&rfds);
        FD_SET(cfd, &rfds);
        select(cfd + 1, &rfds, NULL, NULL, &tv);
        close(cfd);
        ALOGW("%s close(%d) \n", __func__, cfd);
    }//while
    ALOGW("%s rpmb server exit\n", __func__);
    return 0;
}
