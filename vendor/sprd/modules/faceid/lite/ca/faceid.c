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

#include <string.h>
#include <log/log.h>
#include "faceid.h"
#include "tee_faceid.h"
#include "trusty_faceid_ipc.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "Face-CA"
#define FACEID_COMMON_RSP_SIZE (sizeof(struct face_common_rsp))

int32_t open_tee_faceid()
{
    int rc = trusty_faceid_connect();
    if (rc < 0)
    {
        ALOGE("%s: connect faceid ta error(%d).", __func__, rc);
        return -1;
    }
    ALOGD("%s: faceid_ca connect ta, result=%d", __func__, rc);
    return rc;
}

void close_tee_faceid()
{
    trusty_faceid_disconnect();
    ALOGD("%s: disconnect ta.", __func__);
}

static int send_request(uint32_t cmd, void *in, uint32_t in_size,
        uint8_t *out, uint32_t *out_size)
{
    int rc = trusty_faceid_call(cmd, in, in_size, out, out_size);
    if (rc < 0)
    {
        ALOGE("%s: send request to faceid ta error(%d).", __func__, rc);
    }
    return rc;
}

int32_t save_template(uint32_t gid, int32_t index, const void *feature, size_t count)
{
    struct face_save_req req;
    struct face_common_rsp rsp;
    uint32_t recv_len = FACEID_COMMON_RSP_SIZE;

    req.gid = gid;
    req.index = index;
    req.count = (uint32_t) count;
    memcpy(req.feature, feature, count);

    int ret = send_request(FACEID_SAVE_TEMPLATE,
            &req, sizeof(req), (uint8_t*)&rsp, &recv_len);
    if (ret < 0)
    {
        ALOGE("%s: trusty_faceid_call failed", __func__);
        return ret;
    }

    ALOGD("%s ca-save rlt:%d", __func__, rsp.error);
    return rsp.error;
}

int32_t remove_template(uint32_t gid)
{
    struct face_remove_req req;
    struct face_common_rsp rsp;
    uint32_t recv_len = FACEID_COMMON_RSP_SIZE;

    req.gid = gid;
    int ret = send_request(FACEID_REMOVE_TEMPLATE,
            &req, sizeof(req), (uint8_t*)&rsp, &recv_len);
    if (ret < 0)
    {
        ALOGE("%s: trusty_faceid_call failed", __func__);
        return ret;
    }

    ALOGD("%s ca-remove rlt:%d", __func__, rsp.error);
    return rsp.error;
}

int32_t init_auth(uint32_t gid, uint64_t operation_id)
{
    struct face_auth_init_req req;
    struct face_common_rsp rsp;
    uint32_t recv_len = FACEID_COMMON_RSP_SIZE;

    req.gid = gid;
    req.operation_id = operation_id;
    int ret = send_request(FACEID_INIT_AUTH,
            &req, sizeof(req), (uint8_t*)&rsp, &recv_len);
    if (ret < 0)
    {
        ALOGE("%s: trusty_faceid_call failed", __func__);
        return ret;
    }

    ALOGD("%s ca-init rlt:%d", __func__, rsp.error);
    return rsp.error;
}

int32_t get_template_count(uint32_t gid)
{
    struct face_get_tplcnt_req req;
    struct face_common_rsp rsp;
    uint32_t recv_len = sizeof(rsp);

    req.gid = gid;
    int ret = send_request(FACEID_GET_TEMPLATE_COUNT,
            &req, sizeof(req), (uint8_t*)&rsp, &recv_len);
    if (ret < 0)
    {
        ALOGE("%s: trusty_faceid_call failed", __func__);
        return ret;
    }

    ALOGD("%s ca-get template count rlt:%d", __func__, rsp.error);
    return rsp.error; // negative means error occurred, otherwise rsp.error is count value
}

int32_t compare(const void *feature, size_t count, float *max_score, float *mean_score)
{
    struct face_compare_req req;
    struct face_compare_rsp rsp;
    uint32_t recv_len = sizeof(rsp);

    req.count = (uint32_t) count;
    memcpy(req.feature, feature, count);
    int ret = send_request(FACEID_DO_COMPARE,
            &req, sizeof(req), (uint8_t*)&rsp, &recv_len);
    if (ret < 0)
    {
        ALOGE("%s: trusty_faceid_call failed", __func__);
        return ret;
    }

    if (rsp.error != 0) { // errors happened in tee
        ALOGE("%s: errors in trusty", __func__);
        return -1;
    }

    ALOGD("%s ca-cmp rlt:%d %f %f", __func__, rsp.error, rsp.max_score, rsp.mean_score);
    *max_score = rsp.max_score;
    *mean_score = rsp.mean_score;
    return 0;
}

int32_t compare2(const void *feature1, const void *feature2, size_t count, float *score)
{
    struct face_compare_req req;
    struct face_compare_rsp rsp;
    uint32_t recv_len = sizeof(rsp);

    req.count = (uint32_t) count;
    memcpy(req.feature, feature1, count);
    int ret = send_request(FACEID_DO_COMPARE2,
            &req, sizeof(req), (uint8_t*)&rsp, &recv_len);
    if (ret < 0 || rsp.error != 0)
    {
        ALOGE("%s: trusty_faceid_call feature1 failed", __func__);
        return (ret < 0) ? ret : rsp.error;
    }

    memcpy(req.feature, feature2, count);
    ret = send_request(FACEID_DO_COMPARE2,
            &req, sizeof(req), (uint8_t*)&rsp, &recv_len);
    if (ret < 0)
    {
        ALOGE("%s: trusty_faceid_call feature2 failed", __func__);
        return ret;
    }

    if (rsp.error != 0) { // errors happened in tee
        ALOGE("%s: errors in trusty", __func__);
        return -1;
    }
    ALOGD("%s ca-cmp2 rlt:%d %f", __func__, rsp.error, rsp.max_score);
    *score = rsp.max_score;
    return 0;
}

int32_t tee_pre_enroll(uint64_t *challenge)
{
    // pre-enroll request has no data, only command
    struct face_preenroll_rsp rsp;
    uint32_t recv_len = sizeof(rsp);

    int ret = send_request(FACEID_PRE_ENROLL,
            NULL, 0, (uint8_t*)&rsp, &recv_len);
    if (ret < 0)
    {
        ALOGE("%s: trusty_faceid_call pre_enroll failed", __func__);
        return ret;
    }

    if (rsp.error != 0) { // errors happened in tee
        ALOGE("%s: errors in trusty", __func__);
        return -1;
    }

    ALOGD("%s ca-pre_enroll rlt:%d %llu", __func__, rsp.error, rsp.challenge);
    *challenge = rsp.challenge;
    return 0;
}

int32_t tee_enroll(const hw_auth_token_t *hat)
{
    struct face_enroll_req req;
    struct face_common_rsp rsp;
    uint32_t recv_len = sizeof(rsp);

    memcpy(&req.token, hat, sizeof(hw_auth_token_t));
    int ret = send_request(FACEID_ENROLL,
            &req, sizeof(req), (uint8_t*)&rsp, &recv_len);
    if (ret < 0)
    {
        ALOGE("%s: trusty_faceid_call pre_enroll failed", __func__);
        return ret;
    }

    if (rsp.error != 0) { // errors happened in tee
        ALOGE("%s: errors in trusty", __func__);
        return -1;
    }

    return 0;
}

int32_t tee_post_enroll()
{
    // not implements, just return 0
    return 0;
}

int32_t tee_get_auth_token(hw_auth_token_t *hat)
{
    struct face_get_token_rsp rsp;
    uint32_t recv_len = sizeof(rsp);

    int ret = send_request(FACEID_GET_AUTH_TOKEN,
            NULL, 0, (uint8_t*)&rsp, &recv_len);
    if (ret < 0)
    {
        ALOGE("trusty_faceid_call %s failed", __func__);
        return ret;
    }

    if (rsp.error != 0) { // errors happened in tee
        ALOGE("%s: errors in trusty", __func__);
        return -1;
    }

    ALOGD("ca-%s rlt:%d", __func__, rsp.error);
    memcpy(hat, &rsp.token, sizeof(hw_auth_token_t));
    return 0;
}

int32_t tee_get_authenticator_id(uint64_t *auth_id)
{
    *auth_id = 0xABCDEF012345;
    // not implements, just return 0
    return 0;
}
