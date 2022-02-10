/*
 *  faceid_tee.cpp
 *
 *  Copyright (C) 2018 Unisoc Inc.
 *  History:
 *      <Date> 2018/09/29
 *      <Name>
 *  Description: implements interfaces declared in faceid_tee.h
 */

#define LOG_TAG "Face-CA"

#include <string.h>
#include <stdlib.h>
#include <log/log.h>
#include <cutils/properties.h>
#include <errno.h>
#include <time.h>
#include "faceid_tee.h"
#include "faceid_ca_ta.h"
#include "trusty_faceid_ipc.h"


static int send_request(uint32_t cmd, void *in, uint32_t in_size,
                                    uint8_t *out, uint32_t *out_size) {
    int rc = 0;

    rc = trusty_faceid_call(cmd, in, in_size, out, out_size);
    if (rc < 0) {
        ALOGE("%s: send request to faceid ta error(%d).", __func__, rc);
    }

    return rc;
}

static void set_mask(uint32_t *mask, int bit, uint32_t value) {
    if(value) {
        *mask = (0x01 << bit) | (*mask); // set
    } else {
        *mask = (~(0x01 << bit)) & (*mask); // clear
    }
}
static uint8_t needTime = 0;
static uint32_t update_prop(uint32_t gid) {
    uint32_t mask = 0;
    char value[PROPERTY_VALUE_MAX] = {0};
    property_get("persist.vendor.cam.faceid.version" , value , "0");
    if(!strcmp(value , "1")) {
        set_mask(&mask, CAMERA_TYPE_BIT, 1);
        set_mask(&mask, CAMERA_TYPE_BIT+1, 0);
    } else if(!strcmp(value , "2")) {
        set_mask(&mask, CAMERA_TYPE_BIT, 0);
        set_mask(&mask, CAMERA_TYPE_BIT+1, 1);
    }  else if(!strcmp(value , "3")) {
        set_mask(&mask, CAMERA_TYPE_BIT, 1);
        set_mask(&mask, CAMERA_TYPE_BIT+1, 1);
    } else {
        set_mask(&mask, CAMERA_TYPE_BIT, 0);
        set_mask(&mask, CAMERA_TYPE_BIT+1, 0);
    }

    property_get("persist.vendor.faceid.enrollface" , value , "0");
    if(!strcmp(value , "1")) {
        set_mask(&mask, ENROLL_DUMP_BIT, 1);
        set_mask(&mask, ENROLL_DUMP_BIT+1, 0);
    } else if(!strcmp(value , "2")) {
        set_mask(&mask, ENROLL_DUMP_BIT, 0);
        set_mask(&mask, ENROLL_DUMP_BIT+1, 1);
    } else {
        set_mask(&mask, ENROLL_DUMP_BIT, 0);
        set_mask(&mask, ENROLL_DUMP_BIT+1, 0);
    }

    property_get("persist.vendor.faceid.authicateface" , value , "0");
    if(!strcmp(value , "1")) {
        set_mask(&mask, AUTH_DUMP_BIT, 1);
        set_mask(&mask, AUTH_DUMP_BIT+1, 0);
    } else if(!strcmp(value , "2")) {
        set_mask(&mask, AUTH_DUMP_BIT, 0);
        set_mask(&mask, AUTH_DUMP_BIT+1, 1);
    } else {
        set_mask(&mask, AUTH_DUMP_BIT, 0);
        set_mask(&mask, AUTH_DUMP_BIT+1, 0);
    }

    char prop[128] = {0};
    sprintf(prop , "persist.vendor.faceid.livenessmode%d", gid);
    property_get(prop , value , "0");
    if(!strcmp(value , "1")) {
        set_mask(&mask, LIVENESS_MODE_BIT, 1);
    } else {
        set_mask(&mask, LIVENESS_MODE_BIT, 0);
    }

    property_get("persist.vendor.faceid.feature" , value , "0");
    if(!strcmp(value , "1")) {
        set_mask(&mask, ENROLL_DUMP_FEATURE_BIT, 1);
    } else {
        set_mask(&mask, ENROLL_DUMP_FEATURE_BIT, 0);
    }

    property_get("ro.debuggable" , value , "0");
    if(!strcmp(value , "1")) {
        set_mask(&mask, IS_DEBUGGABLE_BIT, 1);
        needTime = 1;
    } else {
        set_mask(&mask, IS_DEBUGGABLE_BIT, 0);
    }
    return mask;
}

static face_error_t ca_err_to_hal_err(int32_t error) {
    if(error > FACE_ERROR_AUTH_FAIL)
        return FACE_ERROR_UNABLE_TO_PROCESS;
    return error;
}

static int32_t ca_help_to_hal_help(int32_t help) {
    return help;
}

int32_t faceid_tee_initialize() {
    ALOGI("faceid_tee_initialize");
#ifdef _DYNAMIC_OPEN_FACEID_SUPPORT_
    char value[PROPERTY_VALUE_MAX] = {0};
    property_get("persist.vendor.display.faceid" , value , "0");
    if(!strcmp(value , "1")) {
        ALOGD("dynamic display faceid menu");
    } else {
        return -1;
    }
#endif
    int rc = trusty_faceid_connect();
    if (rc < 0) {
        ALOGE("%s: connect faceid ta error(%d).", __func__, rc);
        return -1;
    }
    ALOGI("%s: faceid_ca connect ta, result=%d", __func__, rc);
    return rc;
}

void faceid_tee_deinitialize() {
    trusty_faceid_disconnect();
    ALOGD("%s: disconnect ta.", __func__);
}

uint64_t faceid_tee_pre_enroll() {
    struct face_pre_enroll_rsp rsp;
    uint32_t recv_len = sizeof(rsp);
    int ret = send_request(FACEID_PRE_ENROLL,
            NULL, 0, (uint8_t*)&rsp, &recv_len);
    if (ret < 0 || rsp.error != 0) {
        ALOGE("%s: trusty_faceid_call failed, ret(%d) error(%d)", __func__, ret, rsp.error);
        return 0;
    }
    return rsp.challenge;
}
int faceid_tee_verifyToken(const hw_auth_token_t *hat) {
    struct face_hat_req req;
    struct face_common_rsp rsp;
    uint32_t recv_len = sizeof(rsp);

    memcpy(&(req.hat), hat, sizeof(hw_auth_token_t));

    int ret = send_request(FACEID_VERIFY_TOKEN,
            &req, sizeof(req), (uint8_t*)&rsp, &recv_len);
    if (ret < 0 || rsp.error != 0) {
        ALOGE("%s: trusty_faceid_call failed, ret(%d) error(%d)", __func__, ret, rsp.error);
        return -1;
    }
    return 0;
}

int faceid_tee_enroll(uint32_t gid,
                          uint32_t timeout_sec, int32_t width, int32_t height) {
    struct face_enroll_req req;
    struct face_common_rsp rsp;
    uint32_t recv_len = sizeof(rsp);

    uint32_t mask = update_prop(gid);
    send_request(FACEID_UPDATE_PROP,
            &mask, sizeof(mask), (uint8_t*)&rsp, &recv_len);

    req.gid = gid;
    req.timeout_sec = timeout_sec;
    req.width = width;
    req.height = height;

    int ret = send_request(FACEID_ENROLL,
            &req, sizeof(req), (uint8_t*)&rsp, &recv_len);
    if (ret < 0 || rsp.error != 0) {
        ALOGE("%s: trusty_faceid_call failed, ret(%d) error(%d)", __func__, ret, rsp.error);
        return -1;
    }
    return 0;
}

void faceGettime(int32_t *outstamp){
    if (needTime) {
        time_t timep;
        struct tm *tmp;
        time(&timep);
        tmp = localtime(&timep);
        char timestamp[7];
        sprintf(timestamp , "%02d%02d%02d" , tmp->tm_hour, tmp->tm_min , tmp->tm_sec);
        *outstamp = atoi(timestamp);
        ALOGI("timestamp=%06d",*outstamp);
    }
}
enroll_state_t faceid_tee_do_enroll_process(int64_t addr,int64_t lm_addr, const int32_t *info, int32_t count,
                                                int32_t *help, uint32_t *progress,
                                                    uint32_t *fid, face_error_t *error,
                                            const int8_t *byteInfo, int32_t byteCount) {
    struct face_do_enroll_process_rsp rsp;
    uint32_t recv_len = sizeof(rsp);
    enroll_state_t result = ENROLL_FAIL;
    uint32_t req_len = sizeof(struct face_do_enroll_process_req) + sizeof(int32_t) * count + sizeof(int8_t) * byteCount;
    struct face_do_enroll_process_req *req = (struct face_do_enroll_process_req *)malloc(req_len);

    if(req != NULL) {
        uint8_t *p = (uint8_t*)req;
        memcpy(p + sizeof(struct face_do_enroll_process_req), info, sizeof(int32_t) * count);
        memcpy(p + sizeof(struct face_do_enroll_process_req)+sizeof(int32_t) * count, byteInfo, sizeof(int8_t) * byteCount);
        req->addr = addr;
        req->lm_addr = lm_addr;
        req->count = count;
        req->byteCount = byteCount;
        int stamp;
        faceGettime(&stamp);
        req->timestamp = stamp;
    } else {
        ALOGE("faceid_tee_do_enroll_process, malloc face_do_enroll_process_req fail");
        *error = FACE_ERROR_UNABLE_TO_PROCESS;
        return result;
    }

    int ret = send_request(FACEID_DO_ENROLL_PROCESS,
            req, req_len, (uint8_t*)&rsp, &recv_len);

    if(ret < 0) {
        *error = FACE_ERROR_UNABLE_TO_PROCESS;
    } else if(rsp.error != 0) {
        *error = ca_err_to_hal_err(rsp.error);
    } else if(rsp.fid != DEFAULT_FACEID) {
        result = ENROLL_SUCCEED;
        *fid = rsp.fid;
    } else {
        result = ENROLL_CONTINUE;
        *progress = rsp.progress;
        *help = ca_help_to_hal_help(rsp.help);
    }
    free(req);
    return result;
}

int faceid_tee_post_enroll() {
    struct face_common_rsp rsp;
    uint32_t recv_len = sizeof(rsp);
    int ret = send_request(FACEID_POST_ENROLL,
            NULL, 0, (uint8_t*)&rsp, &recv_len);
    if (ret < 0 || rsp.error != 0) {
        ALOGE("%s: trusty_faceid_call failed, ret(%d) error(%d)", __func__, ret, rsp.error);
        return -1;
    }
    return 0;
}

uint64_t faceid_tee_get_authenticator_id() {
    struct face_get_authenticator_id_rsp rsp;
    uint32_t recv_len = sizeof(rsp);
    int ret = send_request(FACEID_GET_AUTHENTICATOR_ID,
            NULL, 0, (uint8_t*)&rsp, &recv_len);
    if (ret < 0 || rsp.error != 0) {
        ALOGE("%s: trusty_faceid_call failed, ret(%d) error(%d)", __func__, ret, rsp.error);
        return 0;
    }
    return rsp.authenticator_id;
}
int faceid_tee_cancel(uint32_t gid) {
    struct face_common_rsp rsp;
    uint32_t recv_len = sizeof(rsp);
    int ret = send_request(FACEID_CANCEL,
            &gid, sizeof(uint32_t), (uint8_t*)&rsp, &recv_len);
    if (ret < 0 || rsp.error != 0) {
        ALOGE("%s: trusty_faceid_call failed, ret(%d) error(%d)", __func__, ret, rsp.error);
        return -1;
    }
    return 0;
}
int faceid_tee_remove(uint32_t gid, uint32_t fid) {
    struct face_remove_req req;
    struct face_common_rsp rsp;
    uint32_t recv_len = sizeof(rsp);

    req.gid = gid;
    req.fid = fid;

    int ret = send_request(FACEID_REMOVE,
            &req, sizeof(req), (uint8_t*)&rsp, &recv_len);
    if (ret < 0 || rsp.error != 0) {
        ALOGE("%s: trusty_faceid_call failed, ret(%d) error(%d)", __func__, ret, rsp.error);
        return -1;
    }
    return 0;
}

int faceid_tee_set_active_group(uint32_t gid) {
    struct face_common_rsp rsp;
    uint32_t recv_len = sizeof(rsp);

    int ret = send_request(FACEID_SET_ACTIVE_GROUP,
            &gid, sizeof(gid), (uint8_t*)&rsp, &recv_len);
    if (ret < 0 || rsp.error != 0) {
        ALOGE("%s: trusty_faceid_call failed, ret(%d) error(%d)", __func__, ret, rsp.error);
        return -1;
    }
    return 0;
}

int faceid_tee_authenticate(uint64_t operation_id, uint32_t gid,
                                     int32_t width, int32_t height) {
    struct face_authenticate_req req;
    struct face_common_rsp rsp;
    uint32_t recv_len = sizeof(rsp);

    uint32_t mask = update_prop(gid);
    send_request(FACEID_UPDATE_PROP,
            &mask, sizeof(mask), (uint8_t*)&rsp, &recv_len);

    req.operation_id = operation_id;
    req.gid = gid;
    req.width = width;
    req.height = height;

    int ret = send_request(FACEID_AUTHENTICATE,
            &req, sizeof(req), (uint8_t*)&rsp, &recv_len);
    if (ret < 0 || rsp.error != 0) {
        ALOGE("%s: trusty_faceid_call failed, ret(%d) error(%d)", __func__, ret, rsp.error);
        return -1;
    }
    return 0;
}

auth_state_t faceid_tee_do_authenticate_process(int64_t main, int64_t sub, int64_t otp,int64_t lm_addr,
                                                    const int32_t *info, int32_t count, int32_t *help, uint32_t *fid,
                                                         hw_auth_token_t *token, face_error_t *error,const int8_t *byteInfo,
                                                         int32_t byteCount) {
    struct face_do_authenticate_process_req *req;
    struct face_do_authenticate_process_rsp rsp;
    uint32_t recv_len = sizeof(rsp);
    auth_state_t result = AUTH_FAIL;

    uint32_t req_len = sizeof(struct face_do_authenticate_process_req) + sizeof(int32_t) * count + sizeof(int8_t) * byteCount;
    req = (struct face_do_authenticate_process_req *)malloc(req_len);
    if(req != NULL) {
        uint8_t *p = (uint8_t*)req;
        memcpy(p + sizeof(struct face_do_authenticate_process_req), info, sizeof(int32_t) * count);
        memcpy(p + sizeof(struct face_do_authenticate_process_req)+sizeof(int32_t) * count, byteInfo, sizeof(int8_t) * byteCount);
        req->main = main;
        req->sub = sub;
        req->otp = otp;
        req->lm_addr = lm_addr;
        req->count = count;
        req->byteCount = byteCount;
        int stamp;
        faceGettime(&stamp);
        req->timestamp = stamp;
    } else {
        ALOGE("faceid_tee_do_authenticate_process, malloc face_do_authenticate_process_req fail");
        *error = FACE_ERROR_UNABLE_TO_PROCESS;
        return result;
    }

    int ret = send_request(FACEID_DO_AUTHENTICATE_PROCESS,
            req, req_len, (uint8_t*)&rsp, &recv_len);

    if(ret < 0) {
        *error = FACE_ERROR_UNABLE_TO_PROCESS;
    } else if(rsp.error != 0) {
        *error = ca_err_to_hal_err(rsp.error);
    } else if(rsp.fid > 0) {
        result = AUTH_SUCCEED;
        *fid = rsp.fid;
        memcpy(token, &(rsp.hat), sizeof(hw_auth_token_t));
    } else {
        result = AUTH_CONTINUE;
        *help = ca_help_to_hal_help(rsp.help);
    }
    free(req);
    return result;
}

int faceid_tee_dump_enroll(uint32_t gid,uint8_t *buf, uint32_t len) {
#ifdef _DUMP_SUPPORT_
	memset(buf, 0, len);
	struct face_remove_req req;
	uint32_t recv_len = len;

	req.gid = gid;
	return send_request(FACEID_DUMP,&req, sizeof(req), buf, &recv_len);

#else
    memset(buf, 0, len);
    ALOGE("not debug, don't support dump");
    return -1;
#endif
}
int faceid_tee_dump_auth(uint8_t *buf, uint32_t len) {
#ifdef _DUMP_SUPPORT_
	memset(buf, 0, len);
    ALOGD("dump done.");
    return 0;
#else
    memset(buf, 0, len);
    ALOGE("not debug, don't support dump");
    return -1;
#endif
}

