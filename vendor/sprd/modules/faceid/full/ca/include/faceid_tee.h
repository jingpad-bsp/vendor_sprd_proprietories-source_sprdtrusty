/*
 *  faceid_tee.h
 *
 *  Copyright (C) 2018 Unisoc Inc.
 *  History:
 *      <Date> 2018/09/27
 *      <Name>
 *      Description
 */

#ifndef __FACEID_TEE_H__
#define __FACEID_TEE_H__

#include <hardware/hardware.h>
#include <hardware/face.h>

typedef enum {
    ENROLL_SUCCEED = 0,     // enroll finished and succeed
    ENROLL_FAIL = 1,        // enroll finished and failed
    ENROLL_CONTINUE = 2,    // enroll continue: request next frame
} enroll_state_t;

typedef enum {
    AUTH_SUCCEED = 0,       // authenticate finished and succeed
    AUTH_FAIL = 1,          // authenticate finished and failed
    AUTH_CONTINUE = 2,      // authenticate continue: request next frame
} auth_state_t;

int32_t faceid_tee_initialize();
void faceid_tee_deinitialize();
uint64_t faceid_tee_pre_enroll();
int faceid_tee_verifyToken(const hw_auth_token_t *hat);

int faceid_tee_enroll(uint32_t gid, uint32_t timeout_sec, int32_t width, int32_t height);
enroll_state_t faceid_tee_do_enroll_process(int64_t addr,int64_t lm_addr, const int32_t *info, int32_t count,
                                              int32_t *help, uint32_t *progress, uint32_t *fid, face_error_t *error,const int8_t *byteInfo, int32_t byteCount);
int faceid_tee_post_enroll();
uint64_t faceid_tee_get_authenticator_id();
int faceid_tee_cancel(uint32_t gid);
int faceid_tee_remove(uint32_t gid, uint32_t fid);
int faceid_tee_set_active_group(uint32_t gid);
int faceid_tee_authenticate(uint64_t operation_id, uint32_t gid, int32_t width, int32_t height);
auth_state_t faceid_tee_do_authenticate_process(int64_t main, int64_t sub, int64_t otp,int64_t lm_addr, const int32_t *info, int32_t count,int32_t *help,
                                                  uint32_t *fid, hw_auth_token_t *token, face_error_t *error,const int8_t *byteInfo, int32_t byteCount);
int faceid_tee_dump_enroll(uint32_t gid,uint8_t *buf, uint32_t len);
int faceid_tee_dump_auth(uint8_t *buf, uint32_t len);

#endif // __FACEID_TEE_H__
