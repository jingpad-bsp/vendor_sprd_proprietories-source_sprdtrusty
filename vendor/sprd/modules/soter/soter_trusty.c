#include <string.h>
#include <log/log.h>

#include "soter_tee.h"
#include "soter_msgs.h"
#include "trusty_soter_ipc.h"

#define LOG_TAG "Soter[CA]"
#define SOTER_TA_RLT_SIZE (sizeof(struct soter_ta_rlt))

soter_error_t soter_open_tee()
{
    int rc = trusty_soter_connect();
    if (rc < 0)
    {
        ALOGE("%s: connect soter ta error(%d).", __func__, rc);
        return SOTER_ERROR_NO_TA_CONNECTED;
    }

    ALOGD("%s: connect ta, result=%d", __func__, rc);
    return (soter_error_t) rc;
}

void soter_close_tee()
{
    trusty_soter_disconnect();
    ALOGD("%s: disconnect ta.", __func__);
}

static int send_request(uint32_t cmd, void *in, uint32_t in_size,
        uint8_t *out, uint32_t *out_size)
{
    int rc = trusty_soter_call(cmd, in, in_size, out, out_size);
    if (rc < 0)
    {
        ALOGE("%s: send request to soter ta error(%d).", __func__, rc);
    }
    return rc;
}

/**
 * Generates ATTK
 */
soter_error_t generate_attk_key_pair(const uint8_t copy_num)
{
    struct soter_ta_rlt rsp;
    uint32_t rsp_len = SOTER_TA_RLT_SIZE;

    int rc = send_request(SOTER_GENERATE_ATTK,
            NULL, 0, (uint8_t*)&rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    ALOGD("%s result:%d", __func__, rsp.error);
    return (soter_error_t) rsp.error;
}

/**
 * Verify ATTK
 */
soter_error_t verify_attk_key_pair()
{
    struct soter_ta_rlt rsp;
    uint32_t rsp_len = SOTER_TA_RLT_SIZE;

    int rc = send_request(SOTER_VERIFY_ATTK,
            NULL, 0, (uint8_t*)&rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    ALOGD("%s result:%d", __func__, rsp.error);
    return (soter_error_t) rsp.error;
}

/**
 * Export the public key of ATTK
 */
soter_error_t export_attk_public_key(uint8_t* pub_key_data, size_t* pub_key_data_length)
{
    uint8_t rsp[EXPORT_KEY_BUF_SIZE];
    uint32_t rsp_len = EXPORT_KEY_BUF_SIZE;

    int rc = send_request(SOTER_EXPORT_ATTK,
            NULL, 0, (uint8_t*)&rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    struct soter_ta_rlt *r = (struct soter_ta_rlt *)rsp;
    uint32_t data_len = rsp_len - SOTER_TA_RLT_SIZE;
    if (r->error != SOTER_ERROR_OK || data_len <= 0) {
        ALOGE("%s error, get rsp_len=%u", __func__, rsp_len);
        return SOTER_ERROR_ATTK_EXPORT_FAILED;
    }
    ALOGD("%s, data_len=%u", __func__, data_len);
    *pub_key_data_length = data_len;
    memcpy(pub_key_data, r->data, data_len);
    return SOTER_ERROR_OK;
}

/**
 * Set the unique id.
 */
soter_error_t set_device_id(const uint8_t* device_id, size_t device_id_length)
{
    struct soter_ta_rlt rsp;
    uint32_t rsp_len = SOTER_TA_RLT_SIZE;

    int rc = send_request(SOTER_SET_DEVICE_ID,
            device_id, device_id_length, (uint8_t*)&rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    ALOGD("%s result:%d", __func__, rsp.error);
    return (soter_error_t) rsp.error;
}

/**
 * Get the unique id.
 */
soter_error_t get_device_id(uint8_t* device_id, size_t* device_id_length)
{
    uint8_t rsp[SIZE_128_BYTES];
    uint32_t rsp_len = SIZE_128_BYTES;

    int rc = send_request(SOTER_GET_DEVICE_ID,
            NULL, 0, (uint8_t*)&rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    struct soter_ta_rlt *r = (struct soter_ta_rlt *)rsp;
    uint32_t data_len = rsp_len - SOTER_TA_RLT_SIZE;
    if (r->error != SOTER_ERROR_OK || data_len <= 0) {
        ALOGE("%s error, get rsp_len=%u", __func__, rsp_len);
        return SOTER_ERROR_GET_DEVICEID_FAILED;
    }
    *device_id_length= data_len;
    memcpy(device_id, rsp, data_len);
    return SOTER_ERROR_OK;
}

/*
 * Generates ASK
 */
soter_error_t generate_ask_key_pair(uint32_t uid)
{
    struct soter_ta_rlt rsp;
    uint32_t rsp_len = SOTER_TA_RLT_SIZE;

    int rc = send_request(SOTER_GENERATE_ASK,
            &uid, sizeof(uid), (uint8_t*)&rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    ALOGD("%s result:%d", __func__, rsp.error);
    return (soter_error_t) rsp.error;
}

/**
 * Export the public key of ASK
 */
soter_error_t export_ask_public_key(uint32_t uid, soter_ask_t* data)
{
    uint8_t rsp[EXPORT_KEY_BUF_SIZE];
    uint32_t rsp_len = EXPORT_KEY_BUF_SIZE;

    int rc = send_request(SOTER_EXPORT_ASK,
            &uid, sizeof(uid), rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    struct soter_ta_rlt *r = (struct soter_ta_rlt *)rsp;
    uint32_t data_len = rsp_len - SOTER_TA_RLT_SIZE;
    if (SOTER_ERROR_OK != r->error || data_len <= 0) {
        ALOGE("export_ask_public_key(uid=%u) error, get rsp_len=%u", uid, rsp_len);
        return SOTER_ERROR_ASK_EXPORT_FAILED;
    }
    ALOGD("%s, data_len=%u", __func__, data_len);
    // no need to parse data here, just pass raw data in json field
    data->json_length = data_len;
    memcpy((char*)data->json, r->data, data_len);
    //data->json_length = *(uint32_t*)(rsp);
    //data->signature_length = rsp_len - data->json_length - sizeof(data->json_length);
    //memcpy(data->json, rsp + sizeof(uint32_t), data->json_length);
    //memcpy(data->signature, rsp + sizeof(uint32_t) + data->json_length, data->signature_length);
    return SOTER_ERROR_OK;
}

/**
 * Remove the ASK and auth keys
 */
soter_error_t remove_all_uid_key(uint32_t uid)
{
    struct soter_ta_rlt rsp;
    uint32_t rsp_len = SOTER_TA_RLT_SIZE;

    int rc = send_request(SOTER_REMOVE_ALL_KEY,
            &uid, sizeof(uid), (uint8_t*)&rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    ALOGD("%s result:%d", __func__, rsp.error);
    return (soter_error_t) rsp.error;
}

/**
 * Check ASK
 */
soter_error_t has_ask_already(uint32_t uid)
{
    struct soter_ta_rlt rsp;
    uint32_t rsp_len = SOTER_TA_RLT_SIZE;

    int rc = send_request(SOTER_CHECK_ASK,
            &uid, sizeof(uid), (uint8_t*)&rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    ALOGD("%s result:%d", __func__, rsp.error);
    return (soter_error_t) rsp.error;
}

/**
 * Generated Auth key
 */
soter_error_t generate_auth_key_pair(uint32_t uid, const char* name)
{
    struct soter_ak_req req;
    struct soter_ta_rlt rsp;
    uint32_t rsp_len = SOTER_TA_RLT_SIZE;

    memset(&req, 0, sizeof(struct soter_ak_req));
    req.uid = uid;
    memcpy(req.name, name, strlen(name));
    int rc = send_request(SOTER_GENERATE_AUTH_KEY,
            &req, sizeof(req), (uint8_t*)&rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    ALOGD("%s result:%d", __func__, rsp.error);
    return (soter_error_t) rsp.error;
}

/**
 * Export the public key of Auth Key
 */
soter_error_t export_auth_key_public_key(uint32_t uid, const char* name,
        soter_auth_key_t* data)
{
    struct soter_ak_req req;
    uint8_t rsp[EXPORT_KEY_BUF_SIZE];
    uint32_t rsp_len = EXPORT_KEY_BUF_SIZE;

    memset(&req, 0, sizeof(struct soter_ak_req));
    req.uid = uid;
    memcpy(req.name, name, strlen(name));
    int rc = send_request(SOTER_EXPORT_AUTH_KEY,
            &req, sizeof(struct soter_ak_req), rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    struct soter_ta_rlt *r = (struct soter_ta_rlt *)rsp;
    uint32_t data_len = rsp_len - SOTER_TA_RLT_SIZE;
    if (SOTER_ERROR_OK != r->error || data_len <= 0) {
        ALOGE("export_auth_key_public_key(uid=%u, name=%s) error, get rsp_len=%u", uid, name, rsp_len);
        return SOTER_ERROR_AK_EXPORT_FAILED;
    }
    ALOGD("%s, data_len=%u", __func__, data_len);
    // no need to parse data here, just pass raw data in json field
    data->json_length = data_len;
    memcpy((char*)data->json, r->data, data_len);
    return SOTER_ERROR_OK;
}

/**
 * Remove the Auth Key
 */
soter_error_t remove_auth_key(uint32_t uid,const char* name)
{
    struct soter_ak_req req;
    struct soter_ta_rlt rsp;
    uint32_t rsp_len = SOTER_TA_RLT_SIZE;

    memset(&req, 0, sizeof(struct soter_ak_req));
    req.uid = uid;
    memcpy(req.name, name, strlen(name));
    int rc = send_request(SOTER_REMOVE_AUTH_KEY,
            &req, sizeof(req), (uint8_t*)&rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    ALOGD("%s result:%d", __func__, rsp.error);
    return (soter_error_t) rsp.error;
}

/**
 * Check Auth Key
 */
soter_error_t has_auth_key(uint32_t uid,const char* name)
{
    struct soter_ak_req req;
    struct soter_ta_rlt rsp;
    uint32_t rsp_len = SOTER_TA_RLT_SIZE;

    memset(&req, 0, sizeof(struct soter_ak_req));
    req.uid = uid;
    memcpy(req.name, name, strlen(name));
    int rc = send_request(SOTER_CHECK_AUTH_KEY,
            &req, sizeof(req), (uint8_t*)&rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    ALOGD("%s result:%d", __func__, rsp.error);
    return (soter_error_t) rsp.error;
}

/**
 * init sign
 */
soter_error_t init_sign(uint32_t uid, const char* name, const char*
        challenge, soter_sign_session_t* session)
{
    struct soter_init_req req;
    uint8_t rsp[SIZE_128_BYTES] = { 0 };
    uint32_t rsp_len = SIZE_128_BYTES;

    memset(&req, 0, sizeof(struct soter_init_req));
    req.uid = uid;
    memcpy(&req.name, name, strlen(name));
    memcpy(&req.challenge, challenge, strlen(challenge));
    int rc = send_request(SOTER_INIT_SIGN,
            &req, sizeof(req), (uint8_t*)&rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    struct soter_ta_rlt *r = (struct soter_ta_rlt *)rsp;
    uint32_t data_len = rsp_len - SOTER_TA_RLT_SIZE;
    if (SOTER_ERROR_OK != r->error || data_len <= 0) {
        ALOGE("init_sign(uid=%u, name=%s) error, get rsp_len=%u", uid, name, rsp_len);
        return SOTER_ERROR_INIT_SIGN_FAILED;
    }
    ALOGD("%s, data_len=%u", __func__, data_len);
    session->session_length = data_len;
    memcpy((char*)session->session, r->data, data_len);
    return SOTER_ERROR_OK;
}

/**
 * finish sign
 */
soter_error_t finish_sign(const soter_sign_session_t* session,
        soter_sign_result_t* result)
{
    struct soter_finish_req req;
    uint8_t rsp[EXPORT_KEY_BUF_SIZE] = { 0 };
    uint32_t rsp_len = EXPORT_KEY_BUF_SIZE;

    memset(&req, 0, sizeof(struct soter_finish_req));
    memcpy(&req.session, session->session, session->session_length);
    int rc = send_request(SOTER_FINISH_SIGN,
            &req, sizeof(req), (uint8_t*)&rsp, &rsp_len);
    if (rc < 0)
    {
        ALOGE("%s: trusty_soter_call failed", __func__);
        return rc;
    }

    struct soter_ta_rlt *r = (struct soter_ta_rlt *)rsp;
    uint32_t data_len = rsp_len - SOTER_TA_RLT_SIZE;
    if (SOTER_ERROR_OK != r->error || data_len == 0) {
        ALOGE("finish_sign(session=%llu) error, get rsp_len=%u", *(uint64_t*)session->session, rsp_len);
        return SOTER_ERROR_FINISH_SIGN_FAILED;
    }
    ALOGD("%s, data_len=%u", __func__, data_len);
    // no need to parse data here, just pass raw data in json field
    result->json_length = data_len;
    memcpy((char*)result->json, r->data, data_len);
    return SOTER_ERROR_OK;
}

