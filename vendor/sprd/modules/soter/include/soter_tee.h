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

#ifndef __SOTER_TEE_H__
#define __SOTER_TEE_H__

#if defined __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define EXPORT_KEY_BUF_SIZE 1536
#define SIZE_128_BYTES 128

// enum errors errors are the same between ca and ta,
// but will be filtered when get out
typedef enum {
    SOTER_ERROR_OK                     = 0,
    SOTER_ERROR_ATTK_IS_VALID          = -1,
    SOTER_ERROR_ATTK_NOT_EXIST         = -2,
    SOTER_ERROR_ATTK_DIGEST_NOT_MATCH  = -3,
    SOTER_ERROR_ATTK_DIGEST_NOT_READY  = -4,
    SOTER_ERROR_ASK_NOT_READY          = -5,
    SOTER_ERROR_AUTH_KEY_NOT_READY     = -6,
    SOTER_ERROR_SESSION_OUT_OF_TIME    = -7,
    SOTER_ERROR_NO_AUTH_KEY_MATCHED    = -8,
    SOTER_ERROR_IS_AUTHING             = -9,
    SOTER_ERROR_NO_TA_CONNECTED        = -10,
    //
    SOTER_ERROR_ATTK_EXPORT_FAILED     = -12,
    //
    SOTER_ERROR_ASK_EXPORT_FAILED      = -14,
    //
    SOTER_ERROR_AK_EXPORT_FAILED       = -16,
    SOTER_ERROR_GET_DEVICEID_FAILED    = -17,
    SOTER_ERROR_INIT_SIGN_FAILED       = -19,
    SOTER_ERROR_FINISH_SIGN_FAILED     = -20,
} soter_error_t;

// data structure
typedef struct {
    const char* json;
    size_t json_length;
    // we use json* field carry data, signature* is useless
    // because we just pass data to application layer pellucidly
    const uint8_t* signature;
    size_t signature_length;
} soter_ask_t;

typedef struct {
    const char* json;
    size_t json_length;
    // we use json* field carry data, signature* is useless
    // because we just pass data to application layer pellucidly
    const uint8_t* signature;
    size_t signature_length;
} soter_auth_key_t;

typedef struct {
    const char* session;
    size_t session_length;
} soter_sign_session_t;

typedef struct {
    const char* json;
    size_t json_length;
    // we use json* field carry data, signature* is useless
    // because we just pass data to application layer pellucidly
    const uint8_t* signature;
    size_t signature_length;
} soter_sign_result_t;


/**
 * Open/Close connection to soter ta.
 */
soter_error_t soter_open_tee();
void soter_close_tee();

/**
 * Generates a pair of ATTK defined in SOTER. Save the private key into RPMB and export the public key in
 *         X.509v3 format. Note that the ATTK generated will never be touched outside the key master.
 *
 * @param[in] copy_num the number of copies that will be saved in the RPMB.
 *         E.g. the ATTK generated will be saved twice if the copy_num is 1.
 */
soter_error_t generate_attk_key_pair(const uint8_t copy_num);

/**
 * Verify the existance ATTK defined in SOTER.
 *
 * Returns: 0 if the ATTK exists.
 */
soter_error_t verify_attk_key_pair();

/**
 * Export the public key of ATTK in X.509v3 format.
 *
 * @param[out] pub_key_data the public key data with X.509v3 format
 *
 * @param[out] pub_key_data_length the length of the public key data.
 */
soter_error_t export_attk_public_key(uint8_t* pub_key_data, size_t* pub_key_data_length);

/**
 * Get the unique id.
 *
 * @param[out] device_id the device id data.
 *         unique_id The unique id for each device, format as below:
 *         1.bytes 0-3: Identify each silicon provider id, defined by WeChat
 *         2.bytes 4-7: SoC model ID, defined by each silicon provider（like Qualcomm and Trustonic）
 *         3.bytes 8-15: Public Chip Serial *Number of SoC, defined by each silicon provider（like Qualcomm and Trustonic）
 *         e.g 090000006795000012706b461410496b
 *         We can use 09 to identify MTK *or QC … etc. chips, Use 6795 to identify different model, Use CSN to identify each device.
 *         NOTE: THE DEVICE ID IS CALSS-SENSITIVE
 *
 * @param[out] device_id_length the length of the device_id
 */
soter_error_t get_device_id(uint8_t* device_id, size_t* device_id_length);
/**
 * Set the unique id.(just chip code, e.g. 7731e/9832e)
 * inner interface, not soter spec.
 */
soter_error_t set_device_id(const uint8_t* device_id, size_t device_id_length);

/*
 * Generates a pair of ASK defined in SOTER. Save the private key into safe storage
 *         file and export the public key in x.509v3 format.
 * App can generate ask more than one time, and the new ask will replace the old ask
 *         which was generated last time.
 *
 * @aram[in] uid User Identifier means which app wants to generate ask_key_pair.
 */
soter_error_t generate_ask_key_pair(uint32_t uid);

/**
 * Export the public key of ASK in x.509v3 format and signed with ATTK with given format.
 *
 * @param[in] uid User Identifier means which app wants to generate ask_key_pair.
 *
 * @param[out] data the data assembled of public key data.
 */
soter_error_t export_ask_public_key(uint32_t uid, soter_ask_t* data);

/**
 * Remove the ASK and auth keys of this ASK defined in stoer.
 *
 * @param[in] uid User Identifier means which app wants to remove ask_key.
 */
soter_error_t remove_all_uid_key(uint32_t uid);

/**
 * Check if the ask of a uid has been already.
 *
 * @param[in] uid User Identifier.
 */
soter_error_t has_ask_already(uint32_t uid);

/**
 * Generated a pair of Auth key defined in soter(Authentication Key).
 * Save the private key into safe storage file and export the public key in x.509v3 format.
 * App can generate auth key more than one time.
 *
 * @param[in] uid User Identifier means which app wants to generate auth_key_pair.
 *
 * @param[in] name the name of the AuthKey.
 */
soter_error_t generate_auth_key_pair(uint32_t uid, const char* name);

/**
 * Export the public key of Auth Key in x.509v3 format and signed with ASK with given format.
 *
 * @param[in] uid User Identifier means which app wants to generate auth_key_pair.
 *
 * @param[in] name the name of the AuthKey.
 *
 * @param[out] data the data assembled of public key.
 */
soter_error_t export_auth_key_public_key(uint32_t uid, const char* name,
        soter_auth_key_t* data);

/**
 * Remove the Auth Key defined in soter.
 *
 * @param[in] uid User Identifier means which app wants to remove auth_key.
 *
 * @param[in] name the name of the AuthKey.
 */
soter_error_t remove_auth_key(uint32_t uid,const char* name);

/**
 * Check if the Auth Key of a name has been already.
 *
 * @param[in] uid User Identifier.
 *
 * @param[in] name the name of the AuthKey.
 */
soter_error_t has_auth_key(uint32_t uid,const char* name);

/**
 * init sign
 *
 * @param[in] uid User Identifier means which app wants to sign with auth_key.
 *
 * @param[in] name the name of the AuthKey.
 *
 * @param[in] challenge generated by 3rd app.
 *
 * @param[out] session generated by SoterTA according to uid, name and challenge.
 */
soter_error_t init_sign(uint32_t uid, const char* name, const char*
        challenge, soter_sign_session_t* session);

/**
 * finish sign. Sign the auth key defined in soter.
 *
 * @param[in] session generated by SoterTA according to uid, name and challenge.
 *
 * @param[out] result result of signature.
 */
soter_error_t finish_sign(const soter_sign_session_t* session,
        soter_sign_result_t* result);

#if defined __cplusplus
}
#endif

#endif // __SOTER_TEE_H__ 

