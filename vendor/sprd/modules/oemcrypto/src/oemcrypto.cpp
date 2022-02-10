/*
 * Copyright (c) 2019, Spreadtrum Communications.
 *
 * The above copyright notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * The Client application's implementation of unisoc OEMCrypto
 *
 */

#include "OEMCryptoCENC.h"

#include <openssl/sha.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oemcrypto_logging.h"
#include "string_conversions.h"
#include "wv_cdm_constants.h"

#include "oemcrypto_ipc.h"
#include "trusty_oemcrypto_ipc.h"
#include "MemIon.h"
#include "sprd_ion.h"
#include "cutils/native_handle.h"

#define TRUSTRY_CALL_LOG   1
#define TRUSTRY_RECV_BUF_SIZE  16

#define IS_PRODUCT_VERSION  1
#if defined(_WIN32)
# define OEMCRYPTO_API extern "C" __declspec(dllexport)
#else  // defined(_WIN32)
# define OEMCRYPTO_API extern "C" __attribute__((visibility("default")))
#endif  // defined(_WIN32)

namespace {
const uint8_t kBakedInCertificateMagicBytes[] = { 0xDE, 0xAD, 0xBE, 0xEF };
}  // namespace

namespace wvoec_unisoc {

static const uint32_t kUint32Size = sizeof(uint32_t);
static const uint32_t kUint64Size = sizeof(uint64_t);
static const uint32_t kSizeSize = sizeof(size_t);
static const uint32_t kSessionSize = sizeof(OEMCrypto_SESSION);
static const uint32_t kOEMCryptoResultSize = sizeof(OEMCryptoResult);
static const uint32_t kProvisionResultSize = sizeof(uint32_t);

OEMCRYPTO_API OEMCryptoResult OEMCrypto_Initialize(void) {

    OEMCryptoResult        result;
    uint8_t   out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t  outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("--  OEMCrypto_Initialize(void)\n");
    }

    int rc = trusty_oemcrypto_connect();

    if (rc < 0) {
       LOGE("[OEMCrypto_Initialize():"
            " tipc_connect(): failed, ret = %d]\n", rc);
       return OEMCrypto_ERROR_INIT_FAILED;
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_INITIALIZE,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_Initialize():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return OEMCrypto_ERROR_INIT_FAILED;
    }
    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_Initialize(): %d failed]\n", result);
        return OEMCrypto_ERROR_INIT_FAILED;
    }
    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGD("[OEMCrypto_Initialize(): success]");
    }

    return result;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_SetSandbox(
                            const uint8_t* sandbox_id,
                            size_t sandbox_id_length) {
    OEMCryptoResult   result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize;
    uint8_t    out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t   outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_SetSandbox()\n");
    }

    int rc = trusty_oemcrypto_connect();

    if (rc < 0) {
       LOGE("[OEMCrypto_SetSandbox():"
            " tipc_connect(): failed, ret = %d]\n", rc);
       return OEMCrypto_ERROR_INIT_FAILED;
    }

    insize = kSizeSize + sandbox_id_length;
    in_msg = reinterpret_cast<uint8_t *>(malloc(insize));
    if (in_msg == NULL) {
         LOGE("OEMCrypto_SetSandbox():"
              " in_msg malloc (%d) failed\n", insize);
         return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &sandbox_id_length, kSizeSize);
    memcpy((in_msg + kSizeSize), sandbox_id, sandbox_id_length);

    result = trusty_oemcrypto_call(OEMCRYPTO_SETSANDBOX,
                in_msg, insize, out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_SetSandbox():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);

    trusty_oemcrypto_disconnect();

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_SetSandbox(): %d failed]\n",result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_Terminate(void) {
    OEMCryptoResult        result;
    uint8_t   out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t  outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_Terminate(void)\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_TERMINATE,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_Terminate():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return OEMCrypto_ERROR_TERMINATE_FAILED;
    }
    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_Terminate(): %d failed]\n", result);
        return OEMCrypto_ERROR_TERMINATE_FAILED;
    }

    trusty_oemcrypto_disconnect();
    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGD("[OEMCrypto_Terminate(): success]");
    }

    return result;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_OpenSession(
                        OEMCrypto_SESSION* session) {

    OEMCryptoResult        result;
    uint8_t   out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t  outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_OpenSession"
         "(OEMCrypto_SESSION *session)\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_OPENSESSION,
                NULL, 0, out_msg, &outsize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_OpenSession():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_OpenSession(): %d failed]\n", result);
        return result;
    }

    memcpy(session,
            (msg->payload + kOEMCryptoResultSize), kSessionSize);

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGD("[OEMCrypto_OpenSession(): SID=%08x]", *session);
    }
    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_CloseSession(
                            OEMCrypto_SESSION session) {
    OEMCryptoResult        result;
    uint8_t   out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t  outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_CloseSession"
         "(OEMCrypto_SESSION session)\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_CLOSESESSION,
                            (void *)&session, kSessionSize,
                                out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_CloseSession(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n",
                session, result);
        return result;
    }

    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_CloseSession(): %d failed]\n", result);
        return result;
    }
    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGD("[OEMCrypto_CloseSession(SID=%08X): success]",
                session);
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_GenerateDerivedKeys(
                                 OEMCrypto_SESSION session,
                                 const uint8_t* mac_key_context,
                                 uint32_t mac_key_context_length,
                                 const uint8_t* enc_key_context,
                                 uint32_t enc_key_context_length) {
    OEMCryptoResult   result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize;
    uint8_t    out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t   outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;
    size_t     tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GenerateDerivedKeys()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("mac_key_context", mac_key_context,
               (size_t)mac_key_context_length);
            dump_hex("enc_key_context", enc_key_context,
               (size_t)enc_key_context_length);
        }
    }

    insize = kSessionSize + kUint32Size + kUint32Size +
        mac_key_context_length + enc_key_context_length;
    in_msg = reinterpret_cast<uint8_t *>(malloc(insize));
    if (in_msg == NULL) {
         LOGE("OEMCrypto_GenerateDerivedKeys():"
              " in_msg malloc (%d) failed\n", insize);
         return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size),
            &mac_key_context_length, kUint32Size);
    tmp_size += kUint32Size;
    memcpy((in_msg + tmp_size),
            mac_key_context, mac_key_context_length);
    tmp_size += mac_key_context_length;
    memcpy((in_msg + tmp_size),
            &enc_key_context_length, kUint32Size);
    tmp_size += kUint32Size;
    memcpy((in_msg + tmp_size),
            enc_key_context, enc_key_context_length);

    result = trusty_oemcrypto_call(OEMCRYPTO_GENERATEDERIVEDKEYS,
                in_msg, insize, out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GenerateDerivedKeys():"
             "rusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GenerateDerivedKeys(): %d failed]\n",
                result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}


OEMCRYPTO_API OEMCryptoResult OEMCrypto_GenerateNonce(
                                        OEMCrypto_SESSION session,
                                        uint32_t* nonce) {
    OEMCryptoResult        result;
    uint8_t   out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t  outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GenerateNonce()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_GENERATENONCE,
                (void *)&session, kSessionSize, out_msg, &outsize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GenerateNonce(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        return result;
    }

    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GenerateNonce(): %d failed]\n", result);
        return result;
    }

    memcpy(nonce, (msg->payload + kOEMCryptoResultSize), kUint32Size);

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("nonce = %08x\n", *nonce);
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_GenerateSignature(
                            OEMCrypto_SESSION session,
                            const uint8_t* message,
                            size_t message_length,
                            uint8_t* signature,
                            size_t* signature_length) {
    OEMCryptoResult     result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize ;
    uint8_t*   out_msg = NULL;
    uint32_t   outsize;
    struct oemcrypto_message* msg = NULL;
    size_t     tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GenerateSignature()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("message", message, message_length);
        }
    }
    if (*signature_length < SHA256_DIGEST_LENGTH) {
        *signature_length = SHA256_DIGEST_LENGTH;
        return OEMCrypto_ERROR_SHORT_BUFFER;
    }

    if (message == NULL || message_length == 0 ||
        signature == NULL || signature_length == 0) {
        LOGE("[OEMCrypto_GenerateSignature():"
             " OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }
    insize = kSessionSize + kSizeSize + message_length + kSizeSize;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_GenerateSignature():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    outsize = kOEMCryptoResultSize + kSizeSize + *signature_length +
        sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_GenerateSignature():"
             " out_msg malloc (%d) failed\n", outsize);
        free(in_msg);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &message_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), message, message_length);
    tmp_size += message_length;
    memcpy((in_msg + tmp_size), signature_length, kSizeSize);

    result = trusty_oemcrypto_call(OEMCRYPTO_GENERATESIGNATURE,
                in_msg, insize, out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GenerateNonce(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n",
                session, result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GenerateNonce(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    memcpy(signature_length,
            msg->payload + kOEMCryptoResultSize, kSizeSize);
    memcpy(signature,
            msg->payload + kOEMCryptoResultSize + kSizeSize,
             *signature_length);

    free(out_msg);
    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("signature", signature, *signature_length);
        }
    }

    return OEMCrypto_SUCCESS;
}

bool RangeCheck(const uint8_t* message,
                uint32_t message_length,
                const uint8_t* field,
                uint32_t field_length,
                bool allow_null) {
  if (field == NULL) return allow_null;
  if (field < message) return false;
  if (field + field_length > message + message_length) return false;
  return true;
}

bool RangeCheck(uint32_t message_length,
                const OEMCrypto_Substring& substring,
                bool allow_null) {
  if (!substring.length) return allow_null;
  if (substring.offset > message_length) return false;
  if (substring.offset + substring.length > message_length) return false;
  return true;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_LoadKeys(
                            OEMCrypto_SESSION session,
                            const uint8_t* message,
                            size_t message_length,
                            const uint8_t* signature,
                            size_t signature_length,
                            OEMCrypto_Substring enc_mac_keys_iv,
                            OEMCrypto_Substring enc_mac_keys,
                            size_t num_keys,
                            const OEMCrypto_KeyObject* key_array,
                            OEMCrypto_Substring pst,
                            OEMCrypto_Substring srm_restriction_data,
                            OEMCrypto_LicenseType license_type) {
    OEMCryptoResult     result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize ;
    uint8_t    out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t   outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;
    uint32_t    key_array_size = num_keys*sizeof(OEMCrypto_KeyObject);
    size_t      tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_LoadKeys()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("message", message, message_length);
            dump_hex("signature", signature, signature_length);
            for (size_t i = 0; i < num_keys; i++) {
                LOGV("key_array[%zu].key_id.length=%zu;\n", i,
                      key_array[i].key_id.length);
                dump_array_part("key_array", i, "key_id",
                        message + key_array[i].key_id.offset,
                        key_array[i].key_id.length);
                dump_array_part("key_array", i, "key_data_iv",
                        message + key_array[i].key_data_iv.offset,
                        key_array[i].key_data_iv.length);
                dump_array_part("key_array", i, "key_data",
                        message + key_array[i].key_data.offset,
                        key_array[i].key_data.length);
                dump_array_part("key_array", i, "key_control_iv",
                        message + key_array[i].key_control_iv.offset,
                        key_array[i].key_control_iv.length);
                dump_array_part("key_array", i, "key_control",
                        message + key_array[i].key_control.offset,
                        key_array[i].key_control.length);
             }
        }
    }

    if (message == NULL || message_length == 0 ||
        signature == NULL || signature_length == 0 ||
        key_array == NULL || num_keys == 0) {
        LOGE("[OEMCrypto_LoadKeys(): OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    // Range check
    if (!RangeCheck(message_length, enc_mac_keys_iv, true) ||
        !RangeCheck(message_length, enc_mac_keys, true) ||
        !RangeCheck(message_length, pst, true) ||
        !RangeCheck(message_length, srm_restriction_data, true)) {
        LOGE("[OEMCrypto_LoadKeys():"
             " OEMCrypto_ERROR_INVALID_CONTEXT - range check.]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    for (unsigned int i = 0; i < num_keys; i++) {
        if (!RangeCheck(message_length, key_array[i].key_id, false) ||
            !RangeCheck(message_length, key_array[i].key_data, false) ||
            !RangeCheck(message_length, key_array[i].key_data_iv, false) ||
            !RangeCheck(message_length, key_array[i].key_control, false) ||
            !RangeCheck(message_length, key_array[i].key_control_iv, false)) {
            LOGE("[OEMCrypto_LoadKeys():"
                 " OEMCrypto_ERROR_INVALID_CONTEXT -range check %d]", i);
            return OEMCrypto_ERROR_INVALID_CONTEXT;
        }
    }

    insize = kSessionSize + (kSizeSize*3) + message_length +
        signature_length +  sizeof(OEMCrypto_Substring)*4 +
            key_array_size + sizeof(OEMCrypto_LicenseType);

    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
         LOGE("OEMCrypto_LoadKeys(): in_msg malloc (%d) failed\n",
                 insize);
         return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    /*Attention: we are currently not support srm at 201804, so don't pass it to TEE*/
    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &message_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), message, message_length);
    tmp_size += message_length;
    memcpy((in_msg + tmp_size), &signature_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), signature, signature_length);
    tmp_size += signature_length;

    memcpy((in_msg + tmp_size),
            &enc_mac_keys_iv, sizeof(OEMCrypto_Substring));
    tmp_size += sizeof(OEMCrypto_Substring);
    memcpy((in_msg + tmp_size),
            &enc_mac_keys, sizeof(OEMCrypto_Substring));
    tmp_size += sizeof(OEMCrypto_Substring);

    memcpy((in_msg + tmp_size), &num_keys, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), key_array, key_array_size);
    tmp_size += key_array_size;

    memcpy((in_msg + tmp_size),
            &pst, sizeof(OEMCrypto_Substring));
    tmp_size += sizeof(OEMCrypto_Substring);
    memcpy((in_msg + tmp_size),
            &srm_restriction_data, sizeof(OEMCrypto_Substring));
    tmp_size += sizeof(OEMCrypto_Substring);

    memcpy((in_msg + tmp_size),
            &license_type, sizeof(OEMCrypto_LicenseType));
    tmp_size += sizeof(OEMCrypto_LicenseType);

    insize = tmp_size;

    result = trusty_oemcrypto_call(OEMCRYPTO_LOADKEYS, in_msg, insize,
                                      out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadKeys(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        return result;
    }
    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadKeys(): %d failed]\n", result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_LoadEntitledContentKeys(
                                    OEMCrypto_SESSION session,
                                    const uint8_t* message,
                                    size_t message_length,
                                    size_t num_keys,
                                    const OEMCrypto_EntitledContentKeyObject* key_array) {
    OEMCryptoResult     result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize ;
    uint8_t    out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t   outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;
    uint32_t    key_array_size = num_keys*sizeof(OEMCrypto_EntitledContentKeyObject);
    size_t      tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_LoadEntitledContentKeys()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("message", message, message_length);
            for (size_t i = 0; i < num_keys; i++) {
                LOGV("key_array[%zu].entitlement_key_id.length=%zu;\n", i,
                      key_array[i].entitlement_key_id.length);
                dump_array_part("key_array", i, "entitlement_key_id",
                        message + key_array[i].entitlement_key_id.offset,
                        key_array[i].entitlement_key_id.length);
                LOGV("key_array[%zu].content_key_id.length=%zu;\n", i,
                      key_array[i].content_key_id.length);
                dump_array_part("key_array", i, "content_key_id",
                        message + key_array[i].content_key_id.offset,
                        key_array[i].content_key_id.length);
                LOGV("key_array[%zu].content_key_data_iv.length=%zu;\n", i,
                      key_array[i].content_key_data_iv.length);
                dump_array_part("key_array", i, "content_key_data_iv",
                        message + key_array[i].content_key_data_iv.offset,
                        key_array[i].content_key_data_iv.length);
                LOGV("key_array[%zu].content_key_data.length=%zu;\n", i,
                      key_array[i].content_key_data.length);
                dump_array_part("key_array", i, "content_key_data",
                        message + key_array[i].content_key_data.offset,
                        key_array[i].content_key_data.length);
             }
        }
    }

    if (message == NULL || message_length == 0 ||
        key_array == NULL || num_keys == 0) {
        LOGE("[OEMCrypto_LoadEntitledContentKeys(): "
             " OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    // Range check
    for (unsigned int i = 0; i < num_keys; i++) {
        if (!RangeCheck(message_length, key_array[i].entitlement_key_id, false) ||
            !RangeCheck(message_length, key_array[i].content_key_id, false) ||
            !RangeCheck(message_length, key_array[i].content_key_data_iv, false) ||
            !RangeCheck(message_length, key_array[i].content_key_data, false)) {
            LOGE("[OEMCrypto_LoadEntitledContentKeys(): "
                "OEMCrypto_ERROR_INVALID_CONTEXT -range check %d]", i);
            return OEMCrypto_ERROR_INVALID_CONTEXT;
        }
    }

    insize = kSessionSize + (kSizeSize * 2) + message_length + key_array_size;

    in_msg = reinterpret_cast<uint8_t *>(malloc(insize));
    if (in_msg == NULL) {
         LOGE("OEMCrypto_LoadEntitledContentKeys():"
              " in_msg malloc (%d) failed\n", insize);
         return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &message_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), message, message_length);
    tmp_size += message_length;

    memcpy((in_msg + tmp_size), &num_keys, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), key_array, key_array_size);
    tmp_size += key_array_size;

    insize = tmp_size;

    result = trusty_oemcrypto_call(OEMCRYPTO_LOADENTITLEDCONTENTKEYS,
                in_msg, insize, out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadEntitledContentKeys(SID=%08X): "
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        return result;
    }
    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadEntiledContentKeys(): %d failed]\n", result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_RefreshKeys(
                    OEMCrypto_SESSION session,
                    const uint8_t* message,
                    size_t message_length,
                    const uint8_t* signature,
                    size_t signature_length,
                    size_t num_keys,
                    const OEMCrypto_KeyRefreshObject* key_array) {
    OEMCryptoResult     result;
    uint8_t*    in_msg = NULL;
    uint32_t    insize ;
    uint8_t     out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t    outsize = TRUSTRY_RECV_BUF_SIZE;
    uint32_t    key_array_size = num_keys*sizeof(OEMCrypto_KeyRefreshObject);
    size_t      tmp_size = 0;

    struct oemcrypto_message      *msg = NULL;
    OEMCrypto_KeyRefreshObject object_array[num_keys];

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_RefreshKeys()\n");
    }

    if (message == NULL || message_length == 0 ||
        signature == NULL || signature_length == 0 ||
        num_keys == 0) {
        LOGE("[OEMCrypto_RefreshKeys(): OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    // Range check
    for (unsigned int i = 0; i < num_keys; i++) {
        if (!RangeCheck(message_length, key_array[i].key_id, true) ||
            !RangeCheck(message_length, key_array[i].key_control, false) ||
            !RangeCheck(message_length, key_array[i].key_control_iv, true)) {
            LOGE("[OEMCrypto_RefreshKeys(): Range Check %d]", i);
            return OEMCrypto_ERROR_INVALID_CONTEXT;
        }
    }

    insize = kSessionSize + (kSizeSize*3) + message_length +
        signature_length + key_array_size;
    in_msg = reinterpret_cast<uint8_t *>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_RefreshKeys(): in_msg malloc (%d) failed\n",
                insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &message_length, kSizeSize);
    tmp_size += kSizeSize;
    if ((message_length > 0) && (message != NULL)) {
        memcpy((in_msg + tmp_size), message, message_length);
        tmp_size += message_length;
    }

    memcpy((in_msg + tmp_size), &signature_length, kSizeSize);
    tmp_size += kSizeSize;
    if ((signature_length > 0) && (signature != NULL)) {
        memcpy((in_msg + tmp_size), signature, signature_length);
        tmp_size += signature_length;
    }

    memcpy((in_msg + tmp_size), &num_keys, kSizeSize);
    tmp_size += kSizeSize;

    memcpy((in_msg + tmp_size), key_array, key_array_size);
    tmp_size += key_array_size;

    insize = tmp_size;

    result = trusty_oemcrypto_call(OEMCRYPTO_REFRESHKEYS,
                in_msg, insize, out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadKeys(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        return result;
    }
    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadKeys(): %d failed]\n", result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_QueryKeyControl(
                                    OEMCrypto_SESSION session,
                                    const uint8_t* key_id,
                                    size_t key_id_length,
                                    uint8_t* key_control_block,
                                    size_t* key_control_block_length) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize ;
    uint8_t*            out_msg = NULL;
    uint32_t            outsize;
    struct oemcrypto_message* msg = NULL;
    size_t              tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_QueryKeyControl"
         "(const OEMCrypto_SESSION session)\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("key_id", key_id, key_id_length);
        }
    }
    uint32_t* block = reinterpret_cast<uint32_t*>(key_control_block);
    if ((key_control_block_length == NULL)
        || (*key_control_block_length < wvcdm::KEY_CONTROL_SIZE)) {
        LOGE("[OEMCrypto_QueryKeyControl(): OEMCrypto_ERROR_SHORT_BUFFER]");
        return OEMCrypto_ERROR_SHORT_BUFFER;
    }
    *key_control_block_length = wvcdm::KEY_CONTROL_SIZE;
    if (key_id == NULL) {
        LOGE("[OEMCrypto_QueryKeyControl():"
             " key_id null. OEMCrypto_ERROR_UNKNOWN_FAILURE]");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
     }

    insize = kSessionSize + kSizeSize  + key_id_length + kSizeSize;
    in_msg = reinterpret_cast<uint8_t *>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_QueryKeyControl(): in_msg malloc (%d) failed\n",
                insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    outsize = kOEMCryptoResultSize + kSizeSize +
        *key_control_block_length + sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t *>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_QueryKeyControl(): out_msg malloc (%d) failed\n",
                outsize);
        free(in_msg);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &key_id_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), key_id, key_id_length);
    tmp_size += key_id_length;
    memcpy((in_msg + tmp_size), key_control_block_length, kSizeSize);

    result = trusty_oemcrypto_call(OEMCRYPTO_QUERYKEYCONTROL,
                in_msg, insize, out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_QueryKeyControl(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_QueryKeyControl(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    memcpy(key_control_block_length,
            msg->payload + kOEMCryptoResultSize, kSizeSize);
    memcpy(key_control_block,
            msg->payload + kOEMCryptoResultSize + kSizeSize,
             *key_control_block_length);

    free(out_msg);

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_SelectKey(
                                    const OEMCrypto_SESSION session,
                                    const uint8_t* key_id,
                                    size_t key_id_length,
                                    OEMCryptoCipherMode cipher_mode) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize ;
    uint8_t             out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t            outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;
    size_t              tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_SelectKey"
             "(const OEMCrypto_SESSION session)\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
             dump_hex("key_id", key_id, key_id_length);
        }
    }

    insize = kSessionSize + kSizeSize  + key_id_length +
        sizeof(OEMCryptoCipherMode);
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_SelectKey(): in_msg malloc (%d) failed\n",
                insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &key_id_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), key_id, key_id_length);
    tmp_size += key_id_length;
    memcpy((in_msg + tmp_size),
            &cipher_mode, sizeof(OEMCryptoCipherMode));

    result = trusty_oemcrypto_call(OEMCRYPTO_SELECTKEY,
                in_msg, insize, out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_SelectKey(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_SelectKey(): %d failed]\n", session, result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_DecryptCENC(OEMCrypto_SESSION session,
                                      const uint8_t* data_addr,
                                      size_t data_length,
                                      bool is_encrypted,
                                      const uint8_t* iv,
                                      size_t block_offset,
                                      OEMCrypto_DestBufferDesc* out_buffer,
                                      const OEMCrypto_CENCEncryptPatternDesc* pattern,
                                      uint8_t subsample_flags) {
    OEMCryptoResult             result;
    OEMCrypto_DestBufferDesc    out_buffer_modified;
    uint8_t*                    in_msg = NULL;
    uint32_t                    insize ;
    uint8_t*                    out_msg = NULL;
    uint32_t                    outsize;
    uint32_t                    buffer_desc_size , pattern_desc_size;
    struct oemcrypto_message*   msg = NULL;
    size_t                      tmp_size = 0;
    unsigned long               phy_addr;
    size_t                      phy_addr_size;
    int                         fd, ret = -1;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_DecryptCENC()\n");
    }
    if (data_addr == NULL || data_length == 0 ||
        iv == NULL || out_buffer == NULL) {
        LOGE("[OEMCrypto_DecryptCENC(): OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    LOGI("[OEMCrypto_DecryptCENC: block_offset:%d,"
         " prepare to transfer %d bytes to trustos]\n",
            block_offset, data_length);

    if (data_length > OEMCRYPTO_MAX_BUFFER_SIZE) {
        LOGE("[OEMCrypto_DecryptCENC(): OEMCrypto_ERROR_BUFFER_TOO_LARGE]");
        return OEMCrypto_ERROR_BUFFER_TOO_LARGE;
    }

    buffer_desc_size = sizeof(OEMCrypto_DestBufferDesc);
    pattern_desc_size = sizeof(OEMCrypto_CENCEncryptPatternDesc);
    insize = kSessionSize + (kSizeSize*2) + sizeof(bool) + sizeof(uint8_t) +
        data_length + buffer_desc_size + pattern_desc_size + wvcdm::KEY_IV_SIZE;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_DecryptCENC(): in_msg malloc (%d) failed\n",
                insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    if (out_buffer->type == OEMCrypto_BufferType_Clear) {
        outsize = kOEMCryptoResultSize + kSizeSize +
            sizeof(struct oemcrypto_message) + data_length;
    } else {
        outsize = kOEMCryptoResultSize + kSizeSize +
            sizeof(struct oemcrypto_message);
    }

    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_DecryptCENC(): out_msg malloc (%d) failed\n",
                outsize);
        free(in_msg);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    if (out_buffer->type == OEMCrypto_BufferType_Direct) {
        LOGI("[OEMCrypto_DecryptCENC:"
             " The type of out_buffer is OEMCrypto_BufferType_Direct]\n");
    } else if (out_buffer->type == OEMCrypto_BufferType_Secure) {
        LOGI("[OEMCrypto_DecryptCENC:"
             " The type of out_buffer is OEMCrypto_BufferType_Secure]\n");
        memset(&out_buffer_modified, 0, buffer_desc_size);
        memcpy(&out_buffer_modified, out_buffer,  buffer_desc_size);

        fd = ((struct native_handle *)(out_buffer->buffer.secure.handle))->data[0];
        if((ret = android::MemIon::Get_phy_addr_from_ion(fd,
                  &phy_addr, &phy_addr_size)) == 0) {
            LOGI("[OEMCrypto_DecryptCENC: MemIon::Get_phy_addr_from_ion():"
                 " %d succeed]\n", ret);
            out_buffer_modified.buffer.secure.handle = (void *)phy_addr;
            out_buffer_modified.buffer.secure.max_length = phy_addr_size;
            LOGI("[OEMCrypto_DecryptCENC:"
                 " out_buffer->buffer.secure.handle:0x%x]\n",
                    out_buffer_modified.buffer.secure.handle);
            LOGI("[OEMCrypto_DecryptCENC:"
                 " out_buffer->buffer.secure.max_length:0x%x]\n",
                    out_buffer_modified.buffer.secure.max_length);
        }

    } else {
        LOGI("[OEMCrypto_DecryptCENC:"
             " The type of out_buffer is OEMCrypto_BufferType_Clear]\n");
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size = kSessionSize;
    memcpy((in_msg + tmp_size), &data_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), data_addr, data_length);
    tmp_size += data_length;
    memcpy((in_msg + tmp_size), iv, wvcdm::KEY_IV_SIZE);
    tmp_size += wvcdm::KEY_IV_SIZE;
    memcpy((in_msg + tmp_size), &block_offset, kSizeSize);
    tmp_size += kSizeSize;
    if (out_buffer->type == OEMCrypto_BufferType_Secure) {
        memcpy((in_msg + tmp_size), &out_buffer_modified, buffer_desc_size);
    } else {
        memcpy((in_msg + tmp_size), out_buffer, buffer_desc_size);
    }
    tmp_size += buffer_desc_size;
    memcpy((in_msg + tmp_size), pattern, pattern_desc_size);
    tmp_size += pattern_desc_size;
    memcpy((in_msg + tmp_size), &is_encrypted, sizeof(bool));
    tmp_size += sizeof(bool);
    memcpy((in_msg + tmp_size), &subsample_flags, sizeof(uint8_t));
    tmp_size += sizeof(uint8_t);
    insize = tmp_size;

    result = trusty_oemcrypto_call(OEMCRYPTO_DECRYPTCENC,
                in_msg, insize, out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_DecryptCENC(SID=%08X):"
             " line:%d, trusty_oemcrypto_call(): %d failed]\n",
                session, __LINE__, result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_DecryptCENC(): line:%d, %d failed]\n",
                __LINE__, result);
        free(out_msg);
        return result;
    }

    if ((out_buffer->type == OEMCrypto_BufferType_Clear) &&
            (out_buffer->buffer.clear.address != NULL)) {
        memcpy(out_buffer->buffer.clear.address,
                msg->payload + kOEMCryptoResultSize, data_length);
    }

    free(out_msg);

    LOGI("[OEMCrypto_DecryptCENC:"
         " block_offset:%d, transferred %d bytes to trustos]\n",
            block_offset, data_length);

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_CopyBuffer(
                                  OEMCrypto_SESSION session,
                                  const uint8_t *data_addr,
                                  size_t data_length,
                                  OEMCrypto_DestBufferDesc* out_buffer,
                                  uint8_t subsample_flags) {
    OEMCryptoResult             result;
    OEMCrypto_DestBufferDesc    out_buffer_modified;
    uint8_t*                    in_msg = NULL;
    uint32_t                    insize ;
    uint8_t*                    out_msg = NULL;
    uint32_t                    outsize;
    uint32_t                    buffer_desc_size;
    size_t                      copy_data_len = 0;
    struct oemcrypto_message*   msg = NULL;
    unsigned long               phy_addr;
    size_t                      phy_addr_size;
    int                         fd, ret = -1;
    size_t                      tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_CopyBuffer()\n");
    }
    if (data_addr == NULL || out_buffer == NULL ||
            out_buffer->buffer.clear.address == NULL) {
        LOGE("[OEMCrypto_CopyBuffer(): OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    LOGI("[OEMCrypto_CopyBuffer: prepare to transfer %d bytes to trustos]\n",
            data_length);

    if (data_length > OEMCRYPTO_MAX_BUFFER_SIZE) {
        LOGE("[OEMCrypto_CopyBuffer(): OEMCrypto_ERROR_BUFFER_TOO_LARGE]");
        return OEMCrypto_ERROR_BUFFER_TOO_LARGE;
    }

    buffer_desc_size = sizeof(OEMCrypto_DestBufferDesc);
    insize = kSessionSize + kSizeSize + sizeof(uint8_t) +
        data_length + buffer_desc_size;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_CopyBuffer(): in_msg malloc (%d) failed\n",
                insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    outsize = kOEMCryptoResultSize + kSizeSize + data_length +
        sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_CopyBuffer(): out_msg malloc (%d) failed\n",
                outsize);
        free(in_msg);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    if (out_buffer->type == OEMCrypto_BufferType_Direct) {
        LOGI("[OEMCrypto_CopyBuffer:"
             " The type of out_buffer is OEMCrypto_BufferType_Direct]\n");
    } else if (out_buffer->type == OEMCrypto_BufferType_Secure) {
        LOGI("[OEMCrypto_CopyBuffer:"
             " The type of out_buffer is OEMCrypto_BufferType_Secure]\n");
        memset(&out_buffer_modified, 0, buffer_desc_size);
        memcpy(&out_buffer_modified, out_buffer,  buffer_desc_size);

        fd = ((struct native_handle*)(out_buffer->buffer.secure.handle))->data[0];
        if((ret = android::MemIon::Get_phy_addr_from_ion(fd,
                        &phy_addr, &phy_addr_size)) == 0) {
            LOGI("[OEMCrypto_CopyBuffer: MemIon::Get_phy_addr_from_ion():"
                 " %d succeed]\n",  ret);
            out_buffer_modified.buffer.secure.handle = (void *)phy_addr;
            out_buffer_modified.buffer.secure.max_length = phy_addr_size;
            LOGI("[OEMCrypto_CopyBuffer:"
                 " out_buffer->buffer.secure.handle:0x%x]\n",
                    out_buffer_modified.buffer.secure.handle);
            LOGI("[OEMCrypto_CopyBuffer:"
                 " out_buffer->buffer.secure.max_length:0x%x]\n",
                    out_buffer_modified.buffer.secure.max_length);
        }
    } else {
        LOGI("[OEMCrypto_CopyBuffer:"
             " The type of out_buffer is OEMCrypto_BufferType_Clear]\n");
    }

    memcpy((in_msg), &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &data_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), data_addr, data_length);
    tmp_size += data_length;
    if (out_buffer->type == OEMCrypto_BufferType_Secure) {
        memcpy((in_msg + tmp_size), &out_buffer_modified, buffer_desc_size);
    } else {
        memcpy((in_msg + tmp_size), out_buffer, buffer_desc_size);
    }
    tmp_size += buffer_desc_size;
    memcpy((in_msg + tmp_size), &subsample_flags, sizeof(uint8_t));
    result = trusty_oemcrypto_call(OEMCRYPTO_COPYBUFFER, in_msg, insize,
                                      out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_CopyBuffer():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_CopyBuffer(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    memcpy(&copy_data_len, msg->payload + kOEMCryptoResultSize, kSizeSize);
    if ((out_buffer->type == OEMCrypto_BufferType_Clear) &&
        (copy_data_len <= data_length) &&
        (out_buffer->buffer.clear.address != NULL)) {
        memcpy(out_buffer->buffer.clear.address,
                msg->payload + kOEMCryptoResultSize + kSizeSize,
                    copy_data_len);
    }

    free(out_msg);

    LOGI("[OEMCrypto_CopyBuffer: transferred %d bytes to trustos]\n",
            data_length);

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_WrapKeyboxOrOEMCert(
                                        const uint8_t* keybox,
                                        size_t keyBoxLength,
                                        uint8_t* wrappedKeybox,
                                        size_t* wrappedKeyBoxLength,
                                        const uint8_t* transportKey,
                                        size_t transportKeyLength) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize;
    uint8_t*            out_msg = NULL;
    uint32_t            outsize;
    uint32_t            tmp_size = 0;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_WrapKeyboxOrOEMCert()\n");
    }
    if (!keybox || !wrappedKeybox || !wrappedKeyBoxLength
            || (keyBoxLength != *wrappedKeyBoxLength)) {
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    insize = kSizeSize*3 + keyBoxLength + transportKeyLength;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_WrapKeyboxOrOEMCert(): in_msg malloc (%d) failed\n",
                insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    outsize = kOEMCryptoResultSize + kSizeSize + keyBoxLength +
        sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_WrapKeyboxOrOEMCert(): out_msg malloc (%d) failed\n",
                outsize);
        free(in_msg);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &keyBoxLength, kSizeSize);
    tmp_size += kSizeSize;
    memcpy(in_msg + tmp_size, keybox, keyBoxLength);
    tmp_size += keyBoxLength;
    memcpy(in_msg + tmp_size, wrappedKeyBoxLength, kSizeSize);
    tmp_size += kSizeSize;
    memcpy(in_msg + tmp_size, &transportKeyLength, kSizeSize);
    tmp_size += kSizeSize;
    memcpy(in_msg + tmp_size, transportKey, transportKeyLength);

    result = trusty_oemcrypto_call(OEMCRYPTO_WRAPKEYBOXOROEMCERT,
                in_msg, insize, out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_WrapKeyboxOrOEMCert():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_WrapKeyboxOrOEMCert(): %d failed]\n",
                result);
        free(out_msg);
        return result;
    }

    memcpy(wrappedKeyBoxLength,
            msg->payload + kOEMCryptoResultSize, kSizeSize);

    if (*wrappedKeyBoxLength) {
        memcpy(wrappedKeybox,
                msg->payload + kOEMCryptoResultSize + kSizeSize,
                *wrappedKeyBoxLength);
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_InstallKeyboxOrOEMCert(
                                        const uint8_t* keybox,
                                        size_t keyBoxLength) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize;
    uint8_t             out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t            outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_InstallKeyboxOrOEMCert()\n");
    }

    insize = kSizeSize + keyBoxLength;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_InstallKeyboxOrOEMCert():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &keyBoxLength, kSizeSize);
    memcpy((in_msg + kSizeSize), keybox, keyBoxLength);

    result = trusty_oemcrypto_call(OEMCRYPTO_INSTALLKEYBOXOROEMCERT,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_InstallKeyboxOrOEMCert():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_InstallKeyboxOrOEMCert(): %d failed]\n",
                result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_LoadTestKeybox(
                                        const uint8_t* buffer,
                                        size_t length) {
    OEMCryptoResult         result;
    uint8_t*                in_msg = NULL;
    uint32_t                insize;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_LoadTestKeybox()\n");
    }

    if ((buffer == NULL) || ((buffer == NULL) && length != 0)) {
        LOGE("OEMCrypto_OEMCrypto_LoadTestKeybox: parameter error\n");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    insize = kSizeSize + length;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_LoadTestKeybox(): in_msg malloc (%d) failed\n",
                insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &length, kSizeSize);
    memcpy((in_msg + kSizeSize), buffer, length);

    result = trusty_oemcrypto_call(OEMCRYPTO_LOADTESTKEYBOX,
                in_msg, insize, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadTestKeybox():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadTestKeybox(): %d failed]\n",
                result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_IsKeyboxOrOEMCertValid(void) {

    OEMCryptoResult         result;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_IsKeyboxOrOEMCertValid()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_ISKEYBOXOROEMCERTVALID,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_IsKeyboxOrOEMCertValid():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_IsKeyboxOrOEMCertValid(): %d failed]\n",
                result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_GetDeviceID(
                                      uint8_t* deviceID,
                                      size_t* idLength) {
    OEMCryptoResult         result;
    uint8_t*                out_msg = NULL;
    uint32_t                outsize;
    uint32_t                kSizeSize;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GetDeviceID()\n");
    }

    if (idLength == NULL) {
        LOGE("[OEMCrypto_GetDeviceID():"
             " null pointer. OEMCrypto_ERROR_SHORT_BUFFER]");
        return OEMCrypto_ERROR_SHORT_BUFFER;
    }

    if (*idLength == 0) *idLength = 1;

    kSizeSize = sizeof(size_t);
    outsize = kOEMCryptoResultSize + kSizeSize + *idLength +
        sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t *>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_GetDeviceID(): out_msg malloc (%d) failed\n",
                outsize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_GETDEVICEID,
                idLength, kSizeSize, out_msg, &outsize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetDeviceID():"
                " trusty_oemcrypto_call(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    memcpy(idLength, msg->payload + kOEMCryptoResultSize, kSizeSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetDeviceID(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    memcpy(deviceID,
            msg->payload + kOEMCryptoResultSize + kSizeSize, *idLength);
    free(out_msg);
    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGD("[OEMCrypto_GetDeviceId(): success]");
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_GetKeyData(
                                    uint8_t* keyData,
                                    size_t* keyDataLength) {
    OEMCryptoResult         result;
    uint8_t*                out_msg = NULL;
    uint32_t                outsize;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GetKeyData()\n");
    }

    if (keyDataLength == NULL) {
        LOGE("[OEMCrypto_GetKeyData():"
             " null pointer. ERROR_UNKNOWN_FAILURE]");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    if (keyData == NULL) {
        LOGE("[OEMCrypto_GetKeyData():"
             " null pointer. ERROR_UNKNOWN_FAILURE]");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    if (*keyDataLength == 0) {
         *keyDataLength = 1;
    }
    outsize = kOEMCryptoResultSize + kSizeSize + *keyDataLength +
        sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t *>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_GetKeyData(): out_msg malloc (%d) failed\n",
                outsize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_GETKEYDATA,
                keyDataLength, kSizeSize, out_msg, &outsize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetKeyData():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);

    memcpy(keyDataLength,
            msg->payload + kOEMCryptoResultSize, kSizeSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetKeyData(): %d failed]\n", result);
        free(out_msg);
        return result;
    }
    memcpy(keyData,
           msg->payload + kOEMCryptoResultSize + kSizeSize,
           *keyDataLength);
    free(out_msg);
    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGD("[OEMCrypto_GetKeyData(): success]");
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_GetRandom(
                            uint8_t* randomData,
                            size_t dataLength) {
    OEMCryptoResult         result;
    uint8_t*                out_msg = NULL;
    uint32_t                outsize;
    uint32_t                data_len;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GetRandom()\n");
    }
    if (!randomData) {
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    outsize = kOEMCryptoResultSize + kSizeSize + dataLength +
        sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t *>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_GetRandom: out_msg malloc (%d) failed\n",
                outsize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_GETRANDOM,
                &dataLength, kSizeSize, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetRandom():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetRandom(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    memcpy(&data_len, msg->payload + kOEMCryptoResultSize, kSizeSize);
    memcpy(randomData,
           msg->payload + kOEMCryptoResultSize + kSizeSize, data_len);
    free(out_msg);

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_RewrapDeviceRSAKey(
                                             OEMCrypto_SESSION session,
                                             const uint8_t* message,
                                             size_t message_length,
                                             const uint8_t* signature,
                                             size_t signature_length,
                                             const uint32_t* unaligned_nonce,
                                             const uint8_t* enc_rsa_key,
                                             size_t enc_rsa_key_length,
                                             const uint8_t* enc_rsa_key_iv,
                                             uint8_t* wrapped_rsa_key,
                                             size_t*  wrapped_rsa_key_length) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize ;
    uint8_t*            out_msg = NULL;
    uint32_t            outsize ;
    struct oemcrypto_message*  msg = NULL;
    size_t              tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls |
        kLoggingTraceNonce)) {
        LOGI("-- OEMCrypto_RewrapDeviceRSAKey()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("message", message, message_length);
            dump_hex("signature", signature, signature_length);
        }

        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("enc_rsa_key", enc_rsa_key, enc_rsa_key_length);
            dump_hex("enc_rsa_key_iv", enc_rsa_key_iv, wvcdm::KEY_IV_SIZE);
        }
    }

    if (wrapped_rsa_key_length == NULL) {
        LOGE("[OEMCrypto_RewrapDeviceRSAKey():"
             " OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }
    // For the reference implementation, the wrapped key and the encrypted
    // key are the same size -- just encrypted with different keys.
    // We add 32 bytes for a context, 32 for iv, and 32 bytes for a signature.
    // Important: This layout must match OEMCrypto_LoadDeviceRSAKey below.
    size_t buffer_size = enc_rsa_key_length + sizeof(WrappedRSAKey);

    if (wrapped_rsa_key == NULL ||
        *wrapped_rsa_key_length < buffer_size) {
        if (LogCategoryEnabled(kLoggingDumpDerivedKeys)) {
           LOGW("[OEMCrypto_RewrapDeviceRSAKey():"
                " Wrapped Keybox Short Buffer]");
        }
        *wrapped_rsa_key_length = buffer_size;
        return OEMCrypto_ERROR_SHORT_BUFFER;
     }
     *wrapped_rsa_key_length = buffer_size;  // Tell caller how much space we used.
    if (message == NULL || message_length == 0 || signature == NULL ||
        signature_length == 0 || unaligned_nonce == NULL ||
        enc_rsa_key == NULL) {
        LOGE("[OEMCrypto_RewrapDeviceRSAKey():"
             " OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    // Range check
    if (!RangeCheck(message, message_length,
            reinterpret_cast<const uint8_t*>(unaligned_nonce),
                  sizeof(uint32_t), true) ||
        !RangeCheck(message, message_length, enc_rsa_key,
            enc_rsa_key_length, true) ||
        !RangeCheck(message, message_length, enc_rsa_key_iv,
            wvcdm::KEY_IV_SIZE, true)) {
        LOGE("[OEMCrypto_RewrapDeviceRSAKey():  - range check.]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    insize = kSessionSize + kSizeSize*4 + kUint32Size + message_length +
        signature_length + enc_rsa_key_length + wvcdm::KEY_IV_SIZE;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_RewrapDeviceRSAKey:malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    outsize = kOEMCryptoResultSize + kSizeSize + *wrapped_rsa_key_length +
        sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_RewrapDeviceRSAKey():"
             " out_msg malloc (%d) failed\n", outsize);
        free(in_msg);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &message_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), message, message_length);
    tmp_size += message_length;
    memcpy((in_msg + tmp_size), &signature_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), signature, signature_length);
    tmp_size += signature_length;
    memcpy((in_msg + tmp_size), unaligned_nonce, kUint32Size);
    tmp_size += kUint32Size;
    memcpy((in_msg + tmp_size), &enc_rsa_key_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), enc_rsa_key, enc_rsa_key_length);
    tmp_size += enc_rsa_key_length;
    memcpy((in_msg + tmp_size), enc_rsa_key_iv, wvcdm::KEY_IV_SIZE);
    tmp_size += wvcdm::KEY_IV_SIZE;
    memcpy((in_msg + tmp_size), wrapped_rsa_key_length, kSizeSize);

    result = trusty_oemcrypto_call(OEMCRYPTO_REWRAPDEVICERSAKEY,
                in_msg, insize, out_msg, &outsize);
    free(in_msg);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_RewrapDeviceRSAKey(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_RewrapDeviceRSAKey(): %d failed]\n",
                result);
        free(out_msg);
        return result;
    }

    memcpy(wrapped_rsa_key_length,
            msg->payload + kOEMCryptoResultSize, kSizeSize);
    memcpy(wrapped_rsa_key,
            msg->payload + kOEMCryptoResultSize + kSizeSize,
                *wrapped_rsa_key_length);
    free(out_msg);

    return result;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_LoadDeviceRSAKey(
                               OEMCrypto_SESSION session,
                               const uint8_t* wrapped_rsa_key,
                               size_t wrapped_rsa_key_length) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize ;
    uint8_t             out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t            outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;
    size_t              tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_LoadDeviceRSAKey()\n");
    }

    if (wrapped_rsa_key == NULL) {
        LOGE("[OEMCrypto_LoadDeviceRSAKey():"
             " OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    insize = kSessionSize + kSizeSize  + wrapped_rsa_key_length;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_LoadDeviceRSAKey:"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &wrapped_rsa_key_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), wrapped_rsa_key, wrapped_rsa_key_length);

    LOGE("[OEMCrypto_LoadDeviceRSAKey():"
         " wrapped_rsa_key_length: %d]", wrapped_rsa_key_length);

    result = trusty_oemcrypto_call(OEMCRYPTO_LOADDEVICERSAKEY,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadDeviceRSAKey():"
             " trusty_oemcrypto_call(): %d failed], line:%d\n",
                result, __LINE__);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("OEMCrypto_LoadDeviceRSAKey():"
             " %d failed, line:%d\n", result, __LINE__);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_LoadTestRSAKey() {
    OEMCryptoResult         result;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_LoadTestRSAKey()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_LOADTESTRSAKEY,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadTestRSAKey():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadTestRSAKey(): %d failed]\n", result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_GenerateRSASignature(
                            OEMCrypto_SESSION session,
                            const uint8_t* message,
                            size_t message_length,
                            uint8_t* signature,
                            size_t* signature_length,
                            RSA_Padding_Scheme padding_scheme) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize ;
    uint8_t*            out_msg = NULL;
    uint32_t            outsize;
    struct oemcrypto_message*   msg = NULL;
    size_t              tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GenerateRSASignature()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("message", message, message_length);
            dump_hex("message", message, message_length);
        }
    }

    if (signature_length == NULL) {
        LOGE("[OEMCrypto_GenerateRSASignature():"
             " OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    if (message == NULL || message_length == 0 ||
       (signature == NULL) && (*signature_length != 0)) {
        LOGE("[OEMCrypto_GenerateRSASignature():"
             " OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    insize = kSessionSize + kSizeSize*2 + message_length +
        sizeof(RSA_Padding_Scheme);
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_GenerateRSASignature():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    outsize = kOEMCryptoResultSize + kSizeSize +
        *signature_length + sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t *>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_GenerateRSASignature():"
             " out_msg malloc (%d) failed\n", outsize);
        free(in_msg);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &message_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), message, message_length);
    tmp_size += message_length;
    memcpy((in_msg + tmp_size), signature_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size),
            &padding_scheme, sizeof(RSA_Padding_Scheme));

    result = trusty_oemcrypto_call(OEMCRYPTO_GENERATERSASIGNATURE,
                in_msg, insize, out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GenerateRSASignature:(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message *) out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    memcpy(signature_length,
            msg->payload + kOEMCryptoResultSize, kSizeSize);
    LOGE("[OEMCrypto_GenerateRSASignature(): signature_length: %d ]",
            *signature_length);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GenerateRSASignature:(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    if ((signature != NULL) && (*signature_length != 0)) {
        memcpy(signature,
                msg->payload + kOEMCryptoResultSize + kSizeSize,
                    *signature_length);
    }
    free(out_msg);

    if (result == OEMCrypto_SUCCESS) {
        if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
            if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
                dump_hex("signature", signature, *signature_length);
            }
        }
    }

    return result;
}

 OEMCRYPTO_API OEMCryptoResult OEMCrypto_DeriveKeysFromSessionKey(
                            OEMCrypto_SESSION session,
                            const uint8_t* enc_session_key,
                            size_t enc_session_key_length,
                            const uint8_t* mac_key_context,
                            size_t mac_key_context_length,
                            const uint8_t* enc_key_context,
                            size_t enc_key_context_length) {
    OEMCryptoResult         result;
    uint8_t*                in_msg = NULL;
    uint32_t                insize;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;
    size_t                  tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_DeriveKeysFromSessionKey()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("enc_session_key", enc_session_key,
                    enc_session_key_length);
            dump_hex("mac_key_context", mac_key_context,
                       (size_t)mac_key_context_length);
            dump_hex("enc_key_context", enc_key_context,
                       (size_t)enc_key_context_length);
        }
    }

    insize = kSessionSize + (kSizeSize*3) + enc_session_key_length +
        mac_key_context_length + enc_key_context_length ;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_DeriveKeysFromSessionKey():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &enc_session_key_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), enc_session_key, enc_session_key_length);
    tmp_size += enc_session_key_length;
    memcpy((in_msg + tmp_size), &mac_key_context_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), mac_key_context, mac_key_context_length);
    tmp_size += mac_key_context_length;
    memcpy((in_msg + tmp_size), &enc_key_context_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), enc_key_context, enc_key_context_length);

    result = trusty_oemcrypto_call(OEMCRYPTO_DERIVEKEYSFROMSESSIONKEY,
                in_msg, insize, out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_DeriveKeysFromSessionKey():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_DeriveKeysFromSessionKey():"
             " %d failed]\n", result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API uint32_t OEMCrypto_APIVersion() {
    OEMCryptoResult         result;
    uint32_t                version;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_APIVersion()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_APIVERSION,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_APIVersion():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&version, msg->payload, sizeof(uint32_t));

    return version;
}

OEMCRYPTO_API uint8_t OEMCrypto_Security_Patch_Level() {
    OEMCryptoResult         result;
    uint8_t                 patch_level;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_APIVersion()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_SECURITY_PATCH_LEVEL,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_APIVersion():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&patch_level, msg->payload, sizeof(uint8_t));

    return patch_level;
}

OEMCRYPTO_API const char* OEMCrypto_SecurityLevel() {
#define SECURITY_LEVEL_MAX_LENGTH 16
    OEMCryptoResult         result;
    uint8_t*                out_msg = NULL;
    uint32_t                outsize;
    struct oemcrypto_message*   msg = NULL;
    char*                   security_level_str[SECURITY_LEVEL_MAX_LENGTH];
    uint32_t                security_level_length = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
      LOGI("-- OEMCrypto_SecurityLevel(): returns %s\n",
              security_level_str);
    }

    outsize = kOEMCryptoResultSize + kSizeSize +
        SECURITY_LEVEL_MAX_LENGTH + sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_SecurityLevel():"
             " out_msg malloc (%d) failed\n", outsize);
        return NULL;
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_SECURITY_LEVEL,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_SecurityLevel():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        free(out_msg);
        return NULL;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("OEMCrypto_SecurityLevel(): %d failed, line:%d\n",
             result, __LINE__);
        free(out_msg);
        return NULL;
    }
    memcpy(&security_level_length,
                msg->payload + kOEMCryptoResultSize, kSizeSize);
    if (security_level_length) {
        memset(security_level_str, '\0', SECURITY_LEVEL_MAX_LENGTH);
        memcpy(security_level_str,
                 msg->payload + kOEMCryptoResultSize + kSizeSize,
                    security_level_length);
        free(out_msg);
        if (strstr((const char *)security_level_str, "L1")) {
            return "L1";
        } else if (strstr((const char *)security_level_str, "L2")) {
            return "L2";
        } else if (strstr((const char *)security_level_str, "L3")) {
            return "L3";
        } else {
            return "ERROR";
        }
    }

    free(out_msg);

    return NULL;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_GetHDCPCapability(
                            OEMCrypto_HDCP_Capability *current,
                            OEMCrypto_HDCP_Capability *maximum) {
    OEMCryptoResult             result;
    uint8_t*                    out_msg = NULL;
    uint32_t                    outsize;
    struct oemcrypto_message*   msg = NULL;
    uint32_t hdcp_capability_length = sizeof(OEMCrypto_HDCP_Capability);

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GetHDCPCapability(%p, %p)\n",
           current, maximum);
    }

    if (current == NULL) return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    if (maximum == NULL) return OEMCrypto_ERROR_UNKNOWN_FAILURE;

    outsize = kOEMCryptoResultSize + hdcp_capability_length*2 +
        sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_GetHDCPCapability():"
             " out_msg malloc (%d) failed\n", outsize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_GETHDCPCAPABILITY,
                NULL, 0, out_msg, &outsize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetHDCPCapability():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("OEMCrypto_GetHDCPCapability():"
             " %d failed, line:%d\n", result, __LINE__);
        free(out_msg);
        return result;
    }
    memcpy(current,
            msg->payload + kOEMCryptoResultSize, hdcp_capability_length);
    memcpy(maximum,
            msg->payload + kOEMCryptoResultSize + hdcp_capability_length,
                hdcp_capability_length);
    free(out_msg);

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API uint32_t OEMCrypto_GetAnalogOutputFlags() {
    OEMCryptoResult         result;
    uint32_t                analog_output_flag;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GetAnalogOutputFlags())\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_GETANALOGOUTPUTFLAGS,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetAnalogOutputFlags():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&analog_output_flag, msg->payload, sizeof(uint32_t));

    return analog_output_flag;
}

OEMCRYPTO_API const char* OEMCrypto_BuildInformation() {
    return "OEMCrypto Ref Code " __DATE__ " " __TIME__;
}

OEMCRYPTO_API uint32_t OEMCrypto_ResourceRatingTier() {
    OEMCryptoResult         result;
    uint32_t                resource_rating_tier;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_ResourceRatingTier()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_RESOURCERATINGTIER,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_ResourceRatingTier():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&resource_rating_tier, msg->payload, sizeof(uint32_t));

    return resource_rating_tier;
}

OEMCRYPTO_API bool OEMCrypto_SupportsUsageTable() {
    OEMCryptoResult         result;
    uint8_t*                out_msg = NULL;
    uint32_t                outsize;
    struct oemcrypto_message*   msg = NULL;
    bool                    supports_usage = false;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_SupportsUsageTable(): returns %s.\n",
            (supports_usage ? "true" : "false"));
    }

    outsize = kOEMCryptoResultSize + sizeof(bool) +
        sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_SupportsUsageTable():"
             " out_msg malloc (%d) failed\n", outsize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_SUPPORTSUSAGETABLE,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_SupportUsageTable():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("OEMCrypto_SupportUsageTable():"
             " %d failed, line:%d\n", result, __LINE__);
        free(out_msg);
        return result;
    }
    memcpy(&supports_usage,
            msg->payload + kOEMCryptoResultSize, sizeof(bool));
    free(out_msg);

    return supports_usage;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_GetNumberOfOpenSessions(
                                                    size_t* count) {
    OEMCryptoResult         result;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GetNumberOfOpenSessions()\n");
    }

    if (count == NULL) return OEMCrypto_ERROR_UNKNOWN_FAILURE;

    result = trusty_oemcrypto_call(OEMCRYPTO_GETNUMBEROFOPENSESSIONS,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetNumberOfOpenSessions():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetNumberOfOpenSessions(): %d failed]\n", result);
        return result;
    }

    memcpy(count, msg->payload + kOEMCryptoResultSize, kSizeSize);

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_GetMaxNumberOfSessions(
                                                size_t* maximum) {
    OEMCryptoResult         result;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GetMaxNumberOfSessions()\n");
    }

    if (maximum == NULL) return OEMCrypto_ERROR_UNKNOWN_FAILURE;

    result = trusty_oemcrypto_call(OEMCRYPTO_GETMAXNUMBEROFSESSIONS,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetMaxNumberOfSessions():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("OEMCrypto_GetMaxNumberOfSessions(): %d failed\n", result);
        return result;
    }

    memcpy(maximum , msg->payload + kOEMCryptoResultSize, kSizeSize);

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API bool OEMCrypto_IsAntiRollbackHwPresent() {
    OEMCryptoResult         result;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;
    bool                    anti_rollback_hw_present = false;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_IsAntiRollbackHwPresent()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_ISANTIROLLBACKHWPRESENT,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_IsAntiRollbackHwPresent():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_IsAntiRollbackHwPresent(): %d failed]\n", result);
        return result;
    }

    memcpy(&anti_rollback_hw_present,
            msg->payload + kOEMCryptoResultSize, sizeof(bool));

    return anti_rollback_hw_present;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_Generic_Encrypt(
                                OEMCrypto_SESSION session,
                                const uint8_t* in_buffer,
                                size_t buffer_length,
                                const uint8_t* iv,
                                OEMCrypto_Algorithm algorithm,
                                uint8_t* out_buffer) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize;
    uint8_t*            out_msg = NULL;
    uint32_t            outsize;
    uint32_t            out_len;
    struct oemcrypto_message*   msg = NULL;
    size_t              tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_Generic_Encrypt()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("in_buffer", in_buffer, buffer_length);
            dump_hex("iv", iv, wvcdm::KEY_IV_SIZE);
        }
    }

    if (in_buffer == NULL || buffer_length == 0 ||
        iv == NULL || out_buffer == NULL) {
        LOGE("[OEMCrypto_Generic_Enrypt():"
             " OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    insize = kSessionSize + kSizeSize + buffer_length +
        wvcdm::KEY_IV_SIZE + sizeof(OEMCrypto_Algorithm);
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
         LOGE("OEMCrypto_Generic_Encrypt():"
              " in_msg malloc (%d) failed\n", insize);
         return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    outsize = kOEMCryptoResultSize + kSizeSize +
        buffer_length + sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
         LOGE("OEMCrypto_Generic_Encrypt():"
              " out_msg malloc (%d) failed\n", outsize);
         free(in_msg);
         return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &buffer_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), in_buffer, buffer_length);
    tmp_size += buffer_length;
    memcpy((in_msg + tmp_size), iv, wvcdm::KEY_IV_SIZE);
    tmp_size += wvcdm::KEY_IV_SIZE;
    memcpy((in_msg + tmp_size), &algorithm, sizeof(OEMCrypto_Algorithm));

    result = trusty_oemcrypto_call(OEMCRYPTO_GENERIC_ENCRYPT,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_Generic_Encrypt(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_Generic_Encrypt(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    memcpy(&out_len, msg->payload + kOEMCryptoResultSize, kSizeSize);
    memcpy(out_buffer,
            msg->payload + kOEMCryptoResultSize + kSizeSize, out_len);
    free(out_msg);

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("out_buffer", out_buffer, buffer_length);
        }
    }
    return result;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_Generic_Decrypt(
                                OEMCrypto_SESSION session,
                                const uint8_t* in_buffer,
                                size_t buffer_length,
                                const uint8_t* iv,
                                OEMCrypto_Algorithm algorithm,
                                uint8_t* out_buffer) {
    OEMCryptoResult         result;
    uint8_t*                in_msg = NULL;
    uint32_t                insize ;
    uint8_t*                out_msg = NULL;
    uint32_t                outsize;
    uint32_t                out_len;
    struct oemcrypto_message*   msg = NULL;
    size_t                  tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_Generic_Decrypt()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("in_buffer", in_buffer, buffer_length);
            dump_hex("iv", iv, wvcdm::KEY_IV_SIZE);
        }
    }

    if (in_buffer == NULL || buffer_length == 0 ||
        iv == NULL || out_buffer == NULL) {
        LOGE("[OEMCrypto_Generic_Decrypt():"
             " OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    insize = kSessionSize + kSizeSize  + buffer_length +
        wvcdm::KEY_IV_SIZE + sizeof(OEMCrypto_Algorithm);
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
         LOGE("OEMCrypto_Generic_Decrypt():"
              " in_msg malloc (%d) failed\n", insize);
         return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    outsize = kOEMCryptoResultSize + kSizeSize +
        buffer_length + sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
         LOGE("OEMCrypto_Generic_Decrypt():"
              " out_msg malloc (%d) failed\n", outsize);
         free(in_msg);
         return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &buffer_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), in_buffer, buffer_length);
    tmp_size += buffer_length;
    memcpy((in_msg + tmp_size), iv, wvcdm::KEY_IV_SIZE);
    tmp_size += wvcdm::KEY_IV_SIZE;
    memcpy((in_msg + tmp_size), &algorithm, sizeof(OEMCrypto_Algorithm));

    result = trusty_oemcrypto_call(OEMCRYPTO_GENERIC_DECRYPT,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_Generic_Decrypt(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_Generic_Decrypt(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    memcpy(&out_len, msg->payload + kOEMCryptoResultSize, kSizeSize);
    memcpy(out_buffer,
            msg->payload + kOEMCryptoResultSize + kSizeSize, out_len);
    free(out_msg);

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE){
            dump_hex("out_buffer", out_buffer, buffer_length);
        }
    }

    return result;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_Generic_Sign(
                            OEMCrypto_SESSION session,
                            const uint8_t* in_buffer,
                            size_t buffer_length,
                            OEMCrypto_Algorithm algorithm,
                            uint8_t* signature,
                            size_t* signature_length) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize ;
    uint8_t*            out_msg = NULL;
    uint32_t            outsize;
    struct oemcrypto_message*   msg = NULL;
    size_t              tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_Generic_Sign()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("in_buffer", in_buffer, buffer_length);
        }
    }

    if (in_buffer == NULL || buffer_length == 0 ||
       (signature == NULL) && (*signature_length != 0)) {
        LOGE("[OEMCrypto_Generic_Sign():"
             " OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    insize = kSessionSize + kSizeSize*2 +
        buffer_length + sizeof(OEMCrypto_Algorithm);
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
         LOGE("OEMCrypto_Generic_Sign():"
              " in_msg malloc (%d) failed\n", insize);
         return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    outsize = kOEMCryptoResultSize + kSizeSize +
        *signature_length + sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
         LOGE("OEMCrypto_Generic_Sign():"
              " out_msg malloc (%d) failed\n", outsize);
         free(in_msg);
         return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &buffer_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), in_buffer, buffer_length);
    tmp_size += buffer_length;
    memcpy((in_msg + tmp_size), signature_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), &algorithm, sizeof(OEMCrypto_Algorithm));

    result = trusty_oemcrypto_call(OEMCRYPTO_GENERIC_SIGN,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_Generic_Sign(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    memcpy(signature_length,
            msg->payload + kOEMCryptoResultSize, kSizeSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_Generic_Sign(): %d failed]\n", result);
        free(out_msg);
        return result;
    }
    if ((*signature_length != 0) && (signature != NULL)) {
        memcpy(signature,
                msg->payload + kOEMCryptoResultSize + kSizeSize,
                    *signature_length);
    }
    free(out_msg);
    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("signature", signature, *signature_length);
        }
    }

    return result;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_Generic_Verify(
                                OEMCrypto_SESSION session,
                                const uint8_t* in_buffer,
                                size_t buffer_length,
                                OEMCrypto_Algorithm algorithm,
                                const uint8_t* signature,
                                size_t signature_length) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize ;
    uint8_t             out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t            outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;
    size_t              tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_Generic_Verify()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("in_buffer", in_buffer, buffer_length);
            dump_hex("signature", signature, signature_length);
        }
    }

    insize = kSessionSize + (kSizeSize*2)  + buffer_length +
        sizeof(OEMCrypto_Algorithm) + signature_length;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
         LOGE("OEMCrypto_Generic_Verify():"
              " in_msg malloc (%d) failed\n", insize);
         return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &buffer_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), in_buffer, buffer_length);
    tmp_size += buffer_length;
    memcpy((in_msg + tmp_size), &signature_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), signature, signature_length);
    tmp_size += signature_length;
    memcpy((in_msg + tmp_size), &algorithm, sizeof(OEMCrypto_Algorithm));

    result = trusty_oemcrypto_call(OEMCRYPTO_GENERIC_VERIFY,
                in_msg, insize, out_msg, &outsize);
    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_Generic_Verify(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_Generic_Verify(): %d failed]\n", result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_UpdateUsageTable() {
    OEMCryptoResult         result;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_UpdateUsageTable()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_UPDATEUSAGETABLE,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_UpdateUsageTable():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_UpdateUsageTable(): %d failed]\n", result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_DeactivateUsageEntry(
                                    OEMCrypto_SESSION session,
                                    const uint8_t* pst,
                                    size_t pst_length) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize ;
    uint8_t             out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t            outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;
    size_t              tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_DeactivateUsageEntry()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("pst", pst, pst_length);
        }
     }

    insize = kSizeSize + pst_length + kSessionSize;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
         LOGE("OEMCrypto_DeactivateUsageEntry():"
              " in_msg malloc (%d) failed\n", insize);
         return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy((in_msg), &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &pst_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), pst, pst_length);

    result = trusty_oemcrypto_call(OEMCRYPTO_DEACTIVATEUSAGEENTRY,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_DeactivateUsageEntry():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_DeactivateUsageEntry(): %d failed]\n",result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_ReportUsage(
                            OEMCrypto_SESSION session,
                            const uint8_t* pst,
                            size_t pst_length,
                            uint8_t* buffer,
                            size_t* buffer_length) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize ;
    uint8_t*            out_msg = NULL;
    uint32_t            outsize;
    struct oemcrypto_message*   msg = NULL;
    size_t              tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_ReportUsage()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("pst", pst, pst_length);
        }
    }
    if (!buffer_length || (buffer == NULL && *buffer_length != 0)) {
        LOGE("OEMCrypto_ReportUsage: OEMCrypto Not Initialized.");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    insize = kSessionSize + kSizeSize*2  + pst_length;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
         LOGE("OEMCrypto_ReportUsage(): in_msg malloc (%d) failed\n", insize);
         return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    outsize = kOEMCryptoResultSize + kSizeSize +
        *buffer_length + sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t *>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_ReportUsage(): out_msg malloc (%d) failed\n", outsize);
        free(in_msg);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &pst_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), pst, pst_length);
    tmp_size += pst_length;
    memcpy((in_msg + tmp_size), buffer_length, kSizeSize);

    result = trusty_oemcrypto_call(OEMCRYPTO_REPORTUSAGE,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_ReportUsage(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    memcpy(buffer_length, msg->payload + kOEMCryptoResultSize, kSizeSize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_ReportUsage(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    if (*buffer_length > 0 && buffer != 0) {
        memcpy(buffer,
                msg->payload + kOEMCryptoResultSize + kSizeSize,
                    *buffer_length);
    }
    free(out_msg);

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("usage buffer", buffer,
               *buffer_length);
        }
    }

    return result;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_DeleteUsageEntry(
                                    OEMCrypto_SESSION session,
                                    const uint8_t* pst,
                                    size_t pst_length,
                                    const uint8_t *message,
                                    size_t message_length,
                                    const uint8_t *signature,
                                    size_t signature_length) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize;
    uint8_t             out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t            outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;
    size_t              tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_DeleteUsageEntry()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("pst", pst, pst_length);
            dump_hex("message", message, message_length);
            dump_hex("signature", signature, signature_length);
        }
    }

    if (message == NULL || message_length == 0 || signature == NULL ||
        signature_length == 0 || pst == NULL || pst_length == 0) {
        LOGE("[OEMCrypto_DeleteUsageEntry():"
             " OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }
    if (!RangeCheck(message, message_length, pst, pst_length, false)) {
        LOGE("[OEMCrypto_DeleteUsageEntry(): range check.]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }

    insize = kSessionSize + (kSizeSize*3) +
        pst_length + message_length + signature_length;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_DeleteUsageEntry():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &pst_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), pst, pst_length);
    tmp_size += pst_length;
    memcpy((in_msg + tmp_size), &message_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), message, message_length);
    tmp_size += message_length;
    memcpy((in_msg + tmp_size), &signature_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), signature, signature_length);

    result = trusty_oemcrypto_call(OEMCRYPTO_DELETEUSAGEENTRY,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_DeleteUsageEntry(SID=%08X):"
             " trusty_oemcrypto_call(): %d failed]\n", session, result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_DeleteUsageEntry(): %d failed]\n", result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_ForceDeleteUsageEntry(
                                            const uint8_t* pst,
                                            size_t pst_length) {
    OEMCryptoResult     result;
    uint8_t*            in_msg = NULL;
    uint32_t            insize;
    uint8_t             out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t            outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_ForceDeleteUsageEntry()\n");
        if (wvcdm::g_cutoff >= wvcdm::LOG_VERBOSE) {
            dump_hex("pst", pst, pst_length);
        }
    }

    insize = kSizeSize + pst_length ;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_ForceDeleteUsageEntry():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
    memcpy((in_msg ), &pst_length, kSizeSize);
    memcpy((in_msg + kSizeSize), pst, pst_length);

    result = trusty_oemcrypto_call(OEMCRYPTO_FORCEDELETEUSAGEENTRY,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_ForceDeleteUsageEntry():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_ForceDeleteUsageEntry(): %d failed]\n",result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_DeleteOldUsageTable() {
    OEMCryptoResult     result;
    uint8_t             out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t            outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_DeleteOldUsageTable()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_DELETEOLDUSAGETABLE,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_DeleteOldUsageTable():"
             " trusty_oemcrypto_call(): %d failed]\n",result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_DeleteOldUsageTable(): %d failed]\n",result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCrypto_ProvisioningMethod OEMCrypto_GetProvisioningMethod() {
    OEMCryptoResult                 result;
    OEMCrypto_ProvisioningMethod    method;
    uint8_t                         out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                        outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*       msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GetProvisioningMethod()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_GETPROVISIONINGMETHOD,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetProvisioningMethod():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return OEMCrypto_ProvisioningError;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&method, msg->payload, kProvisionResultSize);

    return method;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_GetOEMPublicCertificate(
                                        OEMCrypto_SESSION session,
                                        uint8_t* public_cert,
                                        size_t* public_cert_length) {
    OEMCryptoResult     result;
    uint8_t*            out_msg = NULL;
    uint32_t            outsize = 0;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GetOEMPublicCertificate()\n");
    }

    if ((public_cert == NULL) || (public_cert_length == NULL)){
        LOGE("[OEMCrypto_GetOEMPublicCertificate():"
             " OEMCrypto_ERROR_INVALID_CONTEXT]");
        return OEMCrypto_ERROR_INVALID_CONTEXT;
    }
    outsize = kOEMCryptoResultSize + kSizeSize + 1024 +
        sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t *>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_GetOEMPublicCertificate():"
             " out_msg malloc (%d) failed\n", outsize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_GETOEMPUBLICCERTIFICATE,
                (void *)&session, kSessionSize, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetOEMPublicCertificate():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        free(out_msg);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetOEMPublicCertificate():"
             " %d failed]\n",result);
        free(out_msg);
        return result;
    }
    memcpy(public_cert_length,
            msg->payload + kOEMCryptoResultSize, kSizeSize);
    if (*public_cert_length) {
       memcpy(public_cert,
               msg->payload + kOEMCryptoResultSize + kSizeSize,
                 *public_cert_length);
    }

    free(out_msg);

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_RewrapDeviceRSAKey30(
                                OEMCrypto_SESSION session,
                                const uint32_t* unaligned_nonce,
                                const uint8_t* encrypted_message_key,
                                size_t encrypted_message_key_length,
                                const uint8_t* enc_rsa_key,
                                size_t enc_rsa_key_length,
                                const uint8_t* enc_rsa_key_iv,
                                uint8_t* wrapped_rsa_key,
                                size_t* wrapped_rsa_key_length) {
    OEMCryptoResult         result;
    uint8_t*                in_msg = NULL;
    uint32_t                insize = 0;
    uint8_t*                out_msg = NULL;
    uint32_t                outsize = 0;
    uint32_t                tmp_size = 0;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_RewrapDeviceRSAKey30()\n");
    }

    insize = kSessionSize + kUint32Size + kSizeSize +
        encrypted_message_key_length + kSizeSize +
            enc_rsa_key_length + OEMCRYPTO_KEY_IV_SIZE;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
         LOGE("OEMCrypto_RewrapDeviceRSAKey30():"
              " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
    outsize = kOEMCryptoResultSize + kSizeSize +
        enc_rsa_key_length + sizeof(WrappedRSAKey);
    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_RewrapDeviceRSAKey30():"
             " out_msg malloc (%d) failed\n", outsize);
        free(in_msg);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy(in_msg + tmp_size, unaligned_nonce, kUint32Size);
    tmp_size += kUint32Size;
    memcpy(in_msg + tmp_size,
            &encrypted_message_key_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy(in_msg + tmp_size,
            encrypted_message_key, encrypted_message_key_length);
    tmp_size += encrypted_message_key_length;
    memcpy(in_msg + tmp_size, &enc_rsa_key_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy(in_msg + tmp_size, enc_rsa_key, enc_rsa_key_length);
    tmp_size += enc_rsa_key_length;
    memcpy(in_msg + tmp_size,
            enc_rsa_key_iv, OEMCRYPTO_KEY_IV_SIZE);

    result = trusty_oemcrypto_call(OEMCRYPTO_REWRAPDEVICERSAKEY30,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_REWRAPDEVICERSAKEY30():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        free(out_msg);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_REWRAPDEVICERSAKEY30(): %d failed]\n",result);
        free(out_msg);
        return result;
    }
    memcpy(wrapped_rsa_key_length,
            msg->payload + kOEMCryptoResultSize, kSizeSize);
    if (*wrapped_rsa_key_length) {
       memcpy(wrapped_rsa_key,
               msg->payload + kOEMCryptoResultSize + kSizeSize,
                *wrapped_rsa_key_length);
    }

    free(out_msg);

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API uint32_t OEMCrypto_SupportedCertificates() {
    OEMCryptoResult     result;
    uint32_t            supported_types;
    uint8_t             out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t            outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_SupportedCertificates()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_SUPPORTEDCERTIFICATES,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_SupportedCertificates():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_SupportedCertificates(): %d failed]\n",result);
        return result;
    }

    memcpy(&supported_types,
            msg->payload + kOEMCryptoResultSize, sizeof(uint32_t));

    return supported_types;
}

OEMCRYPTO_API bool OEMCrypto_IsSRMUpdateSupported() {
    OEMCryptoResult         result;
    bool                    is_srm_update_supported = false;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_IsSRMUpdateSupported()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_ISSRMUPDATESUPPORTED,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_IsSRMUpdateSupported():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_IsSRMUpdateSupported(): %d failed]\n",result);
        return false;
    }
    memcpy(&is_srm_update_supported,
            msg->payload + kOEMCryptoResultSize, sizeof(bool));

    return is_srm_update_supported;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_GetCurrentSRMVersion(
                                            uint16_t* version) {
    OEMCryptoResult     result;
    uint8_t             out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t            outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GetCurrentSRMVersion()\n");
    }

    if (!version) {
        LOGE("OEMCrypto_GetCurrentSRMVersion(): version null.");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_GETCURRENTSRMVERSION,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetCurrentSRMVersion():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetCurrentSRMVersion(): %d failed]\n",result);
        return result;
    }
    memcpy(version,
            msg->payload + kOEMCryptoResultSize, sizeof(uint16_t));

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_LoadSRM(
                            const uint8_t* buffer,
                            size_t buffer_length) {
    OEMCryptoResult result;
    uint8_t*  in_msg = NULL;
    uint32_t  insize = 0;
    uint8_t   out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t  outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_LoadSRM()\n");
    }

    if ((buffer == NULL) || (buffer_length == 0)) {
        LOGE("OEMCrypto_LoadSRM(): parameter error.");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    insize = kSizeSize + buffer_length;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
         LOGE("OEMCrypto_LoadSRM():"
              " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg, &buffer_length, kSizeSize);
    memcpy(in_msg + kSizeSize, buffer, buffer_length);

    result = trusty_oemcrypto_call(OEMCRYPTO_LOADSRM,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadSRM():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadSRM(): %d failed]\n",result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_RemoveSRM() {
    OEMCryptoResult result;
    uint8_t   out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t  outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_RemoveSRM()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_REMOVESRM,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_RemoveSRM():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_RemoveSRM(): %d failed]\n",result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_CreateUsageTableHeader(
                                        uint8_t* header_buffer,
                                        size_t* header_buffer_length) {
    OEMCryptoResult   result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize ;
    uint8_t    out_msg[128];
    uint32_t   outsize = 128;
    uint32_t signed_header_length;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_CreateUsageTableHeader()\n");
    }

    if (header_buffer_length == NULL) {
        LOGE("OEMCrypto_CreateUsageTableHeader(): parameter wrong.");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    insize = kSizeSize;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
         LOGE("OEMCrypto_CreateUsageTableHeader():"
              " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
    memcpy((in_msg), header_buffer_length, kSizeSize);

    result = trusty_oemcrypto_call(OEMCRYPTO_CREATEUSAGETABLEHEADER,
                    in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_CreateUsageTableHeader():"
            " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    memcpy(&signed_header_length,
            msg->payload+kOEMCryptoResultSize, kSizeSize);
    if (result != OEMCrypto_SUCCESS) {
        *header_buffer_length = signed_header_length;
        LOGE("[OEMCrypto_CreateUsageTableHeader():"
             " %d failed]\n",result);
        return result;
    }

    if(signed_header_length <= *header_buffer_length) {
        memcpy(header_buffer,
                msg->payload+kSizeSize+kOEMCryptoResultSize,
                    signed_header_length);
        *header_buffer_length = signed_header_length;
        return OEMCrypto_SUCCESS;
    } else {
        LOGE("OEMCrypto_CreateUsageTableHeader(): buffer too small");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_LoadUsageTableHeader(
                                            const uint8_t* buffer,
                                            size_t buffer_length) {
    OEMCryptoResult   result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize ;
    uint8_t    out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t   outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_LoadUsageTableHeader()\n");
    }

    if (!buffer) {
        LOGE("OEMCrypto_LoadUsageTableHeader(): parameter wrong.");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    insize = kSizeSize + buffer_length;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_LoadUsageTableHeader():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy((in_msg ), &buffer_length, kSizeSize);
    if (buffer_length > 0) {
        memcpy((in_msg + kSizeSize), buffer, buffer_length);
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_LOADUSAGETABLEHEADER,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadUsageTableHeader():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadUsageTableHeader(): %d failed]\n",result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_CreateNewUsageEntry(
                                    OEMCrypto_SESSION session,
                                    uint32_t* usage_entry_number) {
    OEMCryptoResult   result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize;
    uint8_t    out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t   outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_CreateNewUsageEntry()\n");
    }

    insize = kSessionSize;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_CreateNewUsageEntry():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy((in_msg ), &session, kSessionSize);

    result = trusty_oemcrypto_call(OEMCRYPTO_CREATENEWUSAGEENTRY,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_CreateNewUsageEntry():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_CreateNewUsageEntry(): %d failed]\n",result);
        return result;
    }
    memcpy(usage_entry_number, msg->payload+kOEMCryptoResultSize, kUint32Size);

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_LoadUsageEntry(
                                OEMCrypto_SESSION session,
                                uint32_t index,
                                const uint8_t* buffer,
                                size_t buffer_size) {
    OEMCryptoResult result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize;
    uint8_t    out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t   outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;
    size_t     tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_LoadUsageEntry()\n");
    }

    if (!buffer) {
        LOGE("OEMCrypto_LoadUsageEntry(): parameter wrong.");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    insize = kSessionSize + kUint32Size + buffer_size + kSizeSize;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_LoadUsageEntry():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
    memcpy((in_msg ), &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), &index, kUint32Size);
    tmp_size += kUint32Size;
    memcpy((in_msg + tmp_size), &buffer_size, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), buffer, buffer_size);

    result = trusty_oemcrypto_call(OEMCRYPTO_LOADUSAGEENTRY,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadUsageEntry():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_LoadUsageEntry(): %d failed]\n",result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_UpdateUsageEntry(
                                           OEMCrypto_SESSION session,
                                           uint8_t* header_buffer,
                                           size_t* header_buffer_length,
                                           uint8_t* entry_buffer,
                                           size_t* entry_buffer_length) {
    OEMCryptoResult   result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize;
    uint8_t*   out_msg= NULL;
    uint32_t   outsize;
    uint32_t signed_header_length;
    uint32_t signed_entry_buffer_length;
    struct oemcrypto_message* msg = NULL;
    size_t     tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_UpdateUsageEntry()\n");
    }

    if (!header_buffer_length || !entry_buffer_length ||
        ((header_buffer == NULL) && (*header_buffer_length != 0)) ||
        ((entry_buffer == NULL) && (*entry_buffer_length != 0))) {
        LOGE("OEMCrypto_UpdateUsageEntry(): parameter wrong.");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    insize = kSessionSize + kSizeSize*2;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_UpdateUsageEntry():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
    memcpy(in_msg, &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy((in_msg + tmp_size), header_buffer_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy((in_msg + tmp_size), entry_buffer_length, kSizeSize);

    outsize = kOEMCryptoResultSize + kSizeSize*2 +
        *header_buffer_length + *entry_buffer_length +
            sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_UpdateUsageEntry():"
             " out_msg malloc (%d) failed\n", outsize);
        free(in_msg);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_UPDATEUSAGEENTRY,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_UpdateUsageEntry():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        free(out_msg);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    memcpy(&signed_header_length,
            msg->payload + kOEMCryptoResultSize, kSizeSize);
    memcpy(&signed_entry_buffer_length,
            msg->payload + kOEMCryptoResultSize + kUint32Size, kSizeSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_UpdateUsageEntry(): %d failed]\n",result);
        *header_buffer_length = signed_header_length;
        *entry_buffer_length = signed_entry_buffer_length;
        free(out_msg);
        return result;
    }

    if((signed_header_length <= *header_buffer_length) &&
       (header_buffer != NULL)) {
        memcpy(header_buffer,
                msg->payload + kUint32Size*2 + kOEMCryptoResultSize,
                    signed_header_length);
    } else {
        LOGE("OEMCrypto_UpdateUsageEntry(): buffer too small");
        result = OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
    *header_buffer_length = signed_header_length;

    if((signed_entry_buffer_length <= *entry_buffer_length) &&
       (entry_buffer != NULL)) {
        memcpy(entry_buffer,
                msg->payload + kUint32Size*2 + kOEMCryptoResultSize +
                    signed_header_length, signed_entry_buffer_length);
    } else {
        LOGE("OEMCrypto_UpdateUsageEntry(): buffer too small");
        result = OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
    *entry_buffer_length = signed_entry_buffer_length;
    free(out_msg);

    return result;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_ShrinkUsageTableHeader(
                                                 uint32_t new_table_size,
                                                 uint8_t* header_buffer,
                                                 size_t* header_buffer_length) {
    OEMCryptoResult   result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize;
    uint8_t*   out_msg = NULL;
    uint32_t   outsize;
    uint32_t   signed_header_length;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_ShrinkUsageTableHeader()\n");
    }

    if ((header_buffer_length == NULL) ||
        ((header_buffer == NULL) && (*header_buffer_length != 0))) {
        LOGE("OEMCrypto_ShrinkUsageTableHeader(): parameter wrong.");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
    insize = kUint32Size + kSizeSize;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_ShrinkUsageTableHeader():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
    memcpy((in_msg), &new_table_size, kUint32Size);
    memcpy((in_msg + kUint32Size), header_buffer_length, kSizeSize);

    outsize = kOEMCryptoResultSize + kSizeSize + *header_buffer_length +
        sizeof(struct oemcrypto_message);
    out_msg = reinterpret_cast<uint8_t*>(malloc(outsize));
    if (out_msg == NULL) {
        LOGE("OEMCrypto_ShrinkUsageTableHeader():"
             " out_msg malloc (%d) failed\n", outsize);
        free(in_msg);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_SHRINKUSAGETABLEHEADER,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_ShrinkUsageTableHeader():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        free(out_msg);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    memcpy(&signed_header_length,
            msg->payload+kOEMCryptoResultSize, kUint32Size);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_ShrinkUsageTableHeader(): %d failed]\n",result);
        *header_buffer_length = signed_header_length;
        free(out_msg);
        return result;
    }

    if(signed_header_length <= *header_buffer_length) {
        memcpy(header_buffer,
                msg->payload+kUint32Size+kOEMCryptoResultSize,
                    signed_header_length);
        *header_buffer_length = signed_header_length;
        result = OEMCrypto_SUCCESS;
    } else {
        LOGE("OEMCrypto_ShrinkUsageTableHeader(): buffer too small");
        *header_buffer_length = signed_header_length;
        result = OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    free(out_msg);

    return result;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_MoveEntry(
                            OEMCrypto_SESSION session,
                            uint32_t new_index) {
    OEMCryptoResult   result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize ;
    uint8_t    out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t   outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_MoveEntry()\n");
    }

    insize = kSessionSize + kUint32Size;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_MoveEntry():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
    memcpy((in_msg ), &session, kSessionSize);
    memcpy((in_msg + kSessionSize), &new_index, kUint32Size);

    result = trusty_oemcrypto_call(OEMCRYPTO_MOVEENTRY,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_MoveEntry():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_MoveEntry(): %d failed]\n",result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_CopyOldUsageEntry(
                                            OEMCrypto_SESSION session,
                                            const uint8_t* pst,
                                            size_t pst_length) {
    OEMCryptoResult   result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize ;
    uint8_t    out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t   outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;
    size_t     tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_CopyOldUsageEntry()\n");
    }

    if ((pst == NULL) || (pst_length == 0)) {
        LOGE("OEMCrypto_CopyOldUsageEntry(): Parameter error.");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    insize = kSessionSize + kSizeSize + pst_length;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_CopyOldUsageEntry():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
    memcpy(in_msg , &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy(in_msg + tmp_size, &pst_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy(in_msg + tmp_size, pst, pst_length);

    result = trusty_oemcrypto_call(OEMCRYPTO_COPYOLDUSAGEENTRY,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_CopyOldUsageEntry():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_CopyOldUsageEntry(): %d failed]\n",result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_CreateOldUsageEntry(
                        uint64_t time_since_license_received,
                        uint64_t time_since_first_decrypt,
                        uint64_t time_since_last_decrypt,
                        OEMCrypto_Usage_Entry_Status status,
                        uint8_t *server_mac_key,
                        uint8_t *client_mac_key,
                        const uint8_t* pst,
                        size_t pst_length) {
    OEMCryptoResult   result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize ;
    uint8_t    out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t   outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;
    uint32_t tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_CreateOldUsageEntry()\n");
    }

    if ((server_mac_key == NULL) || (client_mac_key == NULL) ||
        (pst == NULL) || (pst_length == 0)) {
        LOGE("OEMCrypto_CreateOldUsageEntry(): Parameter error.");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    insize = kUint64Size*3 + sizeof(OEMCrypto_Usage_Entry_Status) +
        OEMCRYPTO_MAC_KEY_SIZE*2  + kSizeSize + pst_length;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_CreateOldUsageEntry():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
    memcpy(in_msg , &time_since_license_received, kUint64Size);
    tmp_size += kUint64Size;
    memcpy(in_msg + tmp_size , &time_since_first_decrypt, kUint64Size);
    tmp_size += kUint64Size;
    memcpy(in_msg + tmp_size , &time_since_last_decrypt, kUint64Size);
    tmp_size += kUint64Size;
    memcpy(in_msg + tmp_size , &status, sizeof(OEMCrypto_Usage_Entry_Status));
    tmp_size += sizeof(OEMCrypto_Usage_Entry_Status);
    memcpy(in_msg + tmp_size , server_mac_key, OEMCRYPTO_MAC_KEY_SIZE);
    tmp_size += OEMCRYPTO_MAC_KEY_SIZE;
    memcpy(in_msg + tmp_size , client_mac_key, OEMCRYPTO_MAC_KEY_SIZE);
    tmp_size += OEMCRYPTO_MAC_KEY_SIZE;
    memcpy(in_msg + tmp_size, &pst_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy(in_msg + tmp_size, pst, pst_length);

    result = trusty_oemcrypto_call(OEMCRYPTO_CREATEOLDUSAGEENTRY,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[:OEMCrypto_CreateOldUsageEntry():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_CreateOldUsageEntry(): %d failed]\n",result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API uint32_t OEMCrypto_SupportsDecryptHash() {
    OEMCryptoResult         result;
    uint32_t                supports_decrypt_hash;
    uint8_t                 out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t                outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message*   msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_SupportsDecryptHash()\n");
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_SUPPORTDECRYPTHASH,
                NULL, 0, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_SupportsDecryptHash():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }

    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&supports_decrypt_hash, msg->payload, sizeof(uint32_t));

    return supports_decrypt_hash;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_SetDecryptHash(
                                OEMCrypto_SESSION session,
                                uint32_t frame_number,
                                const uint8_t* hash,
                                size_t hash_length) {
    OEMCryptoResult   result;
    uint8_t*   in_msg = NULL;
    uint32_t   insize ;
    uint8_t    out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t   outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;
    size_t     tmp_size = 0;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_SetDecryptHash()\n");
    }

    if ((hash == NULL) || ((hash == NULL) && (hash_length != 0))) {
        LOGE("OEMCrypto_SetDecryptHash(): Parameter error.");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    insize = kSessionSize + kUint32Size + kSizeSize  + hash_length;
    in_msg = reinterpret_cast<uint8_t*>(malloc(insize));
    if (in_msg == NULL) {
        LOGE("OEMCrypto_SetDecryptHash():"
             " in_msg malloc (%d) failed\n", insize);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    memcpy(in_msg , &session, kSessionSize);
    tmp_size += kSessionSize;
    memcpy(in_msg + tmp_size, &frame_number, kUint32Size);
    tmp_size += kUint32Size;
    memcpy(in_msg + tmp_size, &hash_length, kSizeSize);
    tmp_size += kSizeSize;
    memcpy(in_msg + tmp_size, hash, hash_length);

    result = trusty_oemcrypto_call(OEMCRYPTO_SETDECRYPTHASH,
                in_msg, insize, out_msg, &outsize);

    free(in_msg);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_SetDecryptHash():"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_SetDecryptHash(): %d failed]\n",result);
        return result;
    }

    return OEMCrypto_SUCCESS;
}

OEMCRYPTO_API OEMCryptoResult OEMCrypto_GetHashErrorCode(
                                OEMCrypto_SESSION session,
                                uint32_t* failed_frame_number) {
    OEMCryptoResult   result;
    uint8_t    out_msg[TRUSTRY_RECV_BUF_SIZE];
    uint32_t   outsize = TRUSTRY_RECV_BUF_SIZE;
    struct oemcrypto_message* msg = NULL;

    if (LogCategoryEnabled(kLoggingTraceOEMCryptoCalls)) {
        LOGI("-- OEMCrypto_GetHashErrorCode()\n");
    }

    if (failed_frame_number == NULL) {
        LOGE("OEMCrypto_GeHashErrorCode: Parameter error.");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    result = trusty_oemcrypto_call(OEMCRYPTO_GETHASHERRORCODE,
                (void *)&session, kSessionSize, out_msg, &outsize);

    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetHashErrorCode: %d failed]\n",result);
        return result;
    }
    msg = (struct oemcrypto_message*)out_msg;
    memcpy(&result, msg->payload, kOEMCryptoResultSize);
    if (result != OEMCrypto_SUCCESS) {
        LOGE("[OEMCrypto_GetHashErrorCode:"
             " trusty_oemcrypto_call(): %d failed]\n", result);
        return result;
    }
    memcpy(failed_frame_number,
            msg->payload + kOEMCryptoResultSize, sizeof(uint32_t));

    return OEMCrypto_SUCCESS;
}

}  // namespace wvoec_unisoc
