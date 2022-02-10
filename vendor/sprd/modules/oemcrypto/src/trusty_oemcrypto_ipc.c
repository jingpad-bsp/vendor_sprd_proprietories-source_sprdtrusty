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
 */


#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "Unisoc_OEMCrypto"
#include <cutils/log.h>

#include <trusty/tipc.h>

#include "OEMCryptoCENC.h"
#include "trusty_oemcrypto_ipc.h"
#include "oemcrypto_ipc.h"

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"

static int handle_ = -1;

int trusty_oemcrypto_connect() {
    int rc = tipc_connect(TRUSTY_DEVICE_NAME, OEMCRYPTO_PORT);
    if (rc < 0) {
        return rc;
    }

    handle_ = rc;
    return 0;
}

OEMCryptoResult trusty_oemcrypto_call(uint32_t cmd, void *in, uint32_t in_size, uint8_t *out,
                          uint32_t *out_size)  {
    if (handle_ < 0) {
        ALOGE("not connected\n");
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    size_t msg_size = in_size + sizeof(struct oemcrypto_message);
    struct oemcrypto_message *msg = malloc(msg_size);
    if (msg == NULL) {
        ALOGE("malloc (%d) failed\n", msg_size);
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }
    msg->cmd = cmd;
    if (in_size > 0) {
        memcpy(msg->payload, in, in_size);
    }

    ssize_t rc = write(handle_, msg, msg_size);
    free(msg);

    if (rc < 0) {
        ALOGE("failed to send cmd (%d) to %s: %s\n", cmd,
                OEMCRYPTO_PORT, strerror(errno));
        return OEMCrypto_ERROR_UNKNOWN_FAILURE;
    }

    size_t out_max_size = *out_size;
    *out_size = 0;
    struct iovec iov[2];
    struct oemcrypto_message *header = (struct oemcrypto *)out;
    iov[0].iov_base = header;
    iov[0].iov_len = sizeof(struct oemcrypto_message);
    for(;;){
        iov[1].iov_base = out + sizeof(struct oemcrypto_message) + *out_size;
        iov[1].iov_len = (OEMCRYPTO_MAX_BUFFER_LENGTH > (out_max_size - *out_size)) ? \
            (out_max_size - *out_size) : (OEMCRYPTO_MAX_BUFFER_LENGTH);
        rc = readv(handle_, iov, 2);
        if (rc < 0) {
            ALOGE("failed to retrieve response for cmd (%d) to %s: %s\n", cmd, OEMCRYPTO_PORT,
                  strerror(errno));
            return OEMCrypto_ERROR_UNKNOWN_FAILURE;
        }

        if ((size_t)rc < sizeof(struct oemcrypto_message)) {
            ALOGE("invalid response size (%d)\n", (int)rc);
            return OEMCrypto_ERROR_UNKNOWN_FAILURE;
        }

        if ((cmd | OEMCRYPTO_RESP_BIT) == header->cmd){
            *out_size += ((size_t)rc - sizeof(struct oemcrypto_message));
            break;
        }else if(header->cmd & OEMCRYPTO_CONT_BIT){
            *out_size += ((size_t)rc - sizeof(struct oemcrypto_message));
            continue;
        }else{
            ALOGE("invalid command (%d)", header->cmd);
            return OEMCrypto_ERROR_UNKNOWN_FAILURE;
        }
    }

    return OEMCrypto_SUCCESS;
}

void trusty_oemcrypto_disconnect() {
    if (handle_ >= 0) {
        tipc_close(handle_);
    }
    handle_ = -1;
}

