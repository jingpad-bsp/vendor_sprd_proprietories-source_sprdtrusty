/*
 * Copyright (c) 2017, Spreadtrum.
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

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <iostream>
#include <string>
#include <vector>
#include <cutils/log.h>
#include <log/log.h>
#include "tsupplicant.h"

#include <trusty/tipc.h>

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"
#define TRUSTRY_CALL_LOG   0
#define TRUSTRY_RECV_BUF_SIZE  16

typedef enum TSupplResult {
	TSuppl_SUCCESS                            = 0,
	TSuppl_ERROR_INIT_FAILED                  = 1,
	TSuppl_ERROR_TERMINATE_FAILED             = 2,
	TSuppl_ERROR_OPEN_FAILURE                 = 3,
	TSuppl_ERROR_CLOSE_FAILURE                = 4,
	TSuppl_ERROR_INVALID_DATA                 = 5,
	TSuppl_ERROR_UNKNOWN_FAILURE              = 6,
	TSuppl_ERROR_MALLOC_FAILED                = 7,
	TSuppl_ERROR_OVER_SIZE                    = 8,

} TSupplResult;



static int handle_ = 0;

static const uint32_t kUint32Size = sizeof(uint32_t);
static const uint32_t kTSupplResultSize = sizeof(TSupplResult);


TSupplResult trusty_supplicant_call(uint32_t   cmd,
										void   *in,
									uint32_t   in_size,
									uint8_t   *out,
									uint32_t   *out_size) {
	size_t    msg_size = 0;
	ssize_t   rc = 0;
	struct tamanager_message *msg = NULL;

	if (TRUSTRY_CALL_LOG)
		ALOGD("%s enter in_size = %d out_size = %d\n",
										__func__, in_size, *out_size);
	if (handle_ == 0) {
		ALOGE("not connected\n");
		return TSuppl_ERROR_UNKNOWN_FAILURE;
	}
	msg_size = in_size ;
	msg = reinterpret_cast<struct tamanager_message *>(in);;
	msg->cmd = cmd;

	if (TRUSTRY_CALL_LOG)
		ALOGD("handle = %d msg_size = %d\n", handle_, msg_size);
	rc = write(handle_, (void *) msg, msg_size);
	if (TRUSTRY_CALL_LOG)
		ALOGD("write rc = %d \n", rc);
	if ((rc <= 0) && (errno == EMSGSIZE)) {
		ALOGE("failed to send cmd (%d) to %s: %s\n", cmd,
									TAMANAGER_PORT, strerror(errno));
		return TSuppl_ERROR_OVER_SIZE;
	}
	if (rc <= 0) {
		ALOGE("failed to send cmd (%d) to %s: %s\n", cmd,
									TAMANAGER_PORT, strerror(errno));
		return TSuppl_ERROR_UNKNOWN_FAILURE;
	}
	rc = read(handle_, (void *)out, *out_size);
	if (TRUSTRY_CALL_LOG)
		ALOGD("read rc = %d \n", rc);
	if (rc <= 0) {
		ALOGE("failed to retrieve response for cmd (%d) to %s: %s\n",
								cmd, TAMANAGER_PORT, strerror(errno));
		return TSuppl_ERROR_UNKNOWN_FAILURE;
	}
	if ((size_t) rc < sizeof(struct tamanager_message)) {
		ALOGE("invalid response size (%d)\n", (int) rc);
		return TSuppl_ERROR_UNKNOWN_FAILURE;
	}
	msg = (struct tamanager_message *) out;
	if ((cmd | TAMANAGER_RESP_BIT) != msg->cmd) {
		ALOGE("invalid command (%d)", msg->cmd);
		return TSuppl_ERROR_UNKNOWN_FAILURE;
	}
	*out_size = ((size_t) rc) - sizeof(struct tamanager_message);
	return TSuppl_SUCCESS;
}


static TSupplResult TSuppl_Initialize(void) {

	TSupplResult         result;
	uint8_t   out_msg[TRUSTRY_RECV_BUF_SIZE];
	uint32_t  outsize = TRUSTRY_RECV_BUF_SIZE;
	struct tamanager_message *msg = NULL;
	struct tamanager_message in_msg;

	int rc = tipc_connect(TRUSTY_DEVICE_NAME, TAMANAGER_PORT);

	if (rc < 0) {
		ALOGE("[TSuppl_Initialize(): tipc_connect(): failed]\n");
		return TSuppl_ERROR_INIT_FAILED;
	}
	handle_ = rc;

	ALOGD("[TSuppl_Initialize(): tipc_connect() handle_ = %d ]\n", handle_);

	result = trusty_supplicant_call(TAMANAGER_INITIALIZE, &in_msg,
									sizeof(in_msg), out_msg, &outsize);
	if (result != TSuppl_SUCCESS) {
		ALOGE("[Initialize(): trusty_supplicant_call(): %d failed]\n", result);
		return TSuppl_ERROR_INIT_FAILED;
	}
	msg = (struct tamanager_message *) out_msg;
	memcpy(&result, msg->payload, kTSupplResultSize);
	if (result != TSuppl_SUCCESS) {
		ALOGE("[Initialize(): trusty_supplicant_call(): %d failed]\n", result);
		return TSuppl_ERROR_INIT_FAILED;
	}
	return result;
}


static TSupplResult TSuppl_Terminate(void) {

	TSupplResult        result;
	uint8_t   out_msg[TRUSTRY_RECV_BUF_SIZE];
	uint32_t  outsize = TRUSTRY_RECV_BUF_SIZE;
	struct tamanager_message *msg = NULL;
	struct tamanager_message in_msg;

	if (!handle_) {
		ALOGE("[TSuppl_Terminate(): failed]");
		return TSuppl_ERROR_TERMINATE_FAILED;
	}
	result = trusty_supplicant_call(TAMANAGER_TERMINATE, &in_msg,
									sizeof(in_msg), out_msg, &outsize);
	if (result != TSuppl_SUCCESS) {
		ALOGE("[Terminate(): trusty_supplicant_call(): %d failed]\n", result);
		return TSuppl_ERROR_TERMINATE_FAILED;
	}
	msg = (struct tamanager_message *) out_msg;
	memcpy(&result, msg->payload, kTSupplResultSize);
	if (result != TSuppl_SUCCESS) {
		ALOGE("[Terminate(): trusty_supplicant_call(): %d failed]\n", result);
		return TSuppl_ERROR_TERMINATE_FAILED;
	}

	if (handle_ != 0) {
		tipc_close(handle_);
		handle_ = 0;
	}
	return result;
}

static TSupplResult TSuppl_Wait_load(char **ta) {

	TSupplResult        result;
	uint8_t   *out_msg = NULL;
	uint32_t  outsize , ta_len = 0;
	struct tamanager_message *msg = NULL;
	struct tamanager_ta_buff *buff = NULL;
	struct tamanager_message in_msg;

	if (!handle_) {
		ALOGE("[TSuppl_Wait_load(): failed! handle = 0]");
		return TSuppl_ERROR_TERMINATE_FAILED;
	}

	outsize = kUint32Size + TAMANAGER_LOAD_NAME_LENGTH + sizeof(struct tamanager_message);
	out_msg = reinterpret_cast<uint8_t *>(malloc(outsize));
	if (out_msg == NULL) {
		ALOGE("[TSuppl_Wait_load():malloc (%d) failed!]\n", outsize);
		return TSuppl_ERROR_MALLOC_FAILED;
	}
	result = trusty_supplicant_call(TAMANAGER_WAIT_LOAD, &in_msg, sizeof(in_msg),
	out_msg, &outsize);
	if (result != TSuppl_SUCCESS) {
		ALOGE("[TSuppl_Wait_load(): trusty_supplicant_call(): %d failed]\n", result);
		free(out_msg);
		return TSuppl_ERROR_UNKNOWN_FAILURE;
	}
	msg = (struct tamanager_message *) out_msg;
	buff = reinterpret_cast<struct tamanager_ta_buff *>(msg->payload);

	if ((buff->len == 0) || (buff->name[0] == 0)) {
		ALOGE("[TSuppl_Wait_load(): TSuppl_ERROR_INVALID_DATA len =  %d ]\n", buff->len);
		free(out_msg);
		return TSuppl_ERROR_INVALID_DATA;
	}
	ALOGE("[TSuppl_Wait_load(): path =  %s ]\n", buff->name);
	int i;
	for (i = buff->len -1; i >= 0; i--) {
		if (buff->name[i] == '.') break;
		ta_len++;
	}

	if ((ta_len == 0) || (ta_len > buff->len)) {
		ALOGE("[TSuppl_Wait_load(): invalid len =  %d ]\n", ta_len);
		free(out_msg);
		return TSuppl_ERROR_INVALID_DATA;
	}
	/* get a TA */
	*ta = reinterpret_cast<char *>(malloc(ta_len+1));
	if (*ta == NULL) {
		ALOGE("[TSuppl_Wait_load():malloc ta(%d) failed!]\n", ta_len);
		free(out_msg);
		return TSuppl_ERROR_MALLOC_FAILED;
	}

	memset(*ta, 0, ta_len+1);
	memcpy(*ta, &buff->name[i+1], ta_len);
	free(out_msg);
	return TSuppl_SUCCESS;
}

static TSupplResult TSuppl_Handle_TA_NotFound(void) {

	TSupplResult        result;
	uint8_t   out_msg[TRUSTRY_RECV_BUF_SIZE];
	uint32_t  outsize = TRUSTRY_RECV_BUF_SIZE;
	struct tamanager_message *msg = NULL;
	struct tamanager_message in_msg;

	if (!handle_) {
		ALOGE("[TSuppl_Handle_TA_NotFound(): failed]");
		return TSuppl_ERROR_UNKNOWN_FAILURE;
	}
	result = trusty_supplicant_call(TAMANAGER_STOP_LOAD_REQUEST, &in_msg,
									sizeof(in_msg), out_msg, &outsize);
	if (result != TSuppl_SUCCESS) {
		ALOGE("[TSuppl_Handle_TA_NotFound(): trusty_supplicant_call(): %d failed]\n", result);
		return TSuppl_ERROR_UNKNOWN_FAILURE;
	}
	msg = (struct tamanager_message *) out_msg;
	memcpy(&result, msg->payload, kTSupplResultSize);
	if (result != TSuppl_SUCCESS) {
		ALOGE("[TSuppl_Handle_TA_NotFound(): trusty_supplicant_call(): %d failed]\n", result);
		return TSuppl_ERROR_UNKNOWN_FAILURE;
	}

	return result;
}

#define TAMANAGER_BUFFER_LENGTH0  4032
#define TAMANAGER_BUFFER_LENGTH   (124 * 1024)
static TSupplResult TSuppl_Write_Ta(FILE *f, long file_size) {

	TSupplResult        result = TSuppl_SUCCESS;
	long fsize = file_size;
	uint32_t  wpos = 0, buf_size;
	long      file_buff_size;
	uint8_t   *file_buff = NULL;
	uint8_t   *in_msg = NULL;
	uint32_t   buff_header , msg_hdr , real_size;
	uint8_t   out_msg[TRUSTRY_RECV_BUF_SIZE];
	uint32_t  outsize = TRUSTRY_RECV_BUF_SIZE;
	struct tamanager_message *msg = NULL;
	struct tamanager_write_request *wreq = NULL;
	struct tamanager_write_resq  write_resq;

	ALOGD("[TSuppl_Write_Ta(): fize_sizse %ld ]\n", file_size);
	msg_hdr = sizeof(struct tamanager_message);
	buff_header = msg_hdr + sizeof(struct tamanager_write_request);
	real_size = TAMANAGER_BUFFER_LENGTH - buff_header;
	buf_size  = TAMANAGER_BUFFER_LENGTH;
	in_msg = reinterpret_cast<uint8_t *>(malloc(TAMANAGER_BUFFER_LENGTH));
	if (in_msg == NULL) {
	    ALOGE("[TSuppl_Write_Ta: malloc(%d) failed!]\n", TAMANAGER_BUFFER_LENGTH);
	    result = TSuppl_ERROR_MALLOC_FAILED;
	    goto error_malloc_buff;
	}
        file_buff = reinterpret_cast<uint8_t *>(malloc(file_size));
        if (file_buff == NULL) {
	    ALOGE("[TSuppl_Write_Ta: file buff malloc(%d) failed!]\n", file_size);
	    result = TSuppl_ERROR_MALLOC_FAILED;
	    goto error_malloc_file;
	}
        file_buff_size = fread(file_buff, 1, file_size, f);
	if (ferror(f) != 0) {
	    ALOGE("[TSuppl_Write_Ta: fread  %d error(%s)!]\n", file_buff_size, strerror(errno));
	    result = TSuppl_ERROR_UNKNOWN_FAILURE;
	    goto error_read_file;
	}
	wreq = reinterpret_cast<struct tamanager_write_request *>(in_msg + msg_hdr);
	if (fsize) {
		size_t read_size;
		wreq->total_size = file_size;
		wreq->write_pos  = wpos;
		/* copy Ta data */
		if (real_size < fsize) {
		    read_size = real_size;
		} else {
		    read_size = fsize;
		}
		memcpy(wreq->payload, (file_buff + wpos), read_size);
		wreq->payload_len = read_size;
		outsize = msg_hdr + sizeof(struct tamanager_write_resq);
		/* transmit into trusty*/
		result = trusty_supplicant_call(TAMANAGER_WRITE_TA, in_msg, buf_size,
																out_msg, &outsize);
		if (result ==  TSuppl_ERROR_OVER_SIZE) {
			real_size = TAMANAGER_BUFFER_LENGTH0 - buff_header;
			buf_size  = TAMANAGER_BUFFER_LENGTH0;
			ALOGE("[TSuppl_Write_Ta: trusty_supplicant_call(%d) failed!]\n", result);
		} else if (result !=  TSuppl_SUCCESS) {
		    ALOGE("[TSuppl_Write_Ta: trusty_supplicant_call(%d) failed!]\n", result);
		    goto error_read_file;
		} else {
			msg = (struct tamanager_message *) out_msg;
			memcpy(&write_resq, msg->payload, sizeof(struct tamanager_write_resq));
			if (read_size != write_resq.result) {
				ALOGE("[TSuppl_Write_Ta: data(%d) lost %d!]\n", read_size, write_resq.result);
				wpos += write_resq.result;
				fsize -= write_resq.result;
			} else {
				wpos += read_size;
				fsize -= read_size;
			}
		}

		while (fsize) {
			wreq->total_size = file_size;
			wreq->write_pos  = wpos;
			/* copy Ta data */
			if (real_size < fsize) {
				read_size = real_size;
			} else {
				read_size = fsize;
			}
			memcpy(wreq->payload, (file_buff + wpos), read_size);
			wreq->payload_len = read_size;
			outsize = msg_hdr + sizeof(struct tamanager_write_resq);
			/* transmit into trusty*/
			result = trusty_supplicant_call(TAMANAGER_WRITE_TA, in_msg, buf_size,
																out_msg, &outsize);
			if (result !=  TSuppl_SUCCESS) {
				ALOGE("[TSuppl_Write_Ta: trusty_supplicant_call(%d) failed!]\n", result);
				break;
			}
			msg = (struct tamanager_message *) out_msg;
			memcpy(&write_resq, msg->payload, sizeof(struct tamanager_write_resq));
			if (read_size != write_resq.result) {
				ALOGE("[TSuppl_Write_Ta: data(%d) lost %d!]\n", read_size, write_resq.result);
				wpos += write_resq.result;
				fsize -= write_resq.result;
			} else {
				wpos += read_size;
				fsize -= read_size;
			}

			if (TRUSTRY_CALL_LOG)
				ALOGD("[TSuppl_Write_Ta: write ta %d]\n", write_resq.result);
		}
	}

error_read_file:
	free(file_buff);

error_malloc_file:
  	free(in_msg);

error_malloc_buff:
  	return result;
}

int main(int argc, char** argv)
{
	bool done = false;
	TSupplResult        result;
	char path[TAMANAGER_LOAD_NAME_LENGTH];

	TSuppl_Initialize();

	while (!done) {
		int fs;
		FILE * fp;
		char *ta = NULL;
		long file_size;

		memset(path, 0, TAMANAGER_LOAD_NAME_LENGTH);
		/* wait for a request, return TA name*/
		result = TSuppl_Wait_load(&ta);

		if (result != TSuppl_SUCCESS) {
			goto err_wait_load;
		}
                if (argc < 2) {
			sprintf(path, "/system/vendor/%s.elf", ta);
		} else {
			sprintf(path, "/vendor/%s/%s.elf", argv[1],ta);
		}
		ALOGE("[TSuppl main: ta = %s!]\n",ta);
		fp = fopen(path, "rb");
		if (!fp) {
			ALOGE("[TSuppl main: fopen (%s) failed!]\n", path);
			if (ta != NULL) {
				free(ta);
				ta = NULL;
			}
			result = TSuppl_Handle_TA_NotFound();
			if (result != TSuppl_SUCCESS) {
				ALOGE("[TSuppl main: Stop_TA failed %d!]\n", result);
				goto err_fopen_fail;
			}
			continue;
		}
		fs = fseek(fp, 0, SEEK_END);
		if (fs == -1) {
			ALOGE("[TSuppl main: fseek1 failed!]\n");
			goto err_fseek_fail1;
		}
		file_size = ftell(fp);
		if (file_size == -1) {
			ALOGE("[TSuppl main: ftell failed!]\n");
			goto err_ftell_fail;
		}
		fs = fseek(fp, 0, SEEK_SET);
		if (fs == -1) {
			ALOGE("[TSuppl main: fseek2 failed!]\n");
			goto err_fseek_fail2;
		}
		/* write TA data into trusty */
		result = TSuppl_Write_Ta(fp, file_size);
		if (result != TSuppl_SUCCESS) {
			ALOGE("[TSuppl main: TSuppl_Write_Ta failed %d!]\n", result);
			goto err_write_fail;
		}
		free(ta);
		ta = NULL;
		fclose(fp);
		continue;
err_write_fail:
err_fseek_fail1:
err_fseek_fail2:
err_ftell_fail:
        fclose(fp);

err_fopen_fail:
err_wait_load:
		if (ta != NULL) free(ta);
		break;
	}

	TSuppl_Terminate();

	return 0;
}

