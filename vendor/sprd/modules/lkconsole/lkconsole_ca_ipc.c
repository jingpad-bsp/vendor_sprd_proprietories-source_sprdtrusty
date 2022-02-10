/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <cutils/log.h>
#include <trusty/tipc.h>
#include "lkconsole_ca_ipc.h"
#include <unistd.h>

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"
#define LOG_TAG "lkconsole"

int trusty_lkconsole_connect()
{
	int rc = tipc_connect(TRUSTY_DEVICE_NAME, LKCONSOLE_PORT);
	if (rc < 0) {
		return rc;
	}

	handle_ = rc;
	return 0;
}

int trusty_lkconsole_call(uint32_t cmd, void *in, uint32_t in_size,
				uint8_t *out, uint32_t *out_size)
{
	size_t msg_size;
	struct lkconsole_message *msg;

	if (handle_ == 0) {
		printf("not connected\n");
		return -EINVAL;
	}

	msg_size = in_size + sizeof(struct lkconsole_message);
	msg = malloc(msg_size);
	msg->cmd = cmd;
	memcpy(msg->payload, in, in_size);

	ssize_t rc = write(handle_, msg, msg_size);
	free(msg);

	if (rc < 0) {
		printf("failed to send cmd (%d) to %s: %s\n", cmd,
				LKCONSOLE_PORT, strerror(errno));
		return -errno;
	}

	rc = read(handle_, out, *out_size);
	if (rc < 0) {
		printf("failed to retrieve response for cmd (%d) to %s: %s\n",
				cmd, LKCONSOLE_PORT, strerror(errno));
		return -errno;
	}
	if ((size_t) rc < sizeof(struct lkconsole_message)) {
		printf("invalid response size (%d)\n", (int) rc);
		return -EINVAL;
	}

	msg = (struct lkconsole_message*) out;

	if ((cmd | TA_RESP_BIT) != msg->cmd) {
		printf("invalid command (%d)", msg->cmd);
		return -EINVAL;
	}

	*out_size = ((size_t) rc) - sizeof(struct lkconsole_message);
	return *out_size;
}

void trusty_lkconsole_disconnect()
{
	if (handle_ != 0) {
		tipc_close(handle_);
		handle_ = 0 ;
	}
}
