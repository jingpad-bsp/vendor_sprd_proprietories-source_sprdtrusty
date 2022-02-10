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

#pragma once

#define TAMANAGER_PORT "com.android.trusty.tamanager"
#define TAMANAGER_MAX_BUFFER_LENGTH (124 * 1024)

#define TAMANAGER_LOAD_NAME_LENGTH 64

/* Commands */
enum tamanager_command {
TAMANAGER_RESP_BIT              = 1,
TAMANAGER_REQ_SHIFT             = 1,

TAMANAGER_INITIALIZE               = (1 << TAMANAGER_REQ_SHIFT),
TAMANAGER_TERMINATE                = (2 << TAMANAGER_REQ_SHIFT),
TAMANAGER_WAIT_LOAD                = (3 << TAMANAGER_REQ_SHIFT),
TAMANAGER_LOAD_TA                  = (4 << TAMANAGER_REQ_SHIFT),
TAMANAGER_PORT_PUBLISH             = (5 << TAMANAGER_REQ_SHIFT),
TAMANAGER_READ_TA                  = (6 << TAMANAGER_REQ_SHIFT),
TAMANAGER_WRITE_TA                 = (7 << TAMANAGER_REQ_SHIFT),
TAMANAGER_STOP_LOAD_REQUEST        = (8 << TAMANAGER_REQ_SHIFT),
};


/**
 * tamanager_message - Serial header for communicating with tamanager server
 * @cmd: the command, one of ta_manager_command.
 * @payload: start of the serialized command specific payload
 */
struct tamanager_message {
	uint32_t   cmd;
	uint8_t    payload[0];
};

struct tamanager_write_resq {
	uint32_t   result;         /* result */
};

struct tamanager_write_request {
	uint32_t   total_size;      /* total size */
	uint32_t   write_pos;       /* write position */
	uint32_t   payload_len;     /* payload length */
	uint8_t    payload[0];
};


struct tamanager_ta_buff {
	uint32_t len;
	char name[TAMANAGER_LOAD_NAME_LENGTH];
};


