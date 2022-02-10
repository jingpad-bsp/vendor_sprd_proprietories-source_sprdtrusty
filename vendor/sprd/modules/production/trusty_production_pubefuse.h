/*
 * Copyright (c) 2015, Spreadtrum.
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


#ifndef _TRUSTY_PRODUCTION_PUBEFUSE_H_
#define _TRUSTY_PRODUCTION_PUBEFUSE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cutils/log.h>
#include "trusty_production_efuse_modules.h"

#define NULL ((void*)0)

#define MAX_TRANS_SIZE 4024  //for keybox CA transfort to TA
#define KEYBOX_CHECKSUM_LENGTH 2

#define PROPERTY_VALUE_MAX 128

// secure command id from pc tool
typedef enum {
    CMD_GET_EFUSEUID                     =0x0001,
    CMD_SET_BLOCK                        =0x0002,
    CMD_GET_BLOCK                        =0x0003,
    CMD_ENABLE_SECURE                    =0x0004,
    CMD_CHECK_SECURE_ENABLE              =0x0005,
    CMD_DISABLE_PTEST                    =0x0006,
}puefuse_command_id;

int production_diag_user_handle(uint32_t type, uint32_t block, uint32_t value, uint32_t* block_value, char *buf, uint32_t* len);

#endif /* _SPRD_EFUSE_HW_H_  */

