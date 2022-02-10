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

#ifndef __FACEID_H__
#define __FACEID_H__

#include <stdint.h>
#include <hardware/hw_auth_token.h>

int32_t open_tee_faceid();
void close_tee_faceid();

int32_t save_template(uint32_t gid, int32_t index, const void *feature, size_t count);
int32_t remove_template(uint32_t gid);
int32_t init_auth(uint32_t gid, uint64_t operation_id);
int32_t get_template_count(uint32_t gid);
int32_t compare(const void *feature, size_t count, float *max_score, float *mean_score);
int32_t compare2(const void *feature1, const void *feature2, size_t count, float *score);
int32_t tee_pre_enroll(uint64_t *challenge);
int32_t tee_enroll(const hw_auth_token_t *hat);
int32_t tee_post_enroll();
int32_t tee_get_auth_token(hw_auth_token_t *hat);
int32_t tee_get_authenticator_id(uint64_t *auth_id);

#endif
