/*
 * Copyright (C) 2016 The Android Open Source Project
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

#pragma once


#define LOG_TAG  "rpmbproxy"
#define USE_KLOG 1

#ifdef USE_KLOG
#include <cutils/klog.h>

#define LOG_ERROR(x...)  KLOG_ERROR(LOG_TAG, x)
#define LOG_INFO(x...)   KLOG_INFO(LOG_TAG, x)
#else
#include <cutils/log.h>

#define LOG_ERROR  ALOGE
#define LOG_INFO   ALOGI
#endif
