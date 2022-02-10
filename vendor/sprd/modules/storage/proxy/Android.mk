#
# Copyright (C) 2016 The Android Open-Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

ifeq (ufs,$(strip $(BOARD_MEMORY_TYPE)))
rc_suffix := _ufs
endif

LOCAL_MODULE := sprdstorageproxyd


LOCAL_C_INCLUDES += bionic/libc/kernel/uapi


ifeq (4.4.4,$(filter 4.4.4,$(PLATFORM_VERSION)))
LOCAL_INIT_RC := storageproxyd.rc
else ifeq (7.0,$(filter 7.0,$(PLATFORM_VERSION)))
LOCAL_INIT_RC := storageproxyd.rc
else ifeq ($(PLATFORM_VERSION),8.0.0)
LOCAL_PROPRIETARY_MODULE := true
#LOCAL_MODULE_PATH :=$(TARGET_OUT_VENDOR_EXECUTABLES)
LOCAL_INIT_RC := storageproxyd_androido.rc
else ifeq ($(PLATFORM_VERSION),8.1.0)
LOCAL_PROPRIETARY_MODULE := true
#LOCAL_MODULE_PATH :=$(TARGET_OUT_VENDOR_EXECUTABLES)
LOCAL_INIT_RC := storageproxyd_androidone.rc
else
LOCAL_CFLAGS += -DCUTILS_ANDROID_FILESYSTEM_CONFIG_H
LOCAL_PROPRIETARY_MODULE := true
LOCAL_VENDOR_MODULE = true
#LOCAL_MODULE_PATH :=$(TARGET_OUT_VENDOR_EXECUTABLES)
LOCAL_INIT_RC := storageproxyd_androidp$(rc_suffix).rc
endif

LOCAL_SRC_FILES := \
	ipc.c \
	storage.c \
	emmc.c \
	proxy.c

ifeq (ufs,$(strip $(BOARD_MEMORY_TYPE)))
LOCAL_SRC_FILES += rpmb_ufs.c
else
LOCAL_SRC_FILES += rpmb.c
endif

LOCAL_SHARED_LIBRARIES := \
	liblog \
	libcutils \
	libtrusty


LOCAL_STATIC_LIBRARIES := \
	libsprdtrustystorageinterface \

include $(BUILD_EXECUTABLE)
