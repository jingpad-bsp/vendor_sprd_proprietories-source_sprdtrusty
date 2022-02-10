#
# The MIT License (MIT)
# Copyright (c) 2008-2015 Travis Geiselbrecht
# Copyright (c) 2016, Spreadtrum Communications.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

$(warning =========================hunter=$(BOARD_TEE_CONFIG))
ifeq ($(BOARD_TEE_CONFIG), trusty)
    $(info =========================hunter=$(BOARD_TEE_CONFIG))

#only needed on treble version
ifeq ($(strip $(BOARD_SOTER_TRUSTY)), treble)
    $(info =========================hunter=$(BOARD_SOTER_TRUSTY))

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := libsoter_trusty

LOCAL_SRC_FILES := soter_trusty.c \
    trusty_soter_ipc.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_VENDOR_MODULE := true

#LOCAL_CLFAGS += -fvisibility=hidden -Wall -Werror
LOCAL_CLFAGS += -Wall -Werror
LOCAL_SHARED_LIBRARIES := \
        libtrusty \
        liblog \
        libcutils

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_MODULE_TAGS := optional
include $(BUILD_SHARED_LIBRARY)

endif
endif
