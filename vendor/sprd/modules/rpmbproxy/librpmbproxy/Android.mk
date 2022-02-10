#
# Copyright (C) 2017 spreadtrum.com
#

LOCAL_PATH:= $(call my-dir)

# ==  Static library ==
include $(CLEAR_VARS)

LOCAL_MODULE := librpmbproxy

LOCAL_SRC_FILES := \
        rpmbproxy.c \
        rpmb_ops.c

LOCAL_CLFAGS = -fvisibility=hidden -Wall -Werror

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += bionic/libc/kernel/uapi

LOCAL_STATIC_LIBRARIES := \
    librpmbproxyinterface \
    libtrusty \
    liblog \
    libcutils \
    libcrypto \

include $(BUILD_STATIC_LIBRARY)


# ==   shared library ==
include $(CLEAR_VARS)

LOCAL_MODULE := librpmbproxy

LOCAL_SRC_FILES := \
        rpmbproxy.c \
        rpmb_ops.c

LOCAL_CLFAGS = -fvisibility=hidden -Wall -Werror

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += bionic/libc/kernel/uapi

LOCAL_STATIC_LIBRARIES := \
    librpmbproxyinterface \

LOCAL_SHARED_LIBRARIES := \
    libtrusty \
    liblog \
    libcrypto \
    libcutils

include $(BUILD_SHARED_LIBRARY)
