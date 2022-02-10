LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := libsoter_checkx

LOCAL_SRC_FILES := soter_checkx.c

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_RELATIVE_PATH := npidevice
LOCAL_PROPRIETARY_MODULE := true

LOCAL_C_INCLUDES:= \
    $(TOP)/vendor/sprd/proprietories-source/engpc/sprd_fts_inc \

LOCAL_SHARED_LIBRARIES:= liblog libc libcutils libteeproduction

include $(BUILD_SHARED_LIBRARY)

