LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

######################################
# Building attk_injection
#
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/../../production

LOCAL_SRC_FILES:= attk_injection.c

LOCAL_MODULE := attk_injection

LOCAL_SHARED_LIBRARIES := \
    libtrusty \
    libcutils \
    libteeproduction


LOCAL_VENDOR_MODULE := true

LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)

