LOCAL_PATH := $(call my-dir)

ifeq (Q,$(filter Q,$(PLATFORM_VERSION)))
include $(CLEAR_VARS)
ifeq ($(BOARD_TEE_CONFIG), trusty)
LOCAL_CFLAGS += -Wno-date-time

LOCAL_SRC_FILES:= \
    src/trusty_oemcrypto_ipc.c \
    src/oemcrypto.cpp \
    src/oemcrypto_logging.cpp \

LOCAL_MODULE_TAGS := tests

LOCAL_C_INCLUDES += \
    $(LOCAL_PATH)/include \
    $(LOCAL_PATH)/src \
    $(LOCAL_PATH)/../../../../../../../../vendor/sprd/modules/libmemion \
    $(LOCAL_PATH)/../../../../../../../../vendor/sprd/external/kernel-headers \
    vendor/widevine/libwvdrmengine/cdm/core/include \
    vendor/widevine/libwvdrmengine/cdm/util/include \
    external/gtest/include \
    hardware/libhardware/include \
    system/core/libutils/include \
    system/core/libsystem/include \


LOCAL_SHARED_LIBRARIES := \
    libcrypto \
    libtrusty \
    liblog \
    libcutils \
    libmemion \

LOCAL_STATIC_LIBRARIES := \
    libcdm_utils \

# Proprietary modules are put in vendor/lib instead of /system/lib.
LOCAL_PROPRIETARY_MODULE := true
LOCAL_MODULE := liboemcrypto
LOCAL_MODULE_TARGET_ARCH := arm x86 mips

include $(BUILD_SHARED_LIBRARY)
include $(LOCAL_PATH)/test/Android.mk
#include $(call all-makefiles-under,$(LOCAL_PATH))
endif
endif
