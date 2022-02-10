ifeq ($(BOARD_TEE_CONFIG), trusty)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
ifneq (7.0,$(filter 7.0,$(PLATFORM_VERSION)))
LOCAL_PROPRIETARY_MODULE := true
endif

LOCAL_SRC_FILES:= \
    tsupplicant.cpp

LOCAL_MODULE_TAGS := optional

LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR_EXECUTABLES)

LOCAL_SHARED_LIBRARIES := \
    libtrusty \
    libcutils \
    libutils  \
    liblog

LOCAL_MODULE := tsupplicant

LOCAL_INIT_RC := tsupplicant.rc

include $(BUILD_EXECUTABLE)
endif
