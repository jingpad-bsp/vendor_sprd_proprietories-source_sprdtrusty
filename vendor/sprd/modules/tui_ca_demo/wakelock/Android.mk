
ifeq ($(BOARD_TEE_CONFIG), trusty)
ifeq ($(BOARD_TUI_CONFIG), true)

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := tuiwakelock

LOCAL_SRC_FILES := \
	tuistatelistener.cpp \
	tuiwakelock.cpp \

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \

LOCAL_SHARED_LIBRARIES := \
        liblog \
        libbase \
        libbinder \
        libpowermanager \
        libutils \
        libhidlbase \
        libhidltransport \
        vendor.sprd.hardware.tuistate@1.0

LOCAL_INIT_RC := tuistatelistener.rc
LOCAL_MODULE_TAGS := optional

LOCAL_SANITIZE := cfi
LOCAL_SANITIZE_DIAG := cfi

include $(BUILD_EXECUTABLE)

endif
endif
