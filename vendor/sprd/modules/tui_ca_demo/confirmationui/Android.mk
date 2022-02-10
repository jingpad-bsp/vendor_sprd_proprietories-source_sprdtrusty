
ifeq ($(BOARD_TEE_CONFIG), trusty)

#####################
# lib confirmationui
#####################
ifeq ($(BOARD_TUI_CONFIG), true)

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

PARENT_PATH := $(shell dirname $(LOCAL_PATH))

DISP_DIR := $(PARENT_PATH)/display
INPUT_DIR := $(PARENT_PATH)/input
IPC_DIR := $(PARENT_PATH)/ipc
FT_DIR := $(PARENT_PATH)/vecfont
UTILS_DIR := $(PARENT_PATH)/utils

LOCAL_MODULE := libconfirmationui

LOCAL_SRC_FILES := \
	confirmationcaller.c \
	confirmationui_ipc.c \
	../tuinotify.cpp \
	../display/secure_display_config.c \
	../ipc/tuimon_ipc.c \
    ../ipc/tuica_ipc.c \
	../ipc/vecfont_ipc.c \
	../vecfont/tui_vecft.c \
	../input/secure_tp_register.c \
	../input/secure_keyboard_onoff.c \
	../utils/serializer.c \
	../tuilaunch.c

ifneq ($(filter $(strip $(PLATFORM_VERSION)),Q 10),)
	LOCAL_SRC_FILES += ../display/secure_display_onoff_q.c
else
	LOCAL_SRC_FILES += ../display/secure_display_onoff.c
endif

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include \
    $(DISP_DIR) \
	$(IPC_DIR) \
	$(INPUT_DIR) \
	$(FT_DIR) \
	$(UTILS_DIR)

LOCAL_CLFAGS += -fvisibility=hidden -Wall -Werror

LOCAL_SHARED_LIBRARIES := \
        libtrusty \
        liblog \
        libcutils \
        libhidlbase \
        libutils \
        vendor.sprd.hardware.tuistate@1.0

LOCAL_PROPRIETARY_MODULE := true
LOCAL_MODULE_TAGS := optional

LOCAL_SANITIZE := cfi
LOCAL_SANITIZE_DIAG := cfi

include $(BUILD_SHARED_LIBRARY)

endif
endif
