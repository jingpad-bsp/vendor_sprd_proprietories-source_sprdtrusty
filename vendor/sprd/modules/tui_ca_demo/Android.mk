ifeq ($(BOARD_TEE_CONFIG), trusty)

ifeq ($(BOARD_TUI_CONFIG), true)

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := tuica

DISP_DIR  := display
INPUT_DIR := input
IPC_DIR   := ipc
VECFT_DIR := vecfont
UTILS_DIR := utils

LOCAL_SRC_FILES := \
	tuica.c \
	tuilaunch.c \
	tuinotify.cpp \
	tuicancel.c \
	$(DISP_DIR)/secure_display_config.c \
	$(INPUT_DIR)/key_events.c \
	$(INPUT_DIR)/key_receiver_thread.c \
	$(INPUT_DIR)/secure_keyboard_onoff.c \
	$(INPUT_DIR)/secure_key_register.c \
	$(INPUT_DIR)/secure_tp_register.c \
	$(IPC_DIR)/tuica_ipc.c \
	$(IPC_DIR)/tuimon_ipc.c \
	$(IPC_DIR)/vecfont_ipc.c \
	$(VECFT_DIR)/tui_vecft.c \
	$(UTILS_DIR)/serializer.c

ifneq ($(filter $(strip $(PLATFORM_VERSION)),Q 10),)
	LOCAL_SRC_FILES += $(DISP_DIR)/secure_display_onoff_q.c
else
	LOCAL_SRC_FILES += $(DISP_DIR)/secure_display_onoff.c
endif

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH) \
    $(LOCAL_PATH)/$(DISP_DIR) \
    $(LOCAL_PATH)/$(INPUT_DIR) \
    $(LOCAL_PATH)/$(IPC_DIR) \
    $(LOCAL_PATH)/$(VECFT_DIR) \
    $(LOCAL_PATH)/$(UTILS_DIR)

LOCAL_CLFAGS = -fvisibility=hidden -Wall -Werror

LOCAL_SHARED_LIBRARIES := \
	liblog \
	libcutils \
	libtrusty \
	libhidlbase \
	libutils \
	vendor.sprd.hardware.tuistate@1.0

LOCAL_PROPRIETARY_MODULE := true
LOCAL_MODULE_TAGS := optional

#sign font ta. begin
sign_base_dir := $(PWD)/vendor/sprd/proprietories-source/packimage_scripts/signimage
sign_script := $(sign_base_dir)/dynamicTA/signta.py
sign_key := $(sign_base_dir)/sprd/config/dynamic_ta_privatekey.pem
src_elf_dir := $(PWD)/vendor/sprd/proprietories-source/sprdtrusty/vendor/sprd/modules/tui_ca_demo/vecfont
target_elf_dir := $(PWD)/$(TARGET_OUT_VENDOR)/firmware

zh_ta_uuid := b63dd993491843ab9aa100a52a027e67
unsign_ta_zh := dta_vecft_zh
sign_ta_zh := vecft-zh
sign_ta_zh_cmd := source $(LOCAL_PATH)/sign_ta.sh $(sign_script) $(zh_ta_uuid) $(sign_key) $(src_elf_dir)/$(unsign_ta_zh).elf $(target_elf_dir)/$(sign_ta_zh).elf

en_US_ta_uuid := b63dd993491843ab9aa100a52a027e67
unsign_ta_en_US := dta_vecft_en
sign_ta_en_US := vecft-en-US
sign_ta_en_US_cmd := source $(LOCAL_PATH)/sign_ta.sh $(sign_script) $(en_US_ta_uuid) $(sign_key) $(src_elf_dir)/$(unsign_ta_en_US).elf $(target_elf_dir)/$(sign_ta_en_US).elf

LOCAL_ADDITIONAL_DEPENDENCIES := $(src_elf_dir)/$(unsign_ta_zh).elf  $(src_elf_dir)/$(unsign_ta_en_US).elf  $(sign_key)
LOCAL_POST_INSTALL_CMD := mkdir $(target_elf_dir); $(sign_ta_zh_cmd); $(sign_ta_en_US_cmd)
#sign font ta. end

LOCAL_SANITIZE := cfi
LOCAL_SANITIZE_DIAG := cfi

include $(BUILD_EXECUTABLE)

# ohter targets
include $(call all-makefiles-under,$(LOCAL_PATH))

endif
endif
