ifeq ($(strip $(FACEID_FEATURE_SUPPORT)), true)
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

#build signed faceid ta
LOCAL_MODULE := faceid.elf
LOCAL_SRC_FILES := dummy.elf
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR)/firmware
LOCAL_MODULE_TAGS := optional

ifeq ($(strip $(FACEID_TEE_FULL_SUPPORT)),true)
FACEID_TEE_VERSION := full
else
FACEID_TEE_VERSION := lite
endif

sign_base_dir := $(PWD)/vendor/sprd/proprietories-source/packimage_scripts/signimage
sign_script := $(sign_base_dir)/dynamicTA/signta.py
sign_key := $(sign_base_dir)/sprd/config/dynamic_ta_privatekey.pem
src_elf_dir := $(PWD)/vendor/sprd/proprietories-source/sprdtrusty/vendor/sprd/modules/faceid/$(FACEID_TEE_VERSION)/ta/$(TARGET_BOARD_PLATFORM)
target_elf_dir := $(PWD)/$(TARGET_OUT_VENDOR)/firmware
ta_uuid := f4bc36e68ec246e2a82ef7cb6cdc6f72
ta := faceid

sign_cmd := source $(LOCAL_PATH)/sign_ta.sh $(sign_script) $(ta_uuid) $(sign_key) $(src_elf_dir)/$(ta).elf $(target_elf_dir)/$(ta).elf

LOCAL_ADDITIONAL_DEPENDENCIES := $(src_elf_dir)/$(ta).elf $(sign_key)
LOCAL_POST_INSTALL_CMD := rm $(target_elf_dir)/$(ta).elf; $(sign_cmd)

include $(BUILD_PREBUILT)

include $(call all-makefiles-under,$(LOCAL_PATH))
endif
