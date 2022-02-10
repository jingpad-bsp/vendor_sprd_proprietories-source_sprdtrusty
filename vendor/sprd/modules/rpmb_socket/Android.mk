#
#

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

#ifeq ($(BOARD_TEE_CONFIG), trusty)

include $(CLEAR_VARS)

ifeq (ufs,$(strip $(BOARD_MEMORY_TYPE)))
rc_suffix := _ufs
endif

LOCAL_MODULE := rpmbserver
LOCAL_SRC_FILES := rpmb_server.c
ifeq (4.4.4,$(filter 4.4.4,$(PLATFORM_VERSION)))
LOCAL_INIT_RC := rpmbserver.rc
else ifeq (7.0,$(filter 7.0,$(PLATFORM_VERSION)))
LOCAL_INIT_RC := rpmbserver.rc
else
#LOCAL_MODULE_PATH :=$(TARGET_OUT_VENDOR_EXECUTABLES)
LOCAL_PROPRIETARY_MODULE := true
LOCAL_VENDOR_MODULE = true
LOCAL_INIT_RC := rpmbserver_androido$(rc_suffix).rc
endif

LOCAL_CLFAGS += -Wall -Werror
ifeq (ufs,$(strip $(BOARD_MEMORY_TYPE)))
LOCAL_CFLAGS += -DUSE_UFS
endif

LOCAL_SHARED_LIBRARIES := \
        liblog \
        libcutils

LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)
#endif

include $(CLEAR_VARS)


# ==  rpmbcleinttest ==
include $(CLEAR_VARS)

LOCAL_MODULE := rpmbclienttest
LOCAL_VENDOR_MODULE = true
LOCAL_SRC_FILES := rpmb_client_test.c
LOCAL_CLFAGS += -Wall -Werror
LOCAL_SHARED_LIBRARIES := \
        liblog \
        librpmbclient \
        libcutils

include $(BUILD_EXECUTABLE)


# ==  Static library ==
include $(CLEAR_VARS)

LOCAL_MODULE := librpmbclient
LOCAL_VENDOR_MODULE = true

LOCAL_SRC_FILES := \
        rpmb_client.c

LOCAL_CLFAGS = -fvisibility=hidden -Wall -Werror

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
LOCAL_PROPRIETARY_MODULE := true

LOCAL_SHARED_LIBRARIES := \
    liblog \
    libcutils

include $(BUILD_STATIC_LIBRARY)


# ==   shared library ==
include $(CLEAR_VARS)

LOCAL_MODULE := librpmbclient

LOCAL_SRC_FILES := \
        rpmb_client.c

LOCAL_CLFAGS = -fvisibility=hidden -Wall -Werror

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
LOCAL_PROPRIETARY_MODULE := true

LOCAL_SHARED_LIBRARIES := \
    liblog \
    libcutils

include $(BUILD_SHARED_LIBRARY)




