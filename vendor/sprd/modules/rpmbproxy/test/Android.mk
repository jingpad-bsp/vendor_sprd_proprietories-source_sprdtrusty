#
# Copyright (C) 2017 spreadtrum.com
#

LOCAL_PATH:= $(call my-dir)


include $(CLEAR_VARS)
LOCAL_MODULE := rpmbproxy_test
LOCAL_SRC_FILES := rpmbproxy_test.c

LOCAL_STATIC_LIBRARIES := \
    librpmbproxyinterface \
    librpmbproxy \
    libtrusty   \
    liblog \
    libcrypto \
    libcutils \

#LOCAL_SHARED_LIBRARIES := \

include $(BUILD_EXECUTABLE)



include $(CLEAR_VARS)
LOCAL_MODULE := sprdimgversion_test
LOCAL_SRC_FILES := sprdimgversion_test.c

#LOCAL_SHARED_LIBRARIES := \

LOCAL_STATIC_LIBRARIES := \
    libsprdimgversioninterface \
    libsprdimgversion \
    librpmbproxy \
    libtrusty   \
    liblog \
    libcrypto \
    libcutils \

include $(BUILD_EXECUTABLE)


