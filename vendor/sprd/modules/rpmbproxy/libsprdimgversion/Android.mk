#
# Copyright (C) 2017 spreadtrum.com
#

LOCAL_PATH:= $(call my-dir)


# ==  Static library ==
include $(CLEAR_VARS)

LOCAL_MODULE := libsprdimgversion

LOCAL_SRC_FILES := sprdimgversion.c

LOCAL_STATIC_LIBRARIES := \
    librpmbproxyinterface \
    libsprdimgversioninterface \
    liblog \
    librpmbproxy \
    libcutils \

include $(BUILD_STATIC_LIBRARY)


# ==   shared library ==
include $(CLEAR_VARS)

LOCAL_MODULE := libsprdimgversion

LOCAL_SRC_FILES := sprdimgversion.c

LOCAL_STATIC_LIBRARIES := \
    librpmbproxyinterface \
    libsprdimgversioninterface \

LOCAL_SHARED_LIBRARIES := \
    librpmbproxy \
    liblog \
    libcutils \

include $(BUILD_SHARED_LIBRARY)


