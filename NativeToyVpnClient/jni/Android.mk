LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := NativeToyVpnClient
LOCAL_SRC_FILES := NativeToyVpnClient.cpp
LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
