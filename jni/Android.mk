#Copyright (C) 2018 wang.junren@westone.com.cn

LOCAL_PATH := $(call my-dir)
				
include $(CLEAR_VARS)
LOCAL_MODULE := Client

LOCAL_LDLIBS    += -lm -llog -ldl -pthread



LOCAL_SRC_FILES += \
Agent/Communication/CommunicationClient.cpp \
Agent/Communication/LocalSocketClient.cpp \
Agent/RemoteCall/RemoteCall.cpp \
ContentFrame/ContentFrame.cpp \
ContentFrame/ContentFrame0001.cpp \
MsgFrame/MsgFrame.cpp \
Mutex/Mutex.cpp \
Log/log.cpp 

$(info client src files : = $(LOCAL_SRC_FILES))

LOCAL_C_INCLUDES += \
jni/Log/ \
jni/ReturnCode/ \
jni/Agent/ \
jni/Agent/RemoteCall/ \
jni/Agent/Communication/ \
jni/Agent/ \
jni/ContentFrame/ \
jni/MsgFrame/ \
jni/Mutex/ 

$(info client include : = $(LOCAL_C_INCLUDES))

LOCAL_CPPFLAGS += -fexceptions  -std=c++11
include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)
LOCAL_MODULE := Server

LOCAL_LDLIBS    += -lm -llog -ldl -pthread

LOCAL_SRC_FILES += \
Server/Communication/CommunicationServer.cpp \
Server/Communication/Communication.cpp \
Server/Communication/LocalSocketServer.cpp \
ContentFrame/ContentFrame.cpp \
ContentFrame/ContentFrame0001.cpp \
MsgFrame/MsgFrame.cpp \
Mutex/Mutex.cpp \
Server/RemoteService/RemoteService.cpp \
Server/FunctionParse/FunctionParse.cpp	\
Log/log.cpp
$(info server src files : = $(LOCAL_SRC_FILES))
LOCAL_C_INCLUDES += $(shell find jni/* -type d)
$(info server include : = $(LOCAL_C_INCLUDES))

#LOCAL_CFLAGS += -std=c++11  -std=c++11
LOCAL_CPPFLAGS += -fexceptions  -std=c++11
include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)
LOCAL_MODULE := ClientTest

LOCAL_LDLIBS    += -lm -llog -ldl -pthread

LOCAL_SRC_FILES += \
Agent/TestClient.cpp \

$(info client src files : = $(LOCAL_SRC_FILES))

LOCAL_C_INCLUDES += \
jni/Log/ \
jni/ReturnCode/ \
jni/Agent/ \
jni/Agent/RemoteCall/ \
jni/Agent/Communication/ \
jni/Agent/ \
jni/ContentFrame/ \
jni/MsgFrame/ \
jni/Mutex/ 



$(info client include : = $(LOCAL_C_INCLUDES))
LOCAL_SHARED_LIBRARIES += Client
LOCAL_CPPFLAGS += -fexceptions  -std=c++11
include $(BUILD_SHARED_LIBRARY)



include $(CLEAR_VARS)
LOCAL_MODULE := ServerTest

LOCAL_LDLIBS    += -lm -llog -ldl -pthread

LOCAL_SRC_FILES := Server/TestServer.cpp

$(info client src files : = $(LOCAL_SRC_FILES))

LOCAL_C_INCLUDES += $(shell find jni/* -type d)
$(info client include : = $(LOCAL_C_INCLUDES))
LOCAL_SHARED_LIBRARIES += Server
LOCAL_CPPFLAGS += -fexceptions  -std=c++11
include $(BUILD_SHARED_LIBRARY)

