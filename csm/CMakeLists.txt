# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.
#CMakeLists.txt
cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

find_package (Threads)
################################################################################################
#
#  include head
#
################################################################################################

ADD_DEFINITIONS(-DSCP02_ENCRYPT)
ADD_DEFINITIONS(-DHAVE_PTHREAD)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

#add_compile_options("--version-script=export.map")

################################################################################################
#
#   protocol buffer static library
#
################################################################################################

add_library(
        RemoteCallServer
        STATIC

        src/main/jni/Communication/LocalSocketServer.cpp
        src/main/jni/Communication/BinderServer.cpp
        src/main/jni/RemoteCall/ContentFrame.cpp
        src/main/jni/RemoteCall/Control.cpp
        src/main/jni/RemoteCall/Return.pb.cc
        src/main/jni/RemoteCall/GetPackageName.cpp
        src/main/jni/RemoteCall/FunctionParse.cpp
        src/main/jni/RemoteCall/CSMResAccess.cpp
        src/main/jni/RemoteCall/ContentFrame0001.cpp
        src/main/jni/RemoteCall/ContentFrame0002.cpp
        src/main/jni/RemoteCall/MsgFrame.cpp
        src/main/jni/RemoteCall/RemoteServicePack.cpp
        src/main/jni/RemoteCall/RemoteService.cpp
        src/main/jni/scp02/tiny_des.c
        src/main/jni/scp02/tiny_sha2.c
        src/main/jni/sm/sm3/sm3interface/sm3.c
        src/main/jni/sm/sm3/sm3interface/sm3_core.c
        src/main/jni/sm/sm4/sm4interface/sm4.c
        src/main/jni/sm/sm4/sm4interface/sm4_core.c
        src/main/jni/scp02/Scp02Service.cpp
        src/main/jni/RemoteCall/Mutex.cpp
)

target_include_directories(
        RemoteCallServer
        PRIVATE
        src/main/jni

        src/main/jni/Communication
        src/main/jni/scp02
        src/main/jni/sm/include
        src/main/jni/RemoteCall
)

add_library(
        Server
        SHARED

        src/main/jni/P11/CSMNativeService.cpp
        src/main/jni/P11/AttributesConvert.cpp
        src/main/jni/P11/P11Mapping.cpp
        #src/main/jni/P11/sm3.c
        src/main/jni/P11/pkcs11.pb.cc
        src/main/jni/P11/P11Adapter.cpp
        src/main/jni/P11/p11FunctionParse.cpp
        src/main/jni/P11/p11func_sc.cpp
        src/main/jni/P11/p11func_hd.cpp
        src/main/jni/P11/LibLoadManager.cpp
        src/main/jni/P11/hd_transmitdelay.cpp
        src/main/jni/P11/p11func_jw.cpp
        src/main/jni/P11/Utils_c.cpp

        src/main/jni/SKF/skf.pb.cc
        src/main/jni/SKF/SkfAdapter.cpp
        src/main/jni/SKF/skf_interface.cpp
        src/main/jni/SKF/skfdef.cpp
        src/main/jni/SKF/skfFunctionParse.cpp
        src/main/jni/SKF/skfLibLoader.cpp

        src/main/jni/sm/sm3/sm3interface/sm3.c
        src/main/jni/sm/sm3/sm3interface/sm3_core.c
        src/main/jni/P11/logserver.cpp
        src/main/jni/plog/RecordLog.cpp
)

target_include_directories(
        Server
        PRIVATE

        src/main/jni
        src/main/jni/plog/Appenders
        src/main/jni/plog/Converters
        src/main/jni/plog/Formatters
        src/main/jni/plog

        src/main/jni/RemoteCall
        src/main/jni/P11
        src/main/jni/Communication
        src/main/jni/scp02

        src/main/jni/sm/include
        src/main/jni/SKF
)



add_library(ucm            SHARED             IMPORTED)
 # 设置第三方动态库属性（存储位置）
set_target_properties(
        ucm
        PROPERTIES IMPORTED_LOCATION
        ${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/libuser_cm.so
)

add_library(protobuf            STATIC             IMPORTED)
# 设置第三方动态库属性（存储位置）
set_target_properties(
        protobuf
        PROPERTIES IMPORTED_LOCATION
        ${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/libprotobuf_3.7_static.a
)

target_link_libraries(
        Server
        RemoteCallServer
        protobuf
        log
        ucm
)


add_library(
        skfWrapper
        SHARED
        src/main/jni/SKF/native-lib.cpp
)

target_link_libraries(
        skfWrapper
        log
)

#[[add_library(
        SoftSkf
        SHARED
        src/main/jni/SKF/skf_soft.cpp
        src/main/jni/SKF/skf_soft_util.cpp
        src/main/jni/sm/sm4/sm4interface/sm4.c
        src/main/jni/sm/sm4/sm4interface/sm4_core.c
        src/main/jni/sm/sm3/sm3interface/sm3_core.c
        src/main/jni/sm/sm3/sm3interface/sm3.c
        src/main/jni/sm/sm2/sm2interface/ec_general.c
        src/main/jni/sm/sm2/sm2interface/ec_lib.c
        src/main/jni/sm/sm2/sm2interface/ec_mult.c
        src/main/jni/sm/sm2/sm2interface/eccsm2_p256.c
        src/main/jni/sm/sm2/sm2interface/ecdsa.c
        src/main/jni/sm/sm2/sm2interface/eces.c
        src/main/jni/sm/sm2/sm2interface/ecp_smpl.c
        src/main/jni/sm/sm2/sm2interface/kdf.c
        src/main/jni/sm/sm2/sm2interface/key_ex.c
        src/main/jni/sm/sm2/sm2interface/mm_basic_fun.c
        src/main/jni/sm/sm2/sm2interface/rc4.c
        src/main/jni/sm/sm2/sm2interface/sm2.c
        src/main/jni/sm/sm2/sm2interface/sm2_bn_add.c
        src/main/jni/sm/sm2/sm2interface/sm2_bn_asm.c
        src/main/jni/sm/sm2/sm2interface/sm2_bn_div.c
        src/main/jni/sm/sm2/sm2interface/sm2_bn_gcd.c
        src/main/jni/sm/sm2/sm2interface/sm2_bn_lib.c
        src/main/jni/sm/sm2/sm2interface/sm2_bn_mod.c
        src/main/jni/sm/sm2/sm2interface/sm2_bn_mont.c
        src/main/jni/sm/sm2/sm2interface/sm2_bn_mul.c
        src/main/jni/sm/sm2/sm2interface/sm2_bn_shift.c
)

target_include_directories(
    SoftSkf
    PRIVATE
    src/main/jni/SKF
    src/main/jni/scp02
    src/main/jni/sm/include
)

target_link_libraries(
        SoftSkf
        log
)]]


#[[
set_target_properties(
        SoftSkfMan
        PROPERTIES
        LINK_FLAGS
        "-Wl,--version-script,\"${CMAKE_CURRENT_SOURCE_DIR}/export.map\""
)]]


add_library(
        RpcJniServer
        SHARED
        ../csm/src/main/jni/rpcserver/inf.cpp
)

target_include_directories(
        RpcJniServer
        PRIVATE
        ../csm/src/main/jni/rpcserver
)
target_link_libraries(
        RpcJniServer
        log
)