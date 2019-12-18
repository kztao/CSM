# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.
#CMakeLists.txt
cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.
ADD_DEFINITIONS(-DSCP02_ENCRYPT)
ADD_DEFINITIONS(-DHAVE_PTHREAD)
ADD_DEFINITIONS(-DSOFT_CARD_EXTERN_INTERFACE)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)


message(STATUS "CMAKE_SOURCE_DIR->" ${CMAKE_SOURCE_DIR})
message(STATUS "PROJECT_SOURCE_DIR->)" ${PROJECT_SOURCE_DIR})


find_package (Threads)
################################################################################################
#
#  include head
#
################################################################################################

add_library(
        TFCardManager
        SHARED
        src/main/jni/TFCardManager.cpp
)

add_library(protobuf            STATIC             IMPORTED)
# 设置第三方动态库属性（存储位置）
set_target_properties(
     protobuf
     PROPERTIES IMPORTED_LOCATION
     ${CMAKE_SOURCE_DIR}/../csm/src/main/jniLibs/${ANDROID_ABI}/libprotobuf_3.7_static.a
)

add_library(
     RemoteCallClient
     STATIC
     ../csm/src/main/jni/RemoteCall/Mutex.cpp
     ../csm/src/main/jni/scp02/Scp02Client.cpp
     ../csm/src/main/jni/Communication/LocalSocketClient.cpp
     ../csm/src/main/jni/Communication/BinderClient.cpp
     ../csm/src/main/jni/RemoteCall/ContentFrame.cpp
     ../csm/src/main/jni/RemoteCall/ContentFrame0001.cpp
     ../csm/src/main/jni/RemoteCall/ContentFrame0002.cpp
     ../csm/src/main/jni/RemoteCall/RemoteCall.cpp
     ../csm/src/main/jni/RemoteCall/Return.pb.cc
     ../csm/src/main/jni/RemoteCall/Pack.cpp
     ../csm/src/main/jni/RemoteCall/GetPackageName.cpp
     ../csm/src/main/jni/RemoteCall/MsgFrame.cpp
     ../csm/src/main/jni/scp02/tiny_des.c
     ../csm/src/main/jni/scp02/tiny_sha2.c
     ../csm/src/main/jni/sm/sm3/sm3interface/sm3_core.c
     ../csm/src/main/jni/sm/sm3/sm3interface/sm3.c
     ../csm/src/main/jni/sm/sm4/sm4interface/sm4_core.c
     ../csm/src/main/jni/sm/sm4/sm4interface/sm4.c
)

target_include_directories(
     RemoteCallClient
     PRIVATE
     ../csm/src/main/jni
     ../csm/src/main/jni/RemoteCall
     ../csm/src/main/jni/scp02
     ../csm/src/main/jni/Communication
     ../csm/src/main/jni/sm/include
)

add_library(
     Client
     SHARED
     ../csm/src/main/jni/P11/pkcs11.pb.cc
     ../csm/src/main/jni/P11/pkcs11f.cpp
     ../csm/src/main/jni/P11/log.cpp

    ../csm/src/main/jni/SKF/skf.pb.cc
    ../csm/src/main/jni/SKF/skfClient.cpp
)

target_include_directories(
     Client
     PRIVATE
     ../csm/src/main/jni
     ../csm/src/main/jni/plog/Appenders
     ../csm/src/main/jni/plog/Converters
     ../csm/src/main/jni/plog/Formatters
     ../csm/src/main/jni/plog/
     ../csm/src/main/jni/RemoteCall
     ../csm/src/main/jni/scp02
     ../csm/src/main/jni/Communication
     ../csm/src/main/jni/P11
     ../csm/src/main/jni/SKF
)

target_link_libraries(
     Client
     RemoteCallClient
     protobuf
     log
)

target_include_directories(
        TFCardManager
        PRIVATE
        ../csm/src/main/jni/P11
        ../csm/src/main/jni
        ../csm/src/main/jni/plog
        ../csm/src/main/jni/SKF
)

target_link_libraries(
        TFCardManager
        Client
        log
)


add_library(
        SoftSkf
        SHARED
        ../csm/src/main/jni/SKF/skf_soft.cpp
        ../csm/src/main/jni/SKF/skf_soft_util.cpp
        ../csm/src/main/jni/sm/sm4/sm4interface/sm4.c
        ../csm/src/main/jni/sm/sm4/sm4interface/sm4_core.c
        ../csm/src/main/jni/sm/sm3/sm3interface/sm3_core.c
        ../csm/src/main/jni/sm/sm3/sm3interface/sm3.c
        ../csm/src/main/jni/sm/sm2/sm2interface/ec_general.c
        ../csm/src/main/jni/sm/sm2/sm2interface/ec_lib.c
        ../csm/src/main/jni/sm/sm2/sm2interface/ec_mult.c
        ../csm/src/main/jni/sm/sm2/sm2interface/eccsm2_p256.c
        ../csm/src/main/jni/sm/sm2/sm2interface/ecdsa.c
        ../csm/src/main/jni/sm/sm2/sm2interface/eces.c
        ../csm/src/main/jni/sm/sm2/sm2interface/ecp_smpl.c
        ../csm/src/main/jni/sm/sm2/sm2interface/kdf.c
        ../csm/src/main/jni/sm/sm2/sm2interface/key_ex.c
        ../csm/src/main/jni/sm/sm2/sm2interface/mm_basic_fun.c
        ../csm/src/main/jni/sm/sm2/sm2interface/rc4.c
        ../csm/src/main/jni/sm/sm2/sm2interface/sm2.c
        ../csm/src/main/jni/sm/sm2/sm2interface/sm2_bn_add.c
        ../csm/src/main/jni/sm/sm2/sm2interface/sm2_bn_asm.c
        ../csm/src/main/jni/sm/sm2/sm2interface/sm2_bn_div.c
        ../csm/src/main/jni/sm/sm2/sm2interface/sm2_bn_gcd.c
        ../csm/src/main/jni/sm/sm2/sm2interface/sm2_bn_lib.c
        ../csm/src/main/jni/sm/sm2/sm2interface/sm2_bn_mod.c
        ../csm/src/main/jni/sm/sm2/sm2interface/sm2_bn_mont.c
        ../csm/src/main/jni/sm/sm2/sm2interface/sm2_bn_mul.c
        ../csm/src/main/jni/sm/sm2/sm2interface/sm2_bn_shift.c
)

target_include_directories(
        SoftSkf
        PRIVATE
        ../csm/src/main/jni/SKF
        ../csm/src/main/jni/scp02
        ../csm/src/main/jni/sm/include
)

target_link_libraries(
        SoftSkf
        log
)

add_library(
        SKF_JNI
        SHARED
        src/main/jni/skfjni.cpp

)

target_include_directories(
        SKF_JNI
        PRIVATE
        src/main/jni
        ../csm/src/main/jni/SKF
)

target_link_libraries(SKF_JNI Client log)



add_library(
        RpcJniClient
        SHARED
        ../csm/src/main/jni/rpcclient/interface.cpp
)

#[[target_include_directories(
        RpcJniClient
        PRIVATE
        src/main/jni
)]]


target_link_libraries(
        RpcJniClient
        log
)