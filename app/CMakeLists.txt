# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.
#CMakeLists.txt
cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

################################################################################################
#
#  include head
#
################################################################################################
set(libClient ${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/libClient.so)

add_library(
    Test
    SHARED
    src/main/jni/P11TestFuncList.cpp
    src/main/jni/native.cpp
        src/main/jni/Encrypt.cpp
    src/main/jni/bn.c
    src/main/jni/ecc.c
    src/main/jni/ecp.c
    src/main/jni/sm2.c
    src/main/jni/sm3.c
    src/main/jni/sm4ofb.c
)

target_include_directories(
        Test
        PRIVATE
        /src/main/jni
)

target_link_libraries(Test ${libClient} log)


add_library(
        skfTest
        SHARED
        src/main/skfjni/skftest.cpp
        src/main/skfjni/devAndAppTest.cpp
        src/main/skfjni/pinVerificationTest.cpp
        src/main/skfjni/certificateTest.cpp
        src/main/skfjni/sm4.c
        src/main/jni/sm2.c
        src/main/jni/bn.c
        src/main/jni/ecc.c
        src/main/jni/ecp.c
        src/main/jni/sm3.c
)
target_include_directories(
        skfTest
        PRIVATE
        /src/main/skfjni
        /src/main/jni
)
target_link_libraries(skfTest ${libClient} log)


