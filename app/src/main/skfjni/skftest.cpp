#include "devAndAppTest.h"
#include "pinVerificationTest.h"
#include <android/log.h>
#include "com_westone_testdemo_skfTestNative.h"
#include "certificateTest.h"
#include <string.h>
#include <string>

using namespace std;
#define OUT_INFO(...) __android_log_print(ANDROID_LOG_INFO, "skftestC", __VA_ARGS__);

/*
 * Class:     com_westone_testdemo_skfTestNative
 * Method:    DevandAppTest
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_westone_testdemo_skfTestNative_DevandAppTest
        (JNIEnv *env, jclass){
    string info;
    info.clear();

    info = skf_DevandAppTest();
    if(info !=""){
        jstring restring = env->NewStringUTF(info.c_str());
        return restring;
    }

    info = skf_pinVerifyTest();
    if(info !=""){
        jstring restring = env->NewStringUTF(info.c_str());
        return restring;
    }

    info = skf_certTest();
    if(info !=""){
        jstring restring = env->NewStringUTF(info.c_str());
        return restring;
    }

    OUT_INFO("00000");
    jstring restring = env->NewStringUTF(info.c_str());
    return restring;
}
