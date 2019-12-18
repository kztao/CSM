//
// Created by wjr on 19-4-23.
//

#include <jni.h>
#include <dlfcn.h>
#include <android/log.h>

typedef void (*SKF_Native_Init)(JavaVM *javaVMIn, jint versionIn, jobject telephonyManager);
SKF_Native_Init skf_native_init = NULL;
JavaVM *javaVM = NULL;
jint version = 0;

extern "C" JNIEXPORT void JNICALL Java_com_westone_skfwrapper_Xindun_skfInit
(JNIEnv *env, jclass obj, jobject telephonyManager){

    version = env->GetVersion();
    env->GetJavaVM(&javaVM);

    void *h = dlopen("libSafetyCardLib.so",RTLD_LAZY);
    if(h){
        skf_native_init = (SKF_Native_Init)dlsym(h,"SKF_Native_Init");
        __android_log_print(ANDROID_LOG_INFO,"wjr_skf","skf_native_init = %p",skf_native_init);

        if(skf_native_init){
            skf_native_init(javaVM,version,telephonyManager);
            __android_log_print(ANDROID_LOG_INFO,"wjr_skf","skf_native_init end");
        }
    }
}