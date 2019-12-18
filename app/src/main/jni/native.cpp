//
// Created by wang.junren on 2018/6/6.
//

#include <string>
#include <vector>
#include <cstring>
#include <android/log.h>
#include <stdlib.h>

#include "com_westone_csmmanager_P11TestNative.h"
#include "P11TestFuncList.h"

using namespace std;

static const char *tag = "csm_TestApp";


class ClientReturn{
public:
    string name;
    string info;
    unsigned long ret;
    unsigned long time;
};

static vector<ClientReturn> Vec;
static vector<ClientReturn>::iterator it;
static JavaVM *javaVM;
static jobject jobject1 = NULL;
static bool flg = false;
static jobject gloTFStatus = NULL;

void Save(string funcName,long ret,string otherInfo,long msec){
    ClientReturn clientReturn;
    clientReturn.info = otherInfo;
    clientReturn.name = funcName;
    clientReturn.time = msec;
    clientReturn.ret = ret;

    Vec.push_back(clientReturn);
}

void VecClear(){
    Vec.clear();
}

static P11TestFuncList p11TestFuncList;

static jobject GeneralFunc(JNIEnv *env,string info){

    jclass ReturnInfo = env->FindClass("com/westone/csmmanager/ReturnInfo");


    jfieldID desc = env->GetFieldID(ReturnInfo,"desc","Ljava/lang/String;");
   
    jfieldID funcArrays = env->GetFieldID(ReturnInfo,"funcArrays","[Lcom/westone/csmmanager/ReturnInfo$FuncArray;");
   

    jclass FuncArray = env->FindClass("com/westone/csmmanager/ReturnInfo$FuncArray");
   
    jfieldID name = env->GetFieldID(FuncArray,"name","Ljava/lang/String;");
   
    jfieldID returnCode = env->GetFieldID(FuncArray,"returnCode","J");
   
    jfieldID msec = env->GetFieldID(FuncArray,"msec","J");
   
    jfieldID otherInfo = env->GetFieldID(FuncArray,"otherInfo","Ljava/lang/String;");
   
    jobjectArray  FuncArrayData = env->NewObjectArray(Vec.size(),FuncArray,NULL);
    
    int i = 0;
    for(it = Vec.begin();it != Vec.end();it++){

        jstring func = env->NewStringUTF((const char*)it->name.data());
        jstring infoM = env->NewStringUTF((const char*)it->info.data());

        jobject Func = env->AllocObject(FuncArray);
        env->SetLongField(Func,returnCode,it->ret);
        env->SetObjectField(Func,name,func);
        env->DeleteLocalRef(func);

        env->SetObjectField(Func,otherInfo,infoM);
        env->DeleteLocalRef(infoM);

        env->SetLongField(Func,msec,it->time);
        env->SetObjectArrayElement(FuncArrayData,i,Func);
        i++;
    }

    
    jobject returnData = env->AllocObject(ReturnInfo);
    
    env->SetObjectField(returnData,desc,env->NewStringUTF(info.data()));
    
    env->SetObjectField(returnData,funcArrays,FuncArrayData);
    
    env->DeleteLocalRef(FuncArrayData);
    VecClear();
    return returnData;

}

#include <android/log.h>
#include <unistd.h>

CK_RV p11_test_register_status_callback_func(CK_SLOT_ID slotID,CK_STATUS_ENUM status)
{
    JNIEnv *env = NULL;
    string statusDes;
    jint ret = javaVM->GetEnv((void**)&env,JNI_VERSION_1_6);

    if(ret == JNI_EDETACHED){
        javaVM->AttachCurrentThread(&env,NULL);
    }
    __android_log_print(ANDROID_LOG_INFO,"csm_testApp","slot ID = %ld,status = %d",slotID,status);
    switch (status){
        case CK_STATUS_ENUM_LOGIN:
            statusDes = "CK_STATUS_ENUM_LOGIN";
            break;
        case CK_STATUS_ENUM_ERROR_CLIENT:
            statusDes = "CK_STATUS_ENUM_ERROR_CLIENT";
            break;
        case CK_STATUS_ENUM_DEVICE_OFF:
            statusDes = "CK_STATUS_ENUM_DEVICE_OFF";
            break;
        case CK_STATUS_ENUM_DEVICE_ERROR:
            statusDes = "CK_STATUS_ENUM_DEVICE_ERROR";
            break;
        case CK_STATUS_ENUM_DEVICE_ABNORMAL:
            statusDes = "CK_STATUS_ENUM_DEVICE_ABNORMAL";
            break;
        case CK_STATUS_ENUM_DEVICE_LOCKED:
            statusDes = "CK_STATUS_ENUM_DEVICE_LOCKED";
            break;
        case CK_STATUS_ENUM_UNLOGIN:
            statusDes = "CK_STATUS_ENUM_UNLOGIN";
            break;
        case CK_STATUS_ENUM_ERROR_SERVER:
            statusDes = "CK_STATUS_ENUM_ERROR_SERVER";
            break;
        case CK_STATUS_ENUM_DEVICE_DESTROY:
            statusDes = "CK_STATUS_ENUM_DEVICE_DESTROY";
            break;
        default:
            statusDes = "UNKNOW status";
            break;
    }


    jclass TFClass = env->GetObjectClass(gloTFStatus);
    jmethodID NoTi = env->GetMethodID(TFClass,"TFStatusNotify","(JLjava/lang/String;)V");

    jstring d = env->NewStringUTF(statusDes.data());
    __android_log_print(ANDROID_LOG_INFO,"csm_testApp","Notify 1 gloTFStatus = %p,NoTi = %p",gloTFStatus,NoTi);
    env->CallVoidMethod(gloTFStatus,NoTi,(jlong)slotID,d);
    env->DeleteLocalRef(d);

    __android_log_print(ANDROID_LOG_INFO,"csm_testApp","Notify 2");



    if(ret == JNI_EDETACHED){
        __android_log_print(ANDROID_LOG_INFO,"csm_testApp","DetachCurrentThread");
        javaVM->DetachCurrentThread();
    }

    __android_log_print(ANDROID_LOG_INFO,"csm_testApp","Before return");
    return 0;
}

/*
 * Class:     com_westone_csmmanager_P11TestNative
 * Method:    BaseFunctionTest
 * Signature: (Ljava/lang/String;Ljava/lang/String;Lcom/westone/csmmanager/TFStatus;)Lcom/westone/csmmanager/ReturnInfo;
 */
JNIEXPORT jobject JNICALL Java_com_westone_csmmanager_P11TestNative_BaseFunctionTest
        (JNIEnv *env, jclass P11TestNative, jstring userPin, jstring soPin, jobject tfStatus){

    string user;
    string so;


    if(flg == false){
        env->GetJavaVM(&javaVM);
        flg = true;
    }

    gloTFStatus = env->NewGlobalRef(tfStatus);

    const char *pUser = env->GetStringUTFChars(userPin,0);
    const char *pSo = env->GetStringUTFChars(soPin,0);

    user = pUser;
    so = pSo;



    __android_log_print(ANDROID_LOG_INFO,"csm_testApp","BaseFunc In");
    p11TestFuncList.BaseFunc(user,so,p11_test_register_status_callback_func);
    __android_log_print(ANDROID_LOG_INFO,"csm_testApp","BaseFunc Out");
    return GeneralFunc(env,"BaseFunctionTest");
}

/*
 * Class:     com_westone_csmmanager_P11TestNative
 * Method:    ObjFunctionTest
 * Signature: ()Lcom/westone/csmmanager/ReturnInfo;
 */
JNIEXPORT jobject JNICALL Java_com_westone_csmmanager_P11TestNative_ObjFunctionTest
        (JNIEnv *env, jclass P11TestNative){
    p11TestFuncList.ObjFunc();
    return GeneralFunc(env,"ObjFunctionTest");
}

/*
 * Class:     com_westone_csmmanager_P11TestNative
 * Method:    KeyFunctionTest
 * Signature: ()Lcom/westone/csmmanager/ReturnInfo;
 */
JNIEXPORT jobject JNICALL Java_com_westone_csmmanager_P11TestNative_KeyFunctionTest
        (JNIEnv *env , jclass P11TestNative){

    p11TestFuncList.KeyFunc();

    return GeneralFunc(env,"KeyFunctionTest");
}

/*
 * Class:     com_westone_csm_P11TestNative
 * Method:    EncFunctionTest
 * Signature: ()Lcom/westone/csmmanager/ReturnInfo;
 */
JNIEXPORT jobject JNICALL Java_com_westone_csmmanager_P11TestNative_EncFunctionTest
        (JNIEnv *env, jclass P11TestNative){

    p11TestFuncList.EncFunc();
    return GeneralFunc(env,"EncFunctionTest");
}

/*
 * Class:     com_westone_csm_P11TestNative
 * Method:    DigFunctionTest
 * Signature: ()Lcom/westone/csmmanager/ReturnInfo;
 */
JNIEXPORT jobject JNICALL Java_com_westone_csmmanager_P11TestNative_DigFunctionTest
        (JNIEnv *env, jclass P11TestNative){
    p11TestFuncList.DigFunc();
    return GeneralFunc(env,"DigFunctionTest");
}

/*
 * Class:     com_westone_csm_P11TestNative
 * Method:    SignFunctionTest
 * Signature: ()Lcom/westone/csmmanager/ReturnInfo;
 */
JNIEXPORT jobject JNICALL Java_com_westone_csmmanager_P11TestNative_SignFunctionTest
        (JNIEnv *env, jclass P11TestNative){
    p11TestFuncList.SignFunc();
    return GeneralFunc(env,"SignFunctionTest");
}

/*
 * Class:     com_westone_csm_P11TestNative
 * Method:    RndFunctionTest
 * Signature: ()Lcom/westone/csmmanager/ReturnInfo;
 */
JNIEXPORT jobject JNICALL Java_com_westone_csmmanager_P11TestNative_RndFunctionTest
        (JNIEnv *env, jclass P11TestNative){
    p11TestFuncList.RndFunc();
    return GeneralFunc(env,"RndFunctionTest");
}

/*
 * Class:     com_westone_csm_P11TestNative
 * Method:    ExtFunctionTest
 * Signature: ()Lcom/westone/csmmanager/ReturnInfo;
 */
JNIEXPORT jobject JNICALL Java_com_westone_csmmanager_P11TestNative_ExtFunctionTest
        (JNIEnv *env, jclass P11TestNative){
    p11TestFuncList.ExtFunc();
    return GeneralFunc(env,"ExtFunctionTest");
}

JNIEXPORT jobject JNICALL Java_com_westone_csmmanager_P11TestNative_SCSetUp
        (JNIEnv *env, jclass P11TestNative)
{
    p11TestFuncList.SCsetup();
    return GeneralFunc(env,"SCSetUp");
}

JNIEXPORT jobject JNICALL Java_com_westone_csmmanager_P11TestNative_CallTest
        (JNIEnv *env, jclass P11TestNative)
{
    p11TestFuncList.calltest();
    return GeneralFunc(env,"CallTest");
}

JNIEXPORT void JNICALL Java_com_westone_csmmanager_P11TestNative_testThreadRun
        (JNIEnv *env, jclass P11TestNative, jstring userPin)
{
    string user;

    if(flg == false){
        env->GetJavaVM(&javaVM);
        flg = true;
    }

    const char *pUser = env->GetStringUTFChars(userPin,0);

    user = pUser;

    __android_log_print(ANDROID_LOG_INFO,"csm_testApp","testThreadRun In");
    sleep(1);
    p11TestFuncList.testthreadFunc(user);
    __android_log_print(ANDROID_LOG_INFO,"csm_testApp","testThreadRun Out");


}


jobject perTest(JNIEnv *env,jint cn, jint len,string r,long **timeTest, long *t1){
    if(flg == false){
        env->GetJavaVM(&javaVM);
        flg = true;
    }

    jint ret = javaVM->GetEnv((void**)&env,JNI_VERSION_1_6);

    if(JNI_EDETACHED == ret){
        javaVM->AttachCurrentThread(&env,NULL);
    }
    jclass PerReturnInfo = env->FindClass("com/westone/csmmanager/PerReturnInfo");
    jmethodID per = env->GetMethodID(PerReturnInfo,"<init>","(I)V");
    jfieldID info = env->GetFieldID(PerReturnInfo,"info","Ljava/lang/String;");
    jfieldID count = env->GetFieldID(PerReturnInfo,"count","I");
    jfieldID length = env->GetFieldID(PerReturnInfo,"length","I");
    jfieldID times = env->GetFieldID(PerReturnInfo,"times","[J");

    jobject perReturnInfo = env->NewObject(PerReturnInfo,per,cn);

    env->SetIntField(perReturnInfo,count,cn);
    env->SetIntField(perReturnInfo,length,len);
    jstring ifo = env->NewStringUTF(r.data());
    env->SetObjectField(perReturnInfo,info,ifo);
    env->DeleteLocalRef(ifo);

    jlongArray tt = (jlongArray)env->GetObjectField(perReturnInfo,times);
    jsize arrLen = env->GetArrayLength(tt);
    jlong * re = env->GetLongArrayElements(tt,0);
    *timeTest = t1;

    for(int i =0;i < cn;i++){
 //       LOGI("csm_testapp","%d.value %d",i,*((*timeTest) + i));
        re[i] = *((*timeTest) + i);
    }

    env->ReleaseLongArrayElements(tt,re,0);

    delete[] *timeTest;
    if(JNI_EDETACHED == ret){
        javaVM->DetachCurrentThread();
    }
    return perReturnInfo;
}


jobject perTest(JNIEnv *env,jint cn, jint len,string r,long *timeTest){
    if(flg == false){
        env->GetJavaVM(&javaVM);
        flg = true;
    }

    jint ret = javaVM->GetEnv((void**)&env,JNI_VERSION_1_6);

    if(JNI_EDETACHED == ret){
        javaVM->AttachCurrentThread(&env,NULL);
    }
    jclass PerReturnInfo = env->FindClass("com/westone/csmmanager/PerReturnInfo");
    jmethodID per = env->GetMethodID(PerReturnInfo,"<init>","(I)V");
    jfieldID info = env->GetFieldID(PerReturnInfo,"info","Ljava/lang/String;");
    jfieldID count = env->GetFieldID(PerReturnInfo,"count","I");
    jfieldID length = env->GetFieldID(PerReturnInfo,"length","I");
    jfieldID times = env->GetFieldID(PerReturnInfo,"times","[J");

    jobject perReturnInfo = env->NewObject(PerReturnInfo,per,cn);

    env->SetIntField(perReturnInfo,count,cn);
    env->SetIntField(perReturnInfo,length,len);
    jstring ifo = env->NewStringUTF(r.data());
    env->SetObjectField(perReturnInfo,info,ifo);
    env->DeleteLocalRef(ifo);

    jlongArray tt = (jlongArray)env->GetObjectField(perReturnInfo,times);
    jsize arrLen = env->GetArrayLength(tt);
    jlong * re = env->GetLongArrayElements(tt,0);
    for(int i = 0; i < arrLen;i++){
        re[i] = (jlong)timeTest[i];
    }

    env->ReleaseLongArrayElements(tt,re,0);
    delete[] timeTest;

    if(JNI_EDETACHED == ret){
        javaVM->DetachCurrentThread();
    }
    return perReturnInfo;
}

/*
 * Class:     com_westone_csmmanager_P11TestNative
 * Method:    SM2Test
 * Signature: (II)Lcom/westone/csmmanager/PerReturnInfo;
 */
JNIEXPORT jobject JNICALL Java_com_westone_csmmanager_P11TestNative_SM2Test
        (JNIEnv *env, jclass P11TestNative, jint cn, jint len){
    string dst;
    string &r = dst;
    long ** timeTest = p11TestFuncList.SM2_PerTest(cn,len,r);
    return perTest(env,cn,len,r,timeTest,NULL);
}

/*
 * Class:     com_westone_csmmanager_P11TestNative
 * Method:    SM4Test
 * Signature: (II)Lcom/westone/csmmanager/PerReturnInfo;
 */
JNIEXPORT jobject JNICALL Java_com_westone_csmmanager_P11TestNative_SM4Test
        (JNIEnv *env, jclass P11TestNative, jint cn, jint len){
    string dst;
    string &r = dst;
    jfieldID longTh = env->GetStaticFieldID(P11TestNative,"sm4_modle","J");
    jlong which = env->GetStaticLongField(P11TestNative,longTh);

    long ** timeTest = p11TestFuncList.SM4_PerTest(which,cn,len,r);

    return perTest(env,cn,len,r,timeTest,NULL);
}

/*
 * Class:     com_westone_csmmanager_P11TestNative
 * Method:    ZucTest
 * Signature: (II)Lcom/westone/csmmanager/PerReturnInfo;
 */
JNIEXPORT jobject JNICALL Java_com_westone_csmmanager_P11TestNative_ZucTest
        (JNIEnv *env, jclass P11TestNative, jint cn, jint len){
    string dst;
    string &r = dst;
    //long ** timeTest = p11TestFuncList.Zuc_PerTest(cn,len,r);
    long *timeTest = new long[cn];
    p11TestFuncList.Zuc_PerTest(cn,len,r,timeTest);

    return perTest(env,cn,len,r,timeTest);
}
