//
// Created by Administrator on 2018/12/3.
//

#include "com_westone_skf_SkfNativeFunc.h"
#include <dlfcn.h>
#ifdef __cplusplus
extern "C"{
#endif

#include "skf.h"

#ifdef __cplusplus
};
#endif

#include <string.h>
#include <iostream>
#include <android/log.h>
using std::string;

#define LOG(...) __android_log_print(ANDROID_LOG_INFO,"csm_skfjni",__VA_ARGS__)

void LOD(unsigned char *pData,int len) {
    __android_log_print(ANDROID_LOG_INFO,"csm_skfjni","byte array len = %d",len);
    string s;
    char num[3] = {0,0,0};
    for(int i = 0; i < len;i++){
        sprintf(num,"%02x",(unsigned char)pData[i]);
        s.append(num,2);
        if((i + 1) % 4 == 0 ){
            s.append(" ");
        }

        if((i + 1) % 16 == 0){
            s.append("\n");
        }
    }
    __android_log_print(ANDROID_LOG_INFO,"csm_skfjni","%s",s.data());
}


/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    regCallback
 * Signature: (Lcom/westone/skf/SkfCallback;)V
 */

static jobject globeCallback = NULL;
static JavaVM *pVm = NULL;
static jint jniVersion = 0;

string NotifySkf(){
    JNIEnv *env = NULL;

    jint ret = pVm->GetEnv((void**)&env,jniVersion);

    if(ret == JNI_EDETACHED){
        pVm->AttachCurrentThread(&env,NULL);
    }

    jclass classSkfCallback = env->GetObjectClass(globeCallback);
    jmethodID NotifyInputPin = env->GetMethodID(classSkfCallback,"NotifyInputPin","()[B");

    jbyteArray pin = (jbyteArray)env->CallObjectMethod(globeCallback,NotifyInputPin);
    jbyte *pPin = env->GetByteArrayElements(pin,NULL);
    jsize len = env->GetArrayLength(pin);
    string s;
    s.append((const char*)pPin,len);
    env->ReleaseByteArrayElements(pin,pPin,0);
    if(ret == JNI_EDETACHED){
        pVm->DetachCurrentThread();
    }

    return s;

}

SKFFunctionList skfFunctionList;
JNIEXPORT void JNICALL Java_com_westone_skf_SkfNativeFunc_setLibPath(JNIEnv *env, jclass clazz, jobject ct,jstring libPath){

    string strLibName;

    if(libPath == NULL || env->GetStringLength(libPath) == 0){
        strLibName = "libClient.so";
    } else{
        const char *libName = env->GetStringUTFChars(libPath,NULL);
        strLibName = libName;
        env->ReleaseStringUTFChars(libPath,libName);
    }

    typedef void (*SKF_Native_Init)(JavaVM *javaVMIn, jint versionIn, jobject telephonyManager);
    SKF_Native_Init skf_native_init = NULL;
    JavaVM *javaVM = NULL;
    jint version = 0;
    version = env->GetVersion();
    env->GetJavaVM(&javaVM);

    jobject obj = NULL;

    if(NULL != ct){
        jstring strPhone = env->NewStringUTF("phone");
        jclass classContext = env->GetObjectClass(ct);
        jmethodID methodIdGetSystemService = env->GetMethodID(classContext,"getSystemService","(Ljava/lang/String;)Ljava/lang/Object;");
        obj = env->CallObjectMethod(ct,methodIdGetSystemService,strPhone);
        env->DeleteLocalRef(strPhone);
        env->DeleteLocalRef(classContext);
    }

    __android_log_print(ANDROID_LOG_INFO,"skf","%s IN libname is %s",__FUNCTION__,strLibName.c_str());
    void *handle = dlopen(strLibName.c_str(),RTLD_LAZY);
    if(handle != NULL){
        skf_native_init = (SKF_Native_Init)dlsym(handle,"SKF_Native_Init");
        if(skf_native_init && obj){
            skf_native_init(javaVM,version,obj);
        }

        skfFunctionList.SKF_WaitForDevEvent = (SKF_POINTER(SKF_WaitForDevEvent))dlsym(handle,"SKF_WaitForDevEvent");
        skfFunctionList.SKF_CancelWaitForDevEvent = (SKF_POINTER(SKF_CancelWaitForDevEvent))dlsym(handle,"SKF_CancelWaitForDevEvent");
        skfFunctionList.SKF_EnumDev = (SKF_POINTER(SKF_EnumDev))dlsym(handle,"SKF_EnumDev");
        skfFunctionList.SKF_ConnectDev = (SKF_POINTER(SKF_ConnectDev))dlsym(handle,"SKF_ConnectDev");
        skfFunctionList.SKF_DisConnectDev = (SKF_POINTER(SKF_DisConnectDev))dlsym(handle,"SKF_DisConnectDev");
        skfFunctionList.SKF_GetDevState = (SKF_POINTER(SKF_GetDevState))dlsym(handle,"SKF_GetDevState");
        skfFunctionList.SKF_SetLabel = (SKF_POINTER(SKF_SetLabel))dlsym(handle,"SKF_SetLabel");
        skfFunctionList.SKF_GetDevInfo = (SKF_POINTER(SKF_GetDevInfo))dlsym(handle,"SKF_GetDevInfo");
        skfFunctionList.SKF_LockDev = (SKF_POINTER(SKF_LockDev))dlsym(handle,"SKF_LockDev");
        skfFunctionList.SKF_UnlockDev = (SKF_POINTER(SKF_UnlockDev))dlsym(handle,"SKF_UnlockDev");
        skfFunctionList.SKF_ChangeDevAuthKey = (SKF_POINTER(SKF_ChangeDevAuthKey))dlsym(handle,"SKF_ChangeDevAuthKey");
        skfFunctionList.SKF_DevAuth = (SKF_POINTER(SKF_DevAuth))dlsym(handle,"SKF_DevAuth");
        skfFunctionList.SKF_ChangePIN = (SKF_POINTER(SKF_ChangePIN))dlsym(handle,"SKF_ChangePIN");
        skfFunctionList.SKF_GetPINInfo = (SKF_POINTER(SKF_GetPINInfo))dlsym(handle,"SKF_GetPINInfo");
        skfFunctionList.SKF_VerifyPIN = (SKF_POINTER(SKF_VerifyPIN))dlsym(handle,"SKF_VerifyPIN");
        skfFunctionList.SKF_UnblockPIN = (SKF_POINTER(SKF_UnblockPIN))dlsym(handle,"SKF_UnblockPIN");
        skfFunctionList.SKF_ClearSecureState = (SKF_POINTER(SKF_ClearSecureState))dlsym(handle,"SKF_ClearSecureState");
        skfFunctionList.SKF_CreateApplication = (SKF_POINTER(SKF_CreateApplication))dlsym(handle,"SKF_CreateApplication");
        skfFunctionList.SKF_EnumApplication = (SKF_POINTER(SKF_EnumApplication))dlsym(handle,"SKF_EnumApplication");
        skfFunctionList.SKF_DeleteApplication = (SKF_POINTER(SKF_DeleteApplication))dlsym(handle,"SKF_DeleteApplication");
        skfFunctionList.SKF_OpenApplication = (SKF_POINTER(SKF_OpenApplication))dlsym(handle,"SKF_OpenApplication");
        skfFunctionList.SKF_CloseApplication = (SKF_POINTER(SKF_CloseApplication))dlsym(handle,"SKF_CloseApplication");
        skfFunctionList.SKF_CreateFile = (SKF_POINTER(SKF_CreateFile))dlsym(handle,"SKF_CreateFile");
        skfFunctionList.SKF_DeleteFile = (SKF_POINTER(SKF_DeleteFile))dlsym(handle,"SKF_DeleteFile");
        skfFunctionList.SKF_EnumFiles = (SKF_POINTER(SKF_EnumFiles))dlsym(handle,"SKF_EnumFiles");
        skfFunctionList.SKF_GetFileInfo = (SKF_POINTER(SKF_GetFileInfo))dlsym(handle,"SKF_GetFileInfo");
        skfFunctionList.SKF_ReadFile = (SKF_POINTER(SKF_ReadFile))dlsym(handle,"SKF_ReadFile");
        skfFunctionList.SKF_WriteFile = (SKF_POINTER(SKF_WriteFile))dlsym(handle,"SKF_WriteFile");
        skfFunctionList.SKF_CreateContainer = (SKF_POINTER(SKF_CreateContainer))dlsym(handle,"SKF_CreateContainer");
        skfFunctionList.SKF_DeleteContainer = (SKF_POINTER(SKF_DeleteContainer))dlsym(handle,"SKF_DeleteContainer");
        skfFunctionList.SKF_OpenContainer = (SKF_POINTER(SKF_OpenContainer))dlsym(handle,"SKF_OpenContainer");
        skfFunctionList.SKF_CloseContainer = (SKF_POINTER(SKF_CloseContainer))dlsym(handle,"SKF_CloseContainer");
        skfFunctionList.SKF_EnumContainer = (SKF_POINTER(SKF_EnumContainer))dlsym(handle,"SKF_EnumContainer");
        skfFunctionList.SKF_GetContainerType = (SKF_POINTER(SKF_GetContainerType))dlsym(handle,"SKF_GetContainerType");
        skfFunctionList.SKF_GenRandom = (SKF_POINTER(SKF_GenRandom))dlsym(handle,"SKF_GenRandom");
        skfFunctionList.SKF_GenExtRSAKey = (SKF_POINTER(SKF_GenExtRSAKey))dlsym(handle,"SKF_GenExtRSAKey");
        skfFunctionList.SKF_GenRSAKeyPair = (SKF_POINTER(SKF_GenRSAKeyPair))dlsym(handle,"SKF_GenRSAKeyPair");
        skfFunctionList.SKF_ImportRSAKeyPair = (SKF_POINTER(SKF_ImportRSAKeyPair))dlsym(handle,"SKF_ImportRSAKeyPair");
        skfFunctionList.SKF_RSASignData = (SKF_POINTER(SKF_RSASignData))dlsym(handle,"SKF_RSASignData");
        skfFunctionList.SKF_RSAVerify = (SKF_POINTER(SKF_RSAVerify))dlsym(handle,"SKF_RSAVerify");
        skfFunctionList.SKF_RSAExportSessionKey = (SKF_POINTER(SKF_RSAExportSessionKey))dlsym(handle,"SKF_RSAExportSessionKey");
        skfFunctionList.SKF_ExtRSAPubKeyOperation = (SKF_POINTER(SKF_ExtRSAPubKeyOperation))dlsym(handle,"SKF_ExtRSAPubKeyOperation");
        skfFunctionList.SKF_ExtRSAPriKeyOperation = (SKF_POINTER(SKF_ExtRSAPriKeyOperation))dlsym(handle,"SKF_ExtRSAPriKeyOperation");
        skfFunctionList.SKF_GenECCKeyPair = (SKF_POINTER(SKF_GenECCKeyPair))dlsym(handle,"SKF_GenECCKeyPair");
        skfFunctionList.SKF_ImportECCKeyPair = (SKF_POINTER(SKF_ImportECCKeyPair))dlsym(handle,"SKF_ImportECCKeyPair");
        skfFunctionList.SKF_ECCSignData = (SKF_POINTER(SKF_ECCSignData))dlsym(handle,"SKF_ECCSignData");
        skfFunctionList.SKF_ECCVerify = (SKF_POINTER(SKF_ECCVerify))dlsym(handle,"SKF_ECCVerify");
        skfFunctionList.SKF_ECCExportSessionKey = (SKF_POINTER(SKF_ECCExportSessionKey))dlsym(handle,"SKF_ECCExportSessionKey");
        skfFunctionList.SKF_ExtECCEncrypt = (SKF_POINTER(SKF_ExtECCEncrypt))dlsym(handle,"SKF_ExtECCEncrypt");
        skfFunctionList.SKF_ExtECCDecrypt = (SKF_POINTER(SKF_ExtECCDecrypt))dlsym(handle,"SKF_ExtECCDecrypt");
        skfFunctionList.SKF_ExtECCSign = (SKF_POINTER(SKF_ExtECCSign))dlsym(handle,"SKF_ExtECCSign");
        skfFunctionList.SKF_ExtECCVerify = (SKF_POINTER(SKF_ExtECCVerify))dlsym(handle,"SKF_ExtECCVerify");
        skfFunctionList.SKF_GenerateAgreementDataWithECC = (SKF_POINTER(SKF_GenerateAgreementDataWithECC))dlsym(handle,"SKF_GenerateAgreementDataWithECC");
        skfFunctionList.SKF_GenerateAgreementDataAndKeyWithECC = (SKF_POINTER(SKF_GenerateAgreementDataAndKeyWithECC))dlsym(handle,"SKF_GenerateAgreementDataAndKeyWithECC");
        skfFunctionList.SKF_GenerateKeyWithECC = (SKF_POINTER(SKF_GenerateKeyWithECC))dlsym(handle,"SKF_GenerateKeyWithECC");
        skfFunctionList.SKF_ExportPublicKey = (SKF_POINTER(SKF_ExportPublicKey))dlsym(handle,"SKF_ExportPublicKey");
        skfFunctionList.SKF_ImportSessionKey = (SKF_POINTER(SKF_ImportSessionKey))dlsym(handle,"SKF_ImportSessionKey");
        skfFunctionList.SKF_SetSymmKey = (SKF_POINTER(SKF_SetSymmKey))dlsym(handle,"SKF_SetSymmKey");
        skfFunctionList.SKF_EncryptInit = (SKF_POINTER(SKF_EncryptInit))dlsym(handle,"SKF_EncryptInit");
        skfFunctionList.SKF_Encrypt = (SKF_POINTER(SKF_Encrypt))dlsym(handle,"SKF_Encrypt");
        skfFunctionList.SKF_EncryptUpdate = (SKF_POINTER(SKF_EncryptUpdate))dlsym(handle,"SKF_EncryptUpdate");
        skfFunctionList.SKF_EncryptFinal = (SKF_POINTER(SKF_EncryptFinal))dlsym(handle,"SKF_EncryptFinal");
        skfFunctionList.SKF_DecryptInit = (SKF_POINTER(SKF_DecryptInit))dlsym(handle,"SKF_DecryptInit");
        skfFunctionList.SKF_Decrypt = (SKF_POINTER(SKF_Decrypt))dlsym(handle,"SKF_Decrypt");
        skfFunctionList.SKF_DecryptUpdate = (SKF_POINTER(SKF_DecryptUpdate))dlsym(handle,"SKF_DecryptUpdate");
        skfFunctionList.SKF_DecryptFinal = (SKF_POINTER(SKF_DecryptFinal))dlsym(handle,"SKF_DecryptFinal");
        skfFunctionList.SKF_DigestInit = (SKF_POINTER(SKF_DigestInit))dlsym(handle,"SKF_DigestInit");
        skfFunctionList.SKF_Digest = (SKF_POINTER(SKF_Digest))dlsym(handle,"SKF_Digest");
        skfFunctionList.SKF_DigestUpdate = (SKF_POINTER(SKF_DigestUpdate))dlsym(handle,"SKF_DigestUpdate");
        skfFunctionList.SKF_DigestFinal = (SKF_POINTER(SKF_DigestFinal))dlsym(handle,"SKF_DigestFinal");
        skfFunctionList.SKF_MacInit = (SKF_POINTER(SKF_MacInit))dlsym(handle,"SKF_MacInit");
        skfFunctionList.SKF_Mac = (SKF_POINTER(SKF_Mac))dlsym(handle,"SKF_Mac");
        skfFunctionList.SKF_MacUpdate = (SKF_POINTER(SKF_MacUpdate))dlsym(handle,"SKF_MacUpdate");
        skfFunctionList.SKF_MacFinal = (SKF_POINTER(SKF_MacFinal))dlsym(handle,"SKF_MacFinal");
        skfFunctionList.SKF_CloseHandle = (SKF_POINTER(SKF_CloseHandle))dlsym(handle,"SKF_CloseHandle");
        skfFunctionList.SKF_Transmit = (SKF_POINTER(SKF_Transmit))dlsym(handle,"SKF_Transmit");
        skfFunctionList.SKF_ImportCertificate = (SKF_POINTER(SKF_ImportCertificate))dlsym(handle,"SKF_ImportCertificate");
        skfFunctionList.SKF_ExportCertificate = (SKF_POINTER(SKF_ExportCertificate))dlsym(handle,"SKF_ExportCertificate");
        skfFunctionList.SKF_GetContainerProperty = (SKF_POINTER(SKF_GetContainerProperty))dlsym(handle,"SKF_GetContainerProperty");
    }
}

JNIEXPORT void JNICALL Java_com_westone_skf_SkfNativeFunc_regCallback
        (JNIEnv *env, jclass SkfNativeFunc, jobject callback){
    env->GetJavaVM(&pVm);
    jniVersion = env->GetVersion();
    jobject globeCallback = env->NewGlobalRef(callback);
}
/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_EnumDev
 * Signature: (Ljava/util/List;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1EnumDev
        (JNIEnv *env, jclass SkfNativeFunc, jobject list){

    if(NULL == list){
        return SAR_INVALIDPARAMERR;
    }

    LPSTR szNameList = NULL;
    ULONG pulSize = 0;

    LOG("SKF_EnumDev:--------------------");
    ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_EnumDev(TRUE,szNameList,&pulSize);

    if(ret != SAR_OK){
        return ret;
    }
    LOG("SKF_EnumDev:");
    LOG("szNameList pulSize:%lu ", pulSize);

    if(pulSize == 0){
        return ret;
    }

    szNameList = new CHAR[pulSize];
    memset(szNameList, '\0', pulSize);

    ret = skfFunctionList.SKF_EnumDev(TRUE,szNameList,&pulSize);

    if(ret != SAR_OK){
        delete [] szNameList;
        szNameList = NULL;
        return ret;
    }
    LOG("szNameList pulSize:%d ", pulSize);
    LOD((unsigned char *)szNameList, (int)pulSize);

    jclass classList = env->GetObjectClass(list);
    jmethodID methodIdAdd = env->GetMethodID(classList,"add","(Ljava/lang/Object;)Z");

    LPSTR tmp = NULL;

    for(tmp = szNameList;;){
        if(strlen(tmp) == 0){
            break;
        }

        jstring szNameIndex = env->NewStringUTF(tmp);
        env->CallBooleanMethod(list,methodIdAdd,szNameIndex);
        env->DeleteLocalRef(szNameIndex);
        tmp += strlen(tmp) + 1;

    }

    delete [] szNameList;
    szNameList = NULL;

    return  SAR_OK;

}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ConnectDev
 * Signature: (Ljava/lang/String;Lcom/westone/skf/DEVHANDLE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ConnectDev
        (JNIEnv *env, jclass SkfNativeFunc, jstring name, jobject devHandle){

    if(NULL == name || NULL == devHandle){
        return SAR_INVALIDPARAMERR;
    }

    const char *devName = env->GetStringUTFChars(name,NULL);
    DEVHANDLE devH = NULL;
    
    ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ConnectDev((LPSTR)devName,&devH);


    LOG("SKF_ConnectDev ret = 0x%08x,devH = %p",ret,devH);

    env->ReleaseStringUTFChars(name,devName);
    if(ret != SAR_OK){
        return ret;
    }

    jclass dev = env->GetObjectClass(devHandle);
    jmethodID methodID = env->GetMethodID(dev,"setPointer","(J)V");
    env->CallVoidMethod(devHandle,methodID,(jlong)devH);
    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_DisConnectDev
 * Signature: (Lcom/westone/skf/DEVHANDLE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1DisConnectDev
        (JNIEnv *env, jclass SkfNativeFunc, jobject devHandle){
    if(NULL == devHandle){
        return SAR_INVALIDPARAMERR;
    }

    jclass dev = env->GetObjectClass(devHandle);
    jmethodID methodID = env->GetMethodID(dev,"getPointer","()J");
    jlong point = env->CallLongMethod(devHandle,methodID);
    ULONG ret = SAR_OK;
    ret = skfFunctionList.SKF_DisConnectDev((DEVHANDLE)point);
    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_GetDevState
 * Signature: (Ljava/lang/String;Lcom/westone/skf/DevState;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1GetDevState
        (JNIEnv *env, jclass SkfNativeFunc, jstring devName, jobject devState){
    if(NULL == devName || NULL == devState){
        return  SAR_INVALIDPARAMERR;
    }

    ULONG tDevState = 0;
    const char* pName = env->GetStringUTFChars(devName,NULL);
    ULONG ret = SAR_OK;
    ret = skfFunctionList.SKF_GetDevState((LPSTR)pName,&tDevState);
    env->ReleaseStringUTFChars(devName,pName);

    if(ret != SAR_OK){
        return ret;
    }

    jclass classDevState = env->GetObjectClass(devState);
    jmethodID methodID = env->GetMethodID(classDevState,"setDevState","(J)V");
    env->CallVoidMethod(devState,methodID,(jlong)tDevState);

    return SAR_OK;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_SetLabel
 * Signature: (Lcom/westone/skf/DEVHANDLE;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1SetLabel
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jstring label){
    if(NULL == hDev || NULL == label){
        return  SAR_INVALIDPARAMERR;
    }

    jclass classDev = env->GetObjectClass(hDev);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,method);

    const char *pLabel = env->GetStringUTFChars(label,NULL);
    ULONG ret = SAR_OK;


    ret = skfFunctionList.SKF_SetLabel((DEVHANDLE)pointer,(LPSTR)pLabel);

    env->ReleaseStringUTFChars(label,pLabel);

    return  ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_GetDevInfo
 * Signature: (Lcom/westone/skf/DEVHANDLE;Lcom/westone/skf/DEVINFO;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1GetDevInfo
        (JNIEnv *env, jclass SkfNativeFunc, jobject devHandle, jobject devInfo){
    if(NULL == devHandle || NULL == devInfo){
        return SAR_INVALIDPARAMERR;
    }

    DEVINFO info;
    memset(&info,0,sizeof(info));

    jclass classDev = env->GetObjectClass(devHandle);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(devHandle,method);
    ULONG ret = SAR_OK;


    ret = skfFunctionList.SKF_GetDevInfo((DEVHANDLE)pointer,&info);

    if(ret != SAR_OK){
        return ret;
    }

    jclass classVersion = env->FindClass("com/westone/skf/VERSION");
    jmethodID Version = env->GetMethodID(classVersion,"<init>","()V");
    jmethodID setMajor = env->GetMethodID(classVersion,"setMajor","(B)V");
    jmethodID setMinor = env->GetMethodID(classVersion,"setMinor","(B)V");

    jclass classDevInfo = env->GetObjectClass(devInfo);
    jmethodID setVersion = env->GetMethodID(classDevInfo,"setVersion","(Lcom/westone/skf/VERSION;)V");
    jmethodID setAlgSymCap = env->GetMethodID(classDevInfo,"setAlgSymCap","(J)V");
    jmethodID setDevAuthAlgId = env->GetMethodID(classDevInfo,"setDevAuthAlgId","(J)V");
    jmethodID setFirmwareVersion = env->GetMethodID(classDevInfo,"setFirmwareVersion","(Lcom/westone/skf/VERSION;)V");
    jmethodID setFreeSpace = env->GetMethodID(classDevInfo,"setFreeSpace","(J)V");
    jmethodID setHWVersion = env->GetMethodID(classDevInfo,"setHWVersion","(Lcom/westone/skf/VERSION;)V");
    jmethodID setIssuer = env->GetMethodID(classDevInfo,"setIssuer","(Ljava/lang/String;)V");
    jmethodID setLabel = env->GetMethodID(classDevInfo,"setLabel","(Ljava/lang/String;)V");
    jmethodID setManufacturer = env->GetMethodID(classDevInfo,"setManufacturer","(Ljava/lang/String;)V");
    jmethodID setMaxBufferSize = env->GetMethodID(classDevInfo,"setMaxBufferSize","(J)V");
    jmethodID setMaxECCBufferSize = env->GetMethodID(classDevInfo,"setMaxECCBufferSize","(J)V");
    jmethodID setReserved = env->GetMethodID(classDevInfo,"setReserved","([B)V");
    jmethodID setSerialNumber = env->GetMethodID(classDevInfo,"setSerialNumber","(Ljava/lang/String;)V");
    jmethodID setTotalSpace = env->GetMethodID(classDevInfo,"setTotalSpace","(J)V");
    jmethodID setAlgAsymCap = env->GetMethodID(classDevInfo,"setAlgAsymCap","(J)V");
    jmethodID setAlgHashCap = env->GetMethodID(classDevInfo,"setAlgHashCap","(J)V");


    jobject objVersion = env->NewObject(classVersion,Version);

    env->CallVoidMethod(objVersion,setMajor,(jbyte)info.Version.major);
    env->CallVoidMethod(objVersion,setMinor,(jbyte)info.Version.minor);

    env->CallVoidMethod(devInfo,setVersion,objVersion);
    env->CallVoidMethod(devInfo,setAlgSymCap,(jlong)info.AlgSymCap);
    env->CallVoidMethod(devInfo,setDevAuthAlgId,(jlong)info.DevAuthAlgId);

    env->CallVoidMethod(objVersion,setMajor,(jbyte)info.FirmwareVersion.major);
    env->CallVoidMethod(objVersion,setMinor,(jbyte)info.FirmwareVersion.minor);
    env->CallVoidMethod(devInfo,setFirmwareVersion,objVersion);

    env->CallVoidMethod(devInfo,setFreeSpace,(jlong)info.FreeSpace);

    env->CallVoidMethod(objVersion,setMajor,(jbyte)info.HWVersion.major);
    env->CallVoidMethod(objVersion,setMinor,(jbyte)info.HWVersion.minor);
    env->CallVoidMethod(devInfo,setHWVersion,objVersion);

    jstring issuer = env->NewStringUTF(info.Issuer);
    env->CallVoidMethod(devInfo,setIssuer,issuer);
    env->DeleteLocalRef(issuer);

    jstring label = env->NewStringUTF(info.Label);
    env->CallVoidMethod(devInfo,setLabel,label);
    env->DeleteLocalRef(label);

    jstring manufacturer = env->NewStringUTF(info.Manufacturer);
    env->CallVoidMethod(devInfo,setManufacturer,manufacturer);
    env->DeleteLocalRef(manufacturer);

    env->CallVoidMethod(devInfo,setMaxBufferSize,(jlong)info.MaxBufferSize);
    env->CallVoidMethod(devInfo,setMaxECCBufferSize,(jlong)info.MaxECCBufferSize);

    jbyteArray reserved = env->NewByteArray(sizeof(info.Reserved));
    env->SetByteArrayRegion(reserved,0,sizeof(info.Reserved),(jbyte*)info.Reserved);
    env->CallVoidMethod(devInfo,setReserved,reserved);

    jstring serialNumber = env->NewStringUTF(info.SerialNumber);
    env->CallVoidMethod(devInfo,setSerialNumber,serialNumber);
    env->DeleteLocalRef(serialNumber);

    env->CallVoidMethod(devInfo,setTotalSpace,(jlong)info.TotalSpace);
    env->CallVoidMethod(devInfo,setAlgAsymCap,(jlong)info.AlgAsymCap);
    env->CallVoidMethod(devInfo,setAlgHashCap,(jlong)info.AlgHashCap);

    return SAR_OK;

}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_LockDev
 * Signature: (Lcom/westone/skf/DEVHANDLE;J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1LockDev
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jlong ulTimeOut){
    if(NULL == hDev){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDev = env->GetObjectClass(hDev);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,method);
    ULONG ret = SAR_OK;
    ret = skfFunctionList.SKF_LockDev((DEVHANDLE)pointer,(ULONG)ulTimeOut);
    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_UnlockDev
 * Signature: (Lcom/westone/skf/DEVHANDLE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1UnlockDev
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev){
    if(NULL == hDev){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDev = env->GetObjectClass(hDev);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,method);
    ULONG ret = SAR_OK;


    ret = skfFunctionList.SKF_UnlockDev((DEVHANDLE)pointer);
    return ret;

}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ChangeDevAuthKey
 * Signature: (Lcom/westone/skf/DEVHANDLE;[B)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ChangeDevAuthKey
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jbyteArray pbKeyValue){
    if(NULL == hDev || NULL == pbKeyValue){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDev = env->GetObjectClass(hDev);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,method);

    jbyte *pData = env->GetByteArrayElements(pbKeyValue,NULL);
    ULONG ret = SAR_OK;


    ret = skfFunctionList.SKF_ChangeDevAuthKey((DEVHANDLE)pointer,(BYTE*)pData,env->GetArrayLength(pbKeyValue));
    env->ReleaseByteArrayElements(pbKeyValue,pData,0);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_DevAuth
 * Signature: (Lcom/westone/skf/DEVHANDLE;[B)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1DevAuth
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jbyteArray pbAuthData){
    if(NULL == hDev || NULL == pbAuthData){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDev = env->GetObjectClass(hDev);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,method);

    jbyte *pData = env->GetByteArrayElements(pbAuthData,NULL);
    ULONG ret = SAR_OK;


    ret = skfFunctionList.SKF_DevAuth((DEVHANDLE)pointer,(BYTE*)pData,env->GetArrayLength(pbAuthData));
    env->ReleaseByteArrayElements(pbAuthData,pData,0);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ChangePIN
 * Signature: (Lcom/westone/skf/HAPPLICATION;JLjava/lang/String;Ljava/lang/String;Lcom/westone/skf/PinRetryCount;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ChangePIN
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jlong ulPINType, jstring szOldPIN, jstring szNewPIN, jobject pulRetryCount){
    if(NULL == hApplication || NULL == szOldPIN || NULL == szNewPIN || NULL == pulRetryCount){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDev = env->GetObjectClass(hApplication);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hApplication,method);

    jclass classPinRetryCount = env->GetObjectClass(pulRetryCount);
    jmethodID methodPinRetryCount = env->GetMethodID(classPinRetryCount,"setRetryCount","(J)V");

    const char* pOldPin = env->GetStringUTFChars(szOldPIN,NULL);
    const char* pNewPin = env->GetStringUTFChars(szNewPIN,NULL);

    ULONG *pRetryCount = NULL;
    pRetryCount = new ULONG();
    ULONG ret = SAR_OK;


    ret = skfFunctionList.SKF_ChangePIN((HAPPLICATION)pointer,ulPINType,(LPSTR)pOldPin,(LPSTR)pNewPin,pRetryCount);

    env->ReleaseStringUTFChars(szOldPIN,pOldPin);
    env->ReleaseStringUTFChars(szNewPIN,pNewPin);

    env->CallVoidMethod(pulRetryCount,methodPinRetryCount,(jlong)pRetryCount[0]);
    delete pRetryCount;
    pRetryCount = NULL;

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_GetPINInfo
 * Signature: (Lcom/westone/skf/HAPPLICATION;JLcom/westone/skf/PinInfo;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1GetPINInfo
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jlong ulPINType, jobject ulPinInfo){
    if(NULL == hApplication || NULL == ulPinInfo){
        return SAR_INVALIDPARAMERR;
    }

    ULONG *pMaxRetryCount = NULL;
    ULONG *pRemainRetryCount = NULL;
    BOOL *pFlg = NULL;

    pMaxRetryCount = new ULONG();
    pRemainRetryCount = new ULONG();
    pFlg = new BOOL();

    jclass classDev = env->GetObjectClass(hApplication);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hApplication,method);

    jclass classPinInfo = env->GetObjectClass(ulPinInfo);
    jmethodID methodSetMaxRetryCount = env->GetMethodID(classPinInfo,"setMaxRetryCount","(J)V");
    jmethodID methodSetRemainRetryCount = env->GetMethodID(classPinInfo,"setRemainRetryCount","(J)V");
    jmethodID methodSetDefaultPin = env->GetMethodID(classPinInfo,"setDefaultPin","(Z)V");
    ULONG ret = SAR_OK;


    ret = skfFunctionList.SKF_GetPINInfo((HAPPLICATION)pointer,ulPINType,pMaxRetryCount,pRemainRetryCount,pFlg);

    env->CallVoidMethod(ulPinInfo,methodSetMaxRetryCount,(jlong)pMaxRetryCount[0]);
    env->CallVoidMethod(ulPinInfo,methodSetRemainRetryCount,(jlong)pRemainRetryCount[0]);

    jboolean bFlg = JNI_FALSE;
    if(pFlg[0] == TRUE){
        bFlg = JNI_TRUE;
    }
    env->CallVoidMethod(ulPinInfo,methodSetDefaultPin,bFlg);

    delete pMaxRetryCount;
    pMaxRetryCount = NULL;

    delete pRemainRetryCount;
    pRemainRetryCount = NULL;

    delete pFlg;
    pFlg = NULL;

    return ret;

}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_VerifyPIN
 * Signature: (Lcom/westone/skf/HAPPLICATION;JLjava/lang/String;Lcom/westone/skf/PinRetryCount;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1VerifyPIN
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jlong ulPINType, jstring szPIN, jobject pulRetryCount){
    if(NULL == hApplication || NULL == szPIN || NULL == pulRetryCount){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDev = env->GetObjectClass(hApplication);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hApplication,method);

    jclass classPinRetryCount = env->GetObjectClass(pulRetryCount);
    jmethodID methodPinRetryCount = env->GetMethodID(classPinRetryCount,"setRetryCount","(J)V");

    const char *pPin = env->GetStringUTFChars(szPIN,NULL);

    ULONG *pRetryCount = NULL;
    pRetryCount = new ULONG();
    ULONG ret = SAR_OK;


    ret = skfFunctionList.SKF_VerifyPIN((HAPPLICATION)pointer,ulPINType,(LPSTR)pPin,pRetryCount);


    env->ReleaseStringUTFChars(szPIN,pPin);

    env->CallVoidMethod(pulRetryCount,methodPinRetryCount,(jlong)pRetryCount[0]);
    delete pRetryCount;
    pRetryCount = NULL;

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_UnblockPIN
 * Signature: (Lcom/westone/skf/HAPPLICATION;Ljava/lang/String;Ljava/lang/String;Lcom/westone/skf/PinRetryCount;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1UnblockPIN
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jstring szAdminPIN, jstring szNewUserPIN, jobject pulRetryCount){
    if(NULL == hApplication || NULL == szAdminPIN || NULL == szNewUserPIN || NULL == pulRetryCount){
        return SAR_INVALIDPARAMERR;
    }

    const char *pAdminPin = env->GetStringUTFChars(szAdminPIN,NULL);
    const char *pNewUserPin = env->GetStringUTFChars(szNewUserPIN,NULL);

    jclass classDev = env->GetObjectClass(hApplication);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hApplication,method);

    jclass classPinRetryCount = env->GetObjectClass(pulRetryCount);
    jmethodID methodPinRetryCount = env->GetMethodID(classPinRetryCount,"setRetryCount","(J)V");

    ULONG *pRetryCount = NULL;
    pRetryCount = new ULONG();

    ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_UnblockPIN((HAPPLICATION)pointer,(LPSTR)pAdminPin,(LPSTR)pNewUserPin,pRetryCount);

    env->ReleaseStringUTFChars(szAdminPIN,pAdminPin);
    env->ReleaseStringUTFChars(szNewUserPIN,pNewUserPin);

    env->CallVoidMethod(pulRetryCount,methodPinRetryCount,(jlong)pRetryCount[0]);
    delete pRetryCount;
    pRetryCount = NULL;

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ClearSecureState
 * Signature: (Lcom/westone/skf/HAPPLICATION;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ClearSecureState
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication){
    if(NULL == hApplication){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDev = env->GetObjectClass(hApplication);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hApplication,method);
    ULONG ret = SAR_OK;


    ret = skfFunctionList.SKF_ClearSecureState((HAPPLICATION)pointer);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_CreateApplication
 * Signature: (Lcom/westone/skf/DEVHANDLE;Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;JJLcom/westone/skf/HAPPLICATION;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1CreateApplication
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jstring szAppName, jstring szAdminPIN, jlong dwAdminPinRetryCount, jstring szUserPIN, jlong dwUserPinRetryCount, jlong dwCreateFileRights, jobject phApplication){
    if(NULL == hDev || NULL == szAppName || NULL == szAdminPIN || NULL == phApplication){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDev = env->GetObjectClass(hDev);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,method);

    HAPPLICATION appHandle = NULL;
    const char *pAppName = env->GetStringUTFChars(szAppName,NULL);
    const char *pAdminPin = env->GetStringUTFChars(szAdminPIN,NULL);
    const char *pUserPin = env->GetStringUTFChars(szUserPIN,NULL);
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_CreateApplication((DEVHANDLE)pointer,(LPSTR)pAppName,(LPSTR)pAdminPin,dwAdminPinRetryCount,(LPSTR)pUserPin,dwUserPinRetryCount,dwCreateFileRights,&appHandle);


    env->ReleaseStringUTFChars(szAppName,pAppName);
    env->ReleaseStringUTFChars(szAdminPIN,pAdminPin);
    env->ReleaseStringUTFChars(szUserPIN,pUserPin);

    jclass classApp = env->GetObjectClass(phApplication);
    jmethodID setPointer = env->GetMethodID(classApp,"setPointer","(J)V");
    env->CallVoidMethod(phApplication,setPointer,(jlong)appHandle);

    return ret;

}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_EnumApplication
 * Signature: (Lcom/westone/skf/DEVHANDLE;Ljava/util/List;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1EnumApplication
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jobject szAppName){
    if(NULL == hDev || NULL == szAppName){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDev = env->GetObjectClass(hDev);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,method);

    LPSTR appName = NULL;
    ULONG len = 0;

    ULONG ret = SAR_OK;


    ret = skfFunctionList.SKF_EnumApplication((DEVHANDLE)pointer,appName,&len);

    if(ret != SAR_OK || 0 == len){
        return ret;
    }
    LOG("SKF_EnumApplication:");
    LOG("appName len:%d ", len);

    appName = new CHAR[len];
    memset(appName, '\0', len);


    ret = skfFunctionList.SKF_EnumApplication((DEVHANDLE)pointer,appName,&len);

    if(ret != SAR_OK){
        delete [] appName;
        appName = NULL;
        return ret;
    }
    LOG("appName len:%d ", len);
    LOD((unsigned char *)appName, (int)len);

    jclass classList = env->GetObjectClass(szAppName);
    jmethodID methodIdAdd = env->GetMethodID(classList,"add","(Ljava/lang/Object;)Z");

    LPSTR tmp = NULL;

    for(tmp = appName;;){
        if(strlen(tmp) == 0){
            break;
        }

        jstring szNameIndex = env->NewStringUTF(tmp);
        env->CallBooleanMethod(szAppName,methodIdAdd,szNameIndex);
        env->DeleteLocalRef(szNameIndex);
        tmp += strlen(tmp) + 1;

    }

    delete [] appName;
    appName = NULL;

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_DeleteApplication
 * Signature: (Lcom/westone/skf/DEVHANDLE;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1DeleteApplication
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jstring szAppName){
    if(NULL == hDev || NULL == szAppName){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDev = env->GetObjectClass(hDev);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,method);

    const char *pAppName = env->GetStringUTFChars(szAppName,NULL);
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_DeleteApplication((DEVHANDLE)pointer,(LPSTR)pAppName);


    env->ReleaseStringUTFChars(szAppName,pAppName);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_OpenApplication
 * Signature: (Lcom/westone/skf/DEVHANDLE;Ljava/lang/String;Lcom/westone/skf/HAPPLICATION;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1OpenApplication
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jstring szAppName, jobject phApplication){
    if(NULL == hDev || NULL == szAppName || NULL == phApplication){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDev = env->GetObjectClass(hDev);
    jmethodID method = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,method);

    const char *pAppName = env->GetStringUTFChars(szAppName,NULL);
    HAPPLICATION appHandle = NULL;
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_OpenApplication((DEVHANDLE)pointer,(LPSTR)pAppName,&appHandle);


    jclass classApp = env->GetObjectClass(phApplication);
    jmethodID setPointer = env->GetMethodID(classApp,"setPointer","(J)V");
    env->CallVoidMethod(phApplication,setPointer,(jlong)appHandle);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_CloseApplication
 * Signature: (Lcom/westone/skf/HAPPLICATION;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1CloseApplication
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication){
    if(NULL == hApplication){
        return SAR_INVALIDPARAMERR;
    }

    jclass classApp = env->GetObjectClass(hApplication);
    jmethodID getPointer = env->GetMethodID(classApp,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hApplication,getPointer);
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_CloseApplication((HAPPLICATION)pointer);


    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_CreateFile
 * Signature: (Lcom/westone/skf/HAPPLICATION;Ljava/lang/String;JJJ)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1CreateFile
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jstring szFileName, jlong ulFileSize, jlong ulReadRights, jlong ulWriteRights){
    if(NULL == hApplication || NULL == szFileName){
        SAR_INVALIDPARAMERR;
    }

    /* get application handle */
    jclass classHandle = env->GetObjectClass(hApplication);
    jmethodID methodID = env->GetMethodID(classHandle, "getPointer", "()J");
    jlong point = env->CallLongMethod(hApplication, methodID);

    HAPPLICATION happlication = (HAPPLICATION)point;

    /* get filename */
    const char *szfilename = env->GetStringUTFChars(szFileName, NULL);
    ULONG ret = SAR_OK;

    /* create file */


    ret = skfFunctionList.SKF_CreateFile(happlication, (LPSTR)szfilename, (ULONG)ulFileSize, (ULONG)ulReadRights, (ULONG)ulWriteRights);

    env->ReleaseStringUTFChars(szFileName, szfilename);
    if(ret != SAR_OK){
        return ret;
    }

    return SAR_OK;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_DeleteFile
 * Signature: (Lcom/westone/skf/HAPPLICATION;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1DeleteFile
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jstring szFileName){
    if(NULL == hApplication || NULL == szFileName){
        return SAR_INVALIDPARAMERR;
    }

    /* get application handle */
    jclass classHandle = env->GetObjectClass(hApplication);
    jmethodID methodID = env->GetMethodID(classHandle, "getPointer", "()J");
    jlong point = env->CallLongMethod(hApplication, methodID);

    HAPPLICATION happlication = (HAPPLICATION)point;

    /* get filename */
    const char *szfilename = env->GetStringUTFChars(szFileName, NULL);
    ULONG ret = SAR_OK;

    /* delete file */


    ret = skfFunctionList.SKF_DeleteFile(happlication, (LPSTR)szfilename);


    env->ReleaseStringUTFChars(szFileName, szfilename);
    if(ret != SAR_OK){
        return ret;
    }

    return SAR_OK;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_EnumFiles
 * Signature: (Lcom/westone/skf/HAPPLICATION;Ljava/util/List;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1EnumFiles
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jobject szFileList) {
    if(NULL == hApplication || NULL == szFileList){
        return SAR_INVALIDPARAMERR;
    }

    /* get application handle */
    jclass classHandle = env->GetObjectClass(hApplication);
    jmethodID methodID = env->GetMethodID(classHandle, "getPointer", "()J");
    jlong point = env->CallLongMethod(hApplication, methodID);

    HAPPLICATION happlication = (HAPPLICATION)point;

    /* enum files */
    LPSTR szfilelist = NULL;
    ULONG pulsize = 0;

 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_EnumFiles(happlication, szfilelist, &pulsize);

    if(ret != SAR_OK) {
        return ret;
    }
    if(pulsize == 0) {
        return ret;
    }

    szfilelist = new CHAR[pulsize];


    ret = skfFunctionList.SKF_EnumFiles(happlication, szfilelist, &pulsize);


    if(ret != SAR_OK) {
        delete [] szfilelist;
        szfilelist = NULL;
        return ret;
    }

    /* add file to fileList */
    jclass classList = env->GetObjectClass(szFileList);
    jmethodID methodIdAdd = env->GetMethodID(classList, "add", "(Ljava/lang/Object;)Z");
    LPSTR tmp = NULL;
    for(tmp = szfilelist;;){
        if(strlen(tmp) == 0){
            break;
        }
        jstring szFileIndex = env->NewStringUTF(tmp);
        env->CallBooleanMethod(szFileList, methodIdAdd, szFileIndex);
        env->DeleteLocalRef(szFileIndex);
        tmp += strlen(tmp) + 1;
    }

    delete [] szfilelist;
    szfilelist = NULL;

    return SAR_OK;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_GetFileInfo
 * Signature: (Lcom/westone/skf/HAPPLICATION;Ljava/lang/String;Lcom/westone/skf/FILEATTRIBUTE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1GetFileInfo
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jstring szFileName, jobject pFileInfo){
    if(NULL == hApplication || NULL == szFileName || NULL == pFileInfo){
        return SAR_INVALIDPARAMERR;
    }

    /* get application handle */
    jclass classHandle = env->GetObjectClass(hApplication);
    jmethodID methodID = env->GetMethodID(classHandle, "getPointer", "()J");
    jlong point = env->CallLongMethod(hApplication, methodID);

    HAPPLICATION happlication = (HAPPLICATION)point;

    /* get file name */
    const char *szfilename = env->GetStringUTFChars(szFileName, NULL);

    FILEATTRIBUTE fileinfo;
    memset(&fileinfo, 0, sizeof(fileinfo));

    /* get file info */
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_GetFileInfo(happlication, (LPSTR)szfilename, &fileinfo);


    env->ReleaseStringUTFChars(szFileName, szfilename);
    if(ret != SAR_OK){
        return ret;
    }

    /* get fileinfo handle and set value in it */
    jclass classFileInfo = env->GetObjectClass(pFileInfo);
    jmethodID setFileName = env->GetMethodID(classFileInfo, "setFileName", "(Ljava/lang/String;)V");
    jmethodID setFileSize = env->GetMethodID(classFileInfo, "setFileSize", "(J)V");
    jmethodID setReadRights = env->GetMethodID(classFileInfo, "setReadRights", "(J)V");
    jmethodID setWriteRights = env->GetMethodID(classFileInfo, "setWriteRights", "(J)V");

    jstring filename = env->NewStringUTF(fileinfo.FileName);
    env->CallVoidMethod(pFileInfo, setFileName, filename);
    env->DeleteLocalRef(filename);

    env->CallVoidMethod(pFileInfo, setFileSize, (jlong)fileinfo.FileSize);
    env->CallVoidMethod(pFileInfo, setReadRights, (jlong)fileinfo.ReadRights);
    env->CallVoidMethod(pFileInfo, setWriteRights, (jlong)fileinfo.WriteRights);

    return SAR_OK;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ReadFile
 * Signature: (Lcom/westone/skf/HAPPLICATION;Ljava/lang/String;JJ[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ReadFile
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jstring szFileName, jlong ulOffset, jlong ulSize, jbyteArray pbOutData, jlongArray pulOutLen){
    if(NULL == hApplication || NULL == szFileName || NULL == pulOutLen){
        return SAR_INVALIDPARAMERR;
    }

    /* get application handle */
    jclass handle = env->GetObjectClass(hApplication);
    jmethodID methodID = env->GetMethodID(handle, "getPointer", "()J");
    jlong point = env->CallLongMethod(hApplication, methodID);

    HAPPLICATION happlication = (HAPPLICATION)point;

    /* get filename */
    const char *szfilename = env->GetStringUTFChars(szFileName, NULL);

    /* read file */
    jbyte *pboutdata = NULL;
    ULONG puloutlen = 0;


    if(NULL != pbOutData){
        pboutdata = env->GetByteArrayElements(pbOutData, NULL);
    }

    jlong *pLongLen = env->GetLongArrayElements(pulOutLen,NULL);
    puloutlen = (ULONG)pLongLen[0];
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ReadFile(happlication, (LPSTR)szfilename, (ULONG)ulOffset, (ULONG)ulSize, (BYTE *)pboutdata, &puloutlen);


    env->ReleaseStringUTFChars(szFileName,szfilename);
    do{
        if(ret != SAR_OK){
            break;
        }
        if(NULL != pbOutData){
            env->SetByteArrayRegion(pbOutData, 0, puloutlen, pboutdata);
        }

        pLongLen[0] = (jlong)puloutlen;
    }while(0);

    env->ReleaseLongArrayElements(pulOutLen,pLongLen,0);

    if(NULL != pbOutData){
        env->ReleaseByteArrayElements(pbOutData, pboutdata, 0);
        pboutdata = NULL;
    }

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_WriteFile
 * Signature: (Lcom/westone/skf/HAPPLICATION;Ljava/lang/String;J[B)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1WriteFile
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jstring szFileName, jlong ulOffset, jbyteArray pbData){
    if(NULL == hApplication || NULL == szFileName || NULL == pbData){
        return SAR_INVALIDPARAMERR;
    }

    /* get application handle */
    jclass handle = env->GetObjectClass(hApplication);
    jmethodID methodID = env->GetMethodID(handle, "getPointer", "()J");
    jlong point = env->CallLongMethod(hApplication, methodID);

    HAPPLICATION happlication = (HAPPLICATION)point;

    /* get filename */
    const char *szfilename = env->GetStringUTFChars(szFileName, NULL);

    /* get space */
    jbyte *pbdata = env->GetByteArrayElements(pbData, NULL);


    /* write file */
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_WriteFile(happlication, (LPSTR)szfilename, (ULONG)ulOffset, (BYTE *)pbdata, env->GetArrayLength(pbData));


    env->ReleaseByteArrayElements(pbData, pbdata, 0);
    env->ReleaseStringUTFChars(szFileName, szfilename);
    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_CreateContainer
 * Signature: (Lcom/westone/skf/HAPPLICATION;Ljava/lang/String;Lcom/westone/skf/HCONTAINER;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1CreateContainer
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jstring szContainerName, jobject phContainer){
    if(NULL == hApplication || NULL == szContainerName || NULL == phContainer){
        return SAR_INVALIDPARAMERR;
    }

    /* get application handle */
    jclass classHandle = env->GetObjectClass(hApplication);
    jmethodID methodID = env->GetMethodID(classHandle, "getPointer", "()J");
    jlong point = env->CallLongMethod(hApplication, methodID);

    HAPPLICATION happlication = (HAPPLICATION)point;

    /* get container name */
    const char *szcontainername = env->GetStringUTFChars(szContainerName, NULL);

    HCONTAINER phcontainer = NULL;

    /* create container */
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_CreateContainer(happlication, (LPSTR)szcontainername, &phcontainer);


    env->ReleaseStringUTFChars(szContainerName, szcontainername);
    if(ret != SAR_OK){
        return ret;
    }

    /* get container handle and set value in it */
    jclass classContainer = env->GetObjectClass(phContainer);
    jmethodID methodIdSet = env->GetMethodID(classContainer, "setPointer", "(J)V");
    env->CallVoidMethod(phContainer, methodIdSet, (jlong )phcontainer);

    return SAR_OK;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_DeleteContainer
 * Signature: (Lcom/westone/skf/HAPPLICATION;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1DeleteContainer
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jstring szContainerName){
    if(NULL == hApplication || NULL == szContainerName){
        return SAR_INVALIDPARAMERR;
    }

    /* get application handle */
    jclass classHandle = env->GetObjectClass(hApplication);
    jmethodID methodID = env->GetMethodID(classHandle, "getPointer", "()J");
    jlong point = env->CallLongMethod(hApplication, methodID);

    HAPPLICATION happlication = (HAPPLICATION)point;

    /* get container name */
    const char *szcontainername = env->GetStringUTFChars(szContainerName, NULL);


    /* delete container */
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_DeleteContainer(happlication, (LPSTR)szcontainername);


    env->ReleaseStringUTFChars(szContainerName, szcontainername);
    if(ret != SAR_OK){
        return ret;
    }

    return SAR_OK;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_OpenContainer
 * Signature: (Lcom/westone/skf/HAPPLICATION;Ljava/lang/String;Lcom/westone/skf/HCONTAINER;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1OpenContainer
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jstring szContainerName, jobject phContainer){
    if(NULL == hApplication || NULL == szContainerName || NULL == phContainer){
        return SAR_INVALIDPARAMERR;
    }

    /* get application handle */
    jclass classHandle = env->GetObjectClass(hApplication);
    jmethodID methodID = env->GetMethodID(classHandle, "getPointer", "()J");
    jlong point = env->CallLongMethod(hApplication, methodID);

    HAPPLICATION happlication = (HAPPLICATION)point;

    /* get container name */
    const char *szcontainername = env->GetStringUTFChars(szContainerName, NULL);

    HCONTAINER phcontainer = NULL;

    /* open container */
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_OpenContainer(happlication, (LPSTR)szcontainername, &phcontainer);


    env->ReleaseStringUTFChars(szContainerName, szcontainername);
    if(ret != SAR_OK){
        return ret;
    }

    /* get container handle and set value in it */
    jclass classContainer = env->GetObjectClass(phContainer);
    jmethodID methodIdSet = env->GetMethodID(classContainer, "setPointer", "(J)V");
    env->CallVoidMethod(phContainer, methodIdSet, (jlong)phcontainer);

    return SAR_OK;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_CloseContainer
 * Signature: (Lcom/westone/skf/HCONTAINER;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1CloseContainer
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer){
    if(NULL == hContainer){
        return SAR_INVALIDPARAMERR;
    }

    /* get container handle */
    jclass classContainer = env->GetObjectClass(hContainer);
    jmethodID methodIdGet = env->GetMethodID(classContainer, "getPointer", "()J");
    jlong point = env->CallLongMethod(hContainer, methodIdGet);

    HCONTAINER hcontainer = (HCONTAINER)point;


    /* close container */
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_CloseContainer(hcontainer);


    if(ret != SAR_OK){
        return ret;
    }

    return SAR_OK;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_EnumContainer
 * Signature: (Lcom/westone/skf/HAPPLICATION;Ljava/util/List;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1EnumContainer
        (JNIEnv *env, jclass SkfNativeFunc, jobject hApplication, jobject szContainerName){
    if(NULL == hApplication || NULL == szContainerName){
        return SAR_INVALIDPARAMERR;
    }

    /* get application handle */
    jclass classHandle = env->GetObjectClass(hApplication);
    jmethodID methodID = env->GetMethodID(classHandle, "getPointer", "()J");
    jlong point = env->CallLongMethod(hApplication, methodID);

    HAPPLICATION happlication = (HAPPLICATION)point;

    /* enum containers */
    LPSTR szcontainername = NULL;
    ULONG pulsize = 0;

 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_EnumContainer(happlication, szcontainername, &pulsize);


    if(ret != SAR_OK || pulsize <= 0)
    {
        return ret;
    }
    LOG("SKF_EnumContainer:");
    LOG("szcontainername pulsize:%d ", pulsize);

    szcontainername = new CHAR[pulsize];
    memset(szcontainername, '\0', pulsize);


    ret = skfFunctionList.SKF_EnumContainer(happlication, szcontainername, &pulsize);


    if(ret != SAR_OK){
        delete [] szcontainername;
        szcontainername = NULL;
        return ret;
    }
    LOG("szcontainername pulsize:%d ", pulsize);
    LOD((unsigned char *)szcontainername, (int)pulsize);

    /* add container to containerList */
    jclass classList = env->GetObjectClass(szContainerName);
    jmethodID methodIdAdd = env->GetMethodID(classList, "add", "(Ljava/lang/Object;)Z");
    LPSTR tmp = NULL;
    for(tmp = szcontainername;;){
        if(strlen(tmp) == 0){
            break;
        }
        jstring szContainerIndex = env->NewStringUTF(tmp);
        env->CallBooleanMethod(szContainerName, methodIdAdd, szContainerIndex);
        env->DeleteLocalRef(szContainerIndex);
        tmp += strlen(tmp) + 1;
    }

    delete [] szcontainername;
    szcontainername = NULL;

    return SAR_OK;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_GetContainerType
 * Signature: (Lcom/westone/skf/HCONTAINER;[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1GetContainerType
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jlongArray pulContainerType){
    if( NULL == hContainer || NULL == pulContainerType)
    {
        return SAR_INVALIDPARAMERR;
    }

    jclass classContainer = env->GetObjectClass(hContainer);
    jmethodID getPointer = env->GetMethodID(classContainer,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,getPointer);

    ULONG pulConPropertyLoc = 0;
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_GetContainerType((HCONTAINER)pointer, &pulConPropertyLoc);


    if(!ret){
        jlong *pConProperty = env->GetLongArrayElements(pulContainerType,NULL);
        pConProperty[0] = (jlong)pulConPropertyLoc;
        env->ReleaseLongArrayElements(pulContainerType,pConProperty,0);
    }

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_GenRandom
 * Signature: (Lcom/westone/skf/DEVHANDLE;[BJ)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1GenRandom
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jbyteArray pbRandom, jlong ulRandomLen){
    if(NULL == hDev || NULL == pbRandom || ulRandomLen < 0){
        return SAR_INVALIDPARAMERR;
    }

    jclass dev = env->GetObjectClass(hDev);
    jmethodID methodID = env->GetMethodID(dev,"getPointer","()J");
    jlong point = env->CallLongMethod(hDev,methodID);

    jbyte *pRandom = env->GetByteArrayElements(pbRandom,NULL);
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_GenRandom((DEVHANDLE)point,(BYTE*)pRandom,ulRandomLen);


    env->ReleaseByteArrayElements(pbRandom,pRandom,0);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_GenExtRSAKey
 * Signature: (Lcom/westone/skf/DEVHANDLE;JLcom/westone/skf/RSAPRIVATEKEYBLOB;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1GenExtRSAKey
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jlong ulBitsLen, jobject pBlob){
    if(NULL == hDev || NULL == pBlob){
        return SAR_INVALIDPARAMERR;
    }

    jclass dev = env->GetObjectClass(hDev);
    jmethodID methodID = env->GetMethodID(dev,"getPointer","()J");
    jlong point = env->CallLongMethod(hDev,methodID);

    RSAPRIVATEKEYBLOB rsaprivatekeyblob;
    memset(&rsaprivatekeyblob,0, sizeof(rsaprivatekeyblob));
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_GenExtRSAKey((DEVHANDLE)point,ulBitsLen,&rsaprivatekeyblob);


    jclass classRSAPRIVATEKEYBLOB = env->GetObjectClass(pBlob);
    jmethodID setAlgID = env->GetMethodID(classRSAPRIVATEKEYBLOB,"setAlgID","(J)V");
    jmethodID setBitLen = env->GetMethodID(classRSAPRIVATEKEYBLOB,"setBitLen","(J)V");
    jmethodID setModulus = env->GetMethodID(classRSAPRIVATEKEYBLOB,"setModulus","([B)V");
    jmethodID setPublicExponent = env->GetMethodID(classRSAPRIVATEKEYBLOB,"setPublicExponent","([B)V");
    jmethodID setPrivateExponent = env->GetMethodID(classRSAPRIVATEKEYBLOB,"setPrivateExponent","([B)V");
    jmethodID setPrime1 = env->GetMethodID(classRSAPRIVATEKEYBLOB,"setPrime1","([B)V");
    jmethodID setPrime2 = env->GetMethodID(classRSAPRIVATEKEYBLOB,"setPrime2","([B)V");
    jmethodID setPrime1Exponent = env->GetMethodID(classRSAPRIVATEKEYBLOB,"setPrime1Exponent","([B)V");
    jmethodID setPrime2Exponent = env->GetMethodID(classRSAPRIVATEKEYBLOB,"setPrime2Exponent","([B)V");
    jmethodID setCoefficient = env->GetMethodID(classRSAPRIVATEKEYBLOB,"setCoefficient","([B)V");

    env->CallVoidMethod(pBlob,setAlgID,(jlong)rsaprivatekeyblob.AlgID);
    env->CallVoidMethod(pBlob,setBitLen,(jlong)rsaprivatekeyblob.BitLen);

    jbyteArray modulus = env->NewByteArray(sizeof(rsaprivatekeyblob.Modulus));
    env->SetByteArrayRegion(modulus,0,sizeof(rsaprivatekeyblob.Modulus),(jbyte*)rsaprivatekeyblob.Modulus);
    env->CallVoidMethod(pBlob,setModulus,modulus);
    env->DeleteLocalRef(modulus);

    jbyteArray publicExponent = env->NewByteArray(sizeof(rsaprivatekeyblob.PublicExponent));
    env->SetByteArrayRegion(publicExponent,0,sizeof(rsaprivatekeyblob.PublicExponent),(jbyte*)rsaprivatekeyblob.PublicExponent);
    env->CallVoidMethod(pBlob,setPublicExponent,publicExponent);
    env->DeleteLocalRef(publicExponent);

    jbyteArray privateExponent = env->NewByteArray(sizeof(rsaprivatekeyblob.PrivateExponent));
    env->SetByteArrayRegion(privateExponent,0,sizeof(rsaprivatekeyblob.PrivateExponent),(jbyte*)rsaprivatekeyblob.PrivateExponent);
    env->CallVoidMethod(pBlob,setPrivateExponent,privateExponent);
    env->DeleteLocalRef(privateExponent);

    jbyteArray prime1 = env->NewByteArray(sizeof(rsaprivatekeyblob.Prime1));
    env->SetByteArrayRegion(prime1,0,sizeof(rsaprivatekeyblob.Prime1),(jbyte*)rsaprivatekeyblob.Prime1);
    env->CallVoidMethod(pBlob,setPrime1,prime1);
    env->DeleteLocalRef(prime1);

    jbyteArray prime2 = env->NewByteArray(sizeof(rsaprivatekeyblob.Prime2));
    env->SetByteArrayRegion(prime2,0,sizeof(rsaprivatekeyblob.Prime2),(jbyte*)rsaprivatekeyblob.Prime2);
    env->CallVoidMethod(pBlob,setPrime2,prime2);
    env->DeleteLocalRef(prime2);

    jbyteArray prime1Exponent = env->NewByteArray(sizeof(rsaprivatekeyblob.Prime1Exponent));
    env->SetByteArrayRegion(prime1Exponent,0,sizeof(rsaprivatekeyblob.Prime1Exponent),(jbyte*)rsaprivatekeyblob.Prime1Exponent);
    env->CallVoidMethod(pBlob,setPrime1Exponent,prime1Exponent);
    env->DeleteLocalRef(prime1Exponent);

    jbyteArray prime2Exponent = env->NewByteArray(sizeof(rsaprivatekeyblob.Prime2Exponent));
    env->SetByteArrayRegion(prime2Exponent,0,sizeof(rsaprivatekeyblob.Prime2Exponent),(jbyte*)rsaprivatekeyblob.Prime2Exponent);
    env->CallVoidMethod(pBlob,setPrime2Exponent,prime2Exponent);
    env->DeleteLocalRef(prime2Exponent);

    jbyteArray coefficient = env->NewByteArray(sizeof(rsaprivatekeyblob.Coefficient));
    env->SetByteArrayRegion(coefficient,0,sizeof(rsaprivatekeyblob.Coefficient),(jbyte*)rsaprivatekeyblob.Coefficient);
    env->CallVoidMethod(pBlob,setCoefficient,coefficient);
    env->DeleteLocalRef(coefficient);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_GenRSAKeyPair
 * Signature: (Lcom/westone/skf/HCONTAINER;JLcom/westone/skf/RSAPUBLICKEYBLOB;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1GenRSAKeyPair
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jlong ulBitsLen, jobject pBlob){
    if(NULL == hContainer || NULL == pBlob){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHCONTAINER = env->GetObjectClass(hContainer);
    jmethodID method = env->GetMethodID(classHCONTAINER,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,method);

    RSAPUBLICKEYBLOB rsapublickeyblob;
    memset(&rsapublickeyblob,0,sizeof(rsapublickeyblob));
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_GenRSAKeyPair((HCONTAINER)pointer,ulBitsLen,&rsapublickeyblob);


    if(ret != SAR_OK){
        return ret;
    }

    jclass classRSAPUBLICKEYBLOB = env->GetObjectClass(pBlob);
    jmethodID setAlgID = env->GetMethodID(classRSAPUBLICKEYBLOB,"setAlgID","(J)V");
    jmethodID setBitLen = env->GetMethodID(classRSAPUBLICKEYBLOB,"setBitLen","(J)V");
    jmethodID setModulus = env->GetMethodID(classRSAPUBLICKEYBLOB,"setModulus","([B)V");
    jmethodID setPublicExponent = env->GetMethodID(classRSAPUBLICKEYBLOB,"setPublicExponent","([B)V");

    env->CallVoidMethod(pBlob,setAlgID,(jlong)rsapublickeyblob.AlgID);
    env->CallVoidMethod(pBlob,setBitLen,(jlong)rsapublickeyblob.BitLen);

    jbyteArray modulus = env->NewByteArray(sizeof(rsapublickeyblob.Modulus));
    env->SetByteArrayRegion(modulus,0, sizeof(rsapublickeyblob.Modulus),(jbyte*)rsapublickeyblob.Modulus);
    env->CallVoidMethod(pBlob,setModulus,modulus);
    env->DeleteLocalRef(modulus);

    jbyteArray publicExponent = env->NewByteArray(sizeof(rsapublickeyblob.PublicExponent));
    env->SetByteArrayRegion(publicExponent,0,sizeof(rsapublickeyblob.PublicExponent),(jbyte*)rsapublickeyblob.PublicExponent);
    env->CallVoidMethod(pBlob,setPublicExponent,publicExponent);
    env->DeleteLocalRef(publicExponent);

    return ret;

}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ImportRSAKeyPair
 * Signature: (Lcom/westone/skf/HCONTAINER;J[B[B)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ImportRSAKeyPair
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jlong ulSymAlgId, jbyteArray pbWrappedKey, jbyteArray pbEncryptedData){
    if(NULL == hContainer){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHCONTAINER = env->GetObjectClass(hContainer);
    jmethodID method = env->GetMethodID(classHCONTAINER,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,method);

    ULONG ulWrappedKeyLen = 0;
    BYTE *pWrappedKeyData = NULL;

    ULONG ulEncryptedDataLen = 0;
    BYTE *pEncData = NULL;

    if(NULL != pbWrappedKey){
        ulWrappedKeyLen = env->GetArrayLength(pbWrappedKey);
        pWrappedKeyData = (BYTE*)(env->GetByteArrayElements(pbWrappedKey,NULL));
    }

    if(NULL != pbEncryptedData){
        ulEncryptedDataLen = env->GetArrayLength(pbEncryptedData);
        pEncData = (BYTE*)(env->GetByteArrayElements(pbEncryptedData,NULL));
    }
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ImportRSAKeyPair((HCONTAINER)pointer,(ULONG)ulSymAlgId,pWrappedKeyData,(ULONG)ulWrappedKeyLen,pEncData,(ULONG)ulEncryptedDataLen);

    if(NULL != pbWrappedKey){
        env->ReleaseByteArrayElements(pbWrappedKey,(jbyte*)pWrappedKeyData,0);
    }

    if(NULL != pbEncryptedData){
        env->ReleaseByteArrayElements(pbEncryptedData,(jbyte*)pEncData,0);
    }

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_RSASignData
 * Signature: (Lcom/westone/skf/HANDLE;[B[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1RSASignData
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jbyteArray pbData, jbyteArray pbSignature, jlongArray pulSigLen){
    if(NULL == hContainer){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHCONTAINER = env->GetObjectClass(hContainer);
    jmethodID method = env->GetMethodID(classHCONTAINER,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,method);

    BYTE *pData = NULL;
    ULONG ulDataLen = 0;

    BYTE *pSignature = NULL;
    ULONG *pSignLen = NULL;

    if(NULL != pbData){
        pData = (BYTE*)(env->GetByteArrayElements(pbData,NULL));
        ulDataLen = env->GetArrayLength(pbData);
    }

    if(NULL != pbSignature){
        pSignature = (BYTE*)(env->GetByteArrayElements(pbSignature,NULL));
    }

    if(NULL != pulSigLen){
        pSignLen = (ULONG*)(env->GetLongArrayElements(pulSigLen,NULL));
    }
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_RSASignData((HANDLE)pointer,pData,(ULONG)ulDataLen,pSignature,pSignLen);

    if(NULL != pbData){
        env->ReleaseByteArrayElements(pbData,(jbyte*)pData,0);
    }

    if(NULL != pbSignature){
        env->ReleaseByteArrayElements(pbSignature,(jbyte*)pSignature,0);
    }

    if(NULL != pulSigLen){
        env->ReleaseLongArrayElements(pulSigLen,(jlong*)pSignLen,0);
    }

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_RSAVerify
 * Signature: (Lcom/westone/skf/DEVHANDLE;Lcom/westone/skf/RSAPUBLICKEYBLOB;[B[B)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1RSAVerify
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jobject pRSAPubKeyBlob, jbyteArray pbData, jbyteArray pbSignature){
    if(NULL == hDev || NULL == pRSAPubKeyBlob){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDEVHANDLE = env->GetObjectClass(hDev);
    jmethodID method = env->GetMethodID(classDEVHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,method);

    jclass classRSAPUBLICKEYBLOB = env->GetObjectClass(pRSAPubKeyBlob);
    jmethodID getBitLen = env->GetMethodID(classRSAPUBLICKEYBLOB,"getBitLen","()J");
    jmethodID getAlgID = env->GetMethodID(classRSAPUBLICKEYBLOB,"getAlgID","()J");
    jmethodID getPublicExponent = env->GetMethodID(classRSAPUBLICKEYBLOB,"getPublicExponent","()[B");
    jmethodID getModulus = env->GetMethodID(classRSAPUBLICKEYBLOB,"getModulus","()[B");

    RSAPUBLICKEYBLOB rsapublickeyblob;
    memset(&rsapublickeyblob,0,sizeof(rsapublickeyblob));

    rsapublickeyblob.BitLen = env->CallLongMethod(pRSAPubKeyBlob,getBitLen);
    rsapublickeyblob.AlgID = env->CallLongMethod(pRSAPubKeyBlob,getAlgID);
    jbyteArray modulus = (jbyteArray)env->CallObjectMethod(pRSAPubKeyBlob,getModulus);
    jbyteArray publicExponent = (jbyteArray)env->CallObjectMethod(pRSAPubKeyBlob,getPublicExponent);

    jbyte *pModulus = env->GetByteArrayElements(modulus,NULL);
    memcpy(rsapublickeyblob.Modulus,pModulus,env->GetArrayLength(modulus) > sizeof(rsapublickeyblob.Modulus) ? sizeof(rsapublickeyblob.Modulus) : env->GetArrayLength(modulus));
    env->ReleaseByteArrayElements(modulus,pModulus,0);

    jbyte *pPublicExponent = env->GetByteArrayElements(publicExponent,NULL);
    memcpy(rsapublickeyblob.PublicExponent,pPublicExponent,env->GetArrayLength(publicExponent) >
                                                                   sizeof(rsapublickeyblob.PublicExponent) ? sizeof(rsapublickeyblob.PublicExponent):env->GetArrayLength(publicExponent));
    env->ReleaseByteArrayElements(publicExponent,pPublicExponent,0);

    BYTE *pData = NULL;
    ULONG dataLen = 0;

    BYTE *pSign = NULL;
    ULONG signLen = 0;

    if(NULL != pbData){
        dataLen = env->GetArrayLength(pbData);
        pData = (BYTE*)env->GetByteArrayElements(pbData,NULL);
    }

    if(NULL != pbSignature){
        signLen = env->GetArrayLength(pbSignature);
        pSign = (BYTE*)env->GetByteArrayElements(pbSignature,NULL);
    }

 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_RSAVerify((DEVHANDLE)pointer,&rsapublickeyblob,pData,dataLen,pSign,signLen);

    if(NULL != pbData){
        env->ReleaseByteArrayElements(pbData,(jbyte*)pSign,0);
    }

    if(NULL != pbSignature){
        env->ReleaseByteArrayElements(pbSignature,(jbyte*)pSign,0);
    }

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_RSAExportSessionKey
 * Signature: (Lcom/westone/skf/HCONTAINER;JLcom/westone/skf/RSAPUBLICKEYBLOB;[B[JLcom/westone/skf/HANDLE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1RSAExportSessionKey
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jlong ulAlgID, jobject pPubKey, jbyteArray pbData, jlongArray pulDataLen, jobject phSessionKey){
    if(NULL == hContainer || NULL == pPubKey || NULL == phSessionKey){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHCONTAINER = env->GetObjectClass(hContainer);
    jmethodID method = env->GetMethodID(classHCONTAINER,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,method);

    jclass classRSAPUBLICKEYBLOB = env->GetObjectClass(pPubKey);
    jmethodID getBitLen = env->GetMethodID(classRSAPUBLICKEYBLOB,"getBitLen","()J");
    jmethodID getAlgID = env->GetMethodID(classRSAPUBLICKEYBLOB,"getAlgID","()J");
    jmethodID getPublicExponent = env->GetMethodID(classRSAPUBLICKEYBLOB,"getPublicExponent","()[B");
    jmethodID getModulus = env->GetMethodID(classRSAPUBLICKEYBLOB,"getModulus","()[B");

    RSAPUBLICKEYBLOB rsapublickeyblob;
    memset(&rsapublickeyblob,0,sizeof(rsapublickeyblob));

    rsapublickeyblob.BitLen = env->CallLongMethod(pPubKey,getBitLen);
    rsapublickeyblob.AlgID = env->CallLongMethod(pPubKey,getAlgID);
    jbyteArray modulus = (jbyteArray)env->CallObjectMethod(pPubKey,getModulus);
    jbyteArray publicExponent = (jbyteArray)env->CallObjectMethod(pPubKey,getPublicExponent);

    jbyte *pModulus = env->GetByteArrayElements(modulus,NULL);
    memcpy(rsapublickeyblob.Modulus,pModulus,
           env->GetArrayLength(modulus) > sizeof(rsapublickeyblob.Modulus) ? sizeof(rsapublickeyblob.Modulus) : env->GetArrayLength(modulus));
    env->ReleaseByteArrayElements(modulus,pModulus,0);

    jbyte *pPublicExponent = env->GetByteArrayElements(publicExponent,NULL);
    memcpy(rsapublickeyblob.PublicExponent,pPublicExponent,
           env->GetArrayLength(publicExponent) > sizeof(rsapublickeyblob.PublicExponent) ? sizeof(rsapublickeyblob.PublicExponent):env->GetArrayLength(publicExponent));

    env->ReleaseByteArrayElements(publicExponent,pPublicExponent,0);

    BYTE *pData = NULL;
    ULONG *pDataLen = NULL;
    HANDLE handle = NULL;

    if(NULL != pbData){
        pData = (BYTE*)env->GetByteArrayElements(pbData,NULL);
    }

    if(NULL != pulDataLen){
        pDataLen = (ULONG*)env->GetLongArrayElements(pulDataLen,NULL);
    }

    ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_RSAExportSessionKey((HCONTAINER)pointer,ulAlgID,&rsapublickeyblob,pData,pDataLen,&handle);

    if(NULL != pbData){
        env->ReleaseByteArrayElements(pbData,(jbyte*)pData,0);
    }

    if(NULL != pulDataLen){
        env->ReleaseLongArrayElements(pulDataLen,(jlong*)pDataLen,0);
    }

    jclass classHANDLE = env->GetObjectClass(phSessionKey);
    jmethodID methodsetPointer = env->GetMethodID(classHANDLE,"setPointer","()J");
    env->CallVoidMethod(phSessionKey,methodsetPointer,(jlong)handle);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ExtRSAPubKeyOperation
 * Signature: (Lcom/westone/skf/DEVHANDLE;Lcom/westone/skf/RSAPUBLICKEYBLOB;[B[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ExtRSAPubKeyOperation
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jobject pRSAPubKeyBlob, jbyteArray pbInput, jbyteArray pbOutput, jlongArray pulOutputLen){
    if(NULL == hDev || NULL == pRSAPubKeyBlob){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDEVHANDLE = env->GetObjectClass(hDev);
    jmethodID method = env->GetMethodID(classDEVHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,method);

    jclass classRSAPUBLICKEYBLOB = env->GetObjectClass(pRSAPubKeyBlob);
    jmethodID getBitLen = env->GetMethodID(classRSAPUBLICKEYBLOB,"getBitLen","()J");
    jmethodID getAlgID = env->GetMethodID(classRSAPUBLICKEYBLOB,"getAlgID","()J");
    jmethodID getPublicExponent = env->GetMethodID(classRSAPUBLICKEYBLOB,"getPublicExponent","()[B");
    jmethodID getModulus = env->GetMethodID(classRSAPUBLICKEYBLOB,"getModulus","()[B");

    RSAPUBLICKEYBLOB rsapublickeyblob;
    memset(&rsapublickeyblob,0,sizeof(rsapublickeyblob));

    rsapublickeyblob.BitLen = env->CallLongMethod(pRSAPubKeyBlob,getBitLen);
    rsapublickeyblob.AlgID = env->CallLongMethod(pRSAPubKeyBlob,getAlgID);
    jbyteArray modulus = (jbyteArray)env->CallObjectMethod(pRSAPubKeyBlob,getModulus);
    jbyteArray publicExponent = (jbyteArray)env->CallObjectMethod(pRSAPubKeyBlob,getPublicExponent);

    jbyte *pModulus = env->GetByteArrayElements(modulus,NULL);
    memcpy(rsapublickeyblob.Modulus,pModulus,
           env->GetArrayLength(modulus) > sizeof(rsapublickeyblob.Modulus) ? sizeof(rsapublickeyblob.Modulus) : env->GetArrayLength(modulus));
    env->ReleaseByteArrayElements(modulus,pModulus,0);

    jbyte *pPublicExponent = env->GetByteArrayElements(publicExponent,NULL);
    memcpy(rsapublickeyblob.PublicExponent,pPublicExponent,
           env->GetArrayLength(publicExponent) > sizeof(rsapublickeyblob.PublicExponent) ? sizeof(rsapublickeyblob.PublicExponent):env->GetArrayLength(publicExponent));

    env->ReleaseByteArrayElements(publicExponent,pPublicExponent,0);


    BYTE *pIn = NULL;
    ULONG inLen = 0;

    BYTE *pOut = NULL;
    ULONG *pOutLen = NULL;

    if(NULL != pbInput){
        inLen = env->GetArrayLength(pbInput);
        pIn = (BYTE*)env->GetByteArrayElements(pbInput,NULL);
    }

    if(NULL != pbOutput){
        pOut = (BYTE*)env->GetByteArrayElements(pbOutput,NULL);
    }

    if(NULL != pulOutputLen){
        pOutLen = (ULONG*)env->GetLongArrayElements(pulOutputLen,NULL);
    }

    ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ExtRSAPubKeyOperation((DEVHANDLE)pointer,&rsapublickeyblob,pIn,inLen,pOut,pOutLen);

    if(NULL != pbInput){
        env->ReleaseByteArrayElements(pbInput,(jbyte*)pIn,0);
    }

    if(NULL != pbOutput){
        env->ReleaseByteArrayElements(pbOutput,(jbyte*)pOut,0);
    }

    if(NULL != pulOutputLen){
        env->ReleaseLongArrayElements(pulOutputLen,(jlong*)pOutLen,0);
    }

    return ret;

}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ExtRSAPriKeyOperation
 * Signature: (Lcom/westone/skf/DEVHANDLE;Lcom/westone/skf/RSAPRIVATEKEYBLOB;[B[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ExtRSAPriKeyOperation
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jobject pRSAPriKeyBlob, jbyteArray pbInput, jbyteArray pbOutput, jlongArray pulOutputLen){
    if(NULL == hDev || NULL == pRSAPriKeyBlob){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDEVHANDLE = env->GetObjectClass(hDev);
    jmethodID method = env->GetMethodID(classDEVHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,method);

    jclass classRSAPRIVATEKEYBLOB = env->GetObjectClass(pRSAPriKeyBlob);
    jmethodID getAlgID = env->GetMethodID(classRSAPRIVATEKEYBLOB,"getAlgID","()J");
    jmethodID getBitLen = env->GetMethodID(classRSAPRIVATEKEYBLOB,"getBitLen","()J");
    jmethodID getModulus = env->GetMethodID(classRSAPRIVATEKEYBLOB,"getModulus","()[B");
    jmethodID getPublicExponent = env->GetMethodID(classRSAPRIVATEKEYBLOB,"getPublicExponent","()[B");
    jmethodID getPrivateExponent = env->GetMethodID(classRSAPRIVATEKEYBLOB,"getPrivateExponent","()[B");
    jmethodID getPrime1 = env->GetMethodID(classRSAPRIVATEKEYBLOB,"getPrime1","()[B");
    jmethodID getPrime2 = env->GetMethodID(classRSAPRIVATEKEYBLOB,"getPrime2","()[B");
    jmethodID getPrime1Exponent = env->GetMethodID(classRSAPRIVATEKEYBLOB,"getPrime1Exponent","()[B");
    jmethodID getPrime2Exponent = env->GetMethodID(classRSAPRIVATEKEYBLOB,"getPrime2Exponent","()[B");
    jmethodID getCoefficient = env->GetMethodID(classRSAPRIVATEKEYBLOB,"getCoefficient","()[B");


    RSAPRIVATEKEYBLOB rsaprivatekeyblob;
    memset(&rsaprivatekeyblob,0,sizeof(rsaprivatekeyblob));

    rsaprivatekeyblob.BitLen = env->CallLongMethod(pRSAPriKeyBlob,getBitLen);
    rsaprivatekeyblob.AlgID = env->CallLongMethod(pRSAPriKeyBlob,getAlgID);

    jbyteArray modulus = (jbyteArray)env->CallObjectMethod(pRSAPriKeyBlob,getModulus);
    jbyte *pModulus = env->GetByteArrayElements(modulus,NULL);
    memcpy(rsaprivatekeyblob.Modulus,pModulus,
           env->GetArrayLength(modulus) > sizeof(rsaprivatekeyblob.Modulus) ? sizeof(rsaprivatekeyblob.Modulus) : env->GetArrayLength(modulus));
    env->ReleaseByteArrayElements(modulus,pModulus,0);


    jbyteArray publicExponent = (jbyteArray)env->CallObjectMethod(pRSAPriKeyBlob,getPublicExponent);
    jbyte *pPublicExponent = env->GetByteArrayElements(publicExponent,NULL);
    memcpy(rsaprivatekeyblob.PublicExponent,pPublicExponent,
           env->GetArrayLength(publicExponent) > sizeof(rsaprivatekeyblob.PublicExponent) ? sizeof(rsaprivatekeyblob.PublicExponent):env->GetArrayLength(publicExponent));
    env->ReleaseByteArrayElements(publicExponent,pPublicExponent,0);

    jbyteArray privateExponent = (jbyteArray)env->CallObjectMethod(pRSAPriKeyBlob,getPrivateExponent);
    jbyte *pPrivateExponent = env->GetByteArrayElements(privateExponent,NULL);
    memcpy(rsaprivatekeyblob.PrivateExponent,pPrivateExponent,
           env->GetArrayLength(privateExponent) > sizeof(rsaprivatekeyblob.PrivateExponent) ? sizeof(rsaprivatekeyblob.PrivateExponent):env->GetArrayLength(privateExponent));
    env->ReleaseByteArrayElements(privateExponent,pPrivateExponent,0);

    jbyteArray prime1 = (jbyteArray)env->CallObjectMethod(pRSAPriKeyBlob,getPrime1);
    jbyte *pPrime1 = env->GetByteArrayElements(prime1,NULL);
    memcpy(rsaprivatekeyblob.Prime1,pPrime1,
           env->GetArrayLength(prime1) > sizeof(rsaprivatekeyblob.Prime1) ? sizeof(rsaprivatekeyblob.Prime1):env->GetArrayLength(prime1));
    env->ReleaseByteArrayElements(prime1,pPrime1,0);

    jbyteArray prime2 = (jbyteArray)env->CallObjectMethod(pRSAPriKeyBlob,getPrime2);
    jbyte *pPrime2 = env->GetByteArrayElements(prime2,NULL);
    memcpy(rsaprivatekeyblob.Prime2,pPrime2,
           env->GetArrayLength(prime2) > sizeof(rsaprivatekeyblob.Prime2) ? sizeof(rsaprivatekeyblob.Prime2):env->GetArrayLength(prime2));
    env->ReleaseByteArrayElements(prime2,pPrime2,0);

    jbyteArray prime1Exponent = (jbyteArray)env->CallObjectMethod(pRSAPriKeyBlob,getPrime1Exponent);
    jbyte *pPrime1Exponent = env->GetByteArrayElements(prime1Exponent,NULL);
    memcpy(rsaprivatekeyblob.Prime1Exponent,pPrime1Exponent,
           env->GetArrayLength(prime1Exponent) > sizeof(rsaprivatekeyblob.Prime1Exponent) ? sizeof(rsaprivatekeyblob.Prime1Exponent):env->GetArrayLength(prime1Exponent));
    env->ReleaseByteArrayElements(prime1Exponent,pPrime1Exponent,0);

    jbyteArray prime2Exponent = (jbyteArray)env->CallObjectMethod(pRSAPriKeyBlob,getPrime2Exponent);
    jbyte *pPrime2Exponent = env->GetByteArrayElements(prime2Exponent,NULL);
    memcpy(rsaprivatekeyblob.Prime2Exponent,pPrime2Exponent,
           env->GetArrayLength(prime2Exponent) > sizeof(rsaprivatekeyblob.Prime2Exponent) ? sizeof(rsaprivatekeyblob.Prime2Exponent):env->GetArrayLength(prime2Exponent));
    env->ReleaseByteArrayElements(prime2Exponent,pPrime2Exponent,0);

    jbyteArray coefficient = (jbyteArray)env->CallObjectMethod(pRSAPriKeyBlob,getCoefficient);
    jbyte *pCoefficient = env->GetByteArrayElements(coefficient,NULL);
    memcpy(rsaprivatekeyblob.Coefficient,pCoefficient,
           env->GetArrayLength(coefficient) > sizeof(rsaprivatekeyblob.Coefficient) ? sizeof(rsaprivatekeyblob.Coefficient):env->GetArrayLength(coefficient));
    env->ReleaseByteArrayElements(coefficient,pCoefficient,0);


    BYTE *pIn = NULL;
    ULONG inLen = 0;

    BYTE *pOut = NULL;
    ULONG *pOutLen = NULL;

    if(NULL != pbInput){
        inLen = env->GetArrayLength(pbInput);
        pIn = (BYTE*)env->GetByteArrayElements(pbInput,NULL);
    }

    if(NULL != pbOutput){
        pOut = (BYTE*)env->GetByteArrayElements(pbOutput,NULL);
    }

    if(NULL != pulOutputLen){
        pOutLen = (ULONG*)env->GetLongArrayElements(pulOutputLen,NULL);
    }

    ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ExtRSAPriKeyOperation((DEVHANDLE)pointer,&rsaprivatekeyblob,pIn,inLen,pOut,pOutLen);

    if(NULL != pbInput){
        env->ReleaseByteArrayElements(pbInput,(jbyte*)pIn,0);
    }

    if(NULL != pbOutput){
        env->ReleaseByteArrayElements(pbOutput,(jbyte*)pOut,0);
    }

    if(NULL != pulOutputLen){
        env->ReleaseLongArrayElements(pulOutputLen,(jlong*)pOutLen,0);
    }

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_GenECCKeyPair
 * Signature: (Lcom/westone/skf/HCONTAINER;JLcom/westone/skf/ECCPUBLICKEYBLOB;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1GenECCKeyPair
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jlong ulAlgId, jobject pBlob){
    if(NULL == hContainer || NULL == pBlob){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHCONTAINER = env->GetObjectClass(hContainer);
    jmethodID method = env->GetMethodID(classHCONTAINER,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,method);



    ECCPUBLICKEYBLOB eccpublickeyblob;
    memset(&eccpublickeyblob,0, sizeof(eccpublickeyblob));
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_GenECCKeyPair((HCONTAINER)pointer,ulAlgId,&eccpublickeyblob);
    if(ret != SAR_OK){
        return ret;
    }

    jclass classECCPUBLICKEYBLOB = env->GetObjectClass(pBlob);
    jmethodID setBitLen = env->GetMethodID(classECCPUBLICKEYBLOB,"setBitLen","(J)V");
    jmethodID setXCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"setXCoordinate","([B)V");
    jmethodID setYCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"setYCoordinate","([B)V");

    jbyteArray x = env->NewByteArray(sizeof(eccpublickeyblob.XCoordinate));
    jbyteArray y = env->NewByteArray(sizeof(eccpublickeyblob.YCoordinate));

    env->SetByteArrayRegion(x,0,sizeof(eccpublickeyblob.XCoordinate),(jbyte*)eccpublickeyblob.XCoordinate);
    env->SetByteArrayRegion(y,0,sizeof(eccpublickeyblob.YCoordinate),(jbyte*)eccpublickeyblob.YCoordinate);

    env->CallVoidMethod(pBlob,setBitLen,(jlong)eccpublickeyblob.BitLen);
    env->CallVoidMethod(pBlob,setXCoordinate,x);
    env->CallVoidMethod(pBlob,setYCoordinate,y);

    env->DeleteLocalRef(x);
    env->DeleteLocalRef(y);

    return ret;

}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ImportECCKeyPair
 * Signature: (Lcom/westone/skf/HCONTAINER;Lcom/westone/skf/ENVELOPEDKEYBLOB;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ImportECCKeyPair
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jobject pEnvelopedKeyBlob){
    if(NULL == hContainer || NULL == pEnvelopedKeyBlob){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHCONTAINER = env->GetObjectClass(hContainer);
    jmethodID method = env->GetMethodID(classHCONTAINER,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,method);

    jclass classENVELOPEDKEYBLOB = env->GetObjectClass(pEnvelopedKeyBlob);
    jmethodID getVersion = env->GetMethodID(classENVELOPEDKEYBLOB,"getVersion","()J");
    jmethodID getUlSymmAlgID = env->GetMethodID(classENVELOPEDKEYBLOB,"getUlSymmAlgID","()J");
    jmethodID getUlBits = env->GetMethodID(classENVELOPEDKEYBLOB,"getUlBits","()J");
    jmethodID getCbEncryptedPriKey = env->GetMethodID(classENVELOPEDKEYBLOB,"getCbEncryptedPriKey","()[B");
    jmethodID getPubKey = env->GetMethodID(classENVELOPEDKEYBLOB,"getPubKey","()Lcom/westone/skf/ECCPUBLICKEYBLOB;");
    jmethodID getECCCipherBlob = env->GetMethodID(classENVELOPEDKEYBLOB,"getECCCipherBlob","()Lcom/westone/skf/ECCCIPHERBLOB;");

    jobject pubKey = env->CallObjectMethod(pEnvelopedKeyBlob,getPubKey);
    jobject cipher = env->CallObjectMethod(pEnvelopedKeyBlob,getECCCipherBlob);

    jclass classECCCIPHERBLOB = env->GetObjectClass(cipher);
    jmethodID getXCoordinate = env->GetMethodID(classECCCIPHERBLOB,"getXCoordinate","()[B");
    jmethodID getYCoordinate = env->GetMethodID(classECCCIPHERBLOB,"getYCoordinate","()[B");
    jmethodID getHASH = env->GetMethodID(classECCCIPHERBLOB,"getHASH","()[B");
    jmethodID getCipherLen = env->GetMethodID(classECCCIPHERBLOB,"getCipherLen","()J");
    jmethodID getCipher = env->GetMethodID(classECCCIPHERBLOB,"getCipher","()[B");

    jclass classECCPUBLICKEYBLOB = env->GetObjectClass(pubKey);
    jmethodID getBitLen = env->GetMethodID(classECCPUBLICKEYBLOB,"getBitLen","()J");
    jmethodID getXCoordinatePub = env->GetMethodID(classECCPUBLICKEYBLOB,"getXCoordinate","()[B");
    jmethodID getYCoordinatePub = env->GetMethodID(classECCPUBLICKEYBLOB,"getYCoordinate","()[B");

    jbyteArray cbEncryptedPriKey = (jbyteArray)env->CallObjectMethod(pEnvelopedKeyBlob,getCbEncryptedPriKey);
    BYTE *pCbEncryptedPriKey = (BYTE*)env->GetByteArrayElements(cbEncryptedPriKey,NULL);

    jbyteArray xc = (jbyteArray)env->CallObjectMethod(cipher,getXCoordinate);
    BYTE *pXc = (BYTE*)env->GetByteArrayElements(xc,NULL);

    jbyteArray yc = (jbyteArray)env->CallObjectMethod(cipher,getYCoordinate);
    BYTE *pYc = (BYTE*)env->GetByteArrayElements(yc,NULL);

    jbyteArray hc = (jbyteArray)env->CallObjectMethod(cipher,getHASH);
    BYTE *pHc = (BYTE*)env->GetByteArrayElements(hc,NULL);

    jbyteArray cc = (jbyteArray)env->CallObjectMethod(cipher,getCipher);
    BYTE *pCc = (BYTE*)env->GetByteArrayElements(cc,NULL);

    jbyteArray xp = (jbyteArray)env->CallObjectMethod(pubKey,getXCoordinatePub);
    BYTE *pXp = (BYTE*)env->GetByteArrayElements(xp,NULL);

    jbyteArray yp = (jbyteArray)env->CallObjectMethod(pubKey,getYCoordinatePub);
    BYTE *pYp = (BYTE*)env->GetByteArrayElements(yp,NULL);

    PENVELOPEDKEYBLOB envelopedkeyblob = (PENVELOPEDKEYBLOB)(new BYTE[sizeof(ENVELOPEDKEYBLOB) + env->GetArrayLength(cc)]);

    memset(envelopedkeyblob,0, sizeof(ENVELOPEDKEYBLOB) + env->GetArrayLength(cc));

    envelopedkeyblob->Version = env->CallLongMethod(pEnvelopedKeyBlob,getVersion);
    envelopedkeyblob->ulBits = env->CallLongMethod(pEnvelopedKeyBlob,getUlBits);
    envelopedkeyblob->ulSymmAlgID = env->CallLongMethod(pEnvelopedKeyBlob,getUlSymmAlgID);

    memcpy(envelopedkeyblob->cbEncryptedPriKey,pCbEncryptedPriKey, env->GetArrayLength(cbEncryptedPriKey) >
            sizeof(envelopedkeyblob->cbEncryptedPriKey) ? sizeof(envelopedkeyblob->cbEncryptedPriKey):env->GetArrayLength(cbEncryptedPriKey) );
    env->ReleaseByteArrayElements(cbEncryptedPriKey,(jbyte*)pCbEncryptedPriKey,0);


    envelopedkeyblob->ECCCipherBlob.CipherLen = env->CallLongMethod(cipher,getCipherLen);
    memcpy(envelopedkeyblob->ECCCipherBlob.XCoordinate,
           pXc,
           env->GetArrayLength(xc) > sizeof(envelopedkeyblob->ECCCipherBlob.XCoordinate) ? sizeof(envelopedkeyblob->ECCCipherBlob.XCoordinate):env->GetArrayLength(xc) );
    env->ReleaseByteArrayElements(xc,(jbyte*)pXc,0);


    memcpy(envelopedkeyblob->ECCCipherBlob.YCoordinate,
           pYc,
           env->GetArrayLength(yc) > sizeof(envelopedkeyblob->ECCCipherBlob.YCoordinate) ? sizeof(envelopedkeyblob->ECCCipherBlob.YCoordinate):env->GetArrayLength(yc) );
    env->ReleaseByteArrayElements(yc,(jbyte*)pYc,0);


    memcpy(envelopedkeyblob->ECCCipherBlob.HASH,
           pHc,
           env->GetArrayLength(hc) > sizeof(envelopedkeyblob->ECCCipherBlob.HASH) ? sizeof(envelopedkeyblob->ECCCipherBlob.HASH):env->GetArrayLength(hc) );
    env->ReleaseByteArrayElements(hc,(jbyte*)pHc,0);


    memcpy(envelopedkeyblob->ECCCipherBlob.Cipher,
           pCc,
           env->GetArrayLength(cc));
    env->ReleaseByteArrayElements(cc,(jbyte*)pCc,0);


    envelopedkeyblob->PubKey.BitLen = (ULONG)env->CallLongMethod(pubKey,getBitLen);
    memcpy(envelopedkeyblob->PubKey.XCoordinate,
           pXp,
           env->GetArrayLength(xp) > sizeof(envelopedkeyblob->PubKey.XCoordinate) ? sizeof(envelopedkeyblob->PubKey.XCoordinate):env->GetArrayLength(xp) );
    env->ReleaseByteArrayElements(xp,(jbyte*)pXp,0);


    memcpy(envelopedkeyblob->PubKey.YCoordinate,
           pYp,
           env->GetArrayLength(yp) > sizeof(envelopedkeyblob->PubKey.YCoordinate) ? sizeof(envelopedkeyblob->PubKey.YCoordinate):env->GetArrayLength(yp) );
    env->ReleaseByteArrayElements(yp,(jbyte*)pYp,0);

 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ImportECCKeyPair((HCONTAINER)pointer,envelopedkeyblob);


    delete envelopedkeyblob;
    envelopedkeyblob = NULL;

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ECCSignData
 * Signature: (Lcom/westone/skf/HANDLE;[BLcom/westone/skf/ECCSIGNATUREBLOB;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ECCSignData
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jbyteArray pbData, jobject pSignature){
    if(NULL == hContainer || NULL == pSignature){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHANDLE = env->GetObjectClass(hContainer);
    jmethodID method = env->GetMethodID(classHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,method);

    jclass classECCSIGNATUREBLOB = env->GetObjectClass(pSignature);
    jmethodID setR = env->GetMethodID(classECCSIGNATUREBLOB,"setR","([B)V");
    jmethodID setS = env->GetMethodID(classECCSIGNATUREBLOB,"setS","([B)V");

    ECCSIGNATUREBLOB eccsignatureblob;
    memset(&eccsignatureblob,0, sizeof(eccsignatureblob));

    BYTE *pData = NULL;
    ULONG dataLen = 0;



    if(NULL != pbData){
        pData = (BYTE*)env->GetByteArrayElements(pbData,NULL);
        dataLen = env->GetArrayLength(pbData);
    }
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ECCSignData((HCONTAINER)pointer,pData,dataLen,&eccsignatureblob);

    if(ret != SAR_OK){
        return ret;
    }


    ret = skfFunctionList.SKF_ECCSignData((HCONTAINER)pointer,pData,dataLen,&eccsignatureblob);

    jbyteArray r = env->NewByteArray(sizeof(eccsignatureblob.r));
    jbyteArray s = env->NewByteArray(sizeof(eccsignatureblob.s));

    env->SetByteArrayRegion(r,0,sizeof(eccsignatureblob.r),(jbyte*)eccsignatureblob.r);
    env->SetByteArrayRegion(s,0,sizeof(eccsignatureblob.s),(jbyte*)eccsignatureblob.s);

    env->CallVoidMethod(pSignature,setR,r);
    env->CallVoidMethod(pSignature,setS,s);

    env->DeleteLocalRef(r);
    env->DeleteLocalRef(s);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ECCVerify
 * Signature: (Lcom/westone/skf/DEVHANDLE;Lcom/westone/skf/ECCPUBLICKEYBLOB;[BLcom/westone/skf/ECCSIGNATUREBLOB;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ECCVerify
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jobject pECCPubKeyBlob, jbyteArray pbData, jobject pSignature){
    if(NULL == hDev || NULL == pECCPubKeyBlob || NULL == pbData ||NULL == pSignature){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDEVHANDLE = env->GetObjectClass(hDev);
    jmethodID method = env->GetMethodID(classDEVHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,method);

    jclass classECCPUBLICKEYBLOB = env->GetObjectClass(pECCPubKeyBlob);
    jmethodID getBitLen = env->GetMethodID(classECCPUBLICKEYBLOB,"getBitLen","()J");
    jmethodID getXCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getXCoordinate","()[B");
    jmethodID getYCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getYCoordinate","()[B");

    jclass classECCSIGNATUREBLOB = env->GetObjectClass(pSignature);
    jmethodID getR = env->GetMethodID(classECCSIGNATUREBLOB,"getR","()[B");
    jmethodID getS = env->GetMethodID(classECCSIGNATUREBLOB,"getS","()[B");

    ECCPUBLICKEYBLOB eccpublickeyblob;
    memset(&eccpublickeyblob,0,sizeof(eccpublickeyblob));
    eccpublickeyblob.BitLen = env->CallLongMethod(pECCPubKeyBlob,getBitLen);

    jbyteArray x = (jbyteArray)env->CallObjectMethod(pECCPubKeyBlob,getXCoordinate);
    jbyteArray y = (jbyteArray)env->CallObjectMethod(pECCPubKeyBlob,getYCoordinate);
    BYTE *pX = (BYTE*)env->GetByteArrayElements(x,NULL);
    BYTE *pY = (BYTE*)env->GetByteArrayElements(y,NULL);

    memcpy(eccpublickeyblob.XCoordinate,pX,env->GetArrayLength(x) > sizeof(eccpublickeyblob.XCoordinate) ? sizeof(eccpublickeyblob.XCoordinate):env->GetArrayLength(x));
    memcpy(eccpublickeyblob.YCoordinate,pY,env->GetArrayLength(y) > sizeof(eccpublickeyblob.YCoordinate) ? sizeof(eccpublickeyblob.YCoordinate):env->GetArrayLength(y));
    env->ReleaseByteArrayElements(x,(jbyte*)pX,0);
    env->ReleaseByteArrayElements(y,(jbyte*)pY,0);


    ECCSIGNATUREBLOB eccsignatureblob;
    memset(&eccsignatureblob,0, sizeof(eccsignatureblob));

    jbyteArray r = (jbyteArray)env->CallObjectMethod(pSignature,getR);
    jbyteArray s = (jbyteArray)env->CallObjectMethod(pSignature,getS);

    BYTE *pR = (BYTE*)env->GetByteArrayElements(r,NULL);
    BYTE *pS = (BYTE*)env->GetByteArrayElements(s,NULL);

    memcpy(eccsignatureblob.r,pR,env->GetArrayLength(r) > sizeof(eccsignatureblob.r) ? sizeof(eccsignatureblob.r):env->GetArrayLength(r));
    memcpy(eccsignatureblob.s,pS,env->GetArrayLength(s) > sizeof(eccsignatureblob.s) ? sizeof(eccsignatureblob.s):env->GetArrayLength(s));

    env->ReleaseByteArrayElements(r,(jbyte*)pR,0);
    env->ReleaseByteArrayElements(s,(jbyte*)pS,0);

    BYTE *pData = (BYTE*)env->GetByteArrayElements(pbData,NULL);
    ULONG dataLen = env->GetArrayLength(pbData);
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ECCVerify((DEVHANDLE)pointer,&eccpublickeyblob,pData,dataLen,&eccsignatureblob);
    env->ReleaseByteArrayElements(pbData,(jbyte*)pData,0);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ECCExportSessionKey
 * Signature: (Lcom/westone/skf/HCONTAINER;JLcom/westone/skf/ECCPUBLICKEYBLOB;Lcom/westone/skf/ECCCIPHERBLOB;Lcom/westone/skf/HANDLE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ECCExportSessionKey
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jlong ulAlgID, jobject pPubKey, jobject pData, jobject phSessionKey){
    if(NULL == hContainer || NULL == pPubKey || NULL == pData || NULL == phSessionKey){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHCONTAINER = env->GetObjectClass(hContainer);
    jmethodID methodGetPointer = env->GetMethodID(classHCONTAINER,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,methodGetPointer);

    jclass classECCPUBLICKEYBLOB = env->GetObjectClass(pPubKey);
    jmethodID getBitLen = env->GetMethodID(classECCPUBLICKEYBLOB,"getBitLen","()J");
    jmethodID getXCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getXCoordinate","()[B");
    jmethodID getYCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getYCoordinate","()[B");

    ECCPUBLICKEYBLOB eccpublickeyblob;
    memset(&eccpublickeyblob,0,sizeof(eccpublickeyblob));

    eccpublickeyblob.BitLen = env->CallLongMethod(pPubKey,getBitLen);

    jbyteArray x = (jbyteArray)env->CallObjectMethod(pPubKey,getXCoordinate);
    jbyteArray y = (jbyteArray)env->CallObjectMethod(pPubKey,getYCoordinate);
    BYTE *pX = (BYTE*)env->GetByteArrayElements(x,NULL);
    BYTE *pY = (BYTE*)env->GetByteArrayElements(y,NULL);

    memcpy(eccpublickeyblob.XCoordinate,pX,env->GetArrayLength(x) > sizeof(eccpublickeyblob.XCoordinate) ? sizeof(eccpublickeyblob.XCoordinate):env->GetArrayLength(x));
    memcpy(eccpublickeyblob.YCoordinate,pY,env->GetArrayLength(y) > sizeof(eccpublickeyblob.YCoordinate) ? sizeof(eccpublickeyblob.YCoordinate):env->GetArrayLength(y));
    env->ReleaseByteArrayElements(x,(jbyte*)pX,0);
    env->ReleaseByteArrayElements(y,(jbyte*)pY,0);

    PECCCIPHERBLOB ecccipherblob = (PECCCIPHERBLOB)new BYTE[sizeof(ECCCIPHERBLOB) + 16];
    memset(ecccipherblob,0,sizeof(ECCCIPHERBLOB) + 16);
    ecccipherblob->CipherLen = 16;
    HANDLE handle = NULL;
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ECCExportSessionKey((HCONTAINER)pointer,ulAlgID,&eccpublickeyblob,ecccipherblob,&handle);
    if(ret != SAR_OK){
        delete ecccipherblob;
        ecccipherblob = NULL;
        return ret;
    }

    jclass classECCCIPHERBLOB = env->GetObjectClass(pData);
    jmethodID setXCoordinate = env->GetMethodID(classECCCIPHERBLOB,"setXCoordinate","([B)V");
    jmethodID setYCoordinate = env->GetMethodID(classECCCIPHERBLOB,"setYCoordinate","([B)V");
    jmethodID setHASH = env->GetMethodID(classECCCIPHERBLOB,"setHASH","([B)V");
    jmethodID setCipher = env->GetMethodID(classECCCIPHERBLOB,"setCipher","([B)V");
    jmethodID setCipherLen = env->GetMethodID(classECCCIPHERBLOB,"setCipherLen","(J)V");

    jbyteArray cipherX = env->NewByteArray(sizeof(ecccipherblob->XCoordinate));
    jbyteArray cipherY = env->NewByteArray(sizeof(ecccipherblob->YCoordinate));
    jbyteArray cipherHASH = env->NewByteArray(sizeof(ecccipherblob->HASH));
    jbyteArray cipherCipher = env->NewByteArray(ecccipherblob->CipherLen);

    env->SetByteArrayRegion(cipherX,0,sizeof(ecccipherblob->XCoordinate),(jbyte*)ecccipherblob->XCoordinate);
    env->SetByteArrayRegion(cipherY,0,sizeof(ecccipherblob->YCoordinate),(jbyte*)ecccipherblob->YCoordinate);
    env->SetByteArrayRegion(cipherHASH,0,sizeof(ecccipherblob->HASH),(jbyte*)ecccipherblob->HASH);
    env->SetByteArrayRegion(cipherCipher,0,ecccipherblob->CipherLen,(jbyte*)ecccipherblob->Cipher);

    env->CallVoidMethod(pData,setCipherLen,(jlong)ecccipherblob->CipherLen);
    env->CallVoidMethod(pData,setXCoordinate,cipherX);
    env->CallVoidMethod(pData,setYCoordinate,cipherY);
    env->CallVoidMethod(pData,setHASH,cipherHASH);
    env->CallVoidMethod(pData,setCipher,cipherCipher);

    env->DeleteLocalRef(cipherX);
    env->DeleteLocalRef(cipherY);
    env->DeleteLocalRef(cipherHASH);
    env->DeleteLocalRef(cipherCipher);

    jclass classHANDLE = env->GetObjectClass(phSessionKey);
    jmethodID setPointer = env->GetMethodID(classHANDLE,"setPointer","(J)V");

    env->CallVoidMethod(phSessionKey,setPointer,(jlong)handle);

    delete ecccipherblob;
    ecccipherblob = NULL;

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ExtECCEncrypt
 * Signature: (Lcom/westone/skf/DEVHANDLE;Lcom/westone/skf/ECCPUBLICKEYBLOB;[BLcom/westone/skf/ECCCIPHERBLOB;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ExtECCEncrypt
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jobject pECCPubKeyBlob, jbyteArray pbPlainText, jobject pbCipherText){
    if(NULL == hDev || NULL == pECCPubKeyBlob || NULL == pbPlainText || NULL == pbCipherText){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDEVHANDLE = env->GetObjectClass(hDev);
    jmethodID getPointer = env->GetMethodID(classDEVHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,getPointer);

    jclass classECCPUBLICKEYBLOB = env->GetObjectClass(pECCPubKeyBlob);
    jmethodID getBitLen = env->GetMethodID(classECCPUBLICKEYBLOB,"getBitLen","()J");
    jmethodID getXCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getXCoordinate","()[B");
    jmethodID getYCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getYCoordinate","()[B");

    ECCPUBLICKEYBLOB eccpublickeyblob;
    memset(&eccpublickeyblob,0,sizeof(eccpublickeyblob));

    eccpublickeyblob.BitLen = env->CallLongMethod(pECCPubKeyBlob,getBitLen);

    jbyteArray x = (jbyteArray)env->CallObjectMethod(pECCPubKeyBlob,getXCoordinate);
    jbyteArray y = (jbyteArray)env->CallObjectMethod(pECCPubKeyBlob,getYCoordinate);
    BYTE *pX = (BYTE*)env->GetByteArrayElements(x,NULL);
    BYTE *pY = (BYTE*)env->GetByteArrayElements(y,NULL);

    memcpy(eccpublickeyblob.XCoordinate,pX,env->GetArrayLength(x) > sizeof(eccpublickeyblob.XCoordinate) ? sizeof(eccpublickeyblob.XCoordinate):env->GetArrayLength(x));
    memcpy(eccpublickeyblob.YCoordinate,pY,env->GetArrayLength(y) > sizeof(eccpublickeyblob.YCoordinate) ? sizeof(eccpublickeyblob.YCoordinate):env->GetArrayLength(y));
    env->ReleaseByteArrayElements(x,(jbyte*)pX,0);
    env->ReleaseByteArrayElements(y,(jbyte*)pY,0);


    BYTE *pPlain = (BYTE*)env->GetByteArrayElements(pbPlainText,NULL);

    PECCCIPHERBLOB ecccipherblob = (PECCCIPHERBLOB)new BYTE[sizeof(ECCCIPHERBLOB) + env->GetArrayLength(pbPlainText)];
    memset(ecccipherblob,0,sizeof(ECCCIPHERBLOB) + env->GetArrayLength(pbPlainText));
    ecccipherblob->CipherLen = env->GetArrayLength(pbPlainText);
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ExtECCEncrypt((DEVHANDLE)pointer,&eccpublickeyblob,pPlain,env->GetArrayLength(pbPlainText),ecccipherblob);

    env->ReleaseByteArrayElements(pbPlainText,(jbyte*)pPlain,0);

    if(ret != SAR_OK){
        delete ecccipherblob;
        ecccipherblob = NULL;
        return ret;
    }


    jclass classECCCIPHERBLOB = env->GetObjectClass(pbCipherText);
    jmethodID setXCoordinate = env->GetMethodID(classECCCIPHERBLOB,"setXCoordinate","([B)V");
    jmethodID setYCoordinate = env->GetMethodID(classECCCIPHERBLOB,"setYCoordinate","([B)V");
    jmethodID setHASH = env->GetMethodID(classECCCIPHERBLOB,"setHASH","([B)V");
    jmethodID setCipher = env->GetMethodID(classECCCIPHERBLOB,"setCipher","([B)V");
    jmethodID setCipherLen = env->GetMethodID(classECCCIPHERBLOB,"setCipherLen","(J)V");

    jbyteArray cipherX = env->NewByteArray(sizeof(ecccipherblob->XCoordinate));
    jbyteArray cipherY = env->NewByteArray(sizeof(ecccipherblob->YCoordinate));
    jbyteArray cipherHASH = env->NewByteArray(sizeof(ecccipherblob->HASH));
    jbyteArray cipherCipher = env->NewByteArray(ecccipherblob->CipherLen);

    env->SetByteArrayRegion(cipherX,0,sizeof(ecccipherblob->XCoordinate),(jbyte*)ecccipherblob->XCoordinate);
    env->SetByteArrayRegion(cipherY,0,sizeof(ecccipherblob->YCoordinate),(jbyte*)ecccipherblob->YCoordinate);
    env->SetByteArrayRegion(cipherHASH,0,sizeof(ecccipherblob->HASH),(jbyte*)ecccipherblob->HASH);
    env->SetByteArrayRegion(cipherCipher,0,ecccipherblob->CipherLen,(jbyte*)ecccipherblob->Cipher);

    env->CallVoidMethod(pbCipherText,setCipherLen,(jlong)ecccipherblob->CipherLen);
    env->CallVoidMethod(pbCipherText,setXCoordinate,cipherX);
    env->CallVoidMethod(pbCipherText,setYCoordinate,cipherY);
    env->CallVoidMethod(pbCipherText,setHASH,cipherHASH);
    env->CallVoidMethod(pbCipherText,setCipher,cipherCipher);

    env->DeleteLocalRef(cipherX);
    env->DeleteLocalRef(cipherY);
    env->DeleteLocalRef(cipherHASH);
    env->DeleteLocalRef(cipherCipher);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ExtECCDecrypt
 * Signature: (Lcom/westone/skf/DEVHANDLE;Lcom/westone/skf/ECCPRIVATEKEYBLOB;Lcom/westone/skf/ECCCIPHERBLOB;[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ExtECCDecrypt
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jobject pECCPriKeyBlob, jobject pbCipherText, jbyteArray pbPlainText, jlongArray pulOutputLen){
    if(NULL == hDev || NULL == pECCPriKeyBlob || NULL == pbCipherText || NULL == pulOutputLen){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDEVHANDLE = env->GetObjectClass(hDev);
    jmethodID getPointer = env->GetMethodID(classDEVHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,getPointer);

    jclass classECCPRIVATEKEYBLOB = env->GetObjectClass(pECCPriKeyBlob);
    jmethodID getBitLen = env->GetMethodID(classECCPRIVATEKEYBLOB,"getBitLen","()J");
    jmethodID getPrivateKey = env->GetMethodID(classECCPRIVATEKEYBLOB,"getPrivateKey","()[B");

    ECCPRIVATEKEYBLOB eccprivatekeyblob;
    memset(&eccprivatekeyblob,0,sizeof(eccprivatekeyblob));

    eccprivatekeyblob.BitLen = env->CallLongMethod(pECCPriKeyBlob,getBitLen);
    jbyteArray privateKey = (jbyteArray)env->CallObjectMethod(pECCPriKeyBlob,getPrivateKey);
    jbyte *pPrivateKey = env->GetByteArrayElements(privateKey,NULL);
    memcpy(eccprivatekeyblob.PrivateKey,pPrivateKey,sizeof(eccprivatekeyblob.PrivateKey));
    env->ReleaseByteArrayElements(privateKey,pPrivateKey,0);


    jclass classECCCIPHERBLOB = env->GetObjectClass(pbCipherText);
    jmethodID getXCoordinate = env->GetMethodID(classECCCIPHERBLOB,"getXCoordinate","()[B");
    jmethodID getYCoordinate = env->GetMethodID(classECCCIPHERBLOB,"getYCoordinate","()[B");
    jmethodID getHASH = env->GetMethodID(classECCCIPHERBLOB,"getHASH","()[B");
    jmethodID getCipherLen = env->GetMethodID(classECCCIPHERBLOB,"getCipherLen","()J");
    jmethodID getCipher = env->GetMethodID(classECCCIPHERBLOB,"getCipher","()[B");

    jlong cipherLen = env->CallLongMethod(pbCipherText,getCipherLen);

    PECCCIPHERBLOB ecccipherblob = (PECCCIPHERBLOB)new BYTE[sizeof(ECCCIPHERBLOB) + cipherLen];
    memset(ecccipherblob,0,sizeof(ECCCIPHERBLOB) + cipherLen);

    jbyteArray XCoordinate = (jbyteArray)env->CallObjectMethod(pbCipherText,getXCoordinate);
    jbyteArray YCoordinate = (jbyteArray)env->CallObjectMethod(pbCipherText,getYCoordinate);
    jbyteArray Hash = (jbyteArray)env->CallObjectMethod(pbCipherText,getHASH);
    jbyteArray Cipher = (jbyteArray)env->CallObjectMethod(pbCipherText,getCipher);

    jbyte *pXCoordinate = env->GetByteArrayElements(XCoordinate,NULL);
    jbyte *pYCoordinate = env->GetByteArrayElements(YCoordinate,NULL);
    jbyte *pHash = env->GetByteArrayElements(Hash,NULL);
    jbyte *pCipher = env->GetByteArrayElements(Cipher,NULL);

    ecccipherblob->CipherLen = (ULONG)cipherLen;
    memcpy(ecccipherblob->XCoordinate,pXCoordinate,sizeof(ecccipherblob->XCoordinate));
    memcpy(ecccipherblob->YCoordinate,pYCoordinate,sizeof(ecccipherblob->YCoordinate));
    memcpy(ecccipherblob->HASH,pHash,sizeof(ecccipherblob->HASH));
    memcpy(ecccipherblob->Cipher,pCipher,cipherLen);

    env->ReleaseByteArrayElements(XCoordinate,pXCoordinate,0);
    env->ReleaseByteArrayElements(YCoordinate,pYCoordinate,0);
    env->ReleaseByteArrayElements(Hash,pHash,0);
    env->ReleaseByteArrayElements(Cipher,pCipher,0);

    BYTE *pPlain = NULL;
    if(NULL != pbPlainText){
        pPlain = (BYTE*)env->GetByteArrayElements(pbPlainText,NULL);
    }

    jlong *plainLen = env->GetLongArrayElements(pulOutputLen,NULL);
    ULONG plainTxtLen = (ULONG)plainLen[0];

 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ExtECCDecrypt((DEVHANDLE)pointer,&eccprivatekeyblob,ecccipherblob,pPlain,&plainTxtLen);

    delete []ecccipherblob;
    ecccipherblob = NULL;

    if(NULL != pbPlainText){
        env->ReleaseByteArrayElements(pbPlainText,(jbyte*)pPlain,0);
    }

    plainLen[0] = (jlong)plainTxtLen;
    env->ReleaseLongArrayElements(pulOutputLen,plainLen,0);

    return ret;

}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ExtECCSign
 * Signature: (Lcom/westone/skf/DEVHANDLE;Lcom/westone/skf/ECCPRIVATEKEYBLOB;[BLcom/westone/skf/ECCSIGNATUREBLOB;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ExtECCSign
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jobject pECCPriKeyBlob, jbyteArray pbData, jobject pSignature){
    if(NULL == hDev || NULL == pECCPriKeyBlob || NULL == pbData || NULL == pSignature){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDEVHANDLE = env->GetObjectClass(hDev);
    jmethodID methodGetPointer = env->GetMethodID(classDEVHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,methodGetPointer);

    jclass classECCPRIVATEKEYBLOB = env->GetObjectClass(pECCPriKeyBlob);
    jmethodID getBitLen = env->GetMethodID(classECCPRIVATEKEYBLOB,"getBitLen","()J");
    jmethodID getPrivateKey = env->GetMethodID(classECCPRIVATEKEYBLOB,"getPrivateKey","()[B");

    ECCPRIVATEKEYBLOB eccprivatekeyblob;
    memset(&eccprivatekeyblob,0,sizeof(eccprivatekeyblob));

    eccprivatekeyblob.BitLen = env->CallLongMethod(pECCPriKeyBlob,getBitLen);
    jbyteArray privateKey = (jbyteArray)env->CallObjectMethod(pECCPriKeyBlob,getPrivateKey);
    jbyte *pPrivateKey = env->GetByteArrayElements(privateKey,NULL);
    memcpy(eccprivatekeyblob.PrivateKey,pPrivateKey,sizeof(eccprivatekeyblob.PrivateKey));
    env->ReleaseByteArrayElements(privateKey,pPrivateKey,0);

    BYTE *pData = (BYTE*)env->GetByteArrayElements(pbData,NULL);

    ECCSIGNATUREBLOB eccsignatureblob;
    memset(&eccsignatureblob,0, sizeof(eccsignatureblob));
    ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ExtECCSign((DEVHANDLE)pointer,&eccprivatekeyblob,pData,env->GetArrayLength(pbData),&eccsignatureblob);
    env->ReleaseByteArrayElements(pbData,(jbyte*)pData,0);

    if(ret != SAR_OK){
        return ret;
    }

    jclass classECCSIGNATUREBLOB = env->GetObjectClass(pSignature);
    jmethodID setR = env->GetMethodID(classECCSIGNATUREBLOB,"setR","([B)V");
    jmethodID setS = env->GetMethodID(classECCSIGNATUREBLOB,"setS","([B)V");

    jbyteArray r = env->NewByteArray(sizeof(eccsignatureblob.r));
    jbyteArray s = env->NewByteArray(sizeof(eccsignatureblob.s));

    env->SetByteArrayRegion(r,0,sizeof(eccsignatureblob.r),(jbyte*)eccsignatureblob.r);
    env->SetByteArrayRegion(s,0,sizeof(eccsignatureblob.s),(jbyte*)eccsignatureblob.s);

    env->CallVoidMethod(pSignature,setR,r);
    env->CallVoidMethod(pSignature,setS,s);
    env->DeleteLocalRef(r);
    env->DeleteLocalRef(s);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ExtECCVerify
 * Signature: (Lcom/westone/skf/DEVHANDLE;Lcom/westone/skf/ECCPUBLICKEYBLOB;[BLcom/westone/skf/ECCSIGNATUREBLOB;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ExtECCVerify
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jobject pECCPubKeyBlob, jbyteArray pbData, jobject pSignature){
    if(NULL == hDev || NULL == pECCPubKeyBlob || NULL == pSignature || NULL == pbData){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDEVHANDLE = env->GetObjectClass(hDev);
    jmethodID methodGetPointer = env->GetMethodID(classDEVHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,methodGetPointer);

    jclass classECCPUBLICKEYBLOB = env->GetObjectClass(pECCPubKeyBlob);
    jmethodID getBitLen = env->GetMethodID(classECCPUBLICKEYBLOB,"getBitLen","()J");
    jmethodID getXCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getXCoordinate","()[B");
    jmethodID getYCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getYCoordinate","()[B");

    ECCPUBLICKEYBLOB eccpublickeyblob;
    memset(&eccpublickeyblob,0,sizeof(eccpublickeyblob));

    eccpublickeyblob.BitLen = env->CallLongMethod(pECCPubKeyBlob,getBitLen);

    jbyteArray x = (jbyteArray)env->CallObjectMethod(pECCPubKeyBlob,getXCoordinate);
    jbyteArray y = (jbyteArray)env->CallObjectMethod(pECCPubKeyBlob,getYCoordinate);
    BYTE *pX = (BYTE*)env->GetByteArrayElements(x,NULL);
    BYTE *pY = (BYTE*)env->GetByteArrayElements(y,NULL);

    memcpy(eccpublickeyblob.XCoordinate,pX,env->GetArrayLength(x) > sizeof(eccpublickeyblob.XCoordinate) ? sizeof(eccpublickeyblob.XCoordinate):env->GetArrayLength(x));
    memcpy(eccpublickeyblob.YCoordinate,pY,env->GetArrayLength(y) > sizeof(eccpublickeyblob.YCoordinate) ? sizeof(eccpublickeyblob.YCoordinate):env->GetArrayLength(y));
    env->ReleaseByteArrayElements(x,(jbyte*)pX,0);
    env->ReleaseByteArrayElements(y,(jbyte*)pY,0);

    jclass classECCSIGNATUREBLOB = env->GetObjectClass(pSignature);
    jmethodID getR = env->GetMethodID(classECCSIGNATUREBLOB,"getR","()[B");
    jmethodID getS = env->GetMethodID(classECCSIGNATUREBLOB,"getS","()[B");

    jbyteArray r = (jbyteArray)env->CallObjectMethod(pSignature,getR);
    jbyteArray s = (jbyteArray)env->CallObjectMethod(pSignature,getS);
    jbyte *pR = env->GetByteArrayElements(r,NULL);
    jbyte *pS = env->GetByteArrayElements(s,NULL);
    BYTE* pData = (BYTE*)env->GetByteArrayElements(pbData,NULL);

    ECCSIGNATUREBLOB eccsignatureblob;
    memset(&eccsignatureblob,0, sizeof(eccsignatureblob));

    memcpy(eccsignatureblob.r,pR,sizeof(eccsignatureblob.r));
    memcpy(eccsignatureblob.s,pS,sizeof(eccsignatureblob.s));

    env->ReleaseByteArrayElements(r,pR,0);
    env->ReleaseByteArrayElements(s,pS,0);
    ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ExtECCVerify((DEVHANDLE)pointer,&eccpublickeyblob,pData,env->GetArrayLength(pbData),&eccsignatureblob);
    env->ReleaseByteArrayElements(pbData,(jbyte*)pData,0);
    return ret;

}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_GenerateAgreementDataWithECC
 * Signature: (Lcom/westone/skf/HCONTAINER;JLcom/westone/skf/ECCPUBLICKEYBLOB;[BLcom/westone/skf/HANDLE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1GenerateAgreementDataWithECC
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jlong ulAlgId, jobject pTempECCPubKeyBlob, jbyteArray pbID, jobject phAgreementHandle){
    if(NULL == hContainer || NULL == pTempECCPubKeyBlob || NULL == pbID || NULL == phAgreementHandle){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHCONTAINER = env->GetObjectClass(hContainer);
    jmethodID methodGetPointer = env->GetMethodID(classHCONTAINER,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,methodGetPointer);


    ECCPUBLICKEYBLOB eccpublickeyblob;
    memset(&eccpublickeyblob,0, sizeof(eccpublickeyblob));

    BYTE *pID = (BYTE*)env->GetByteArrayElements(pbID,NULL);
    HANDLE handle = NULL;
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_GenerateAgreementDataWithECC((HCONTAINER)pointer,ulAlgId,&eccpublickeyblob,pID,env->GetArrayLength(pbID),&handle);

    env->ReleaseByteArrayElements(pbID,(jbyte*)pID,0);

    if(ret != SAR_OK){
        return ret;
    }

    jclass classECCPUBLICKEYBLOB = env->GetObjectClass(pTempECCPubKeyBlob);
    jmethodID setBitLen = env->GetMethodID(classECCPUBLICKEYBLOB,"setBitLen","(J)V");
    jmethodID setXCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"setXCoordinate","([B)V");
    jmethodID setYCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"setYCoordinate","([B)V");

    jbyteArray x = env->NewByteArray(sizeof(eccpublickeyblob.XCoordinate));
    jbyteArray y = env->NewByteArray(sizeof(eccpublickeyblob.YCoordinate));

    env->SetByteArrayRegion(x,0,sizeof(eccpublickeyblob.XCoordinate),(jbyte*)eccpublickeyblob.XCoordinate);
    env->SetByteArrayRegion(y,0,sizeof(eccpublickeyblob.YCoordinate),(jbyte*)eccpublickeyblob.YCoordinate);

    env->CallVoidMethod(pTempECCPubKeyBlob,setBitLen,(jlong)eccpublickeyblob.BitLen);
    env->CallVoidMethod(pTempECCPubKeyBlob,setXCoordinate,x);
    env->CallVoidMethod(pTempECCPubKeyBlob,setYCoordinate,y);

    env->DeleteLocalRef(x);
    env->DeleteLocalRef(y);


    jclass classHANDLE = env->GetObjectClass(phAgreementHandle);
    jmethodID methodSetPointer = env->GetMethodID(classHANDLE,"setPointer","(J)V");
    env->CallVoidMethod(phAgreementHandle,methodSetPointer,(jlong)handle);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_GenerateAgreementDataAndKeyWithECC
 * Signature: (Lcom/westone/skf/HANDLE;JLcom/westone/skf/ECCPUBLICKEYBLOB;Lcom/westone/skf/ECCPUBLICKEYBLOB;Lcom/westone/skf/ECCPUBLICKEYBLOB;[B[BLcom/westone/skf/HANDLE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1GenerateAgreementDataAndKeyWithECC
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jlong ulAlgId, jobject pSponsorECCPubKeyBlob,
         jobject pSponsorTempECCPubKeyBlob, jobject pTempECCPubKeyBlob, jbyteArray pbID, jbyteArray pbSponsorID, jobject phKeyHandle){
    if(NULL == hContainer || NULL == pSponsorECCPubKeyBlob ||
       NULL == pSponsorTempECCPubKeyBlob || NULL == pTempECCPubKeyBlob
       || NULL == phKeyHandle || NULL == pbID || NULL == pbSponsorID){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHCONTAINER = env->GetObjectClass(hContainer);
    jmethodID methodGetPointer = env->GetMethodID(classHCONTAINER,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,methodGetPointer);

    jclass classECCPUBLICKEYBLOB = env->GetObjectClass(pSponsorECCPubKeyBlob);
    jmethodID getBitLen = env->GetMethodID(classECCPUBLICKEYBLOB,"getBitLen","()J");
    jmethodID getXCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getXCoordinate","()[B");
    jmethodID getYCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getYCoordinate","()[B");
    jmethodID setBitLen = env->GetMethodID(classECCPUBLICKEYBLOB,"setBitLen","(J)V");
    jmethodID setXCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"setXCoordinate","([B)V");
    jmethodID setYCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"setYCoordinate","([B)V");



    ECCPUBLICKEYBLOB sponsor,sponsorTemp,temp;
    memset(&sponsor,0,sizeof(sponsor));
    memset(&sponsorTemp,0, sizeof(sponsorTemp));
    memset(&temp,0,sizeof(temp));

    jbyteArray sponsorX = (jbyteArray)env->CallObjectMethod(pSponsorECCPubKeyBlob,getXCoordinate);
    jbyteArray sponsorY = (jbyteArray)env->CallObjectMethod(pSponsorECCPubKeyBlob,getYCoordinate);
    jbyte *pSponsorX = env->GetByteArrayElements(sponsorX,NULL);
    jbyte *pSponsorY = env->GetByteArrayElements(sponsorY,NULL);
    memcpy(sponsor.XCoordinate,pSponsorX,sizeof(sponsor.XCoordinate));
    memcpy(sponsor.YCoordinate,pSponsorY,sizeof(sponsor.YCoordinate));
    sponsor.BitLen = env->CallLongMethod(pSponsorECCPubKeyBlob,getBitLen);
    env->ReleaseByteArrayElements(sponsorX,pSponsorX,0);
    env->ReleaseByteArrayElements(sponsorY,pSponsorY,0);

    jbyteArray sponsorTempX = (jbyteArray)env->CallObjectMethod(pSponsorTempECCPubKeyBlob,getXCoordinate);
    jbyteArray sponsorTempY = (jbyteArray)env->CallObjectMethod(pSponsorTempECCPubKeyBlob,getYCoordinate);
    jbyte *pSponsorTempX = env->GetByteArrayElements(sponsorTempX,NULL);
    jbyte *pSponsorTempY = env->GetByteArrayElements(sponsorTempY,NULL);
    memcpy(sponsorTemp.XCoordinate,pSponsorTempX,sizeof(sponsorTemp.XCoordinate));
    memcpy(sponsorTemp.YCoordinate,pSponsorTempY,sizeof(sponsorTemp.YCoordinate));
    sponsorTemp.BitLen = env->CallLongMethod(pSponsorTempECCPubKeyBlob,getBitLen);
    env->ReleaseByteArrayElements(sponsorTempX,pSponsorTempX,0);
    env->ReleaseByteArrayElements(sponsorTempY,pSponsorTempY,0);

    BYTE *pID = (BYTE*)env->GetByteArrayElements(pbID,NULL);
    BYTE *pSponsorID = (BYTE*)env->GetByteArrayElements(pbSponsorID,NULL);

    HANDLE handle = NULL;
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_GenerateAgreementDataAndKeyWithECC((HANDLE)pointer,ulAlgId,&sponsor,
            &sponsorTemp,&temp,pID,env->GetArrayLength(pbID),pSponsorID,env->GetArrayLength(pbSponsorID),&handle);

    env->ReleaseByteArrayElements(pbID,(jbyte*)pID,0);
    env->ReleaseByteArrayElements(pbSponsorID,(jbyte*)pSponsorID,0);


    env->CallVoidMethod(pTempECCPubKeyBlob,setBitLen,(jlong)temp.BitLen);


    jbyteArray x = env->NewByteArray(sizeof(temp.XCoordinate));
    jbyteArray y = env->NewByteArray(sizeof(temp.YCoordinate));

    env->SetByteArrayRegion(x,0,sizeof(temp.XCoordinate),(jbyte*)temp.XCoordinate);
    env->SetByteArrayRegion(y,0,sizeof(temp.YCoordinate),(jbyte*)temp.YCoordinate);

    env->CallVoidMethod(pTempECCPubKeyBlob,setXCoordinate,x);
    env->CallVoidMethod(pTempECCPubKeyBlob,setYCoordinate,y);

    env->DeleteLocalRef(x);
    env->DeleteLocalRef(y);

    jclass classHANDLE = env->GetObjectClass(phKeyHandle);
    jmethodID setPointer = env->GetMethodID(classHANDLE,"setPointer","(J)V");
    env->CallVoidMethod(phKeyHandle,setPointer,(jlong)handle);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_GenerateKeyWithECC
 * Signature: (Lcom/westone/skf/HANDLE;Lcom/westone/skf/ECCPUBLICKEYBLOB;Lcom/westone/skf/ECCPUBLICKEYBLOB;[BLcom/westone/skf/HANDLE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1GenerateKeyWithECC
        (JNIEnv *env, jclass skfNativeFunc, jobject hAgreementHandle, jobject pECCPubKeyBlob, jobject pTempECCPubKeyBlob, jbyteArray pbID, jobject phKeyHandle){
    if(NULL == hAgreementHandle || NULL == pECCPubKeyBlob || NULL == pTempECCPubKeyBlob || NULL == pbID || NULL == phKeyHandle){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHANDLE = env->GetObjectClass(hAgreementHandle);
    jmethodID getPointer = env->GetMethodID(classHANDLE,"getPointer","()J");
    jmethodID setPointer = env->GetMethodID(classHANDLE,"setPointer","(J)V");
    jlong pointer = env->CallLongMethod(hAgreementHandle,getPointer);

    jclass classECCPUBLICKEYBLOB = env->GetObjectClass(pECCPubKeyBlob);
    jmethodID getBitLen = env->GetMethodID(classECCPUBLICKEYBLOB,"getBitLen","()J");
    jmethodID getXCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getXCoordinate","()[B");
    jmethodID getYCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getYCoordinate","()[B");

    ECCPUBLICKEYBLOB ecc,temp;
    memset(&ecc,0,sizeof(ecc));
    memset(&temp,0, sizeof(temp));

    jbyteArray eccX = (jbyteArray)env->CallObjectMethod(pECCPubKeyBlob,getXCoordinate);
    jbyteArray eccY = (jbyteArray)env->CallObjectMethod(pECCPubKeyBlob,getYCoordinate);
    jbyte *pEccX = env->GetByteArrayElements(eccX,NULL);
    jbyte *pEccY = env->GetByteArrayElements(eccY,NULL);

    ecc.BitLen = env->CallLongMethod(pECCPubKeyBlob,getBitLen);
    memcpy(ecc.XCoordinate,pEccX,sizeof(ecc.XCoordinate));
    memcpy(ecc.YCoordinate,pEccY,sizeof(ecc.YCoordinate));

    env->ReleaseByteArrayElements(eccX,pEccX,0);
    env->ReleaseByteArrayElements(eccY,pEccY,0);


    jbyteArray tempX = (jbyteArray)env->CallObjectMethod(pTempECCPubKeyBlob,getXCoordinate);
    jbyteArray tempY = (jbyteArray)env->CallObjectMethod(pTempECCPubKeyBlob,getYCoordinate);
    jbyte *pTempX = env->GetByteArrayElements(tempX,NULL);
    jbyte *pTempY = env->GetByteArrayElements(tempY,NULL);

    temp.BitLen = env->CallLongMethod(pTempECCPubKeyBlob,getBitLen);
    memcpy(temp.XCoordinate,pTempX,sizeof(temp.XCoordinate));
    memcpy(temp.YCoordinate,pTempY,sizeof(temp.YCoordinate));

    env->ReleaseByteArrayElements(tempX,pTempX,0);
    env->ReleaseByteArrayElements(tempY,pTempY,0);

    HANDLE handle = NULL;
    BYTE *pID = (BYTE*)env->GetByteArrayElements(pbID,NULL);
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_GenerateKeyWithECC((HANDLE)pointer,&ecc,&temp,pID,env->GetArrayLength(pbID),&handle);

    env->ReleaseByteArrayElements(pbID,(jbyte*)pID,0);
    if(ret != SAR_OK){
        return ret;
    }


    env->CallVoidMethod(phKeyHandle,setPointer,(jlong)handle);
    return ret;
}
/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ExportPublicKey
 * Signature: (Lcom/westone/skf/HCONTAINER;Z[Ljava/lang/Object;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ExportPublicKey
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jboolean bSignFlag, jobject obj)
{
    if(NULL == hContainer || NULL == obj){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHCONTAINER = env->GetObjectClass(hContainer);
    jmethodID getPointer = env->GetMethodID(classHCONTAINER,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,getPointer);

    BYTE *pBlob = NULL;
    ULONG blobLen = 0;


 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ExportPublicKey((HCONTAINER)pointer,bSignFlag,pBlob,&blobLen);

    if(ret != SAR_OK || blobLen <= 0){
        return (jlong)ret;
    }

    pBlob = new BYTE[blobLen];


    ret = skfFunctionList.SKF_ExportPublicKey((HCONTAINER)pointer,bSignFlag,pBlob,&blobLen);

    if(ret != SAR_OK || blobLen <= 0){
        delete [] pBlob;
        pBlob = NULL;
        return (jlong)ret;
    }

    ULONG pulConProperty = 0;


    ret = skfFunctionList.SKF_GetContainerType((HCONTAINER)pointer,&pulConProperty);

    if(ret != SAR_OK || (1 != pulConProperty && 2 != pulConProperty)){
        delete [] pBlob;
        pBlob = NULL;
        return (jlong)ret;
    }

    if(pulConProperty == 1){
        /*PRSAPUBLICKEYBLOB tmp = (PRSAPUBLICKEYBLOB )pBlob;
        jclass classRSAPUBLICKEYBLOB = env->FindClass("com/westone/skf/RSAPUBLICKEYBLOB");

        jmethodID init = env->GetMethodID(classRSAPUBLICKEYBLOB,"<init>","()V");

        jmethodID setBitLen = env->GetMethodID(classRSAPUBLICKEYBLOB,"setBitLen","(J)V");
        jmethodID setAlgID = env->GetMethodID(classRSAPUBLICKEYBLOB,"setAlgID","(J)V");
        jmethodID setModulus = env->GetMethodID(classRSAPUBLICKEYBLOB,"setModulus","([B)V");
        jmethodID setPublicExponent = env->GetMethodID(classRSAPUBLICKEYBLOB,"setPublicExponent","([B)V");

        jbyteArray modulus = env->NewByteArray(sizeof(tmp->Modulus));
        jbyteArray PublicExponent = env->NewByteArray(sizeof(tmp->PublicExponent));

        env->SetByteArrayRegion(modulus,0,sizeof(tmp->Modulus),(jbyte*)tmp->Modulus);
        env->SetByteArrayRegion(PublicExponent,0,sizeof(tmp->PublicExponent),(jbyte*)tmp->PublicExponent);

        env->CallVoidMethod(obj,setBitLen,(jlong)tmp->BitLen);
        env->CallVoidMethod(obj,setAlgID,(jlong)tmp->AlgID);
        env->CallVoidMethod(obj,setModulus,modulus);
        env->CallVoidMethod(obj,setPublicExponent,PublicExponent);
        env->DeleteLocalRef(modulus);
        env->DeleteLocalRef(PublicExponent);*/
    } else{
        //PECCPUBLICKEYBLOB tmp = (PECCPUBLICKEYBLOB )pBlob;
        ECCPUBLICKEYBLOB tmp;
        memcpy(&tmp,pBlob, sizeof(tmp));
        delete [] pBlob;
        pBlob = NULL;

        jclass classECCPUBLICKEYBLOB = env->FindClass("com/westone/skf/ECCPUBLICKEYBLOB");
        jmethodID init = env->GetMethodID(classECCPUBLICKEYBLOB,"<init>","()V");

        jmethodID setBitLen = env->GetMethodID(classECCPUBLICKEYBLOB,"setBitLen","(J)V");
        jmethodID setXCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"setXCoordinate","([B)V");
        jmethodID setYCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"setYCoordinate","([B)V");

        jbyteArray XCoordinate = env->NewByteArray(sizeof(tmp.XCoordinate));
        jbyteArray YCoordinate = env->NewByteArray(sizeof(tmp.YCoordinate));
        env->SetByteArrayRegion(XCoordinate,0,sizeof(tmp.XCoordinate),(jbyte*)tmp.XCoordinate);
        env->SetByteArrayRegion(YCoordinate,0,sizeof(tmp.YCoordinate),(jbyte*)tmp.YCoordinate);

        env->CallVoidMethod(obj,setBitLen,(jlong)(tmp.BitLen));
        env->CallVoidMethod(obj,setXCoordinate,XCoordinate);
        env->CallVoidMethod(obj,setYCoordinate,YCoordinate);
        env->DeleteLocalRef(XCoordinate);
        env->DeleteLocalRef(YCoordinate);
    }

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ImportSessionKey
 * Signature: (Lcom/westone/skf/HCONTAINER;JLjava/lang/Object;Lcom/westone/skf/HANDLE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ImportSessionKey
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jlong ulAlgID, jobject pbWrapedData, jobject phKey){
    if(NULL == hContainer || NULL == pbWrapedData || NULL == phKey){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHCONTAINER = env->GetObjectClass(hContainer);
    jmethodID getPointer = env->GetMethodID(classHCONTAINER,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,getPointer);

    ULONG containerType = 0;

 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_GetContainerType((HCONTAINER)pointer,&containerType);
    if(ret != SAR_OK){
        return ret;
    }

    BYTE *pData = NULL;
    ULONG dataLen = 0;
    jbyteArray cipher = NULL;
    PECCCIPHERBLOB ecccipherblob = NULL;

    if(containerType == 1){
        cipher = (jbyteArray)pbWrapedData;
        pData = (BYTE*)env->GetByteArrayElements(cipher,NULL);
        dataLen = (ULONG)env->GetArrayLength(cipher);
    } else if (containerType == 2){
        jclass classECCCIPHERBLOB = env->FindClass("com/westone/skf/ECCCIPHERBLOB");
        jmethodID getXCoordinate = env->GetMethodID(classECCCIPHERBLOB,"getXCoordinate","()[B");
        jmethodID getYCoordinate = env->GetMethodID(classECCCIPHERBLOB,"getYCoordinate","()[B");
        jmethodID getHASH = env->GetMethodID(classECCCIPHERBLOB,"getHASH","()[B");
        jmethodID getCipherLen = env->GetMethodID(classECCCIPHERBLOB,"getCipherLen","()J");
        jmethodID getCipher = env->GetMethodID(classECCCIPHERBLOB,"getCipher","()[B");

        jlong cipherLen = env->CallLongMethod(pbWrapedData,getCipherLen);

        ecccipherblob = (PECCCIPHERBLOB)new BYTE[sizeof(ECCCIPHERBLOB) + cipherLen];
        memset(ecccipherblob,0,sizeof(ECCCIPHERBLOB) + cipherLen);

        jbyteArray XCoordinate = (jbyteArray)env->CallObjectMethod(pbWrapedData,getXCoordinate);
        jbyteArray YCoordinate = (jbyteArray)env->CallObjectMethod(pbWrapedData,getYCoordinate);
        jbyteArray Hash = (jbyteArray)env->CallObjectMethod(pbWrapedData,getHASH);
        jbyteArray Cipher = (jbyteArray)env->CallObjectMethod(pbWrapedData,getCipher);

        jbyte *pXCoordinate = env->GetByteArrayElements(XCoordinate,NULL);
        jbyte *pYCoordinate = env->GetByteArrayElements(YCoordinate,NULL);
        jbyte *pHash = env->GetByteArrayElements(Hash,NULL);
        jbyte *pCipher = env->GetByteArrayElements(Cipher,NULL);

        ecccipherblob->CipherLen = (ULONG)cipherLen;
        memcpy(ecccipherblob->XCoordinate,pXCoordinate,sizeof(ecccipherblob->XCoordinate));
        memcpy(ecccipherblob->YCoordinate,pYCoordinate,sizeof(ecccipherblob->YCoordinate));
        memcpy(ecccipherblob->HASH,pHash,sizeof(ecccipherblob->HASH));
        memcpy(ecccipherblob->Cipher,pCipher,cipherLen);

        env->ReleaseByteArrayElements(XCoordinate,pXCoordinate,0);
        env->ReleaseByteArrayElements(YCoordinate,pYCoordinate,0);
        env->ReleaseByteArrayElements(Hash,pHash,0);
        env->ReleaseByteArrayElements(Cipher,pCipher,0);

        pData = (BYTE*)ecccipherblob;
        dataLen = sizeof(ECCCIPHERBLOB) + cipherLen;

    } else{
        return SAR_INVALIDHANDLEERR;
    }

    HANDLE handle = NULL;



    ret = skfFunctionList.SKF_ImportSessionKey((HCONTAINER)pointer,ulAlgID,pData,dataLen,&handle);

    if(containerType == 1){
        env->ReleaseByteArrayElements(cipher,(jbyte*)pData,0);
    } else{
        delete [] ecccipherblob;
        ecccipherblob = NULL;
    }

    if(ret != SAR_OK){
        return ret;
    }

    jclass classHANDLE = env->GetObjectClass(phKey);
    jmethodID setPointer = env->GetMethodID(classHANDLE,"setPointer","(J)V");
    env->CallVoidMethod(phKey,setPointer,(jlong)handle);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_SetSymmKey
 * Signature: (Lcom/westone/skf/DEVHANDLE;[BJLcom/westone/skf/HANDLE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1SetSymmKey
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jbyteArray pbKey, jlong ulAlgID, jobject phKey){
    if(NULL == hDev || NULL == pbKey || NULL == phKey){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHDEVHANDLE = env->GetObjectClass(hDev);
    jmethodID getPointer = env->GetMethodID(classHDEVHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,getPointer);

    BYTE *pKey = (BYTE*)env->GetByteArrayElements(pbKey,NULL);
    HANDLE handle = NULL;
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_SetSymmKey((DEVHANDLE)pointer,pKey,ulAlgID,&handle);

    env->ReleaseByteArrayElements(pbKey,(jbyte*)pKey,0);

    if(ret != SAR_OK){
        return ret;
    }

    jclass classHANDLE = env->GetObjectClass(phKey);
    jmethodID setPointer = env->GetMethodID(classHANDLE,"setPointer","(J)V");
    env->CallVoidMethod(phKey,setPointer,(jlong)handle);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_EncryptInit
 * Signature: (Lcom/westone/skf/HANDLE;Lcom/westone/skf/BLOCKCIPHERPARAM;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1EncryptInit
        (JNIEnv *env, jclass SkfNativeFunc, jobject hKey, jobject EncryptParam){
    if(NULL == hKey || NULL == EncryptParam){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHANDLE = env->GetObjectClass(hKey);
    jmethodID getPointer = env->GetMethodID(classHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hKey,getPointer);

    jclass classBLOCKCIPHERPARAM = env->GetObjectClass(EncryptParam);
    jmethodID getIV = env->GetMethodID(classBLOCKCIPHERPARAM,"getIV","()[B");
    jmethodID getIVLen = env->GetMethodID(classBLOCKCIPHERPARAM,"getIVLen","()J");
    jmethodID getFeedBitLen = env->GetMethodID(classBLOCKCIPHERPARAM,"getFeedBitLen","()J");
    jmethodID getPaddingType = env->GetMethodID(classBLOCKCIPHERPARAM,"getPaddingType","()J");

    BLOCKCIPHERPARAM blockcipherparam;
    memset(&blockcipherparam,0,sizeof(blockcipherparam));
    blockcipherparam.IVLen = env->CallLongMethod(EncryptParam,getIVLen);
    blockcipherparam.FeedBitLen = env->CallLongMethod(EncryptParam,getFeedBitLen);
    blockcipherparam.PaddingType = env->CallLongMethod(EncryptParam,getPaddingType);
    jbyteArray iv = (jbyteArray)env->CallObjectMethod(EncryptParam,getIV);
    jbyte *pIv = env->GetByteArrayElements(iv,NULL);

    memcpy(blockcipherparam.IV,pIv,env->GetArrayLength(iv) > sizeof(blockcipherparam.IV) ? sizeof(blockcipherparam.IV):env->GetArrayLength(iv));
    env->ReleaseByteArrayElements(iv,pIv,0);
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_EncryptInit((HANDLE)pointer,blockcipherparam);


    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_Encrypt
 * Signature: (Lcom/westone/skf/HANDLE;[B[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1Encrypt
        (JNIEnv *env, jclass SkfNativeFunc, jobject hKey, jbyteArray pbData, jbyteArray pbEncryptedData, jlongArray pulEncryptedLen){
    if(NULL == hKey || NULL == pbData || NULL == pulEncryptedLen){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHANDLE = env->GetObjectClass(hKey);
    jmethodID getPointer = env->GetMethodID(classHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hKey,getPointer);

    BYTE *pEnc = NULL;
    ULONG encLen = 0;

    BYTE *pData = (BYTE*)env->GetByteArrayElements(pbData,NULL);
    if(NULL != pbEncryptedData){
        pEnc = (BYTE*)env->GetByteArrayElements(pbEncryptedData,NULL);
    }

    jlong *pEncLen = env->GetLongArrayElements(pulEncryptedLen,NULL);
    encLen = (ULONG)pEncLen[0];
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_Encrypt((HANDLE)pointer,pData,env->GetArrayLength(pbData),pEnc,&encLen);


    env->ReleaseByteArrayElements(pbData,(jbyte*)pData,0);

    if(NULL != pbEncryptedData){
        env->ReleaseByteArrayElements(pbEncryptedData,(jbyte*)pEnc,0);
    }
    pEncLen[0] = (jlong)encLen;
    env->ReleaseLongArrayElements(pulEncryptedLen,pEncLen,0);
    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_EncryptUpdate
 * Signature: (Lcom/westone/skf/HANDLE;[B[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1EncryptUpdate
        (JNIEnv *env, jclass SkfNativeFunc, jobject hKey, jbyteArray pbData, jbyteArray pbEncryptedData, jlongArray pulEncryptedLen){
    if(NULL == hKey || NULL == pbData || NULL == pulEncryptedLen){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHANDLE = env->GetObjectClass(hKey);
    jmethodID getPointer = env->GetMethodID(classHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hKey,getPointer);

    BYTE *pEnc = NULL;
    ULONG encLen = 0;

    BYTE *pData = (BYTE*)env->GetByteArrayElements(pbData,NULL);
    if(NULL != pbEncryptedData){
        pEnc = (BYTE*)env->GetByteArrayElements(pbEncryptedData,NULL);
    }

    jlong *pEncLen = env->GetLongArrayElements(pulEncryptedLen,NULL);
    encLen = pEncLen[0];
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_EncryptUpdate((HANDLE)pointer,pData,env->GetArrayLength(pbData),pEnc,&encLen);


    env->ReleaseByteArrayElements(pbData,(jbyte*)pData,0);

    if(NULL != pbEncryptedData){
        env->ReleaseByteArrayElements(pbEncryptedData,(jbyte*)pEnc,0);
    }

    pEncLen[0] = (jlong)encLen;
    env->ReleaseLongArrayElements(pulEncryptedLen,(jlong*)pEncLen,0);


    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_EncryptFinal
 * Signature: (Lcom/westone/skf/HANDLE;[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1EncryptFinal
        (JNIEnv *env, jclass SkfNativeFunc, jobject hKey, jbyteArray pbEncryptedData, jlongArray pulEncryptedLen){
    if(NULL == hKey || NULL == pulEncryptedLen){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHANDLE = env->GetObjectClass(hKey);
    jmethodID getPointer = env->GetMethodID(classHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hKey,getPointer);

    BYTE *pEnc = NULL;
    jlong *pEncLen = NULL;
    ULONG encLen = 0;

    if(NULL != pbEncryptedData){
        pEnc = (BYTE*)env->GetByteArrayElements(pbEncryptedData,NULL);
    }

    pEncLen = env->GetLongArrayElements(pulEncryptedLen,NULL);
    encLen = (ULONG)pEncLen[0];
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_EncryptFinal((HANDLE)pointer,pEnc,&encLen);



    if(NULL != pbEncryptedData){
        env->ReleaseByteArrayElements(pbEncryptedData,(jbyte*)pEnc,0);
    }

    pEncLen[0] = (jlong)encLen;
    env->ReleaseLongArrayElements(pulEncryptedLen,(jlong*)pEncLen,0);
    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_DecryptInit
 * Signature: (Lcom/westone/skf/HANDLE;Lcom/westone/skf/BLOCKCIPHERPARAM;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1DecryptInit
        (JNIEnv *env, jclass SkfNativeFunc, jobject hKey, jobject DecryptParam){
    if(NULL == hKey || NULL == DecryptParam){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHANDLE = env->GetObjectClass(hKey);
    jmethodID getPointer = env->GetMethodID(classHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hKey,getPointer);

    jclass classBLOCKCIPHERPARAM = env->GetObjectClass(DecryptParam);
    jmethodID getIV = env->GetMethodID(classBLOCKCIPHERPARAM,"getIV","()[B");
    jmethodID getIVLen = env->GetMethodID(classBLOCKCIPHERPARAM,"getIVLen","()J");
    jmethodID getFeedBitLen = env->GetMethodID(classBLOCKCIPHERPARAM,"getFeedBitLen","()J");
    jmethodID getPaddingType = env->GetMethodID(classBLOCKCIPHERPARAM,"getPaddingType","()J");

    BLOCKCIPHERPARAM blockcipherparam;
    memset(&blockcipherparam,0,sizeof(blockcipherparam));
    blockcipherparam.IVLen = env->CallLongMethod(DecryptParam,getIVLen);
    blockcipherparam.FeedBitLen = env->CallLongMethod(DecryptParam,getFeedBitLen);
    blockcipherparam.PaddingType = env->CallLongMethod(DecryptParam,getPaddingType);
    jbyteArray iv = (jbyteArray)env->CallObjectMethod(DecryptParam,getIV);
    jbyte *pIv = env->GetByteArrayElements(iv,NULL);

    memcpy(blockcipherparam.IV,pIv,env->GetArrayLength(iv) > sizeof(blockcipherparam.IV) ? sizeof(blockcipherparam.IV):env->GetArrayLength(iv));
    env->ReleaseByteArrayElements(iv,pIv,0);
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_DecryptInit((HANDLE)pointer,blockcipherparam);


    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_Decrypt
 * Signature: (Lcom/westone/skf/HANDLE;[B[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1Decrypt
        (JNIEnv *env, jclass SkfNativeFunc, jobject hKey, jbyteArray pbEncryptedData, jbyteArray pbData, jlongArray pulDataLen){
    if(NULL == hKey || NULL == pbEncryptedData || NULL == pulDataLen){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHANDLE = env->GetObjectClass(hKey);
    jmethodID getPointer = env->GetMethodID(classHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hKey,getPointer);

    BYTE *pEnc = (BYTE*)env->GetByteArrayElements(pbEncryptedData,NULL);

    BYTE *pData = NULL;
    jlong *pDataLen = NULL;
    ULONG  dataLen = 0;

    if(NULL != pbData){
        pData = (BYTE*)env->GetByteArrayElements(pbData,NULL);
    }

    pDataLen = env->GetLongArrayElements(pulDataLen,NULL);
    dataLen = (ULONG)pDataLen[0];
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_Decrypt((HANDLE)pointer,pEnc,env->GetArrayLength(pbEncryptedData),pData,&dataLen);


    env->ReleaseByteArrayElements(pbEncryptedData,(jbyte*)pEnc,0);

    if(NULL != pbData){
        env->ReleaseByteArrayElements(pbData,(jbyte*)pData,0);
    }

    pDataLen[0] = dataLen;
    env->ReleaseLongArrayElements(pulDataLen,(jlong*)pDataLen,0);
    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_DecryptUpdate
 * Signature: (Lcom/westone/skf/HANDLE;[B[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1DecryptUpdate
        (JNIEnv *env, jclass SkfNativeFunc, jobject hKey, jbyteArray pbEncryptedData, jbyteArray pbData, jlongArray pulDataLen){
    if(NULL == hKey || NULL == pbEncryptedData || NULL == pulDataLen){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHANDLE = env->GetObjectClass(hKey);
    jmethodID getPointer = env->GetMethodID(classHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hKey,getPointer);

    BYTE *pEnc = (BYTE*)env->GetByteArrayElements(pbEncryptedData,NULL);

    BYTE *pData = NULL;
    jlong *pDataLen = NULL;

    if(NULL != pbData){
        pData = (BYTE*)env->GetByteArrayElements(pbData,NULL);
    }

    pDataLen = env->GetLongArrayElements(pulDataLen,NULL);
    ULONG dataLen = (ULONG)pDataLen[0];
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_DecryptUpdate((HANDLE)pointer,pEnc,env->GetArrayLength(pbEncryptedData),pData,&dataLen);


    env->ReleaseByteArrayElements(pbEncryptedData,(jbyte*)pEnc,0);

    if(NULL != pbData){
        env->ReleaseByteArrayElements(pbData,(jbyte*)pData,0);
    }

    pDataLen[0] = (jlong)dataLen;
    env->ReleaseLongArrayElements(pulDataLen,(jlong*)pDataLen,0);
    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_DecryptFinal
 * Signature: (Lcom/westone/skf/HANDLE;[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1DecryptFinal
        (JNIEnv *env, jclass SkfNativeFunc, jobject hKey, jbyteArray pbPlainText, jlongArray pulDecyptedDataLen){
    if(NULL == hKey || NULL == pulDecyptedDataLen){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHANDLE = env->GetObjectClass(hKey);
    jmethodID getPointer = env->GetMethodID(classHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hKey,getPointer);

    BYTE *pPlain = NULL;
    jlong *pPlainLen = NULL;

    if(NULL != pbPlainText){
        pPlain = (BYTE*)env->GetByteArrayElements(pbPlainText,NULL);
    }


    pPlainLen = env->GetLongArrayElements(pulDecyptedDataLen,NULL);
    ULONG plainLen = (ULONG)pPlainLen[0];
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_DecryptFinal((HANDLE)pointer,pPlain,&plainLen);

    if(NULL != pbPlainText){
        env->ReleaseByteArrayElements(pbPlainText,(jbyte*)pPlain,0);
    }

    pPlainLen[0] = (jlong)plainLen;
    env->ReleaseLongArrayElements(pulDecyptedDataLen,(jlong*)pPlainLen,0);
    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_DigestInit
 * Signature: (Lcom/westone/skf/DEVHANDLE;JLcom/westone/skf/ECCPUBLICKEYBLOB;[BLcom/westone/skf/HANDLE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1DigestInit
        (JNIEnv *env, jclass SkfNativeFunc, jobject hDev, jlong ulAlgID, jobject pPubKey, jbyteArray pucID, jobject phHash){
    if(NULL == hDev || NULL == phHash){
        return SAR_INVALIDPARAMERR;
    }

    jclass classDEVHANDLE = env->GetObjectClass(hDev);
    jmethodID getPointer = env->GetMethodID(classDEVHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,getPointer);

    ECCPUBLICKEYBLOB *pEccpublickeyblob = NULL;
    BYTE *pPucID = NULL;
    ULONG idLen = 0;

    if(NULL != pPubKey){
        jclass classECCPUBLICKEYBLOB = env->GetObjectClass(pPubKey);
        jmethodID getBitLen = env->GetMethodID(classECCPUBLICKEYBLOB,"getBitLen","()J");
        jmethodID getXCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getXCoordinate","()[B");
        jmethodID getYCoordinate = env->GetMethodID(classECCPUBLICKEYBLOB,"getYCoordinate","()[B");

        pEccpublickeyblob = new ECCPUBLICKEYBLOB();
        memset(pEccpublickeyblob,0,sizeof(ECCPUBLICKEYBLOB));

        jbyteArray eccX = (jbyteArray)env->CallObjectMethod(pPubKey,getXCoordinate);
        jbyteArray eccY = (jbyteArray)env->CallObjectMethod(pPubKey,getYCoordinate);
        jbyte *pEccX = env->GetByteArrayElements(eccX,NULL);
        jbyte *pEccY = env->GetByteArrayElements(eccY,NULL);

        pEccpublickeyblob->BitLen = env->CallLongMethod(pPubKey,getBitLen);
        memcpy(pEccpublickeyblob->XCoordinate,pEccX,sizeof(pEccpublickeyblob->XCoordinate));
        memcpy(pEccpublickeyblob->YCoordinate,pEccY,sizeof(pEccpublickeyblob->YCoordinate));

        env->ReleaseByteArrayElements(eccX,pEccX,0);
        env->ReleaseByteArrayElements(eccY,pEccY,0);

    }

    if(NULL != pucID){
        idLen = env->GetArrayLength(pucID);
        pPucID = new BYTE[idLen];
        jbyte *puc = env->GetByteArrayElements(pucID,NULL);
        memcpy(pPucID,puc,idLen);
        env->ReleaseByteArrayElements(pucID,puc,0);
    }

    HANDLE handle = NULL;
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_DigestInit((DEVHANDLE)pointer,ulAlgID,pEccpublickeyblob,pPucID,idLen,&handle);


    jclass classHANDLE = env->GetObjectClass(phHash);
    jmethodID setPointer = env->GetMethodID(classHANDLE,"setPointer","(J)V");
    env->CallVoidMethod(phHash,setPointer,(jlong)handle);

    if(NULL != pPubKey){
        delete [] pEccpublickeyblob;
        pEccpublickeyblob = NULL;
    }

    if(NULL != pucID){
        delete pPucID;
        pPucID = NULL;
    }

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_Digest
 * Signature: (Lcom/westone/skf/HANDLE;[B[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1Digest
        (JNIEnv *env, jclass SkfNativeFunc, jobject hHash, jbyteArray pbData, jbyteArray pbHashData, jlongArray pulHashLen){
    if(NULL == hHash || NULL == pbData || NULL == pulHashLen){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHANDLE = env->GetObjectClass(hHash);
    jmethodID getPointer = env->GetMethodID(classHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hHash,getPointer);

    BYTE *pData = (BYTE*)env->GetByteArrayElements(pbData,NULL);
    BYTE *pHash = NULL;
    jlong *pHashLen = NULL;

    if(NULL != pbHashData){
        pHash = (BYTE*)env->GetByteArrayElements(pbHashData,NULL);
    }

    pHashLen = env->GetLongArrayElements(pulHashLen,NULL);
    ULONG hashLen = (ULONG)pHashLen[0];
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_Digest((HANDLE)pointer,pData,env->GetArrayLength(pbData),pHash,&hashLen);


    if(NULL != pbHashData){
        LOD((unsigned char *)pHash, hashLen);
    }

    env->ReleaseByteArrayElements(pbData,(jbyte*)pData,0);

    if(NULL != pbHashData){
        env->ReleaseByteArrayElements(pbHashData,(jbyte*)pHash,0);
    }

    pHashLen[0] = (jlong)hashLen;
    env->ReleaseLongArrayElements(pulHashLen,(jlong*)pHashLen,0);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_DigestUpdate
 * Signature: (Lcom/westone/skf/HANDLE;[B)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1DigestUpdate
        (JNIEnv *env, jclass SkfNativeFunc, jobject hHash, jbyteArray pbData){
    if(NULL == hHash || NULL == pbData){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHANDLE = env->GetObjectClass(hHash);
    jmethodID getPointer = env->GetMethodID(classHANDLE,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hHash,getPointer);

    BYTE *pData = (BYTE*)env->GetByteArrayElements(pbData,NULL);
    ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_DigestUpdate((HANDLE)pointer,pData,env->GetArrayLength(pbData));

    env->ReleaseByteArrayElements(pbData,(jbyte*)pData,0);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_DigestFinal
 * Signature: (Lcom/westone/skf/HANDLE;[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1DigestFinal
        (JNIEnv * env, jclass SkfNativeFunc, jobject hHash, jbyteArray pHashData, jlongArray pulHashLen){

    if(NULL == hHash || NULL == pulHashLen){
        return SAR_INVALIDPARAMERR;
    }

    jclass classHash = env->GetObjectClass(hHash);
    jmethodID getPointer = env->GetMethodID(classHash,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hHash,getPointer);

    jbyte * pHashDataLoc = NULL;
    jlong* pulHashLenLoc = NULL;

    if(pHashData != NULL){
        pHashDataLoc = env->GetByteArrayElements(pHashData, NULL);
    }

    pulHashLenLoc = env->GetLongArrayElements(pulHashLen,NULL);
    ULONG hashLen = (ULONG)pulHashLenLoc[0];
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_DigestFinal(
            (HANDLE) pointer,
            (BYTE *)pHashDataLoc,
            &hashLen
    );

    if(NULL != pHashData){
        env->ReleaseByteArrayElements(pHashData,pHashDataLoc,0);
    }

    pulHashLenLoc[0] = (jlong)hashLen;
    env->ReleaseLongArrayElements(pulHashLen,pulHashLenLoc,0);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_MacInit
 * Signature: (Lcom/westone/skf/HANDLE;Lcom/westone/skf/BLOCKCIPHERPARAM;Lcom/westone/skf/HANDLE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1MacInit
        (JNIEnv * env, jclass SkfNativeFunc, jobject hKey, jobject MacParam, jobject phMac){

    if(NULL == hKey || NULL == MacParam || NULL == phMac){
        return SAR_INVALIDPARAMERR;
    }

    jclass classKey = env->GetObjectClass(hKey);
    jmethodID getPointer = env->GetMethodID(classKey,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hKey,getPointer);

    jclass classBLOCKCIPHERPARAM = env->GetObjectClass(MacParam);
    jmethodID getIV = env->GetMethodID(classBLOCKCIPHERPARAM,"getIV","()[B");
    jmethodID getIVLen = env->GetMethodID(classBLOCKCIPHERPARAM,"getIVLen","()J");
    jmethodID getFeedBitLen = env->GetMethodID(classBLOCKCIPHERPARAM,"getFeedBitLen","()J");
    jmethodID getPaddingType = env->GetMethodID(classBLOCKCIPHERPARAM,"getPaddingType","()J");

    BLOCKCIPHERPARAM blockcipherparam;
    memset(&blockcipherparam,0, sizeof(blockcipherparam));

    blockcipherparam.IVLen = env->CallLongMethod(MacParam,getIVLen);
    blockcipherparam.FeedBitLen = env->CallLongMethod(MacParam,getFeedBitLen);
    blockcipherparam.PaddingType = env->CallLongMethod(MacParam,getPaddingType);

    jbyteArray iv = (jbyteArray)env->CallObjectMethod(MacParam,getIV);
    jbyte *pIv = env->GetByteArrayElements(iv,NULL);

    memcpy(blockcipherparam.IV,pIv,sizeof(blockcipherparam.IV) > env->GetArrayLength(iv) ? env->GetArrayLength(iv):sizeof(blockcipherparam.IV));
    env->ReleaseByteArrayElements(iv,pIv,0);

    jclass classHANDLE = env->GetObjectClass(phMac);
    jmethodID methodSetPointer = env->GetMethodID(classHANDLE,"setPointer","(J)V");

    HANDLE handle = NULL;
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_MacInit(
            (HANDLE)pointer,
            &blockcipherparam,
            &handle
    );

    if(ret != SAR_OK){
        return ret;
    }

    env->CallVoidMethod(phMac,methodSetPointer,(jlong)handle);

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_Mac
 * Signature: (Lcom/westone/skf/HANDLE;[B[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1Mac
        (JNIEnv * env, jclass SkfNativeFunc, jobject hMac, jbyteArray pbData, jbyteArray pbMacData, jlongArray pulMacLen){
    if(NULL == hMac || pbData == NULL){
        return SAR_INVALIDPARAMERR;
    }
    jclass classMac = env->GetObjectClass(hMac);
    jmethodID getPointer = env->GetMethodID(classMac,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hMac,getPointer);

    BYTE * pbDataLoc = (BYTE*)env->GetByteArrayElements(pbData, 0);
    ULONG ulDataLenLoc = env->GetArrayLength(pbData);

    BYTE *pMacData = NULL;
    ULONG *pMacLen = NULL;

    if(NULL != pbMacData){
        pMacData = (BYTE*)env->GetByteArrayElements(pbMacData,NULL);
    }

    if(NULL != pulMacLen){
        pMacLen = (ULONG*)env->GetLongArrayElements(pulMacLen,NULL);
    }
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_Mac(
            HANDLE (pointer),
            pbDataLoc,
            ulDataLenLoc,
            pMacData,
            pMacLen
    );

    if(NULL != pbMacData){
        env->ReleaseByteArrayElements(pbMacData,(jbyte*)pMacData,0);
    }

    if(NULL != pulMacLen){
        env->ReleaseLongArrayElements(pulMacLen,(jlong*)pMacLen,0);
    }

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_MacUpdate
 * Signature: (Lcom/westone/skf/HANDLE;[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1MacUpdate
        (JNIEnv * env, jclass SkfNativeFunc, jobject hMac, jbyteArray pbData)
{
    if(NULL == hMac || pbData == NULL){
        return SAR_INVALIDPARAMERR;
    }
    jclass classMac = env->GetObjectClass(hMac);
    jmethodID getPointer = env->GetMethodID(classMac,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hMac,getPointer);

    jbyte* pbDataLoc = env->GetByteArrayElements(pbData, 0);
    ULONG ulDataLen = env->GetArrayLength(pbData);
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_MacUpdate(
            (HANDLE) pointer,
            (BYTE*) pbDataLoc,
            (ULONG) ulDataLen
    );

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_MacFinal
 * Signature: (Lcom/westone/skf/HANDLE;[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1MacFinal
        (JNIEnv * env, jclass SkfNativeFunc, jobject hMac, jbyteArray pbMacData, jlongArray pulMacDataLen)
{
    if(NULL == hMac || pulMacDataLen == NULL){
        return SAR_INVALIDPARAMERR;
    }
    jclass classMac = env->GetObjectClass(hMac);
    jmethodID getPointer = env->GetMethodID(classMac,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hMac,getPointer);

    BYTE *pMacData = NULL;
    ULONG *pMacLen = NULL;

    if(NULL != pbMacData){
        pMacData = (BYTE*)env->GetByteArrayElements(pbMacData,NULL);
    }

    if(NULL != pulMacDataLen){
        pMacLen = (ULONG*)env->GetLongArrayElements(pulMacDataLen,NULL);
    }
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_MacFinal(
            (HANDLE) pointer,
            pMacData,
            pMacLen
    );

    if(NULL != pbMacData){
        env->ReleaseByteArrayElements(pbMacData,(jbyte*)pMacData,0);
    }

    if(NULL != pulMacDataLen){
        env->ReleaseLongArrayElements(pulMacDataLen,(jlong*)pMacLen,0);
    }

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_CloseHandle
 * Signature: (Lcom/westone/skf/HANDLE;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1CloseHandle
        (JNIEnv * env, jclass SkfNativeFunc, jobject hHandle)
{
    if( NULL == hHandle )
    {
        return SAR_INVALIDPARAMERR;
    }

    jclass classHandle = env->GetObjectClass(hHandle);
    jmethodID getPointer = env->GetMethodID(classHandle,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hHandle,getPointer);

 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_CloseHandle(
            (HANDLE) pointer
    );

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_Transmit
 * Signature: (Lcom/westone/skf/DEVHANDLE;[B[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1Transmit
        (JNIEnv * env, jclass SkfNativeFunc, jobject hDev, jbyteArray pbCommand, jbyteArray pbData, jlongArray pulDataLen)
{
    if( NULL == hDev || NULL == pbCommand || NULL == pulDataLen)
    {
        return SAR_INVALIDPARAMERR;
    }

    jclass classDev = env->GetObjectClass(hDev);
    jmethodID getPointer = env->GetMethodID(classDev,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hDev,getPointer);

    BYTE * pCommand = (BYTE*)env->GetByteArrayElements(pbCommand, 0);
    ULONG pCommandLenLoc = env->GetArrayLength(pbCommand);

    BYTE *pData = NULL;
    ULONG *pLen = NULL;

    if(NULL != pbData){
        pData = (BYTE*)env->GetByteArrayElements(pbData,NULL);
    }

    if(NULL != pulDataLen){
        pLen = (ULONG*)env->GetLongArrayElements(pulDataLen,NULL);
    }
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_Transmit(
            (DEVHANDLE)pointer,
            pCommand,
            pCommandLenLoc,
            pData,
            pLen
    );

    if(NULL != pbData){
        env->ReleaseByteArrayElements(pbData,(jbyte*)pData,0);
    }

    if(NULL != pulDataLen){
        env->ReleaseLongArrayElements(pulDataLen,(jlong*)pLen,0);
    }

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ImportCertificate
 * Signature: (Lcom/westone/skf/HCONTAINER;Z[B)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ImportCertificate
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jboolean bSignFlag, jbyteArray pbCert){
    if(NULL == hContainer){
        return SAR_INVALIDPARAMERR;
    }

    /* get container handle */
    jclass classContainer = env->GetObjectClass(hContainer);
    jmethodID methodIdGet = env->GetMethodID(classContainer, "getPointer", "()J");
    jlong point = env->CallLongMethod(hContainer, methodIdGet);

    HCONTAINER hcontainer = (HCONTAINER)point;

    /* get space */
    jbyte *pbcert = env->GetByteArrayElements(pbCert, NULL);


    BOOL signFlg = FALSE;
    if(bSignFlag == JNI_TRUE){
        signFlg = TRUE;
    }
    /* import certificate */
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ImportCertificate(hcontainer, signFlg, (BYTE *)pbcert, env->GetArrayLength(pbCert));


    env->ReleaseByteArrayElements(pbCert, pbcert, 0);
    if(ret != SAR_OK){
        return ret;
    }

    return SAR_OK;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_ExportCertificate
 * Signature: (Lcom/westone/skf/HCONTAINER;Z[B[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1ExportCertificate
        (JNIEnv *env, jclass SkfNativeFunc, jobject hContainer, jboolean bSignFlag, jbyteArray pbCert, jlongArray pulCertLen){
    if(NULL == hContainer || NULL == pulCertLen){
        return SAR_INVALIDPARAMERR;
    }

    /* get container handle */
    jclass classContainer = env->GetObjectClass(hContainer);
    jmethodID methodIdGet = env->GetMethodID(classContainer, "getPointer", "()J");
    jlong point = env->CallLongMethod(hContainer, methodIdGet);

    HCONTAINER hcontainer = (HCONTAINER)point;

    /* export certificate */
    jbyte *pbcert = NULL;
    ULONG pulcertlen = 0;


    jlong * certlen = env->GetLongArrayElements(pulCertLen,NULL);
    pulcertlen = (ULONG)certlen[0];

    if(NULL != pbCert){
        pbcert = env->GetByteArrayElements(pbCert, NULL);
    }

    BOOL signFlg = FALSE;
    if(bSignFlag == JNI_TRUE){
        signFlg = TRUE;
    }
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_ExportCertificate(hcontainer, signFlg, (BYTE *)pbcert, &pulcertlen);


    LOG("SKF_ExportCertificate len = %d",pulcertlen);

    do{
        if(ret != SAR_OK){
            break;
        }
        if(NULL != pbCert){
            env->SetByteArrayRegion(pbCert, 0, pulcertlen, pbcert);
        }
        certlen[0] = (jlong)pulcertlen;
    }while(0);

    env->ReleaseLongArrayElements(pulCertLen,certlen,0);

    if(NULL != pbCert){
        env->ReleaseByteArrayElements(pbCert, pbcert, 0);
        pbcert = NULL;
    }

    return ret;
}

/*
 * Class:     com_westone_skf_SkfNativeFunc
 * Method:    SKF_GetContainerProperty
 * Signature: (Lcom/westone/skf/HCONTAINER;[J)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_skf_SkfNativeFunc_SKF_1GetContainerProperty
        (JNIEnv * env, jclass SkfNativeFunc, jobject hContainer, jlongArray pulConProperty){

    if( NULL == hContainer || NULL == pulConProperty)
    {
        return SAR_INVALIDPARAMERR;
    }

    jclass classContainer = env->GetObjectClass(hContainer);
    jmethodID getPointer = env->GetMethodID(classContainer,"getPointer","()J");
    jlong pointer = env->CallLongMethod(hContainer,getPointer);

    ULONG pulConPropertyLoc = 0;
 ULONG ret = SAR_OK;

    ret = skfFunctionList.SKF_GetContainerProperty((HAPPLICATION)pointer, &pulConPropertyLoc);

    LOG("jni SKF_GetContainerProperty === %ld",pulConPropertyLoc);
    if(!ret){
        jlong *pConProperty = env->GetLongArrayElements(pulConProperty,NULL);
        pConProperty[0] = (jlong)pulConPropertyLoc;
        env->ReleaseLongArrayElements(pulConProperty,pConProperty,0);
    }

    return ret;
}
