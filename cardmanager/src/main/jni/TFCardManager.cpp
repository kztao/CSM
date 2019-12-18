//
// Created by wang.junren on 2018/7/20.
//

#include "com_westone_cardmanager_Card.h"
#include "cryptoki.h"
#include <iostream>
#include <map>
#include <android/log.h>
#include<string>
#include <RemoteCall/ReturnCode.h>

#include "skf.h"

//#define LOG(tag,...) __android_log_print(ANDROID_LOG_INFO,tag,__VA_ARGS__)
static const char *tag = "CSM_tfcard_jni";
using namespace std;
static map<string,CK_SLOT_ID> mapCard;
static map<string,CK_SLOT_ID>::iterator it;

#define TFCARD_VERSION "3.1.8"
#define LOGI(tag,...) __android_log_print(ANDROID_LOG_DEBUG, tag, __VA_ARGS__);


//#define SOFT_CARD_EXTERN_INTERFACE

#ifdef SOFT_CARD_EXTERN_INTERFACE
CK_RV softCreateCipherCard(string token, string userName, string licSesrverAddr, string csppAddr);
CK_RV DestroyCipherCard();
#endif

/*
 * Class:     com_westone_cardmanager_Card
 * Method:    GetCard
 * Signature: ()[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL Java_com_westone_cardmanager_Card_GetCard
        (JNIEnv *env, jclass TFManager){
    CK_RV ret;
    string CardDes;
    CK_SLOT_INFO slotInfo;

    CK_SLOT_ID_PTR gloSlotIdPtr = NULL;
    CK_ULONG gloSlotNum = 0;
    LOGI(tag,"tfcard version %s",TFCARD_VERSION);

    ret = C_Initialize(NULL);
    if(ret != CKR_OK && ret != CKR_CRYPTOKI_ALREADY_INITIALIZED){
        if(ret == RETURN_CODE_ERROR_MONOPOLIZE_ALREADY)
        {
            //monopolized, return cached card list
            LOGI(tag,"monopolized,return list， size is %d", mapCard.size());
            jclass String = env->FindClass("java/lang/String");
            jobjectArray StringArray = env->NewObjectArray(mapCard.size(),String,NULL);
            it = mapCard.begin();
            for(int i = 0; i < mapCard.size();i++){
                jstring str = env->NewStringUTF((it->first).data());
                env->SetObjectArrayElement(StringArray,i,str);
                env->DeleteLocalRef(str);
                it++;
            }

            return StringArray;
        }
        LOGI(tag,"C_Initialize err = 0x%lx",ret);
        return NULL;
    }
    mapCard.clear();
    ret = C_GetSlotList(CK_TRUE,gloSlotIdPtr,&gloSlotNum);
    if(ret != CKR_OK || gloSlotNum == 0){
        LOGI(tag,"C_GetSlotList err = 0x%lx ,or gloSlotNum = 0",ret);
        return NULL;
    }

    gloSlotIdPtr = new CK_SLOT_ID[gloSlotNum];
    ret = C_GetSlotList(CK_TRUE,gloSlotIdPtr,&gloSlotNum);
    if(ret != CKR_OK || gloSlotNum == 0){
        delete [] gloSlotIdPtr;
        gloSlotIdPtr = NULL;
        LOGI(tag,"C_GetSlotList err = 0x%lx ,or gloSlotNum = 0",ret);
        return NULL;
    }

    for(int i = 0; i < gloSlotNum;i++){
        memset(&slotInfo,0, sizeof(slotInfo));
        ret = C_GetSlotInfo(gloSlotIdPtr[i],&slotInfo);
        if(ret != CKR_OK ){
            delete [] gloSlotIdPtr;
            gloSlotIdPtr = NULL;
            LOGI(tag,"C_GetSlotInfo err = 0x%lx",ret);
            return NULL;
        }
   //     int rr = memcmp(slotInfo.manufacturerID,"HDZB",strlen("HDZB"));
   //     LOG(tag,"slot %d, manufacturerID is %s, cmp result is %d",i,slotInfo.manufacturerID,rr);
        if(memcmp(slotInfo.manufacturerID,"JW",strlen("JW")) == 0){
            LOGI(tag,"find jw card");
            CardDes = "硬卡，嘉微";
        }else if(memcmp(slotInfo.manufacturerID,"HDZB",strlen("HDZB")) == 0){
            LOGI(tag,"find hd card");
            CardDes = "硬卡，华大";
        } else {
            LOGI(tag,"find sc card");
            CardDes = "软卡,卫士通";
        }

//        mapCard.insert(make_pair(CardDes,gloSlotIdPtr[i]));
        mapCard[CardDes] = gloSlotIdPtr[i];
    }

    jclass String = env->FindClass("java/lang/String");
    jobjectArray StringArray = env->NewObjectArray(gloSlotNum,String,NULL);
    it = mapCard.begin();
    for(int i = 0; i < gloSlotNum;i++){
        jstring str = env->NewStringUTF((it->first).data());
        env->SetObjectArrayElement(StringArray,i,str);
        env->DeleteLocalRef(str);
        it++;
    }

    delete [] gloSlotIdPtr;
    gloSlotIdPtr = NULL;

    return StringArray;
}

/*
 * Class:     com_westone_cardmanager_Card
 * Method:    GetCardStatus
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jintArray JNICALL Java_com_westone_cardmanager_Card_GetCardStatus
        (JNIEnv *env, jclass TFManager, jstring cardDes){
    const char *s;
    CK_STATUS_ENUM ck_status_enum = CK_STATUS_ENUM_DEVICE_OFF;
    CK_RV ret;
    jint Res[2] = {CKR_SLOT_ID_INVALID,CK_STATUS_ENUM_DEVICE_OFF};
    jintArray Return = env->NewIntArray(2);

    if(cardDes == NULL){
        env->SetIntArrayRegion(Return,0,2,Res);
        return Return;
    }

    s = env->GetStringUTFChars(cardDes,0);
    it = mapCard.find(s);
    env->ReleaseStringUTFChars(cardDes, s);

    if(it != mapCard.end()){
        ret = C_Extend_GetStatus(it->second,&ck_status_enum);
        Res[0] = ret;
        Res[1] = ck_status_enum;
    }


    env->SetIntArrayRegion(Return,0,2,Res);
    return Return;
}

static JavaVM *javaVM = NULL;
static jobject gloITFStatus = NULL;
static jmethodID Notify = NULL;

static CK_RV register_status_callback_func_(CK_SLOT_ID slotID,CK_STATUS_ENUM status){
    JNIEnv * env = NULL;
    string cardDes;
    jint ret = javaVM->GetEnv((void**)&env,JNI_VERSION_1_6);
    if(ret == JNI_EDETACHED){
        javaVM->AttachCurrentThread(&env,NULL);
    }

    for(it = mapCard.begin();it != mapCard.end();it++){
        if(it->second == slotID){
            cardDes = it->first;
        }
    }

    jstring jstring1 = env->NewStringUTF(cardDes.data());
    env->CallVoidMethod(gloITFStatus,Notify,jstring1,status);
    env->DeleteLocalRef(jstring1);

    if(ret == JNI_EDETACHED){
        javaVM->DetachCurrentThread();
    }
    return 0;
}
/*
 * Class:     com_westone_cardmanager_Card
 * Method:    RegCardStatusCallback
 * Signature: (Lcom/westone/cardmanager/ITFStatus;)V
 */
JNIEXPORT void JNICALL Java_com_westone_cardmanager_Card_RegCardStatusCallback
        (JNIEnv * env, jclass TFManager, jobject ITFStatus){
    env->GetJavaVM(&javaVM);
    gloITFStatus = env->NewGlobalRef(ITFStatus);
    jclass ITF = env->FindClass("com/westone/cardmanager/ITFStatus");
    Notify = env->GetMethodID(ITF,"Notify","(Ljava/lang/String;I)V");
    C_Extend_Register_Callback(register_status_callback_func_);
}

/*
 * Class:     com_westone_cardmanager_Card
 * Method:    Login
 * Signature: (Ljava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jlong JNICALL Java_com_westone_cardmanager_Card_Login
        (JNIEnv *env, jclass TFManager, jstring cardDes, jstring pw){
    if(cardDes == NULL || pw == NULL){
        return CKR_ARGUMENTS_BAD;
    }

    const char *des = env->GetStringUTFChars(cardDes,0);
    jlong ret = CKR_SLOT_ID_INVALID;
    CK_SLOT_ID id = 0;
    it = mapCard.find(des);
    LOGI(tag,"open loginsesion for %s",des);
    env->ReleaseStringUTFChars(cardDes,des);
    if(it != mapCard.end()){
        id = it->second;
    }else{
            return ret;
    };

    CK_SESSION_HANDLE sessionHandlelogin = 0;
    ret = C_OpenSession(id,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&sessionHandlelogin);
    if(ret != CKR_OK){
        LOGI(tag,"Login,opensession fail with ret = %lx",ret);
        return ret;
    }

    const char*pin = env->GetStringUTFChars(pw,0);
    ret = C_Login(sessionHandlelogin,CKU_USER,(CK_UTF8CHAR_PTR)pin,strlen(pin));
    env->ReleaseStringUTFChars(pw,pin);

    if(ret == CKR_OK)
    {
        LOGI(tag,"login OK");
        return ret;
    }
    LOGI(tag,"login return %lx",ret);
    C_CloseSession(sessionHandlelogin);

    return ret;
}

/*
 * Class:     com_westone_cardmanager_Card
 * Method:    ChangePin
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jlong JNICALL Java_com_westone_cardmanager_Card_ChangePin
        (JNIEnv *env, jclass TFManager, jstring cardDes, jstring oldPin, jstring newPin){
    if(cardDes == NULL || oldPin == NULL || newPin == NULL){
        return CKR_ARGUMENTS_BAD;
    }

    const char *des = env->GetStringUTFChars(cardDes,0);
    jlong ret = CKR_SLOT_ID_INVALID;
    CK_SLOT_ID id = 0;
    it = mapCard.find(des);
    env->ReleaseStringUTFChars(cardDes, des);

    if(it != mapCard.end()){
        id = it->second;
    }else{
        return ret;
    };
    CK_SESSION_HANDLE sessionHandle;
    ret = C_OpenSession(id,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&sessionHandle);
    if(ret != CKR_OK){
        return ret;
    }

    const char*pinO = env->GetStringUTFChars(oldPin,0);
    const char*pinN = env->GetStringUTFChars(newPin,0);

    ret = C_SetPIN(sessionHandle,(CK_UTF8CHAR_PTR)pinO,strlen(pinO),(CK_UTF8CHAR_PTR)pinN,strlen(pinN));
    env->ReleaseStringUTFChars(oldPin, pinO);
    env->ReleaseStringUTFChars(newPin, pinN);

    C_CloseSession(sessionHandle);

    return ret;
}

/*
 * Class:     com_westone_cardmanager_Card
 * Method:    RestUserPin
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jlongArray JNICALL Java_com_westone_cardmanager_Card_ResetUserPinwithOTP
        (JNIEnv *env, jclass TFManager, jstring cardDes, jstring OTPPin,jstring userPin){
    jlong Return[2] = {CKR_SLOT_ID_INVALID,0};
    jlongArray  Res = env->NewLongArray(2);
    env->SetLongArrayRegion(Res,0,2,Return);

    if(cardDes == NULL || OTPPin == NULL || userPin == NULL){
        env->SetLongArrayRegion(Res,0,2,Return);
        return Res;
    }

    const char *des = env->GetStringUTFChars(cardDes,0);

    CK_SLOT_ID id = 0;
    it = mapCard.find(des);
    env->ReleaseStringUTFChars(cardDes, des);

    if(it != mapCard.end()){
        id = it->second;
    }else{
        return Res;
    };
    CK_SESSION_HANDLE sessionHandle;
    Return[0] = C_OpenSession(id,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&sessionHandle);
    if(Return[0] != CKR_OK){
        env->SetLongArrayRegion(Res,0,2,Return);
        return Res;
    }

    const char*pinO = env->GetStringUTFChars(OTPPin,0);
    const char*pinN = env->GetStringUTFChars(userPin,0);
    CK_ULONG remainCount = 0;

    Return[0] = C_Extend_Reset_Pin_With_OTP(sessionHandle,(CK_UTF8CHAR_PTR)pinO,strlen(pinO),(CK_UTF8CHAR_PTR)pinN,strlen(pinN));
    env->ReleaseStringUTFChars(OTPPin, pinO);
    env->ReleaseStringUTFChars(userPin, pinN);

    if(CKR_OK != Return[0]){
        C_Extend_Get_OTP_Unlock_Count(sessionHandle,&remainCount);
        Return[1] = remainCount;

        env->SetLongArrayRegion(Res,0,2,Return);
        C_CloseSession(sessionHandle);
        return Res;
    }


    Return[0] = C_Extend_Get_OTP_Unlock_Count(sessionHandle,&remainCount);

    if(CKR_OK != Return[0]){
        env->SetLongArrayRegion(Res,0,2,Return);
        C_CloseSession(sessionHandle);
        return Res;
    }

    Return[1] = remainCount;
    Return[0] = C_CloseSession(sessionHandle);
    if(CKR_OK != Return[0]){
        env->SetLongArrayRegion(Res,0,2,Return);
        return Res;
    }

    env->SetLongArrayRegion(Res,0,2,Return);
    return Res;
}

/*
 * Class:     com_westone_cardmanager_Card
 * Method:    GetRemainLockedTimes
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jlongArray JNICALL Java_com_westone_cardmanager_Card_GetRemainLockedTimes
        (JNIEnv *env, jclass TFManager, jstring cardDes){
    jlong Return[2] = {CKR_SLOT_ID_INVALID,0};
    jlongArray  Res = env->NewLongArray(2);
    env->SetLongArrayRegion(Res,0,2,Return);

    if(cardDes == NULL){
        env->SetLongArrayRegion(Res,0,2,Return);
        return Res;
    }

    const char *des = env->GetStringUTFChars(cardDes,0);

    CK_SLOT_ID id = 0;
    it = mapCard.find(des);
    env->ReleaseStringUTFChars(cardDes, des);
    if(it != mapCard.end()){
        id = it->second;
    }else{
        return Res;
    };
    CK_SESSION_HANDLE sessionHandle;
    Return[0] = C_OpenSession(id,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&sessionHandle);
    if(Return[0] != CKR_OK){
        env->SetLongArrayRegion(Res,0,2,Return);
        return Res;
    }

    CK_ULONG remainCount=0;
    Return[0] = C_Extend_GetPinRemainCount(sessionHandle,&remainCount);

    if(CKR_OK != Return[0]){
        env->SetLongArrayRegion(Res,0,2,Return);
        C_CloseSession(sessionHandle);
        return Res;
    }

    Return[1] = remainCount;
    Return[0] = C_CloseSession(sessionHandle);
    if(CKR_OK != Return[0]){
        env->SetLongArrayRegion(Res,0,2,Return);
        return Res;
    }

    LOGI(tag,"remaincount: %lu",remainCount);
    env->SetLongArrayRegion(Res,0,2,Return);
    return Res;
}

/*
 * Class:     com_westone_cardmanager_Card
 * Method:    VerifyPin
 * Signature: (Ljava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jlong JNICALL Java_com_westone_cardmanager_Card_VerifyPin
        (JNIEnv *env, jclass TFManager, jstring cardDes, jstring pin){
    if(cardDes == NULL || pin == NULL){
        return CKR_ARGUMENTS_BAD;
    }

    const char *des = env->GetStringUTFChars(cardDes,0);
    jlong ret = CKR_SLOT_ID_INVALID;
    CK_SLOT_ID id = 0;
    it = mapCard.find(des);
    env->ReleaseStringUTFChars(cardDes, des);

    if(it != mapCard.end()){
        id = it->second;
    }else{
        return ret;
    };
    CK_SESSION_HANDLE sessionHandle;
    ret = C_OpenSession(id,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&sessionHandle);
    if(ret != CKR_OK){
        return ret;
    }

    const char*pinO = env->GetStringUTFChars(pin,0);
    const char*pw = env->GetStringUTFChars(pin,0);
    ret = C_SetPIN(sessionHandle,(CK_UTF8CHAR_PTR)pw,strlen(pw),(CK_UTF8CHAR_PTR)pw,strlen(pw));
    env->ReleaseStringUTFChars(pin, pinO);
    env->ReleaseStringUTFChars(pin, pw);

    if(CKR_OK != ret){
        C_CloseSession(sessionHandle);
        return ret;
    }

    ret = C_CloseSession(sessionHandle);

    return ret;
}


/*
 * Class:     com_westone_cardmanager_Card
 * Method:    GetCardVersionInfo
 * Signature: (Ljava/lang/String;)Lcom/westone/cardmanager/Card/JniCardUnloginInfo;
 */
JNIEXPORT jobject JNICALL Java_com_westone_cardmanager_Card_GetCardVersionInfo
        (JNIEnv *env, jclass TFManager, jstring cardDes){
    if(cardDes == NULL ){
        return NULL;
    }

    const char *s;
    CK_RV ret;
    LOGI(tag,"GetCardVersionInfo IN");
    CK_TOKEN_INFO tokeninfo = {0};
    CK_SLOT_INFO slotinfo = {0};
    CK_INFO getinfo = {0};
    s = env->GetStringUTFChars(cardDes,0);
    it = mapCard.find(s);
    env->ReleaseStringUTFChars(cardDes, s);

    if(it != mapCard.end()){
        ret = C_GetSlotInfo(it->second,&slotinfo);
        LOGI(tag,"C_GetSlotInfo end, ret = %lu", ret);

        ret = C_GetTokenInfo(it->second,&tokeninfo);
        LOGI(tag,"C_GetTokenInfo end, ret = %lu", ret);

        ret = C_GetInfo(&getinfo);
        LOGI(tag,"C_GetInfo end, ret = %lu", ret);
    }


    jclass cls =env->FindClass("com/westone/cardmanager/JniCardInfo");
    jmethodID id = env->GetMethodID(cls, "<init>", "()V");

    jobject jnicardinfo_out = env->NewObject(cls,id);
    jfieldID jpLibVersion = env->GetFieldID(cls,"pLibVersion","Ljava/lang/String;");
    jfieldID jpCardCosVersion = env->GetFieldID(cls,"pCardCosVersion","Ljava/lang/String;");
    jfieldID jpSerialNo = env->GetFieldID(cls,"pSerialNo","Ljava/lang/String;");
    jfieldID jpCardHardWareVersion = env->GetFieldID(cls,"pCardHardWareVersion","Ljava/lang/String;");
    jfieldID jpP11LibVersion = env->GetFieldID(cls,"pP11LibVersion","Ljava/lang/String;");
    jfieldID jpManufacturerID = env->GetFieldID(cls,"pManufacturerID","Ljava/lang/String;");
    jfieldID jpCryServerVersion = env->GetFieldID(cls,"pCryServerVersion","Ljava/lang/String;");

    string tmpinfo;
    char n[512]={0};

    //pLibVersion(client)
    tmpinfo.clear();
    sprintf(n,"%s",getinfo.libraryDescription);
    tmpinfo.append(n);
    jstring jstringclientversion = env->NewStringUTF(tmpinfo.data());
    env->SetObjectField(jnicardinfo_out,jpLibVersion,jstringclientversion);

    //pCardCosVersion
    tmpinfo.clear();
    sprintf(n,"%d.%d",tokeninfo.firmwareVersion.major,tokeninfo.firmwareVersion.minor);
    tmpinfo.append(n);
    jstring jcosversion = env->NewStringUTF(tmpinfo.data());
    env->SetObjectField(jnicardinfo_out,jpCardCosVersion,jcosversion);

    //pSerialNo
    tmpinfo.clear();
    CK_CHAR t_serialNumber[17] = {0};
    memcpy(t_serialNumber,tokeninfo.serialNumber,sizeof(tokeninfo.serialNumber));
    sprintf(n,"%s",t_serialNumber);
    tmpinfo.append(n);
    jstring sNO = env->NewStringUTF(tmpinfo.data());
    env->SetObjectField(jnicardinfo_out,jpSerialNo,sNO);

    //pCardHardWareVersion
    tmpinfo.clear();
    sprintf(n,"%d.%d",tokeninfo.hardwareVersion.major,tokeninfo.hardwareVersion.minor);
    tmpinfo.append(n);
    jstring jhdversion = env->NewStringUTF(tmpinfo.data());
    env->SetObjectField(jnicardinfo_out,jpCardHardWareVersion,jhdversion);

    //pP11LibVersion(from card provider)
    CK_BYTE hd_major = 1;
    CK_BYTE hd_minor = 19;
    tmpinfo.clear();
    if(s == "硬卡，华大")
    {
        sprintf(n,"%d.%d",hd_major,hd_minor);
        tmpinfo.append(n);
    }
    else
    {
        sprintf(n,"%d.%d",slotinfo.firmwareVersion.major,slotinfo.firmwareVersion.minor);
        tmpinfo.append(n);
    }

    jstring jstringp11version = env->NewStringUTF(tmpinfo.data());
    env->SetObjectField(jnicardinfo_out,jpP11LibVersion,jstringp11version);

    //pManufacturerID
    tmpinfo.clear();
    CK_CHAR t_manufacturerID[33] = {0};
    memcpy(t_manufacturerID,tokeninfo.manufacturerID,sizeof(tokeninfo.manufacturerID));
    sprintf(n,"%s",t_manufacturerID);
    tmpinfo.append(n);
    jstring manuid = env->NewStringUTF(tmpinfo.data());
    env->SetObjectField(jnicardinfo_out,jpManufacturerID,manuid);

    //pCryServerVersion
    tmpinfo.clear();
    sprintf(n,"%d.%d",getinfo.libraryVersion.major,getinfo.libraryVersion.minor);
    tmpinfo.append(n);
    jstring jstringserverversion = env->NewStringUTF(tmpinfo.data());
    env->SetObjectField(jnicardinfo_out,jpCryServerVersion,jstringserverversion);

    env->DeleteLocalRef(cls);

    return jnicardinfo_out;
}

/*
 * Class:     com_westone_cardmanager_Card
 * Method:    softCreateCipherCard
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_westone_cardmanager_Card_softCreateCipherCard
        (JNIEnv * env, jclass, jstring jtoken, jstring juserName, jstring jlicSesrverAddr, jstring jcsppAddr){
    jlong ret = 0;
#ifdef SOFT_CARD_EXTERN_INTERFACE
    if(NULL == jtoken || NULL == juserName || NULL == jlicSesrverAddr || NULL == jcsppAddr){
        return CKR_ARGUMENTS_BAD;
    }

    const char *token;
    const char *userName;
    const char *licSesrverAddr;
    const char *csppAddr;

    token = env->GetStringUTFChars(jtoken, NULL);
    userName = env->GetStringUTFChars(juserName, NULL);
    licSesrverAddr = env->GetStringUTFChars(jlicSesrverAddr, NULL);
    csppAddr = env->GetStringUTFChars(jcsppAddr, NULL);

    ret = softCreateCipherCard(token,userName,licSesrverAddr,csppAddr);

    env->ReleaseStringUTFChars(jtoken, token);
    env->ReleaseStringUTFChars(juserName, userName);
    env->ReleaseStringUTFChars(jlicSesrverAddr, licSesrverAddr);
    env->ReleaseStringUTFChars(jcsppAddr, csppAddr);

#endif

    return ret;
}

/*
 * Class:     com_westone_cardmanager_Card
 * Method:    DestroyCipherCard
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_com_westone_cardmanager_Card_DestroyCipherCard
        (JNIEnv *, jclass){
    jlong ret = 0;
#ifdef SOFT_CARD_EXTERN_INTERFACE
    ret = DestroyCipherCard();
#endif
    return ret;
}
