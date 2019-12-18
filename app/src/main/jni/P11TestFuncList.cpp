//
// Created by wang.junren on 2018/7/6.
//

#include "P11TestFuncList.h"
#include <sys/time.h>
#include <time.h>
#include "sm3.h"
#include "Encrypt.h"
#include <android/log.h>

struct timeval t1,t2;

CK_ULONG_PTR slotList;
CK_SLOT_ID testslot = -1;

CK_SESSION_HANDLE hSession = 0;

void TimeStart(){
    gettimeofday(&t1,NULL);
}

long TimeEnd(){
    gettimeofday(&t2,NULL);
    return  (t2.tv_sec - t1.tv_sec) * 1000 + (t2.tv_usec - t1.tv_usec) / 1000;
}

string DataArray(string sm, long x) {
    string out;
    char num[1024] = {0};
    out.append("\n\t\t\t");
    out.append(sm);
    sprintf(num,"\t\t\t\t\t\t\t0x%08lx",x);
    out.append(num);
    out.append("\n\n");

    return out;
}

string DataArray(string sm, unsigned char *data, int len) {
    string out;
    out.append("\n\t\t\t");
    out.append(sm);
    out.append("\n\t\t\t\t\t\t");
    char num[3] = {0};
    for(int i = 0 ; i < len;i++){
        sprintf(num,"%02x",data[i]);
        out.append(num);
        if((i + 1) % 4 == 0){
            out.append(" ");
        }
    }
    out.append("\n\n");
    return out;
}

void* get_server_status(unsigned int status){
    __android_log_print(ANDROID_LOG_INFO,"csm_TestApp","get_server_status: %d", status);
    return NULL;
}

#define LOGI(tag,...) __android_log_print(ANDROID_LOG_INFO,tag,__VA_ARGS__)
#define LOGE(tag,...) __android_log_print(ANDROID_LOG_ERROR,tag,__VA_ARGS__)
#define LOGD(tag,...) __android_log_print(ANDROID_LOG_DEBUG,tag,__VA_ARGS__)


void P11TestFuncList::BaseFunc(string userPin,string soPin,register_status_callback_func func) {
    string info;
    char n[1024 * 1024] = {0};
    CK_ULONG UlDevInfoLen = 0;
    long ret = 0;

    TimeStart();
    ret = Register_Exception_Notify_Callback(get_server_status);
    Save("Register_Exception_Notify_Callback",ret,"",TimeEnd());
    if(0 != ret){return ;}

    TimeStart();
    ret= C_Initialize(NULL);
    Save("C_Initialize",ret,"",TimeEnd());

    TimeStart();
    ret = C_Extend_Register_Callback
    (
            func
            //NULL_PTR
    );
    Save("C_Extend_Register_Callback",ret,"",TimeEnd());
    if(0 != ret){return ;}

    CK_ULONG num = 0;
    TimeStart();

    ret = C_GetSlotList(CK_TRUE,NULL,&num);
    sprintf(n,"%ld",num);
    info = DataArray("slot count = ",num);

    Save("C_GetSlotList NULL",ret,info,TimeEnd());
    if(ret != 0 || num == 0) {
        if(func){
            __android_log_print(ANDROID_LOG_INFO,"csm_TestApp","Before call func1");
            func(0,CK_STATUS_ENUM_DEVICE_OFF);
            __android_log_print(ANDROID_LOG_INFO,"csm_TestApp","End call func1");
            return;
        }
    }

    slotList = new CK_ULONG[num];
    TimeStart();
    ret = C_GetSlotList(CK_TRUE,slotList,&num);
    info.clear();
    info.append("num: ");
    sprintf(n,"%d",num);
    info.append(n);

    for(int i = 0;i < num;i++){
        if(func){
            __android_log_print(ANDROID_LOG_INFO,"csm_TestApp","Before call func");
     //       func(slotList[i],CK_STATUS_ENUM_UNLOGIN);
            __android_log_print(ANDROID_LOG_INFO,"csm_TestApp","End call func");
        }
  //      info = DataArray("slot ID = ",slotList[i]);
        info.append("slot ");
        sprintf(n,"%d: ",i);
        info.append(n);
        sprintf(n,"%d",slotList[i]);
        info.append(n);
    }
    Save("C_GetSlotList",ret,info,TimeEnd());

    if(ret != 0) return;

    TimeStart();
    CK_SLOT_INFO slotInfo;

    int i = 0;

    for(i = 0; i < num;i++){
        ret = C_GetSlotInfo(slotList[i],&slotInfo);
        if(ret != 0)
        {
            info.clear();
            info.append("i: ");
            sprintf(n,"%d:",i);
            info.append(n);
            sprintf(n,"slotid: 0x%08lx",slotList[i]);
            info.append(n);
            Save("C_GetSlotInfo",ret,info,TimeEnd());
            return;
        }

        info.clear();
        info.append(DataArray("slotInfo.firmwareVersion.major",&slotInfo.firmwareVersion.major,1));
        info.append(DataArray("slotInfo.firmwareVersion.minor",&slotInfo.firmwareVersion.minor,1));
        info.append(DataArray("slotInfo.hardwareVersion.major",&slotInfo.hardwareVersion.major,1));
        info.append(DataArray("slotInfo.hardwareVersion.minor",&slotInfo.hardwareVersion.minor,1));

        info.append(DataArray("slotInfo.flags",slotInfo.flags));
        for(int i = 0 ; i < 32; i++){
            if(slotInfo.manufacturerID[i] == 0x20){
                slotInfo.manufacturerID[i] = 0;
                break;
            }
        }

        info.append("\t\t\tslotInfo.manufacturerID = ");
        info.append((const char*)slotInfo.manufacturerID);
        info.append("\n\n");
        info.append(DataArray("slotInfo.slotDescription",slotInfo.slotDescription,64));
        info.append("\n");

        Save("C_GetSlotInfo",ret,info,TimeEnd());

        if(memcmp(slotInfo.manufacturerID,"JW",strlen("JW")) == 0){
            testslot = slotList[i];
        }else if(memcmp(slotInfo.manufacturerID,"HDZB",strlen("HDZB")) == 0){
            testslot = slotList[i];
        } else if(memcmp(slotInfo.manufacturerID,"westone",strlen("westone")) == 0){
//              testslot = slotList[i];
        } else{
            testslot = -1;
            __android_log_print(ANDROID_LOG_ERROR,"csm_TestApp","testslot ERROR!");
            return;
        }
    }

    LOGI("csm_testApp", "testslot is %d", testslot);
    for(int i=0;i<1;i++){
        TimeStart();
        info.clear();
        ret = C_OpenSession(testslot,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL_PTR,NULL_PTR,&hSession);
        Save("C_OpenSession",ret,info,TimeEnd());
        if(ret != 0) return;
    }




    CK_USER_TYPE userType = CKU_USER;
    if(userPin.length() == 0){
        Save("C_Login User",ret,"User Pin len = 0",TimeEnd());
        return;
    }

    TimeStart();
    info.clear();
    ret = C_Login(hSession,userType,(CK_UTF8CHAR_PTR)userPin.data(),userPin.length());
    Save("C_Login User",ret,info,TimeEnd());
 //   if(ret != 0 && ret != CKR_USER_ALREADY_LOGGED_IN) return;

//    TimeStart();
//    info.clear();
//    ret = C_SetPIN(hSession,(CK_UTF8CHAR_PTR)userPin.data(),userPin.length(),(CK_UTF8CHAR_PTR)"987654",strlen("987654"));
//    Save("C_SetPIN User",ret,info,TimeEnd());

    CK_ULONG UiRemainCount = 0;

    for(int i=0;i<1000;i++)
    {

        __android_log_print(ANDROID_LOG_INFO,"csm_Test","loop %d",i);

        ret = C_Extend_GetPinRemainCount(hSession,&UiRemainCount);
//        info.append("userpin remain count:");
//        sprintf(n,"%d",UiRemainCount);
//        info.append(n);
//        Save("C_Extend_GetPinRemainCount",ret,info,TimeEnd());
        if(ret != 0) return;
    }

    TimeStart();
    info.clear();
    ret = C_Extend_GetPinRemainCount(hSession,&UiRemainCount);
    info.append("userpin remain count:");
    sprintf(n,"%d",UiRemainCount);
    info.append(n);
    Save("C_Extend_GetPinRemainCount",ret,info,TimeEnd());
    if(ret != 0) return;

//    TimeStart();
//    info.clear();
//    ret = C_SetPIN(hSession,(CK_UTF8CHAR_PTR)userPin.data(),userPin.length(),(CK_UTF8CHAR_PTR)userPin.data(),userPin.length());
//    Save("C_SetPIN",ret,info,TimeEnd());
//
//    TimeStart();
//    info.clear();
//    ret = C_Extend_GetPinRemainCount(hSession,&UiRemainCount);
//    info.append("userpin remain count:");
//    sprintf(n,"%d",UiRemainCount);
//    info.append(n);
//    Save("C_Extend_GetPinRemainCount",ret,info,TimeEnd());
//    if(ret != 0) return;

#if 0
    TimeStart();
    CK_IP_PARAMS ipparam = {0};
    const char * ip = "192.168.2.118";
    memcpy(ipparam.ip, ip, strlen(ip));
    ipparam.oWayPort = 39069;
    ipparam.tWayPort = 39068;
    ret = C_Extend_GetDevInfo(testslot, "13618079709",&ipparam,NULL, &UlDevInfoLen);
    info.clear();
    info.append("UlDevInfoLen: ");
    sprintf(n,"%d",UlDevInfoLen);
    info.append(n);
    Save("C_Extend_GetDevInfo NULL",ret,info,TimeEnd());
    if(ret != 0)
        return;

    CK_BYTE_PTR DevInfo = NULL_PTR;
    DevInfo = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * UlDevInfoLen);
    memset(DevInfo,0,UlDevInfoLen);
    info.clear();
    info.append("UlDevInfoLen1: ");
    sprintf(n,"%d",UlDevInfoLen);
    info.append(n);

    TimeStart();
    ret = C_Extend_GetDevInfo(testslot, "13618079709",&ipparam,DevInfo, &UlDevInfoLen);

    info.append("UlDevInfoLen2: ");
    sprintf(n,"%d",UlDevInfoLen);
    info.append(n);
 /*   info.append(", DevInfo: 0x");
    for(int i=0;i<UlDevInfoLen;i++)
    {
        if(i%4 == 0 && i%16!=0)
        {
            info.append(" ");
        }
        if(i%16 == 0)
        {
            info.append("\n");
        }
        sprintf(n,"%02x",DevInfo[i]);
        info.append(n);
    }
*/
    Save("C_Extend_GetDevInfo",ret,info,TimeEnd());
    free(DevInfo);
    if(ret !=0)
        return;


    CK_BYTE test[64] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
    };
    CK_BYTE signature[128] = {0};
    CK_ULONG     ulSignatureLen = 128;

    TimeStart();
    ret = C_Extend_DevSign(testslot,test,sizeof(test),NULL,&ulSignatureLen);
    info.clear();
    info.append("ulSignatureLen: ");
    sprintf(n,"%d",ulSignatureLen);
    info.append(n);
    Save("C_Extend_DevSign",ret,info,TimeEnd());

    TimeStart();
    ret = C_Extend_DevSign(testslot,test,sizeof(test),signature,&ulSignatureLen);
    info.clear();
    info.append("ulSignatureLen: ");
    sprintf(n,"%d",ulSignatureLen);
    info.append(n);
    info.append("signature: 0x");
    for(int i=0;i<64;i++)
    {
        sprintf(n,"%02x",signature[i]);
        info.append(n);
    }

    Save("C_Extend_DevSign",ret,info,TimeEnd());
#endif
}

void P11TestFuncList::testthreadFunc(string userPin) {
    string info;
    char n[1024 * 1024] = {0};

    long ret = C_Initialize(NULL);

    CK_ULONG num = 0;
    int loop = 0;
    CK_ULONG slotList_test[3] = {0};

    CK_SLOT_INFO slotInfo;
    CK_SLOT_ID testslot1 = -1;
    int i = 0;
    CK_SESSION_HANDLE hSession_test = 0;

    for(loop = 0;loop<1;loop++)
    {
        __android_log_print(ANDROID_LOG_INFO,"csm_Testthread","loop %d",loop);

        ret = C_GetSlotList(CK_TRUE,NULL,&num);

        ret = C_GetSlotList(CK_TRUE,slotList_test,&num);
        if(ret != 0) return;


        for(i = 0; i < num;i++){

            ret = C_GetSlotInfo(slotList_test[i],&slotInfo);
            if(ret != 0)
            {
                return;
            }

            if(memcmp(slotInfo.manufacturerID,"JW",strlen("JW")) == 0){
                testslot1 = slotList_test[i];
            }else if(memcmp(slotInfo.manufacturerID,"HDZB",strlen("HDZB")) == 0){
                testslot1 = slotList_test[i];
            } else if(memcmp(slotInfo.manufacturerID,"westone",strlen("westone")) == 0){

            } else{
                testslot1 = -1;
                __android_log_print(ANDROID_LOG_ERROR,"csm_Testthread","testslot ERROR!");
                return;
            }
        }

        LOGI("csm_Testthread", "testslot1 is %d", testslot1);

        if(hSession_test==0)
        {
            ret = C_OpenSession(testslot1,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL_PTR,NULL_PTR,&hSession_test);
        }
        if(ret != 0) return;

        CK_USER_TYPE userType = CKU_USER;
        if(userPin.length() == 0){
            return;
        }
//
//        ret = C_Login(hSession_test,userType,(CK_UTF8CHAR_PTR)userPin.data(),userPin.length());
//        if(ret != 0 && ret != CKR_USER_ALREADY_LOGGED_IN) return;
//
//        CK_ULONG UiRemainCount = 0;
//        ret = C_Extend_GetPinRemainCount(hSession_test,&UiRemainCount);
//        if(ret != 0) return;
    }
}

void P11TestFuncList::ObjDataFunc() {
    CK_ULONG ret;
    string info;

    CK_OBJECT_CLASS dataClass = CKO_DATA;

    CK_ATTRIBUTE attributeClear[] = {
            {CKA_CLASS,&dataClass, sizeof(dataClass)}
    };

    TimeStart();
    ret = C_FindObjectsInit(hSession,attributeClear,1);
    Save("C_FindObjectsInit",ret,info,TimeEnd());
    if(ret != 0) return;

    CK_OBJECT_HANDLE dd;
    CK_ULONG num = 0;

    while(1){
        TimeStart();
        ret = C_FindObjects(hSession,&dd,1,&num);
        Save("C_FindObjects",ret,DataArray("find data class obj num = ",num),TimeEnd());
        if(ret != 0 || num == 0){
            break;
        }

        if(ret == 0){
            ret = C_DestroyObject(hSession,dd);
            Save("C_DestroyObject",ret,"",TimeEnd());
        }
    }


    CK_OBJECT_HANDLE object_handle;
    const char *Label = "";
    const char *Application = "";

    CK_BYTE ttrue = TRUE,ffalse = FALSE;
    const char dataValue[16] = {
            1,2,3,4,
            5,6,7,8,
            9,10,11,12,
            13,14,15,16
    };

    CK_ATTRIBUTE attributeData[] = {
            {CKA_LABEL,(CK_VOID_PTR)"Label",strlen("Label")},
            {CKA_APPLICATION,(CK_VOID_PTR)"Application",strlen("Application")},
            {CKA_CLASS,&dataClass, sizeof(dataClass)},
            {CKA_TOKEN,&ttrue, sizeof(ttrue)},
            {CKA_VALUE,(CK_VOID_PTR)dataValue, sizeof(dataValue)}
    };


    TimeStart();
    ret = C_CreateObject(hSession,attributeData, sizeof(attributeData) / sizeof(CK_ATTRIBUTE),&object_handle);
    Save("C_CreateObject",ret,info,TimeEnd());
    if(ret != 0) {
        ret = C_CloseSession(hSession);
        return;}

    CK_ATTRIBUTE attributeDataValue[] = {
            {CKA_VALUE,NULL,0}
    };

    TimeStart();
    ret = C_GetAttributeValue(hSession,object_handle,attributeDataValue, sizeof(attributeDataValue) /
            sizeof(CK_ATTRIBUTE));
    Save("C_GetAttributeValue null ",ret,DataArray("data len = ",attributeDataValue[0].ulValueLen),TimeEnd());
    if(ret != 0) {
        ret = C_CloseSession(hSession);
        return;
    }

    if(attributeDataValue[0].ulValueLen != sizeof(dataValue)){
        Save("C_GetAttributeValue",ret,DataArray("correct data len should be = ",sizeof(dataValue)),TimeEnd());
        ret = C_CloseSession(hSession);
        return;
    }

    attributeDataValue[0].pValue = new CK_BYTE[attributeDataValue[0].ulValueLen];
    TimeStart();
    ret = C_GetAttributeValue(hSession,object_handle,attributeDataValue, sizeof(attributeDataValue) /
                                                                         sizeof(CK_ATTRIBUTE));
    Save("C_GetAttributeValue",ret,DataArray("data = ",
                                             (CK_BYTE_PTR)attributeDataValue[0].pValue,attributeDataValue[0].ulValueLen),TimeEnd());
    if(ret != 0) {delete[](attributeDataValue[0].pValue);
        attributeDataValue[0].pValue = NULL;
        ret = C_CloseSession(hSession);
        return;}

    delete[](attributeDataValue[0].pValue);
    attributeDataValue[0].pValue = NULL;

    const char NewData[20] = {
            20,19,18,17,
            16,15,14,13,
            12,11,10,9,
            8,7,6,5,
            4,3,2,1
    };
    CK_ATTRIBUTE attributeDataValueNew[] = {
            {CKA_VALUE,(CK_VOID_PTR)NewData, sizeof(NewData)}
    };

    TimeStart();
    ret = C_SetAttributeValue(hSession,object_handle,attributeDataValueNew, sizeof(attributeDataValueNew) /
            sizeof(CK_ATTRIBUTE));
    Save("C_SetAttributeValue",ret,info,TimeEnd());

    TimeStart();
    ret = C_GetAttributeValue(hSession,object_handle,attributeDataValue, sizeof(attributeDataValue) /
                                                                         sizeof(CK_ATTRIBUTE));
    Save("C_GetAttributeValue null ",ret,DataArray("data len = ",attributeDataValue[0].ulValueLen),TimeEnd());
    if(ret != 0) {
        ret = C_CloseSession(hSession);
        return;
    }

    if(attributeDataValue[0].ulValueLen != sizeof(NewData)){
        Save("C_GetAttributeValue",ret,DataArray("correct data len should be = ",sizeof(dataValue)),TimeEnd());
        ret = C_CloseSession(hSession);
        return;
    }

    attributeDataValue[0].pValue = new CK_BYTE[attributeDataValue[0].ulValueLen];
    TimeStart();
    ret = C_GetAttributeValue(hSession,object_handle,attributeDataValue, sizeof(attributeDataValue) /
                                                                         sizeof(CK_ATTRIBUTE));
    Save("C_GetAttributeValue",ret,DataArray("new data = ",
                                             (CK_BYTE_PTR)attributeDataValue[0].pValue,attributeDataValue[0].ulValueLen),TimeEnd());
    if(ret != 0) {delete[](attributeDataValue[0].pValue);
        attributeDataValue[0].pValue = NULL;
        ret = C_CloseSession(hSession);
        return;}

    delete[](attributeDataValue[0].pValue);
    attributeDataValue[0].pValue = NULL;

    TimeStart();
    ret = C_DestroyObject(hSession,object_handle);
    Save("C_DestroyObject",ret,"",TimeEnd());
    if(ret != 0){
        return;
    }

/*    TimeStart();
    ret = C_CloseSession(hSession);
    Save("C_CloseSession",ret,"",TimeEnd());
    if(ret != 0){
        return;
    }
*/
}


void P11TestFuncList::ObjKeyFunc() {
    CK_ULONG ret;
    CK_SESSION_HANDLE handle;

    TimeStart();
    ret = C_OpenSession(slotList[0],CKF_SERIAL_SESSION | CKF_RW_SESSION,NULL,NULL,&handle);
    Save("C_OpenSession ObjKeyFunc",ret,"",TimeEnd());
    if(0 != ret){
        return;
    }

    CK_KEY_TYPE key_type_sm4 = CKK_SM4,key_type_sm2 = CKK_SM2;
    CK_OBJECT_CLASS
            object_class_sm4 = CKO_SECRET_KEY,
            object_class_sm2_pub = CKO_PUBLIC_KEY,
            object_class_sm2_pri = CKO_PRIVATE_KEY;

    CK_BYTE ttrue = TRUE,ffalse = FALSE;
    CK_BYTE sm4Value[16] = {
        2,3,4,5,
        8,6,4,5,
        1,2,3,7,
        8,6,5,1
    };

    CK_ATTRIBUTE attribute_sm4[] = {
            {CKA_CLASS,&object_class_sm4, sizeof(object_class_sm4)},
            {CKA_LABEL,(CK_VOID_PTR)"sm4",strlen("sm4")},
            {CKA_LOCAL,&ffalse, sizeof(ffalse)},
            {CKA_ENCRYPT,&ttrue, sizeof(ttrue)},
            {CKA_DECRYPT,&ttrue, sizeof(ttrue)},
            {CKA_WRAP,&ttrue, sizeof(ttrue)},
            {CKA_UNWRAP,&ttrue, sizeof(ttrue)},
            {CKA_VALUE,sm4Value, sizeof(sm4Value)},
            {CKA_KEY_TYPE,&key_type_sm4, sizeof(key_type_sm4)}
    };

    CK_OBJECT_HANDLE object_handle;

    TimeStart();
    ret = C_CreateObject(handle,attribute_sm4, sizeof(attribute_sm4) / sizeof(CK_ATTRIBUTE),&object_handle);
    Save("C_CreateObject ObjKeyFunc",ret,"",TimeEnd());
    if(0 != ret){
        return;
    }
    TimeStart();
    ret = C_DestroyObject(hSession,object_handle);
    Save("C_DestroyObject sm4 key",ret,"",TimeEnd());
    if(0 != ret){
        return;
    }

}


void P11TestFuncList::ObjFunc() {
    ObjDataFunc();
   // ObjKeyFunc();
}

void P11TestFuncList::SM2KeyFunc() {
    CK_RV ret;
    CK_SESSION_HANDLE session_handle;

    TimeStart();
    ret = C_OpenSession(slotList[0],CKF_SERIAL_SESSION | CKF_RW_SESSION,NULL,NULL,&session_handle);
    Save("C_OpenSession SM2KeyFunc",ret,"",TimeEnd());
    if(0 != ret){
        return;
    }


    CK_OBJECT_HANDLE handlePub;
    CK_OBJECT_HANDLE handlePri;
    CK_BYTE ttrue = CK_TRUE;
    CK_BYTE ffalse = CK_FALSE;

    CK_BYTE      idid[] = {0x01,0x01,0x01,0x03};
    CK_MECHANISM      ECCMechanism = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_KEY_TYPE  ECCKeyType = CKK_SM2;
    CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY,priclass=CKO_PRIVATE_KEY;
    CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_LABEL,(CK_VOID_PTR)"testSM2",strlen("testSM2")},
            {CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)},
            {CKA_WRAP, &ttrue, sizeof(CK_BBOOL)},
            {CKA_KEY_TYPE,&ECCKeyType,sizeof(CK_KEY_TYPE)},
            {CKA_SENSITIVE, &ffalse, sizeof(CK_BBOOL)},
            {CKA_ID, idid, sizeof(idid)},
            {CKA_ISEXCHANGEKEY, &ttrue, sizeof(CK_BBOOL)}
    };
    CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_LABEL,(CK_VOID_PTR)"testSM2",strlen("testSM2")},
            {CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)},
            {CKA_PRIVATE, &ttrue, sizeof(CK_BBOOL)},
            {CKA_SENSITIVE, &ttrue, sizeof(CK_BBOOL)},
            {CKA_UNWRAP, &ttrue, sizeof(CK_BBOOL)},
            {CKA_KEY_TYPE,&ECCKeyType,sizeof(CK_KEY_TYPE)},
            {CKA_ID, idid, sizeof(idid)},
            {CKA_ISEXCHANGEKEY, &ttrue, sizeof(CK_BBOOL)}
    };



    TimeStart();
    ret = C_GenerateKeyPair(hSession,&ECCMechanism,publicKeyTemplate,
                            sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE) - 1,
                            privateKeyTemplate,sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE) - 1,
                      &handlePub,&handlePri);
    Save("C_GenerateKeyPair general",ret,DataArray("pub handle = ",handlePub),TimeEnd());
    Save("C_GenerateKeyPair general",ret,DataArray("pri handle = ",handlePri),TimeEnd());

    if(0 != ret){
        return;
    }

    //对Key进行查找和属性的后续修改
    CK_ATTRIBUTE findPub[] = {
            {CKA_LABEL,(CK_VOID_PTR)"testSM2",strlen("testSM2")},
            {CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_ID, idid, sizeof(idid)}
    };

    CK_ATTRIBUTE findPri[] = {
            {CKA_LABEL,(CK_VOID_PTR)"testSM2",strlen("testSM2")},
            {CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_ID, idid, sizeof(idid)}
    };

    TimeStart();
    ret = C_FindObjectsInit(hSession,findPub, sizeof(findPub) / sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit pub",ret,"",TimeEnd());
    if(0 != ret){
        return;
    }

    CK_OBJECT_HANDLE pubH[10];
    CK_OBJECT_HANDLE priH[10];
    CK_ULONG pubHN,priHN;

    TimeStart();
    ret = C_FindObjects(hSession,pubH, sizeof(pubH),&pubHN);
    Save("C_FindObjects pub",ret,DataArray("find pub num = ",pubHN),TimeEnd());
    if(0 != ret){
        return;
    }

    TimeStart();
    ret = C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal pub",ret,"",TimeEnd());
    if(0 != ret){
        return;
    }


    for(int i = 0; i < pubHN;i++){
        TimeStart();
        ret = C_FindObjectsFinal(hSession);
        Save("C_FindObjectsFinal pub",ret,"",TimeEnd());
        if(0 != ret){
            return;
        }
    }

    TimeStart();
    ret = C_DestroyObject(hSession,handlePub);
    Save("C_DestroyObject pub",ret,"",TimeEnd());
    if(0 != ret){
        return;
    }

    TimeStart();
    ret = C_DestroyObject(hSession,handlePri);
    Save("C_DestroyObject pri",ret,"",TimeEnd());
    if(0 != ret){
        return;
    }



    /******************************************打包的公私钥对的测试****************************************************/
    TimeStart();
    ret = C_GenerateKeyPair(hSession,&ECCMechanism,publicKeyTemplate, sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
                            privateKeyTemplate,sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
                            &handlePub,&handlePri);
    Save("C_GenerateKeyPair wrap",ret,DataArray("pub handle = ",handlePub),TimeEnd());
    Save("C_GenerateKeyPair wrap",ret,DataArray("pri handle = ",handlePri),TimeEnd());

    if(0 != ret){
        return;
    }

    TimeStart();
    ret = C_DestroyObject(hSession,handlePub);
    Save("C_DestroyObject pub wrap",ret,"",TimeEnd());
    if(0 != ret){
        return;
    }

    TimeStart();
    ret = C_DestroyObject(hSession,handlePri);
    Save("C_DestroyObject pri wrap",ret,"",TimeEnd());
    if(0 != ret){
        return;
    }

}


void P11TestFuncList::KeyFunc() {
 //   SM2KeyFunc();
 //   xtest_SM2_keytest();
 //   xtest_generatekeytest();
    xtest_symkey_test();

}

void P11TestFuncList::EncFunc() {
   // xtest_SM4_KEY(CKM_SM4_ECB);
   // xtest_SM2calcimportkey(1, 32);
    xtest_wrapkeybyBKtest();
}

void P11TestFuncList::SignFunc() {
    xtest_SM2_signtest();
}

void P11TestFuncList::RndFunc() {

}



void P11TestFuncList::ExtFunc() {
//    checkOTP();
    SCdestroyKey();
}

void P11TestFuncList::SCsetup()
{
    setcokek();
//    OTPupdate();
//    checkOTP();
//    BKupdate();
    TTupdate();
    setDestroyRND();
}

void P11TestFuncList::calltest()
{
    TT();
}

void P11TestFuncList::DigFunc()
{
    long ret = 0;
    string info;
    char n[1024 * 1024] = {0};

    int i = 0;
    CK_BYTE srcData[64] = {0};
    for(i = 0;i < sizeof(srcData)/4;i++)
    {
        memcpy(&srcData[i*4],"abcd",4);
    }
    unsigned char pszCorrectResult_SM3[]={0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d, 0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32};
    CK_BYTE digData[100]= {0};
    CK_ULONG ulDigLen=32;

    CK_MECHANISM mechanism={CKM_HASH_SM3,NULL_PTR,0};


    TimeStart();
    SM3_Data(srcData, sizeof(srcData), digData, 32);
    info.clear();
    info.append("SM3 DAta = ");
    for(int i = 0 ; i < 32;i++){
        sprintf(n,"%02x",digData[i]);
        info.append(n);
    }

    ret = 0;
    Save("C_DigestSoft",ret,info,TimeEnd());


    TimeStart();
    ret = C_DigestInit(hSession,&mechanism);
    Save("C_DigestInit",ret,"mechanism",TimeEnd());

    ulDigLen=sizeof(digData);
    info.clear();
    TimeStart();
    ret = C_Digest(hSession,srcData,sizeof(srcData),digData,&ulDigLen);

    info.append("2 段式,");
    info.append(DataArray("\n结果是",digData,ulDigLen));

    if (memcmp(pszCorrectResult_SM3, digData, ulDigLen))
    {
        info.append(DataArray("正确结果应该是",pszCorrectResult_SM3, sizeof(pszCorrectResult_SM3)));
      //  sprintf(n,"%d",ulDigLen);
      //  info.append(n);
    } else
    {
        info.append("正确！");
    }
    Save("C_Digest",ret,info,TimeEnd());

    TimeStart();
    ret=C_DigestInit(hSession,&mechanism);
    Save("C_DigestInit",ret,"",TimeEnd());

    TimeStart();
    ret=C_DigestUpdate(hSession,srcData,sizeof(srcData)/2);
    Save("C_DigestUpdate",ret,"",TimeEnd());

    TimeStart();
    ret = C_DigestUpdate(hSession,srcData+sizeof(srcData)/2,sizeof(srcData)-sizeof(srcData)/2);
    Save("C_DigestUpdate",ret,"",TimeEnd());

    ulDigLen=sizeof(digData);
    info.clear();
    TimeStart();
    ret = C_DigestFinal(hSession,digData,&ulDigLen);

    info.append("3 段式,");
    info.append(DataArray("\n结果是",digData,ulDigLen));

    if (memcmp(pszCorrectResult_SM3, digData, ulDigLen))
    {
        info.append(DataArray("正确结果应该是",pszCorrectResult_SM3, sizeof(pszCorrectResult_SM3)));
    }
    else
    {
        info.append("正确！");
    }
    Save("C_DigestFinal",ret,info,TimeEnd());
}


long** P11TestFuncList::SM2_PerTest(long count, long length, string &dst) {
    long * timeCount = new long[count];


    for(long i = 0;i < count;i++){
        timeCount[i] = i + 5;
    }

    return &timeCount;
}

long** P11TestFuncList::SM4_PerTest(long which, long count, long length, string &dst) {
    long * timeCount = new long[count];
    for(long i = 0;i < count;i++){
        timeCount[i] = i + 7;
    }
    return &timeCount;
}

static bool zucFlg = false;

void P11TestFuncList::Zuc_PerTest(int count, int length, string &dst, long *mtimes) {
    if(zucFlg == false){
        TT();
        zucFlg = true;
    }

    memset(mtimes,0, sizeof(long) * count);

    CK_RV rv= 0;
    char desc[1024] = {0};
    CK_MECHANISM ZUCmechanism = {CKM_ZUC_EEA, NULL, 0};
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL ttrue = CK_TRUE;
    CK_BBOOL ffalse = CK_FALSE;
    CK_KEY_TYPE SessKeyExchangeKeyType = CKK_SESSKEY_EXCHANGE;
    CK_BYTE keyID3 = CK_SESSKEY_ID2;
    CK_ATTRIBUTE SessKeyDeriveTemplate[] =
        {
                {CKA_CLASS, &keyClass, sizeof(keyClass)},
                {CKA_TOKEN, &ffalse, sizeof(ffalse)},
                {CKA_KEY_TYPE, &SessKeyExchangeKeyType, sizeof(CK_KEY_TYPE)},
                {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
                {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
                {CKA_SESSKEY_ID, &keyID3, sizeof(CK_BYTE)}
        };

    rv = C_Extend_EncryptInit(hSession,&ZUCmechanism,SessKeyDeriveTemplate,sizeof(SessKeyDeriveTemplate)/sizeof(CK_ATTRIBUTE));
    if(rv != 0){
        sprintf(desc,"C_Extend_EncryptInit error = 0x%08x",rv);
        dst.clear();
        dst.append(desc);
        return;
    }

    rv = C_Extend_DecryptInit(hSession, &ZUCmechanism, SessKeyDeriveTemplate,sizeof(SessKeyDeriveTemplate)/sizeof(CK_ATTRIBUTE));
    if(rv != 0){
        sprintf(desc,"C_Extend_DecryptInit error = 0x%08x",rv);
        dst.clear();
        dst.append(desc);
        return;
    }

    unsigned char	ZUCiv[16];

    CK_BYTE_PTR indata = NULL,outdata = NULL;
    CK_ULONG indatalen = 0,outdatalen = 0;

    indata = new CK_BYTE[length];
    outdata = new CK_BYTE[length];
    indatalen = outdatalen = length;

    for(int i = 0; i < count;i++){
        TimeStart();
        rv = C_Extend_EncryptUpdate(hSession, ZUCiv, 16, indata, indatalen, outdata, &outdatalen);
        if(rv != 0){
            sprintf(desc,"C_Extend_EncryptUpdate [%d times] error = 0x%08x",i + 1,rv);
            dst.clear();
            dst.append(desc);
            delete [] indata;
            delete [] outdata;
            return;
        }

        rv = C_Extend_DecryptUpdate(hSession, ZUCiv, 16,outdata,outdatalen, indata, &indatalen);
        if(rv != 0){
            sprintf(desc,"C_Extend_DecryptUpdate [%d times]error = 0x%08x",i+ 1,rv);
            dst.clear();
            dst.append(desc);
            delete [] indata;
            delete [] outdata;
            return;
        }

        mtimes[i] = TimeEnd() / 2;
    }

    rv = C_Extend_EncryptFinalize(hSession,outdata,&outdatalen);

    rv = C_Extend_DecryptFinalize(hSession,outdata,&outdatalen);

    delete [] indata;
    delete [] outdata;

}


long** P11TestFuncList::Zuc_PerTest(long count, long length, string &dst) {
    if(zucFlg == false){
        TT();
        zucFlg = true;
    }

    long * timeCount = new long[count];
    memset(timeCount,0,count);
    int i = 0;

    CK_RV rv=0;
    string info;
    char n[1024*1024]={0};

    CK_MECHANISM ZUCmechanism_Enc = {CKM_ZUC_EEA, NULL, 0};
    CK_MECHANISM ZUCmechanism_Dec = {CKM_ZUC_EEA, NULL, 0};

    CK_SESSION_HANDLE session = hSession;

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL ttrue = CK_TRUE;
    CK_BBOOL ffalse = CK_FALSE;
    CK_KEY_TYPE SessKeyExchangeKeyType = CKK_SESSKEY_EXCHANGE;
    CK_BYTE keyID3 = CK_SESSKEY_ID2;
    CK_ATTRIBUTE SessKeyDeriveTemplate[] =
    {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_TOKEN, &ffalse, sizeof(ffalse)},
            {CKA_KEY_TYPE, &SessKeyExchangeKeyType, sizeof(CK_KEY_TYPE)},
            {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
            {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
            {CKA_SESSKEY_ID, &keyID3, sizeof(CK_BYTE)}
    };


    srand( (unsigned)time( NULL ) );

    rv = C_Extend_EncryptInit(session,&ZUCmechanism_Enc,SessKeyDeriveTemplate,sizeof(SessKeyDeriveTemplate)/sizeof(CK_ATTRIBUTE));
    rv = C_Extend_DecryptInit(session, &ZUCmechanism_Dec, SessKeyDeriveTemplate,sizeof(SessKeyDeriveTemplate)/sizeof(CK_ATTRIBUTE));

    unsigned char	ZUCplain[256] = {0};
    unsigned char	ZUCiv_Enc[16] = {0};
    unsigned char	ZUCiv_Dec[16] = {0};

    CK_BYTE indata[141] = {0};
    CK_ULONG indatalen=sizeof(indata);
    CK_BYTE outdata[141] = {0};
    CK_ULONG outdatalen=sizeof(outdata);

    CK_BYTE indata1[141] = {0};
    CK_ULONG indatalen1=sizeof(indata1);
    CK_BYTE outdata1[141] = {0};
    CK_ULONG outdatalen1=sizeof(outdata1);

    for(i = 0;i < count;i++){
        memset(ZUCplain,0,length);
        outdatalen1=sizeof(outdata1);
        memset(outdata1,0,outdatalen1);

        //生成随机数明文
        RandomGenerate(ZUCplain,length);
        //生成随机数初始向量
        RandomGenerate(ZUCiv_Enc,16);

        //for test
        memset(ZUCplain,0x01,length);
        memset(ZUCiv_Enc,0x01,16);
        //

        memcpy(indata, ZUCplain, length);
        indatalen = length;
        memcpy(ZUCiv_Dec,ZUCiv_Enc,16);

        /*******************????**********************/

        TimeStart();
        rv = C_Extend_EncryptUpdate(session, ZUCiv_Enc, 16, indata, indatalen, outdata, &outdatalen);
        timeCount[i] = TimeEnd();


        /******************????***********************/
        memcpy(indata1, outdata, outdatalen);
        indatalen1 = outdatalen;

        rv = C_Extend_DecryptUpdate(session, ZUCiv_Dec, 16,indata1,indatalen1, outdata1, &outdatalen1);

        if ((outdatalen1 != length) || (memcmp(outdata1, ZUCplain, outdatalen1)))
        {
            //Error
           /* __android_log_print(ANDROID_LOG_INFO,"csm_testApp_p11testfunclist","ZUCper calc ERROR! len = %ld,i=%d",outdatalen1,i);

            __android_log_print(ANDROID_LOG_INFO,"csm_testApp_p11testfunclist","outdata1:%d",outdatalen1);

            Print_Data("csm_testApp_p11testfunclist outdata1 ",outdata1,length);

            Print_Data("csm_testApp_p11testfunclist ZUCplain",ZUCplain,outdatalen1);*/

            rv = C_Extend_EncryptFinalize(session,outdata,&outdatalen);

            rv = C_Extend_DecryptFinalize(session,outdata1,&outdatalen1);

            return &timeCount;

        }

    }

    rv = C_Extend_EncryptFinalize(session,outdata,&outdatalen);

    rv = C_Extend_DecryptFinalize(session,outdata1,&outdatalen1);

    return &timeCount;
}