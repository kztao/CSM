#include "skf.h"
#include "devAndAppTest.h"
#include "generaldefine.h"
#include <android/log.h>
#include <string.h>
#include <string>
#include "sm4.h"

static DEVHANDLE	hdev = NULL;
static char pszdev[32]  = {0};
static CHAR pApp[1024] = {0};

//////正确获取设备信息
string test_getdev(){
    ULONG ulRslt = 0;
    char		*szDevName = NULL;
    ULONG		ulNameLen = 0;
    string info = "";
    ULONG pulDevState = 0;
    DEVINFO myDevInfo;
    memset(&myDevInfo, 0, sizeof(myDevInfo));

    ulRslt = SKF_EnumDev(1, NULL, &ulNameLen);
    OUT_INFO("SKF_EnumDev(null）,ulNameLen = %lu, ulRslt = %lu",ulNameLen,ulRslt);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取设备信息失败","SKF_EnumDev(null)",info);
    ASSERT_VALUE_NOT("ulNameLen",ulNameLen,0,"No card","SKF_EnumDev",info);

    if(ulNameLen>2){
        szDevName = new char[ulNameLen-2];
        ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
        delete [] szDevName;
        szDevName = NULL;
        WARNING_VALUE("ret",ulRslt,SAR_BUFFER_TOO_SMALL,"获取设备信息失败","SKF_EnumDev(short)",info);
    }

    szDevName = new char[ulNameLen];
    ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
    strncpy(pszdev,szDevName,sizeof(pszdev));
    delete [] szDevName;
    szDevName = NULL;
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取设备信息失败","SKF_EnumDev",info);
    OUT_INFO("pszdev1: %s",pszdev);

    ulRslt = SKF_GetDevState(pszdev, &pulDevState);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取设备信息失败","SKF_GetDevState",info);
    WARNING_VALUE("pulDevState",pulDevState,DEV_PRESENT_STATE,"正确获取设备信息失败","SKF_GetDevState",info);    ///????

    ulRslt = SKF_ConnectDev(pszdev, &hdev);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取设备信息失败","SKF_ConnectDev",info);
    ASSERT_VALUE_NOT("hdev",hdev,NULL,"获取设备信息失败","SKF_ConnectDev",info);

    ulRslt = SKF_GetDevState(pszdev, &pulDevState);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取设备信息失败","SKF_GetDevState",info);
    WARNING_VALUE("pulDevState",pulDevState,DEV_PRESENT_STATE,"正确获取设备信息失败","SKF_GetDevState again",info);

    ulRslt = SKF_GetDevInfo(hdev, &myDevInfo);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取设备信息失败","SKF_GetDevInfo",info);
    OUT_INFO("SKF_GetDevInfo,manufactor:%s",myDevInfo.Manufacturer);   //欣盾卡："CSIZG"

    return info;
}

/////////断开设备连接
string test_disconnectdev(){
    ULONG ulRslt = 0;
    string info = "";
    ULONG pulDevState = 0;
    DEVINFO myDevInfo;
    memset(&myDevInfo, 0, sizeof(myDevInfo));

    ulRslt = SKF_DisConnectDev(hdev);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"断开设备连接失败","SKF_DisConnectDev",info);

    ulRslt = SKF_GetDevState(pszdev, &pulDevState);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"断开设备连接失败","SKF_GetDevState",info);
    WARNING_VALUE("pulDevState",pulDevState,DEV_PRESENT_STATE,"正确获取设备信息失败","SKF_GetDevState again",info);

    ulRslt = SKF_GetDevInfo(hdev, &myDevInfo);
    ASSERT_VALUE_NOT("ret",ulRslt,SAR_OK,"断开设备连接失败","SKF_GetDevInfo",info);

    return info;
}

//枚举应用，未设备认证时，创建应用和修改认证密钥失败
string test_beforedevauth(){
    ULONG ulRslt = 0;
    string info = "";
    char		*szDevName = NULL;
    ULONG		ulNameLen = 0;
    ULONG  appSize = 0;
    HAPPLICATION appHandle = 0;

    ulRslt = SKF_EnumDev(1, NULL, &ulNameLen);
    OUT_INFO("SKF_EnumDev(null）,ulNameLen = %lu, ulRslt = %d",ulNameLen,ulRslt);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"再次获取设备失败","SKF_EnumDev(null)",info);
    ASSERT_VALUE_NOT("ulNameLen",ulNameLen,0,"No card","SKF_EnumDev",info);

    szDevName = new char[ulNameLen];
    ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
    strncpy(pszdev,szDevName,sizeof(pszdev));
    delete [] szDevName;
    szDevName = NULL;
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"再次获取设备失败","SKF_EnumDev",info);

    ulRslt = SKF_ConnectDev(pszdev, &hdev);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"再次连接设备失败","SKF_ConnectDev",info);
    ASSERT_VALUE_NOT("hdev",hdev,NULL,"再次连接设备失败","SKF_ConnectDev",info);

    ulRslt = SKF_ChangeDevAuthKey(hdev, (BYTE *)"1234567812345678", strlen("1234567812345678"));
    ASSERT_VALUE("ret",ulRslt,SAR_USER_NOT_LOGGED_IN,"修改设备口令错误码","SKF_ChangeDevAuthKey",info);

    ulRslt = SKF_EnumApplication(hdev, NULL, &appSize);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"枚举应用失败","SKF_EnumApplication",info);

    ulRslt = SKF_CreateApplication(hdev, TEST_APP_NAME, ADMIN_PIN, MAX_ADMIN_COUNT, USER_PIN, MAX_USER_COUNT, SECURE_USER_ACCOUNT, &appHandle);
    ASSERT_VALUE_NOT("ret",ulRslt,SAR_OK,"创建应用不应成功","SKF_CreateApplication",info);

    return info;
}

////////成功创建应用并修改设备认证密钥
string test_createapp(){
    ULONG ulRslt = 0;
    string info = "";
    HAPPLICATION appHandle = 0;
    ULONG  appSize = 0;
    BYTE devRandom[16];
    BYTE devAuth[16];
    ULONG devAuthLen = sizeof(devAuth);
    memset(devRandom, 0, 16);
    memset(devAuth, 0, 16);
    CHAR pApp[1024] = { 0 };

    sm4_context ctx_sm4;
    BYTE * devauthKey = (BYTE *)"1234567812345678";
    BYTE * devauthKey_new = (BYTE *)"1234567888888888";

    ulRslt = SKF_DevAuth(hdev, devAuth, devAuthLen);
    ASSERT_VALUE_NOT("ret",ulRslt,SAR_OK,"错误设备认证不应成功","SKF_DevAuth",info);

    ulRslt = SKF_CreateApplication(hdev, TEST_APP_NAME, ADMIN_PIN, MAX_ADMIN_COUNT, USER_PIN, MAX_USER_COUNT, SECURE_USER_ACCOUNT, &appHandle);
    ASSERT_VALUE_NOT("ret",ulRslt,SAR_OK,"再次创建应用不应成功","SKF_CreateApplication",info);

    ulRslt = SKF_GenRandom(hdev, devRandom, 8);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"随机数产生失败","SKF_GenRandom",info);

    sm4_setkey_enc(&ctx_sm4, devauthKey);
    sm4_crypt_ecb(&ctx_sm4, SM4_ENCRYPT, devAuthLen, devRandom, devAuth);

    ulRslt = SKF_DevAuth(hdev, devAuth, devAuthLen);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"设备认证失败","SKF_DevAuth",info);

    ulRslt = SKF_EnumApplication(hdev, NULL, &appSize);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"枚举应用失败","SKF_EnumApplication",info);
    OUT_INFO("SKF_EnumApplication, appSize = %d", appSize);

    ulRslt = SKF_EnumApplication(hdev, pApp, &appSize);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"枚举应用失败","SKF_EnumApplication",info);

    if(appSize == 0){
        ulRslt = SKF_CreateApplication(hdev, TEST_APP_NAME, ADMIN_PIN, MAX_ADMIN_COUNT, USER_PIN, MAX_USER_COUNT, SECURE_USER_ACCOUNT, &appHandle);
        ASSERT_VALUE("ret",ulRslt,SAR_OK,"创建应用失败","SKF_CreateApplication",info);
    }

    //修改认证密钥
    ulRslt = SKF_ChangeDevAuthKey(hdev, devauthKey_new, strlen((const char *)devauthKey_new));
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"修改认证密钥失败","SKF_ChangeDevAuthKey",info);

    memset(devRandom, 0, 16);
    memset(devAuth, 0, 16);
    ulRslt = SKF_GenRandom(hdev, devRandom, 8);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"随机数产生失败","SKF_GenRandom",info);

    sm4_setkey_enc(&ctx_sm4, devauthKey_new);
    sm4_crypt_ecb(&ctx_sm4, SM4_ENCRYPT, devAuthLen, devRandom, devAuth);
    ulRslt = SKF_DevAuth(hdev, devAuth, devAuthLen);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"修改后设备认证失败","SKF_DevAuth",info);

    //恢复原设备认证密钥
    ulRslt = SKF_ChangeDevAuthKey(hdev, devauthKey, strlen((const char *)devauthKey));
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"恢复原认证密钥失败","SKF_ChangeDevAuthKey",info);

    return info;
}

//////////重复创建已存在的应用
string test_createexistapp(){
    ULONG ulRslt = 0;
    string info = "";
    HAPPLICATION appHandle = 0;
    ULONG  appSize = 0;

    ulRslt = SKF_EnumApplication(hdev, NULL, &appSize);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"枚举应用失败(exist)","SKF_EnumApplication",info);
    ASSERT_VALUE_NOT("appSize",appSize,0,"没有应用","SKF_EnumApplication",info);

    ulRslt = SKF_EnumApplication(hdev, pApp, &appSize);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"枚举应用失败","SKF_EnumApplication",info);

    ulRslt = SKF_CreateApplication(hdev, pApp, ADMIN_PIN, MAX_ADMIN_COUNT, USER_PIN, MAX_USER_COUNT, SECURE_USER_ACCOUNT, &appHandle);
    ASSERT_VALUE_NOT("ret",ulRslt,SAR_OK,"创建应用不应用成功","SKF_CreateApplication",info);

    return info;
}

//////////删除应用(无认证权限和有权限)
string test_deleteapp(){
    ULONG ulRslt = 0;
    string info = "";
    ULONG  appSize = 0;
    ULONG  appSize_after = 0;
    BYTE devRandom[16];
    BYTE devAuth[16];
    ULONG devAuthLen = sizeof(devAuth);
    memset(devRandom, 0, 16);
    memset(devAuth, 0, 16);

    sm4_context ctx_sm4;
    BYTE * devauthKey = (BYTE *)"1234567812345678";

    ulRslt = SKF_DisConnectDev(hdev);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"断开连接失败","SKF_DisConnectDev",info);

    ulRslt = SKF_ConnectDev(pszdev, &hdev);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"断开后连接设备失败","SKF_ConnectDev",info);
    ASSERT_VALUE_NOT("hdev",hdev,NULL,"断开后连接设备失败","SKF_ConnectDev",info);

    ulRslt = SKF_DeleteApplication(hdev, pApp);
    ASSERT_VALUE_NOT("ret",ulRslt,SAR_OK,"删除应用不应成功","SKF_DeleteApplication",info);

    ulRslt = SKF_EnumApplication(hdev, NULL, &appSize);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"枚举应用失败(exist)","SKF_EnumApplication",info);
    ASSERT_VALUE_NOT("appSize",appSize,0,"没有应用","SKF_EnumApplication",info);

    memset(devRandom, 0, 16);
    memset(devAuth, 0, 16);
    ulRslt = SKF_GenRandom(hdev, devRandom, 8);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"随机数产生失败","SKF_GenRandom",info);

    sm4_setkey_enc(&ctx_sm4, devauthKey);
    sm4_crypt_ecb(&ctx_sm4, SM4_ENCRYPT, devAuthLen, devRandom, devAuth);
    ulRslt = SKF_DevAuth(hdev, devAuth, devAuthLen);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"设备认证失败","SKF_DevAuth",info);

    ulRslt = SKF_DeleteApplication(hdev, pApp);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"删除应用失败","SKF_DeleteApplication",info);

    ulRslt = SKF_EnumApplication(hdev, NULL, &appSize_after);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"删除后枚举应用失败","SKF_EnumApplication",info);
    if(appSize_after>=appSize){
        char n[1024*1024]={0};
        info.append("删除后枚举应用错误! ");
        sprintf(n,"appSize_after=%d, appSize=%d\n",appSize_after,appSize);
        info.append(n);
        return info;
    }

    return info;
}

string skf_DevandAppTest(){
    string info = "";

    info.append(test_getdev());
    if(info!=""){
        info.append("test_getdev fail!");
        return info;
    }

    info.append(test_disconnectdev());
    if(info!=""){
        info.append("test_disconnectdev fail!");
        return info;
    }

    info.append(test_beforedevauth());
    if(info!=""){
        info.append("test_beforedevauth fail!");
        return info;
    }

    info.append(test_createapp());
    if(info!=""){
        info.append("test_createapp fail!");
        return info;
    }

    info.append(test_createexistapp());
    if(info!=""){
        info.append("test_createexistapp fail!");
        return info;
    }

    info.append(test_deleteapp());
    if(info!=""){
        info.append("test_deleteapp fail!");
        return info;
    }

    return info;
}
