#include "skf.h"
#include "pinVerificationTest.h"
#include "generaldefine.h"
#include <android/log.h>
#include <string.h>
#include <string>
#include "sm4.h"

static DEVHANDLE	hdev = NULL;
static char pszdev[32]  = {0};
static CHAR pApp[1024] = {0};
static HAPPLICATION appHandle = 0;

///////////重新创建应用并打开
string test_createAppandOpen(){
    ULONG ulRslt = 0;
    string info = "";
    char		*szDevName = NULL;
    ULONG		ulNameLen = 0;
    ULONG  appSize = 0;
    ULONG  appSize_after = 0;

    BYTE devRandom[16];
    BYTE devAuth[16];
    ULONG devAuthLen = sizeof(devAuth);
    memset(devRandom, 0, 16);
    memset(devAuth, 0, 16);
    sm4_context ctx_sm4;
    BYTE * devauthKey = (BYTE *)"1234567812345678";

    ulRslt = SKF_EnumDev(1, NULL, &ulNameLen);
    OUT_INFO("SKF_EnumDev(null）,ulNameLen = %lu, ulRslt = %d",ulNameLen,ulRslt);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取设备失败","SKF_EnumDev(null)",info);
    ASSERT_VALUE_NOT("ulNameLen",ulNameLen,0,"No card","SKF_EnumDev",info);

    szDevName = new char[ulNameLen];
    ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
    strncpy(pszdev,szDevName,sizeof(pszdev));
    delete [] szDevName;
    szDevName = NULL;
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取设备失败","SKF_EnumDev",info);

    ulRslt = SKF_ConnectDev(pszdev, &hdev);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"连接设备失败","SKF_ConnectDev",info);
    ASSERT_VALUE_NOT("hdev",hdev,NULL,"连接设备失败","SKF_ConnectDev",info);

    ulRslt = SKF_EnumApplication(hdev, NULL, &appSize);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"枚举应用失败","SKF_EnumApplication",info);

    ulRslt = SKF_GenRandom(hdev, devRandom, 8);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"随机数产生失败","SKF_GenRandom",info);

    sm4_setkey_enc(&ctx_sm4, devauthKey);
    sm4_crypt_ecb(&ctx_sm4, SM4_ENCRYPT, devAuthLen, devRandom, devAuth);

    ulRslt = SKF_DevAuth(hdev, devAuth, devAuthLen);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"设备认证失败","SKF_DevAuth",info);

    ulRslt = SKF_CreateApplication(hdev, TEST_APP_NAME, ADMIN_PIN, MAX_ADMIN_COUNT, USER_PIN, MAX_USER_COUNT, SECURE_USER_ACCOUNT, &appHandle);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"创建应用失败","SKF_CreateApplication",info);

    ulRslt = SKF_DisConnectDev(hdev);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"断开连接失败","SKF_DisConnectDev",info);

    ulRslt = SKF_ConnectDev(pszdev, &hdev);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"连接设备失败","SKF_ConnectDev",info);
    ASSERT_VALUE_NOT("hdev",hdev,NULL,"连接设备失败","SKF_ConnectDev",info);

    ulRslt = SKF_EnumApplication(hdev, pApp, &appSize_after);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"创建后枚举应用失败","SKF_EnumApplication",info);
    if(appSize_after<=appSize){
        char n[1024*1024]={0};
        info.append("重新创建后枚举应用错误! ");
        sprintf(n,"appSize_after=%d, appSize=%d\n",appSize_after,appSize);
        info.append(n);
        return info;
    }

    ulRslt = SKF_OpenApplication(hdev, pApp, &appHandle);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"打开应用失败","SKF_OpenApplication",info);
    ASSERT_VALUE("appHandle",NULL,SAR_OK,"打开应用失败","SKF_OpenApplication",info);

    return info;
}

/////////正确校验并重复校验应用用户PIN码
string test_verifypin(){
    ULONG ulRslt = 0;
    string info = "";
    ULONG  remainC = 0;
    ULONG maxRe = 0;
    BOOL def;

    for(int i= 0 ;i<2;++i){
        ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, USER_PIN, &remainC);
        ASSERT_VALUE("ret",ulRslt,SAR_OK,"验证用户PIN失败","SKF_VerifyPIN",info);
        WARNING_VALUE("remainCount",remainC,MAX_USER_COUNT,"验证用户PIN成功输出次数","SKF_VerifyPIN",info);

        ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
        ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
        ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
        ASSERT_VALUE("remainCount",remainC,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    }

    return info;
}

///////错误校验应用用户PIN码,并在正确校验后恢复
string test_verifypinErrorandRecover(){
    ULONG ulRslt = 0;
    string info = "";
    ULONG  remainC = 0;
    ULONG maxRe = 0;
    BOOL def;
    int tmp_time = MAX_USER_COUNT;

    for(int i= 0 ;i<2;++i){
        ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, USER_PIN_WRONG, &remainC);
        ASSERT_VALUE("ret",ulRslt,SAR_PIN_INCORRECT,"验证错误PIN不应成功","SKF_VerifyPIN",info);
        tmp_time = tmp_time-1;
        ASSERT_VALUE("remainCount",remainC,tmp_time,"验证用户PIN失败输出次数","SKF_VerifyPIN",info);

        ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
        ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
        ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
        ASSERT_VALUE("remainCount",remainC,tmp_time,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    }

    ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, USER_PIN, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"验证用户PIN失败","SKF_VerifyPIN",info);
    WARNING_VALUE("remainCount",remainC,MAX_USER_COUNT,"验证用户PIN成功输出次数","SKF_VerifyPIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);

    return info;
}

////////使用错误原PIN修改PIN
string test_changepinerror(){
    ULONG ulRslt = 0;
    string info = "";
    ULONG  remainC = 0;
    ULONG maxRe = 0;
    BOOL def;
    int tmp_time = MAX_USER_COUNT;

    ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);

    ulRslt = SKF_ChangePIN(appHandle, USER_TYPE,USER_PIN_WRONG, USER_PIN_NEW, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_PIN_INCORRECT,"修改PIN不应成功","SKF_ChangePIN",info);
    tmp_time = tmp_time-1;
    ASSERT_VALUE("remainCount",remainC,tmp_time,"修改PIN错误输出次数","SKF_ChangePIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,tmp_time,"获取用户PIN信息失败","SKF_GetPINInfo",info);

    ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, USER_PIN_WRONG, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_PIN_INCORRECT,"验证错误PIN不应成功","SKF_VerifyPIN",info);
    tmp_time = tmp_time-1;
    ASSERT_VALUE("remainCount",remainC,tmp_time,"验证用户PIN失败输出次数","SKF_VerifyPIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,tmp_time,"获取用户PIN信息失败","SKF_GetPINInfo",info);

    return info;
}

////////使用正确原PIN修改PIN
string test_changepin(){
    ULONG ulRslt = 0;
    string info = "";
    ULONG  remainC = 0;
    ULONG maxRe = 0;
    BOOL def;

    ulRslt = SKF_ChangePIN(appHandle, USER_TYPE,USER_PIN, USER_PIN_NEW, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"修改PIN失败","SKF_ChangePIN",info);
    WARNING_VALUE("remainCount",remainC,MAX_USER_COUNT,"修改PIN输出次数","SKF_ChangePIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);

    ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, USER_PIN_NEW, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"验证新PIN失败","SKF_VerifyPIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);

    ulRslt = SKF_ChangePIN(appHandle, USER_TYPE,USER_PIN_NEW, USER_PIN, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"修改PIN失败","SKF_ChangePIN",info);

    return info;
}

//////////使用长度过短的PIN验证和修改PIN
string test_shortpin(){
    ULONG ulRslt = 0;
    string info = "";
    ULONG  remainC = 0;
    ULONG maxRe = 0;
    BOOL def;

    ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, "12345", &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_PIN_LEN_RANGE,"验证PIN长度短失败","SKF_VerifyPIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);

    ulRslt = SKF_ChangePIN(appHandle, USER_TYPE,"12345", USER_PIN_NEW, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_PIN_LEN_RANGE,"验证PIN长度短失败","SKF_ChangePIN",info);
    ASSERT_VALUE("remainCount",remainC,MAX_USER_COUNT,"修改PIN输出次数","SKF_ChangePIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);

    return info;
}

///////////锁死用户PIN
string test_lockpin(){
    ULONG ulRslt = 0;
    string info = "";
    ULONG  remainC = 0;
    ULONG maxRe = 0;
    BOOL def;
    int tmp_time = MAX_USER_COUNT;

    for(int i = 0 ;i<MAX_USER_COUNT;++i){
        ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, USER_PIN_WRONG, &remainC);
        ASSERT_VALUE("ret",ulRslt,SAR_PIN_INCORRECT,"验证错误PIN不应成功","SKF_VerifyPIN",info);
        tmp_time = tmp_time-1;
        ASSERT_VALUE("remainCount",remainC,tmp_time,"验证用户PIN失败输出次数","SKF_VerifyPIN",info);

        ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
        ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
        ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
        ASSERT_VALUE("remainCount",remainC,tmp_time,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    }

    ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, USER_PIN_WRONG, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_PIN_LOCKED,"验证用户PIN应返回锁定","SKF_VerifyPIN",info);
    ASSERT_VALUE("remainCount",remainC,0,"验证用户PIN输出次数应为0","SKF_VerifyPIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,0,"获取用户PIN信息失败","SKF_GetPINInfo",info);

    ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, USER_PIN, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_PIN_LOCKED,"验证用户PIN应返回锁定","SKF_VerifyPIN",info);
    ASSERT_VALUE("remainCount",remainC,0,"验证用户PIN输出次数应为0","SKF_VerifyPIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,0,"获取用户PIN信息失败","SKF_GetPINInfo",info);

    ulRslt = SKF_ChangePIN(appHandle, USER_TYPE,USER_PIN, USER_PIN_NEW, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_PIN_LOCKED,"修改PIN应失败","SKF_ChangePIN",info);
    ASSERT_VALUE("remainCount",remainC,0,"验证用户PIN输出次数应为0","SKF_ChangePIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,0,"获取用户PIN信息失败","SKF_GetPINInfo",info);

    return info;
}

////////锁死用户PIN后解锁(错误PIN及正确PIN)
string test_unlockpin(){
    ULONG ulRslt = 0;
    string info = "";
    ULONG  remainC = 0;
    ULONG maxRe = 0;
    BOOL def;
    int tmp_time = MAX_USER_COUNT;

    ulRslt = SKF_UnblockPIN(appHandle, ADMIN_PIN_WRONG, USER_PIN, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_PIN_INCORRECT,"错误解锁应失败","SKF_UnblockPIN",info);

    ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, USER_PIN, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_PIN_LOCKED,"验证用户PIN应返回锁定","SKF_VerifyPIN",info);
    ASSERT_VALUE("remainCount",remainC,0,"验证用户PIN输出次数应为0","SKF_VerifyPIN",info);

    ulRslt = SKF_UnblockPIN(appHandle, ADMIN_PIN, USER_PIN, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"解锁PIN失败","SKF_UnblockPIN",info);

    ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, USER_PIN, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"验证用户PIN失败","SKF_VerifyPIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, USER_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,MAX_USER_COUNT,"获取用户PIN信息失败","SKF_GetPINInfo",info);

    return info;
}

///////////锁死admin PIN
string test_lockadminpin(){
    ULONG ulRslt = 0;
    string info = "";
    ULONG  remainC = 0;
    ULONG maxRe = 0;
    BOOL def;
    int tmp_time = MAX_ADMIN_COUNT;

    for(int i = 0 ;i<MAX_ADMIN_COUNT;++i){
        ulRslt = SKF_VerifyPIN(appHandle, ADMIN_TYPE, ADMIN_PIN_WRONG, &remainC);
        ASSERT_VALUE("ret",ulRslt,SAR_PIN_INCORRECT,"验证错误adminPIN不应成功","SKF_VerifyPIN",info);
        tmp_time = tmp_time-1;
        ASSERT_VALUE("remainCount",remainC,tmp_time,"验证adminPIN失败输出次数","SKF_VerifyPIN",info);

        ulRslt = SKF_GetPINInfo(appHandle, ADMIN_TYPE, &maxRe, &remainC, &def);
        ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取用户PIN信息失败","SKF_GetPINInfo",info);
        ASSERT_VALUE("maxCount",maxRe,MAX_ADMIN_COUNT,"获取adminPIN信息失败","SKF_GetPINInfo",info);
        ASSERT_VALUE("remainCount",remainC,tmp_time,"获取adminPIN信息失败","SKF_GetPINInfo",info);
    }

    ulRslt = SKF_VerifyPIN(appHandle, ADMIN_TYPE, ADMIN_PIN_WRONG, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_PIN_LOCKED,"验证adminPIN应返回锁定","SKF_VerifyPIN",info);
    ASSERT_VALUE("remainCount",remainC,0,"验证adminPIN输出次数应为0","SKF_VerifyPIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, ADMIN_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取adminPIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取adminPIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,0,"获取adminPIN信息失败","SKF_GetPINInfo",info);

    ulRslt = SKF_VerifyPIN(appHandle, ADMIN_TYPE, ADMIN_PIN, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_PIN_LOCKED,"验证adminPIN应返回锁定","SKF_VerifyPIN",info);
    ASSERT_VALUE("remainCount",remainC,0,"验证adminPIN输出次数应为0","SKF_VerifyPIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, ADMIN_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取adminPIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取adminPIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,0,"获取adminPIN信息失败","SKF_GetPINInfo",info);

    ulRslt = SKF_ChangePIN(appHandle, ADMIN_TYPE,ADMIN_PIN_WRONG, ADMIN_PIN, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_PIN_LOCKED,"修改adminPIN应失败","SKF_ChangePIN",info);
    ASSERT_VALUE("remainCount",remainC,0,"验证adminPIN输出次数应为0","SKF_ChangePIN",info);

    ulRslt = SKF_GetPINInfo(appHandle, ADMIN_TYPE, &maxRe, &remainC, &def);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取adminPIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("maxCount",maxRe,MAX_USER_COUNT,"获取adminPIN信息失败","SKF_GetPINInfo",info);
    ASSERT_VALUE("remainCount",remainC,0,"获取adminPIN信息失败","SKF_GetPINInfo",info);

    return info;
}

string test_recoverapp(){
    ULONG ulRslt = 0;
    string info = "";
    char		*szDevName = NULL;
    ULONG		ulNameLen = 0;
    ULONG  appSize = 0;
    ULONG  appSize_after = 0;

    BYTE devRandom[16];
    BYTE devAuth[16];
    ULONG devAuthLen = sizeof(devAuth);
    memset(devRandom, 0, 16);
    memset(devAuth, 0, 16);
    sm4_context ctx_sm4;
    BYTE * devauthKey = (BYTE *)"1234567812345678";

    ulRslt = SKF_GenRandom(hdev, devRandom, 8);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"随机数产生失败","SKF_GenRandom",info);

    sm4_setkey_enc(&ctx_sm4, devauthKey);
    sm4_crypt_ecb(&ctx_sm4, SM4_ENCRYPT, devAuthLen, devRandom, devAuth);

    ulRslt = SKF_DevAuth(hdev, devAuth, devAuthLen);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"设备认证失败","SKF_DevAuth",info);

    ulRslt = SKF_EnumApplication(hdev, pApp, &appSize_after);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"创建后枚举应用失败","SKF_EnumApplication",info);

    ulRslt = SKF_DeleteApplication(hdev, pApp);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"删除应用失败","SKF_DeleteApplication",info);

    info.append(test_createAppandOpen());

    return info;
}


string skf_pinVerifyTest(){
    string info = "";

    info.append(test_createAppandOpen());
    if(info!=""){
        info.append("test_createAppandOpen fail!");
        return info;
    }

    info.append(test_verifypin());
    if(info!=""){
        info.append("test_verifypin fail!");
        return info;
    }

    info.append(test_verifypinErrorandRecover());
    if(info!=""){
        info.append("test_verifypinError fail!");
        return info;
    }

    info.append(test_changepinerror());
    if(info!=""){
        info.append("test_changepinerror fail!");
        return info;
    }

    info.append(test_changepin());
    if(info!=""){
        info.append("test_changepin fail!");
        return info;
    }

    info.append(test_shortpin());
    if(info!=""){
        info.append("test_shortpin fail!");
        return info;
    }

    info.append(test_lockpin());
    if(info!=""){
        info.append("test_shortpin fail!");
        return info;
    }

    info.append(test_unlockpin());
    if(info!=""){
        info.append("test_unlockpin fail!");
        return info;
    }

    info.append(test_lockadminpin());
    if(info!=""){
        info.append("test_lockadminpin fail!");
        return info;
    }

    info.append(test_recoverapp());
    if(info!=""){
        info.append("test_recoverapp fail!");
        return info;
    }

    return info;
}
