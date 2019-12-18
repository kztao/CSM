#include <jni.h>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

#include <iostream>
#include <set>
#include <android/log.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skf.h"
#ifdef __cplusplus
};
#endif

//#include "cryptoki.h"

#include "skf.pb.h"
#include "Return.pb.h"
#include "RemoteCall.h"

#include "LocalSocketClient.h"
#include "BinderClient.h"


using std::string;
using std::set;
using namespace google::protobuf;
using namespace com::westone::returncode;
using namespace com::westone::skf;

#define LOGI(tag,...)  __android_log_print(ANDROID_LOG_INFO, tag, __VA_ARGS__)
#define LOGE(tag,...)  __android_log_print(ANDROID_LOG_ERROR, tag, __VA_ARGS__)
#define LOGD(tag,...)  __android_log_print(ANDROID_LOG_DEBUG, tag, __VA_ARGS__)

#define OPERATION_TIMEOUT 10000

static const char* tag = "csm_Client";

static int CommStatus = CLIENT_DISCONNECTED;
//static NotifyFunc commNotifyFunc = NULL;

static void CommClientStatus(int status){
    CommStatus = status;
  /*  if(NULL != commNotifyFunc){
        commNotifyFunc(status);
    }*/
}

//static CommunicationClient *pClient = new LocalSocketClient((char*)LOCAL_SOCKET_SERVER_NAME,CommClientStatus);
//static CommunicationClient *pClient = ((BinderClient::getInstance("com.westone.csm.CSM") == NULL) ? new BinderClient("com.westone.csm.CSM",CommClientStatus):BinderClient::getInstance("com.westone.csm.CSM"));

static CommunicationClient *pClient = NULL;
static SKFFunctionList skfFunctionList = {0};

DEVAPI extern "C" ULONG SKF_GetFunctionList(SKFFunctionList_PTR_PTR ppList){

    if(NULL == ppList){
        return SAR_INVALIDPARAMERR;
    }

    skfFunctionList.SKF_WaitForDevEvent = SKF_WaitForDevEvent;
    skfFunctionList.SKF_CancelWaitForDevEvent = SKF_CancelWaitForDevEvent;
    skfFunctionList.SKF_EnumDev = SKF_EnumDev;
    skfFunctionList.SKF_ConnectDev = SKF_ConnectDev;
    skfFunctionList.SKF_DisConnectDev = SKF_DisConnectDev;
    skfFunctionList.SKF_GetDevState = SKF_GetDevState;
    skfFunctionList.SKF_SetLabel = SKF_SetLabel;
    skfFunctionList.SKF_GetDevInfo = SKF_GetDevInfo;
    skfFunctionList.SKF_LockDev = SKF_LockDev;
    skfFunctionList.SKF_UnlockDev = SKF_UnlockDev;
    skfFunctionList.SKF_ChangeDevAuthKey = SKF_ChangeDevAuthKey;
    skfFunctionList.SKF_DevAuth = SKF_DevAuth;
    skfFunctionList.SKF_ChangePIN = SKF_ChangePIN;
    skfFunctionList.SKF_GetPINInfo = SKF_GetPINInfo;
    skfFunctionList.SKF_VerifyPIN = SKF_VerifyPIN;
    skfFunctionList.SKF_UnblockPIN = SKF_UnblockPIN;
    skfFunctionList.SKF_ClearSecureState = SKF_ClearSecureState;
    skfFunctionList.SKF_CreateApplication = SKF_CreateApplication;
    skfFunctionList.SKF_EnumApplication = SKF_EnumApplication;
    skfFunctionList.SKF_DeleteApplication = SKF_DeleteApplication;
    skfFunctionList.SKF_OpenApplication = SKF_OpenApplication;
    skfFunctionList.SKF_CloseApplication = SKF_CloseApplication;
    skfFunctionList.SKF_CreateFile = SKF_CreateFile;
    skfFunctionList.SKF_DeleteFile = SKF_DeleteFile;
    skfFunctionList.SKF_EnumFiles = SKF_EnumFiles;
    skfFunctionList.SKF_GetFileInfo = SKF_GetFileInfo;
    skfFunctionList.SKF_ReadFile = SKF_ReadFile;
    skfFunctionList.SKF_WriteFile = SKF_WriteFile;
    skfFunctionList.SKF_CreateContainer = SKF_CreateContainer;
    skfFunctionList.SKF_DeleteContainer = SKF_DeleteContainer;
    skfFunctionList.SKF_OpenContainer = SKF_OpenContainer;
    skfFunctionList.SKF_CloseContainer = SKF_CloseContainer;
    skfFunctionList.SKF_EnumContainer = SKF_EnumContainer;
    skfFunctionList.SKF_GetContainerType = SKF_GetContainerType;
    skfFunctionList.SKF_GenRandom = SKF_GenRandom;
    skfFunctionList.SKF_GenExtRSAKey = SKF_GenExtRSAKey;
    skfFunctionList.SKF_GenRSAKeyPair = SKF_GenRSAKeyPair;
    skfFunctionList.SKF_ImportRSAKeyPair = SKF_ImportRSAKeyPair;
    skfFunctionList.SKF_RSASignData = SKF_RSASignData;
    skfFunctionList.SKF_RSAVerify = SKF_RSAVerify;
    skfFunctionList.SKF_RSAExportSessionKey = SKF_RSAExportSessionKey;
    skfFunctionList.SKF_ExtRSAPubKeyOperation = SKF_ExtRSAPubKeyOperation;
    skfFunctionList.SKF_ExtRSAPriKeyOperation = SKF_ExtRSAPriKeyOperation;
    skfFunctionList.SKF_GenECCKeyPair = SKF_GenECCKeyPair;
    skfFunctionList.SKF_ImportECCKeyPair = SKF_ImportECCKeyPair;
    skfFunctionList.SKF_ECCSignData = SKF_ECCSignData;
    skfFunctionList.SKF_ECCVerify = SKF_ECCVerify;
    skfFunctionList.SKF_ECCExportSessionKey = SKF_ECCExportSessionKey;
    skfFunctionList.SKF_ExtECCEncrypt = SKF_ExtECCEncrypt;
    skfFunctionList.SKF_ExtECCDecrypt = SKF_ExtECCDecrypt;
    skfFunctionList.SKF_ExtECCSign = SKF_ExtECCSign;
    skfFunctionList.SKF_ExtECCVerify = SKF_ExtECCVerify;
    skfFunctionList.SKF_GenerateAgreementDataWithECC = SKF_GenerateAgreementDataWithECC;
    skfFunctionList.SKF_GenerateAgreementDataAndKeyWithECC = SKF_GenerateAgreementDataAndKeyWithECC;
    skfFunctionList.SKF_GenerateKeyWithECC = SKF_GenerateKeyWithECC;
    skfFunctionList.SKF_ExportPublicKey = SKF_ExportPublicKey;
    skfFunctionList.SKF_ImportSessionKey = SKF_ImportSessionKey;
    skfFunctionList.SKF_SetSymmKey = SKF_SetSymmKey;
    skfFunctionList.SKF_EncryptInit = SKF_EncryptInit;
    skfFunctionList.SKF_Encrypt = SKF_Encrypt;
    skfFunctionList.SKF_EncryptUpdate = SKF_EncryptUpdate;
    skfFunctionList.SKF_EncryptFinal = SKF_EncryptFinal;
    skfFunctionList.SKF_DecryptInit = SKF_DecryptInit;
    skfFunctionList.SKF_Decrypt = SKF_Decrypt;
    skfFunctionList.SKF_DecryptUpdate = SKF_DecryptUpdate;
    skfFunctionList.SKF_DecryptFinal = SKF_DecryptFinal;
    skfFunctionList.SKF_DigestInit = SKF_DigestInit;
    skfFunctionList.SKF_Digest = SKF_Digest;
    skfFunctionList.SKF_DigestUpdate = SKF_DigestUpdate;
    skfFunctionList.SKF_DigestFinal = SKF_DigestFinal;
    skfFunctionList.SKF_MacInit = SKF_MacInit;
    skfFunctionList.SKF_Mac = SKF_Mac;
    skfFunctionList.SKF_MacUpdate = SKF_MacUpdate;
    skfFunctionList.SKF_MacFinal = SKF_MacFinal;
    skfFunctionList.SKF_CloseHandle = SKF_CloseHandle;
    skfFunctionList.SKF_Transmit = SKF_Transmit;
    skfFunctionList.SKF_ImportCertificate = SKF_ImportCertificate;
    skfFunctionList.SKF_ExportCertificate = SKF_ExportCertificate;
    skfFunctionList.SKF_GetContainerProperty = SKF_GetContainerProperty;
    *ppList = &skfFunctionList;
    return SAR_OK;
}

/************************************************************************/
/*  1. 设备管理                                                         */
/*  SKF_WaitForDevEvent                                                 */
/*  SKF_CancelWaitForDevEvent                                           */
/*  SKF_EnumDev                                                         */
/*  SKF_ConnectDev                                                      */
/*  SKF_DisConnectDev                                                   */
/*  SKF_GetDevState                                                     */
/*  SKF_SetLabel                                                        */
/*  SKF_GetDevInfo                                                      */
/*  SKF_LockDev                                                         */
/*  SKF_UnlockDev                                                       */
/************************************************************************/

DEVAPI extern "C" ULONG SKF_WaitForDevEvent(
        OUT LPSTR szDevName,
        OUT ULONG *pulDevNameLen,
        OUT ULONG *pulEvent
    )
{
	int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_WaitForDevEvent response;
    Req_SKF_WaitForDevEvent request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    if(pClient == NULL){
        pClient = getInstance((char *)"com.westone.csm.CSM");
    }
    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            if(NULL != pulDevNameLen)
            {
                if(NULL != szDevName)
                {
                    request.set_szdevname(szDevName, *pulDevNameLen);
                }
                request.mutable_puldevnamelen()->set_u32value(*pulDevNameLen);
            }
            if(NULL != pulEvent)
            {
                request.mutable_pulevent()->set_u32value(*pulEvent);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.szdevname().size() && (szDevName != NULL))
            {
                memcpy(szDevName, response.szdevname().data(), response.szdevname().size());
            }
            if(response.has_puldevnamelen() && (pulDevNameLen != NULL))
            {
                *pulDevNameLen = response.mutable_puldevnamelen()->u32value();
            }
            if(response.has_pulevent() && (pulEvent != NULL))
            {
                *pulEvent = response.mutable_pulevent()->u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  取消等待设备的插拔事件
 */
DEVAPI extern "C" ULONG SKF_CancelWaitForDevEvent()
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  获得当前系统中的设备列表
 *  bPresent        [IN]为TRUE表示取当前设备状态为存在的设备列表。为FALSE表示取当前驱动支持的设备列表
 *  szNameList      [OUT]设备名称列表。如果该参数为NULL，将由pulSize返回所需要的内存空间大小。每个设备的名称以单个'\0'结束，以双'\0'表示列表的结束
 *  pulSize         [IN,OUT]输入参数，输入设备名称列表的缓冲区长度，输出参数，返回szNameList所需要的空间大小
 */
DEVAPI extern "C" ULONG SKF_EnumDev(
    IN BOOL bPresent,
    OUT LPSTR szNameList,
    OUT ULONG* pulSize
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_EnumDev response;
    Req_SKF_EnumDev request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    if(pClient == NULL){
        pClient = getInstance((char *)"com.westone.csm.CSM");
    }

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_bpresent()->set_boolvalue(bPresent);
            if(NULL != pulSize)
            {
                if(NULL != szNameList)
                {
                    request.set_sznamelist(szNameList, *pulSize);
                }
                request.mutable_pulsize()->set_u32value(*pulSize);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                break;
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.sznamelist().size() && (szNameList != NULL))
            {
                memcpy(szNameList, response.sznamelist().data(), response.sznamelist().size());
            }
            if(response.has_pulsize() && (pulSize != NULL))
            {
                *pulSize = response.mutable_pulsize()->u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  通过设备名称连接设备，返回设备的句柄
 *  szName      [IN]设备名称
 *  phDev       [OUT]返回设备操作句柄
 */
DEVAPI extern "C" ULONG SKF_ConnectDev(
    IN LPSTR szName,
    OUT DEVHANDLE* phDev
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ConnectDev response;
    Req_SKF_ConnectDev request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            if(NULL != szName)
            {
                request.set_szname(szName, strlen(szName)+1);
            }
            if(NULL != phDev)
            {
                request.mutable_phdev()->set_u32value(*(UINT32 *)phDev);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_phdev() && (phDev != NULL))
            {
                *phDev = (DEVHANDLE)response.mutable_phdev()->u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  断开一个已经连接的设备，并释放句柄。
 *  hDev        [IN]连接设备时返回的设备句柄
 */
DEVAPI extern "C" ULONG SKF_DisConnectDev(
    IN DEVHANDLE hDev
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_DisConnectDev response;
    Req_SKF_DisConnectDev request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  获取设备是否存在的状态
 *  szDevName   [IN]连接名称
 *  pulDevState [OUT]返回设备状态
 */
DEVAPI extern "C" ULONG SKF_GetDevState(
    IN  LPSTR    szDevName,
    OUT ULONG* pulDevState
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_GetDevState response;
    Req_SKF_GetDevState request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            if(NULL != szDevName)
            {
                request.set_szdevname(szDevName, strlen(szDevName)+1);
            }
            if(NULL != pulDevState)
            {
                request.mutable_puldevstate()->set_u32value(*pulDevState);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_puldevstate() && (pulDevState != NULL))
            {
                *pulDevState = response.puldevstate().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  设置设备标签
 *  hDev        [IN]连接设备时返回的设备句柄
 *  szLabel     [IN]设备标签字符串。该字符串应小于32字节
 */
DEVAPI extern "C" ULONG SKF_SetLabel(
    IN DEVHANDLE hDev,
    IN LPSTR szLabel)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_SetLabel response;
    Req_SKF_SetLabel request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != szLabel)
            {
                request.set_szlabel(szLabel, strlen(szLabel)+1);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  获取设备的一些特征信息，包括设备标签、厂商信息、支持的算法等
 *  hDev        [IN]连接设备时返回的设备句柄
 *  pDevInfo    [OUT]返回设备信息
 */
DEVAPI extern "C" ULONG SKF_GetDevInfo(
    IN DEVHANDLE    hDev,
    OUT PDEVINFO    pDevInfo
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_GetDevInfo response;
    Req_SKF_GetDevInfo request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    if(NULL == pDevInfo)
    {
        //bad argument
        return SAR_INVALIDPARAMERR;
    }

    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            {
                //set version
                request.mutable_pdevinfo()->mutable_version()->mutable_major()->set_u32value(pDevInfo->Version.major);
                request.mutable_pdevinfo()->mutable_version()->mutable_minor()->set_u32value(pDevInfo->Version.minor);
                //
                if(NULL != pDevInfo->Manufacturer)
                {
                    request.mutable_pdevinfo()->set_manufacturer(pDevInfo->Manufacturer, sizeof(pDevInfo->Manufacturer));
                }
                if(NULL != pDevInfo->Issuer)
                {
                    request.mutable_pdevinfo()->set_issuer(pDevInfo->Issuer, sizeof(pDevInfo->Issuer));
                }
                if(NULL != pDevInfo->Label)
                {
                    request.mutable_pdevinfo()->set_label(pDevInfo->Label, sizeof(pDevInfo->Label));
                }
                if(NULL != pDevInfo->SerialNumber)
                {
                    request.mutable_pdevinfo()->set_serialnumber(pDevInfo->SerialNumber, sizeof(pDevInfo->SerialNumber));
                }
                //hw version
                request.mutable_pdevinfo()->mutable_hwversion()->mutable_major()->set_u32value(pDevInfo->HWVersion.major);
                request.mutable_pdevinfo()->mutable_hwversion()->mutable_minor()->set_u32value(pDevInfo->HWVersion.minor);
                //firmware version
                request.mutable_pdevinfo()->mutable_firmwareversion()->mutable_major()->set_u32value(pDevInfo->FirmwareVersion.major);
                request.mutable_pdevinfo()->mutable_firmwareversion()->mutable_minor()->set_u32value(pDevInfo->FirmwareVersion.minor);
                //
                request.mutable_pdevinfo()->mutable_algsymcap()->set_u32value(pDevInfo->AlgSymCap);
                request.mutable_pdevinfo()->mutable_algasymcap()->set_u32value(pDevInfo->AlgAsymCap);
                request.mutable_pdevinfo()->mutable_alghashcap()->set_u32value(pDevInfo->AlgHashCap);
                request.mutable_pdevinfo()->mutable_devauthalgid()->set_u32value(pDevInfo->DevAuthAlgId);
                request.mutable_pdevinfo()->mutable_totalspace()->set_u32value(pDevInfo->TotalSpace);
                request.mutable_pdevinfo()->mutable_freespace()->set_u32value(pDevInfo->FreeSpace);
                request.mutable_pdevinfo()->mutable_maxeccbuffersize()->set_u32value(pDevInfo->MaxECCBufferSize);
                request.mutable_pdevinfo()->mutable_maxbuffersize()->set_u32value(pDevInfo->MaxBufferSize);
                //
                if(NULL != pDevInfo->Reserved)
                {
                    request.mutable_pdevinfo()->set_reserved(pDevInfo->Reserved, sizeof(pDevInfo->Reserved));
                }
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_pdevinfo())
            {
                if(response.pdevinfo().has_version())
                {
                    //set version
                    if(response.pdevinfo().version().has_major())
                    {
                        pDevInfo->Version.major = response.pdevinfo().version().major().u32value();
                    }
                    if(response.pdevinfo().version().has_minor())
                    {
                        pDevInfo->Version.minor = response.pdevinfo().version().minor().u32value();
                    }
                }
                if(response.pdevinfo().manufacturer().size() && NULL != pDevInfo->Manufacturer)
                {
                    memset(pDevInfo->Manufacturer, 0, sizeof(pDevInfo->Manufacturer));
                    memcpy(pDevInfo->Manufacturer, response.pdevinfo().manufacturer().data(), response.pdevinfo().manufacturer().size());
                }
                if(response.pdevinfo().issuer().size() && NULL != pDevInfo->Issuer)
                {
                    memset(pDevInfo->Issuer, 0, sizeof(pDevInfo->Issuer));
                    memcpy(pDevInfo->Issuer, response.pdevinfo().issuer().data(), response.pdevinfo().issuer().size());
                }
                if(response.pdevinfo().label().size() && NULL != pDevInfo->Label)
                {
                    memset(pDevInfo->Label, 0, sizeof(pDevInfo->Label));
                    memcpy(pDevInfo->Label, response.pdevinfo().label().data(), response.pdevinfo().label().size());
                }
                if(response.pdevinfo().serialnumber().size() && NULL != pDevInfo->SerialNumber)
                {
                    memset(pDevInfo->SerialNumber, 0, sizeof(pDevInfo->SerialNumber));
                    memcpy(pDevInfo->SerialNumber, response.pdevinfo().serialnumber().data(), response.pdevinfo().serialnumber().size());
                }
                if(response.pdevinfo().has_hwversion())
                {
                    //hw version
                    if(response.pdevinfo().hwversion().has_major())
                    {
                        pDevInfo->HWVersion.major = response.pdevinfo().hwversion().major().u32value();
                    }
                    if(response.pdevinfo().hwversion().has_minor())
                    {
                        pDevInfo->HWVersion.minor = response.pdevinfo().hwversion().minor().u32value();
                    }
                }
                if(response.pdevinfo().has_firmwareversion())
                {
                    //firmware version
                    if(response.pdevinfo().firmwareversion().has_major())
                    {
                        pDevInfo->FirmwareVersion.major = response.pdevinfo().firmwareversion().major().u32value();
                    }
                    if(response.pdevinfo().firmwareversion().has_minor())
                    {
                        pDevInfo->FirmwareVersion.minor = response.pdevinfo().firmwareversion().minor().u32value();
                    }
                }
                //
                if(response.pdevinfo().has_algsymcap())
                {
                    pDevInfo->AlgSymCap = response.pdevinfo().algsymcap().u32value();
                }
                if(response.pdevinfo().has_algasymcap())
                {
                    pDevInfo->AlgAsymCap = response.pdevinfo().algasymcap().u32value();
                }
                if(response.pdevinfo().has_alghashcap())
                {
                    pDevInfo->AlgHashCap = response.pdevinfo().alghashcap().u32value();
                }
                if(response.pdevinfo().has_devauthalgid())
                {
                    pDevInfo->DevAuthAlgId = response.pdevinfo().devauthalgid().u32value();
                }
                if(response.pdevinfo().has_totalspace())
                {
                    pDevInfo->TotalSpace = response.pdevinfo().totalspace().u32value();
                }
                if(response.pdevinfo().has_freespace())
                {
                    pDevInfo->FreeSpace = response.pdevinfo().freespace().u32value();
                }
                if(response.pdevinfo().has_maxeccbuffersize())
                {
                    pDevInfo->MaxECCBufferSize = response.pdevinfo().maxeccbuffersize().u32value();
                }
                if(response.pdevinfo().has_maxbuffersize())
                {
                    pDevInfo->MaxBufferSize = response.pdevinfo().maxbuffersize().u32value();
                }
                //
                if(response.pdevinfo().reserved().size() && NULL != pDevInfo->Reserved)
                {
                    memset(pDevInfo->Reserved, 0, sizeof(pDevInfo->Reserved));
                    memcpy(pDevInfo->Reserved, response.pdevinfo().reserved().data(), response.pdevinfo().reserved().size());
                }                    
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  获得设备的独占使用权
 *  hDev        [IN]连接设备时返回的设备句柄
 *  ulTimeOut   [IN]超时时间，单位为毫秒。如果为0xFFFFFFFF表示无限等待
 */
DEVAPI extern "C" ULONG SKF_LockDev(
    IN DEVHANDLE    hDev,
    IN ULONG ulTimeOut
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_LockDev response;
    Req_SKF_LockDev request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            request.mutable_ultimeout()->set_u32value(ulTimeOut);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  释放对设备的独占使用权
 *  hDev        [IN]连接设备时返回的设备句柄
 */
DEVAPI extern "C" ULONG SKF_UnlockDev(
    IN DEVHANDLE    hDev
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_UnlockDev response;
    Req_SKF_UnlockDev request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/************************************************************************/
/*  2. 访问控制                                                         */
/*  SKF_ChangeDevAuthKey                                                */
/*  SKF_DevAuth                                                         */
/*  SKF_ChangePIN                                                       */
/*  SKF_GetPINInfo                                                      */
/*  SKF_VerifyPIN                                                       */
/*  SKF_UnblockPIN                                                      */
/*  SKF_ClearSecureState                                                */
/************************************************************************/

/*
 *  更改设备认证密钥
 *  hDev        [IN]连接时返回的设备句柄
 *  pbKeyValue  [IN]密钥值
 *  ulKeyLen    [IN]密钥长度
 */
DEVAPI extern "C" ULONG SKF_ChangeDevAuthKey(
    IN DEVHANDLE    hDev,
    IN BYTE     *pbKeyValue,
    IN ULONG        ulKeyLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ChangeDevAuthKey response;
    Req_SKF_ChangeDevAuthKey request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != pbKeyValue)
            {
                request.set_pbkeyvalue(pbKeyValue, ulKeyLen);
            }
            request.mutable_ulkeylen()->set_u32value(ulKeyLen);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  设备认证是设备对应用程序的认证
 *  hDev            [IN]连接时返回的设备句柄
 *  pbAuthData      [IN]认证数据
 *  ulLen           [IN]认证数据的长度
 */
DEVAPI extern "C" ULONG SKF_DevAuth(
    IN DEVHANDLE    hDev,
    IN BYTE*        pbAuthData,
    IN ULONG        ulLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_DevAuth response;
    Req_SKF_DevAuth request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != pbAuthData)
            {
                request.set_pbauthdata(pbAuthData, ulLen);
            }
            request.mutable_ullen()->set_u32value(ulLen);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  修改PIN，可以修改Admin和User的PIN，如果原PIN错误，返回剩余重试次数，当剩余次数为0时，表示PIN已经被锁死
 *  hApplication    [IN]应用句柄
 *  ulPINType       [IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
 *  szOldPIN        [IN]原PIN值
 *  szNewPIN        [IN]新PIN值
 *  pulRetryCount   [OUT]出错后重试次数
 */
DEVAPI extern "C" ULONG SKF_ChangePIN(
    IN HAPPLICATION hApplication,
    IN ULONG            ulPINType,
    IN LPSTR            szOldPIN,
    IN LPSTR            szNewPIN,
    OUT ULONG*      pulRetryCount
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ChangePIN response;
    Req_SKF_ChangePIN request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            request.mutable_ulpintype()->set_u32value(ulPINType);
            if(NULL != szOldPIN)
            {
                request.set_szoldpin(szOldPIN, strlen(szOldPIN)+1);
            }
            if(NULL != szNewPIN)
            {
                request.set_sznewpin(szNewPIN, strlen(szNewPIN)+1);
            }
            if(NULL != pulRetryCount)
            {
                request.mutable_pulretrycount()->set_u32value(*pulRetryCount);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_pulretrycount() && (pulRetryCount != NULL))
            {
                *pulRetryCount = response.pulretrycount().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  获取PIN码信息，包括最大重试次数、当前剩余重试次数，以及当前PIN码是否为出厂默认PIN码
 *  hApplication        [IN]应用句柄
 *  ulPINType           [IN]PIN类型
 *  pulMaxRetryCount    [OUT]最大重试次数
 *  pulRemainRetryCount [OUT]当前剩余重试次数，当为0时表示已锁死
 *  pbDefaultPin        [OUT]是否为出厂默认PIN码
 */
DEVAPI extern "C" ULONG SKF_GetPINInfo(
    IN HAPPLICATION hApplication,
    IN ULONG            ulPINType,
    OUT ULONG*      pulMaxRetryCount,
    OUT ULONG*      pulRemainRetryCount,
    OUT BOOL*           pbDefaultPin
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_GetPINInfo response;
    Req_SKF_GetPINInfo request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            request.mutable_ulpintype()->set_u32value(ulPINType);
            if(NULL != pulMaxRetryCount)
            {
                request.mutable_pulmaxretrycount()->set_u32value(*pulMaxRetryCount);
            }
            if(NULL != pulRemainRetryCount)
            {
                request.mutable_pulremainretrycount()->set_u32value(*pulRemainRetryCount);
            }
            if(NULL != pbDefaultPin)
            {
                request.mutable_pbdefaultpin()->set_boolvalue(*pbDefaultPin);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_pulmaxretrycount() && (pulMaxRetryCount != NULL))
            {
                *pulMaxRetryCount = response.pulmaxretrycount().u32value();
            }
            if(response.has_pulremainretrycount() && (pulRemainRetryCount != NULL))
            {
                *pulRemainRetryCount = response.pulremainretrycount().u32value();
            }
            if(response.has_pbdefaultpin() && (pbDefaultPin != NULL))
            {
                *pbDefaultPin = response.pbdefaultpin().boolvalue();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  校验PIN码。校验成功后，会获得相应的权限，如果PIN码错误，会返回PIN码的重试次数，当重试次数为0时表示PIN码已经锁死
 *  hApplication    [IN]应用句柄
 *  ulPINType       [IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
 *  szPIN           [IN]PIN值
 *  pulRetryCount   [OUT]出错后返回的重试次数
 */
DEVAPI extern "C" ULONG SKF_VerifyPIN(
    IN HAPPLICATION hApplication,
    IN ULONG            ulPINType,
    IN LPSTR            szPIN,
    OUT ULONG*      pulRetryCount
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_VerifyPIN response;
    Req_SKF_VerifyPIN request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            request.mutable_ulpintype()->set_u32value(ulPINType);
            if(NULL != szPIN)
            {
                request.set_szpin(szPIN, strlen(szPIN)+1);
            }
            if(NULL != pulRetryCount)
            {
                request.mutable_pulretrycount()->set_u32value(*pulRetryCount);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_pulretrycount() && (pulRetryCount != NULL))
            {
                *pulRetryCount = response.pulretrycount().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  当用户的PIN码锁死后，通过调用该函数来解锁用户PIN码。
 *  解锁后，用户PIN码被设置成新值，用户PIN码的重试次数也恢复到原值。
 *  hApplication    [IN]应用句柄
 *  szAdminPIN      [IN]管理员PIN码
 *  szNewUserPIN    [IN]新的用户PIN码
 *  pulRetryCount   [OUT]管理员PIN码错误时，返回剩余重试次数
 */
DEVAPI extern "C" ULONG SKF_UnblockPIN(
    IN HAPPLICATION hApplication,
    IN LPSTR            szAdminPIN,
    IN LPSTR            szNewUserPIN,
    OUT ULONG*      pulRetryCount
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_UnblockPIN response;
    Req_SKF_UnblockPIN request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            if(NULL != szAdminPIN)
            {
                request.set_szadminpin(szAdminPIN, strlen(szAdminPIN)+1);
            }
            if(NULL != szNewUserPIN)
            {
                request.set_sznewuserpin(szNewUserPIN, strlen(szNewUserPIN)+1);
            }
            if(NULL != pulRetryCount)
            {
                request.mutable_pulretrycount()->set_u32value(*pulRetryCount);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_pulretrycount() && (pulRetryCount != NULL))
            {
                *pulRetryCount = response.pulretrycount().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  清除应用当前的安全状态
 *  hApplication    [IN]应用句柄
 */
DEVAPI extern "C" ULONG SKF_ClearSecureState(
    IN HAPPLICATION hApplication
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ClearSecureState response;
    Req_SKF_ClearSecureState request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/************************************************************************/
/*  3. 应用管理                                                         */
/*  SKF_CreateApplication                                               */
/*  SKF_EnumApplication                                                 */
/*  SKF_DeleteApplication                                               */
/*  SKF_OpenApplication                                                 */
/*  SKF_CloseApplication                                                */
/************************************************************************/

/*
 *  创建一个应用
 *  hDev                    [IN]连接设备时返回的设备句柄
 *  szAppName               [IN]应用名称
 *  szAdminPIN              [IN]管理员PIN
 *  dwAdminPinRetryCount    [IN]管理员PIN最大重试次数
 *  szUserPIN               [IN]用户PIN
 *  dwAdminPinRetryCount    [IN]用户PIN最大重试次数
 *  dwCreateFileRights      [IN]在该应用下创建文件和容器的权限
 *  phApplication           [OUT]应用的句柄
 */
DEVAPI extern "C" ULONG SKF_CreateApplication(
    IN DEVHANDLE        hDev,
    IN LPSTR            szAppName,
    IN LPSTR            szAdminPIN,
    IN DWORD            dwAdminPinRetryCount,
    IN LPSTR            szUserPIN,
    IN DWORD            dwUserPinRetryCount,
    IN DWORD            dwCreateFileRights,
    OUT HAPPLICATION*   phApplication
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_CreateApplication response;
    Req_SKF_CreateApplication request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != szAppName)
            {
                request.set_szappname(szAppName, strlen(szAppName)+1);
            }
            if(NULL != szAdminPIN)
            {
                request.set_szadminpin(szAdminPIN, strlen(szAdminPIN)+1);
            }
            request.mutable_dwadminpinretrycount()->set_u32value(dwAdminPinRetryCount);
            if(NULL != szUserPIN)
            {
                request.set_szuserpin(szUserPIN, strlen(szUserPIN)+1);
            }
            request.mutable_dwuserpinretrycount()->set_u32value(dwUserPinRetryCount);
            request.mutable_dwcreatefilerights()->set_u32value(dwCreateFileRights);
            if(NULL != phApplication)
            {
                request.mutable_phapplication()->set_u32value(*(UINT32*)phApplication);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_phapplication() && (phApplication != NULL))
            {
                *phApplication = (HAPPLICATION)response.phapplication().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  枚举设备中所存在的所有应用
 *  hDev            [IN]连接设备时返回的设备句柄
 *  szAppName       [OUT]返回应用名称列表, 如果该参数为空，将由pulSize返回所需要的内存空间大小。
 *                       每个应用的名称以单个'\0'结束，以双'\0'表示列表的结束。
 *  pulSize         [IN,OUT]输入参数，输入应用名称的缓冲区长度，输出参数，返回szAppName所占用的的空间大小
 */
DEVAPI extern "C" ULONG SKF_EnumApplication(
    IN DEVHANDLE        hDev,
    OUT LPSTR           szAppName,
    OUT ULONG*      pulSize
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_EnumApplication response;
    Req_SKF_EnumApplication request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != pulSize)
            {
                if(NULL != szAppName)
                {
                    request.set_szappname(szAppName, *pulSize);
                }
                request.mutable_pulsize()->set_u32value(*pulSize);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.szappname().size() && (szAppName != NULL))
            {
                memcpy(szAppName, response.szappname().data(), response.szappname().size());
            }
            if(response.has_pulsize() && (pulSize != NULL))
            {
                *pulSize = response.pulsize().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  删除指定的应用
 *  hDev            [IN]连接设备时返回的设备句柄
 *  szAppName       [IN]应用名称
 */
DEVAPI extern "C" ULONG SKF_DeleteApplication(
    IN DEVHANDLE        hDev,
    IN LPSTR            szAppName
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_DeleteApplication response;
    Req_SKF_DeleteApplication request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != szAppName)
            {
                request.set_szappname(szAppName, strlen(szAppName)+1);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  打开指定的应用
 *  hDev            [IN]连接设备时返回的设备句柄
 *  szAppName       [IN]应用名称
 *  phApplication   [OUT]应用的句柄
 */
DEVAPI extern "C" ULONG SKF_OpenApplication(
    IN DEVHANDLE        hDev,
    IN LPSTR            szAppName,
    OUT HAPPLICATION*   phApplication
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_OpenApplication response;
    Req_SKF_OpenApplication request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != szAppName)
            {
                request.set_szappname(szAppName, strlen(szAppName)+1);
            }
            if(NULL != phApplication)
            {
                request.mutable_phapplication()->set_u32value(*(UINT32*)phApplication);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_phapplication() && (phApplication != NULL))
            {
                *phApplication = (HAPPLICATION)response.phapplication().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  关闭应用并释放应用句柄
 *  hApplication    [IN]应用的句柄
 */
DEVAPI extern "C" ULONG SKF_CloseApplication(
    IN HAPPLICATION hApplication
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_CloseApplication response;
    Req_SKF_CloseApplication request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/************************************************************************/
/*  4. 文件管理                                                         */
/*  SKF_CreateFile                                                      */
/*  SKF_DeleteFile                                                      */
/*  SKF_EnumFiles                                                       */
/*  SKF_GetFileInfo                                                     */
/*  SKF_ReadFile                                                        */
/*  SKF_WriteFile                                                       */
/************************************************************************/

/*
 *  创建一个文件。创建文件时要指定文件的名称，大小，以及文件的读写权限
 *  hApplication        [IN]应用句柄
 *  szFileName          [IN]文件名称，长度不得大于32个字节
 *  ulFileSize          [IN]文件大小
 *  ulReadRights        [IN]文件读权限
 *  ulWriteRights       [IN]文件写权限
 */
DEVAPI extern "C" ULONG SKF_CreateFile(
    IN HAPPLICATION hApplication,
    IN LPSTR            szFileName,
    IN ULONG            ulFileSize,
    IN ULONG            ulReadRights,
    IN ULONG            ulWriteRights
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_CreateFile response;
    Req_SKF_CreateFile request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            if(NULL != szFileName)
            {
                request.set_szfilename(szFileName, strlen(szFileName)+1);
            }
            request.mutable_ulfilesize()->set_u32value(ulFileSize);
            request.mutable_ulreadrights()->set_u32value(ulReadRights);
            request.mutable_ulwriterights()->set_u32value(ulWriteRights);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  删除指定文件，文件删除后，文件中写入的所有信息将丢失。文件在设备中的占用的空间将被释放。
 *  hApplication        [IN]要删除文件所在的应用句柄
 *  szFileName          [IN]要删除文件的名称
 */
DEVAPI extern "C" ULONG SKF_DeleteFile(
    IN HAPPLICATION hApplication,
    IN LPSTR            szFileName
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_DeleteFile response;
    Req_SKF_DeleteFile request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            if(NULL != szFileName)
            {
                request.set_szfilename(szFileName, strlen(szFileName)+1);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  枚举一个应用下存在的所有文件
 *  hApplication        [IN]应用的句柄
 *  szFileList          [OUT]返回文件名称列表，该参数为空，由pulSize返回文件信息所需要的空间大小。每个文件名称以单个'\0'结束，以双'\0'表示列表的结束。
 *  pulSize             [OUT]输入为数据缓冲区的大小，输出为实际文件名称的大小
 */
DEVAPI extern "C" ULONG SKF_EnumFiles(
    IN HAPPLICATION hApplication,
    OUT LPSTR           szFileList,
    OUT ULONG*      pulSize
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_EnumFiles response;
    Req_SKF_EnumFiles request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            if(NULL != pulSize)
            {
                if(NULL != szFileList)
                {
                    request.set_szfilename(szFileList, *pulSize);
                }
                request.mutable_pulsize()->set_u32value(*pulSize);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.szfilename().size() && (szFileList != NULL))
            {
                memcpy(szFileList, response.szfilename().data(), response.szfilename().size());
            }
            if(response.has_pulsize() && (pulSize != NULL))
            {
                *pulSize = response.pulsize().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  获取应用文件的属性信息，例如文件的大小、权限等
 *  hApplication        [IN]文件所在应用的句柄
 *  szFileName          [IN]文件名称
 *  pFileInfo           [OUT]文件信息，指向文件属性结构的指针
 */
DEVAPI extern "C" ULONG SKF_GetFileInfo(
    IN HAPPLICATION     hApplication,
    IN LPSTR                szFileName,
    OUT FILEATTRIBUTE*  pFileInfo
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_GetFileInfo response;
    Req_SKF_GetFileInfo request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    if(NULL == pFileInfo)
    {
        //bad argument
        return SAR_INVALIDPARAMERR;
    }

    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            if(NULL != szFileName)
            {
                request.set_szfilename(szFileName, strlen(szFileName)+1);
            }
            {
                if(NULL != pFileInfo->FileName)
                {
                    request.mutable_pfileinfo()->set_filename(pFileInfo->FileName, sizeof(pFileInfo->FileName));
                }
                request.mutable_pfileinfo()->mutable_filesize()->set_u32value(pFileInfo->FileSize);
                request.mutable_pfileinfo()->mutable_readrights()->set_u32value(pFileInfo->ReadRights);
                request.mutable_pfileinfo()->mutable_writerights()->set_u32value(pFileInfo->WriteRights);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_pfileinfo() && NULL != pFileInfo)
            {
                if(response.pfileinfo().filename().size() && NULL != pFileInfo->FileName)
                {
                    memset(pFileInfo->FileName, 0, sizeof(pFileInfo->FileName));
                    memcpy(pFileInfo->FileName, response.pfileinfo().filename().data(), response.pfileinfo().filename().size());
                }
                if(response.pfileinfo().has_filesize())
                {
                    pFileInfo->FileSize = response.pfileinfo().filesize().u32value();
                }
                if(response.pfileinfo().has_readrights())
                {
                    pFileInfo->ReadRights = response.pfileinfo().readrights().u32value();
                }
                if(response.pfileinfo().has_writerights())
                {
                    pFileInfo->WriteRights = response.pfileinfo().writerights().u32value();
                }
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  读取文件内容
 *  hApplication        [IN]文件所在的应用句柄
 *  szFileName          [IN]文件名
 *  ulOffset            [IN]文件读取偏移位置
 *  ulSize              [IN]要读取的长度
 *  pbOutData           [OUT]返回数据的缓冲区
 *  pulOutLen           [OUT]输入表示给出的缓冲区大小；输出表示实际读取返回的数据大小
 */
DEVAPI extern "C" ULONG SKF_ReadFile(
    IN HAPPLICATION hApplication,
    IN LPSTR            szFileName,
    IN ULONG            ulOffset,
    IN ULONG            ulSize,
    OUT BYTE*           pbOutData,
    OUT ULONG*      pulOutLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ReadFile response;
    Req_SKF_ReadFile request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            if(NULL != szFileName)
            {
                request.set_szfilename(szFileName, strlen(szFileName)+1);
            }
            request.mutable_uloffset()->set_u32value(ulOffset);
            request.mutable_ulsize()->set_u32value(ulSize);
            if(NULL != pulOutLen)
            {
                if(NULL != pbOutData)
                {
                    request.set_pboutdata(pbOutData, *pulOutLen);
                }
                request.mutable_puloutlen()->set_u32value(*pulOutLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.pboutdata().size() && (pbOutData != NULL))
            {
                memcpy(pbOutData, response.pboutdata().data(), response.pboutdata().size());
            }
            if(response.has_puloutlen() && (pulOutLen != NULL))
            {
                *pulOutLen = response.puloutlen().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  写数据到文件中
 *  hApplication        [IN]文件所在的应用句柄
 *  szFileName          [IN]文件名
 *  ulOffset            [IN]写入文件的偏移量
 *  pbData              [IN]写入数据缓冲区
 *  ulSize              [IN]写入数据的大小
 */
DEVAPI extern "C" ULONG SKF_WriteFile(
    IN HAPPLICATION hApplication,
    IN LPSTR            szFileName,
    IN ULONG            ulOffset,
    IN BYTE*            pbData,
    IN ULONG            ulSize
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_WriteFile response;
    Req_SKF_WriteFile request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            if(NULL != szFileName)
            {
                request.set_szfilename(szFileName, strlen(szFileName)+1);
            }
            request.mutable_uloffset()->set_u32value(ulOffset);
            if(NULL != pbData)
            {
                request.set_pbdata(pbData, ulSize);
            }
            request.mutable_ulsize()->set_u32value(ulSize);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/************************************************************************/
/*  5. 容器管理                                                         */
/*  SKF_CreateContainer                                                 */
/*  SKF_DeleteContainer                                                 */
/*  SKF_OpenContainer                                                   */
/*  SKF_CloseContainer                                                  */
/*  SKF_EnumContainer                                                   */
/************************************************************************/

/*
 *  在应用下建立指定名称的容器并返回容器句柄
 *  hApplication        [IN]应用句柄
 *  szContainerName     [IN]ASCII字符串，表示所建立容器的名称，容器名称的最大长度不能超过64字节
 *  phContainer         [OUT]返回所建立容器的容器句柄
 */
DEVAPI extern "C" ULONG SKF_CreateContainer(
    IN HAPPLICATION hApplication,
    IN LPSTR            szContainerName,
    OUT HCONTAINER* phContainer
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_CreateContainer response;
    Req_SKF_CreateContainer request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            if(NULL != szContainerName)
            {
                request.set_szcontainername(szContainerName, strlen(szContainerName)+1);
            }
            if(NULL != phContainer)
            {
                request.mutable_phcontainer()->set_u32value(*(UINT32*)phContainer);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_phcontainer() && (phContainer != NULL))
            {
                *phContainer = (HCONTAINER)response.phcontainer().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  在应用下删除指定名称的容器并释放容器相关的资源
 *  hApplication        [IN]应用句柄
 *  szContainerName     [IN]指向删除容器的名称
 */
DEVAPI extern "C" ULONG SKF_DeleteContainer(
    IN HAPPLICATION hApplication,
    IN LPSTR            szContainerName
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_DeleteContainer response;
    Req_SKF_DeleteContainer request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            if(NULL != szContainerName)
            {
                request.set_szcontainername(szContainerName, strlen(szContainerName)+1);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  获取容器句柄
 *  hApplication        [IN]应用句柄
 *  szContainerName     [IN]容器名称
 *  phContainer         [OUT]返回所打开容器的句柄
 */
DEVAPI extern "C" ULONG SKF_OpenContainer(
    IN HAPPLICATION hApplication,
    IN LPSTR            szContainerName,
    OUT HCONTAINER* phContainer
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_OpenContainer response;
    Req_SKF_OpenContainer request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            if(NULL != szContainerName)
            {
                request.set_szcontainername(szContainerName, strlen(szContainerName)+1);
            }
            if(NULL != phContainer)
            {
                request.mutable_phcontainer()->set_u32value(*(UINT32*)phContainer);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_phcontainer() && (phContainer != NULL))
            {
                *phContainer = (HCONTAINER)response.phcontainer().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  关闭容器句柄，并释放容器句柄相关资源
 *  hContainer          [OUT]容器句柄
 */
DEVAPI extern "C" ULONG SKF_CloseContainer(
    IN HCONTAINER hContainer
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_CloseContainer response;
    Req_SKF_CloseContainer request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hcontainer()->set_u32value((long)hContainer);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  枚举应用下的所有容器并返回容器名称列表
 *  hApplication        [IN]应用句柄
 *  szContainerName     [OUT]指向容器名称列表缓冲区，如果此参数为NULL时，pulSize表示返回数据所需要缓冲区的长度，如果此参数不为NULL时，返回容器名称列表，每个容器名以单个'\0'为结束，列表以双'\0'结束
 *  pulSize             [OUT]调用前表示szContainerName缓冲区的长度，返回容器名称列表的长度
 */
DEVAPI extern "C" ULONG SKF_EnumContainer(
    IN HAPPLICATION hApplication,
    OUT LPSTR           szContainerName,
    OUT ULONG*      pulSize
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_EnumContainer response;
    Req_SKF_EnumContainer request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_happlication()->set_u32value((long)hApplication);
            if(NULL != pulSize)
            {
                if(NULL != szContainerName)
                {
                    request.set_szcontainername(szContainerName, *pulSize);
                }
                request.mutable_pulsize()->set_u32value(*pulSize);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.szcontainername().size() && (szContainerName != NULL))
            {
                memcpy(szContainerName, response.szcontainername().data(), response.szcontainername().size());
            }
            if(response.has_pulsize() && (pulSize != NULL))
            {
                *pulSize = response.pulsize().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  功能描述    获取容器的类型
 *  hContainer  [IN]容器句柄。
 *  pulContainerType    [OUT] 获得的容器类型。指针指向的值为0表示未定、尚未分配类型或者为空容器，为1表示为RSA容器，为2表示为SM2容器。
 *
 */
DEVAPI extern "C" ULONG SKF_GetContainerType(
    IN HCONTAINER hContainer,
    OUT ULONG *pulContainerType)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_GetContainerType response;
    Req_SKF_GetContainerType request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hcontainer()->set_u32value((long)hContainer);
            if(NULL != pulContainerType)
            {
                request.mutable_pulcontainertype()->set_u32value(*pulContainerType);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_pulcontainertype() && (pulContainerType != NULL))
            {
                *pulContainerType = response.pulcontainertype().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/************************************************************************/
/*  6. 密码服务                                                         */
/*  SKF_GetRandom                                                       */
/*  SKF_GenExtRSAKey                                                    */
/*  SKF_GenRSAKeyPair                                                   */
/*  SKF_ImportRSAKeyPair                                                */
/*  SKF_RSASignData                                                     */
/*  SKF_RSAVerify                                                       */
/*  SKF_RSAExportSessionKey                                             */
/*  SKF_ExtRSAPubKeyOperation                                           */
/*  SKF_ExtRSAPriKeyOperation                                           */
/*  SKF_GenECCKeyPair                                                   */
/*  SKF_ImportECCKeyPair                                                */
/*  SKF_ECCSignData                                                     */
/*  SKF_ECCVerify                                                       */
/*  SKF_ECCExportSessionKey                                             */
/*  SKF_ExtECCEncrypt                                                   */
/*  SKF_ExtECCDecrypt                                                   */
/*  SKF_ExtECCSign                                                      */
/*  SKF_ExtECCVerify                                                    */
/*  SKF_ExportPublicKey                                                 */
/*  SKF_ImportSessionKey                                                */
/*  SKF_SetSymmKey                                                      */
/*  SKF_EncryptInit                                                     */
/*  SKF_Encrypt                                                         */
/*  SKF_EncryptUpdate                                                   */
/*  SKF_EncryptFinal                                                    */
/*  SKF_DecryptInit                                                     */
/*  SKF_Decrypt                                                         */
/*  SKF_DecryptUpdate                                                   */
/*  SKF_DecryptFinal                                                    */
/*  SKF_DegistInit                                                      */
/*  SKF_Degist                                                          */
/*  SKF_DegistUpdate                                                    */
/*  SKF_DegistFinal                                                     */
/*  SKF_MACInit                                                         */
/*  SKF_MAC                                                             */
/*  SKF_MACUpdate                                                       */
/*  SKF_MACFinal                                                        */
/************************************************************************/

/*
 *  产生指定长度的随机数
 *  hDev            [IN] 设备句柄
 *  pbRandom        [OUT] 返回的随机数
 *  ulRandomLen     [IN] 随机数长度
 */
DEVAPI extern "C" ULONG SKF_GenRandom(
    IN DEVHANDLE hDev,
    OUT BYTE *pbRandom,
    IN ULONG ulRandomLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_GenRandom response;
    Req_SKF_GenRandom request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != pbRandom)
            {
                request.set_pbrandom(pbRandom, ulRandomLen);
            }
            request.mutable_ulrandomlen()->set_u32value(ulRandomLen);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.pbrandom().size() && (pbRandom != NULL))
            {
                memcpy(pbRandom, response.pbrandom().data(), response.pbrandom().size());
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  由设备生成RSA密钥对并明文输出
 *  hDev            [IN] 设备句柄
 *  ulBitsLen       [IN] 密钥模长
 *  pBlob           [OUT] 返回的私钥数据结构
 */
DEVAPI extern "C" ULONG SKF_GenExtRSAKey(
    IN DEVHANDLE hDev,
    IN ULONG ulBitsLen,
    OUT RSAPRIVATEKEYBLOB* pBlob
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  生成RSA签名密钥对并输出签名公钥
 *  hContainer      [IN] 容器句柄
 *  ulBitsLen       [IN] 密钥模长
 *  pBlob           [OUT] 返回的RSA公钥数据结构
 */
DEVAPI extern "C" ULONG SKF_GenRSAKeyPair(
    IN HCONTAINER hContainer,
    IN ULONG ulBitsLen,
    OUT RSAPUBLICKEYBLOB *pBlob
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  导入RSA加密公私钥对
 *  hContainer      [IN] 容器句柄
 *  ulSymAlgId      [IN] 对称算法密钥标识
 *  pbWrappedKey    [IN] 使用该容器内签名公钥保护的对称算法密钥
 *  ulWrappedKeyLen [IN] 保护的对称算法密钥长度
 *  pbEncryptedData [IN] 对称算法密钥保护的RSA加密私钥。私钥的格式遵循PKCS #1 v2.1: RSA Cryptography Standard中的私钥格式定义
 *  ulEncryptedDataLen  [IN] 对称算法密钥保护的RSA加密公私钥对长度
 */
DEVAPI extern "C" ULONG SKF_ImportRSAKeyPair(
    IN HCONTAINER hContainer,
    IN ULONG ulSymAlgId,
    IN BYTE *pbWrappedKey,
    IN ULONG ulWrappedKeyLen,
    IN BYTE *pbEncryptedData,
    IN ULONG ulEncryptedDataLen
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  使用hContainer指定容器的签名私钥，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名的长度
 *  hContainer      [IN] 用来签名的私钥所在容器句柄
 *  pbData          [IN] 被签名的数据
 *  ulDataLen       [IN] 签名数据长度，应不大于RSA密钥模长-11
 *  pbSignature     [OUT] 存放签名结果的缓冲区指针，如果值为NULL，用于取得签名结果长度
 *  pulSigLen       [IN,OUT] 输入为签名结果缓冲区大小，输出为签名结果长度
 */
DEVAPI extern "C" ULONG SKF_RSASignData(
    IN HANDLE hContainer,
    IN BYTE *pbData,
    IN ULONG ulDataLen,
    OUT BYTE *pbSignature,
    OUT ULONG *pulSigLen
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  验证RSA签名。用pRSAPubKeyBlob内的公钥值对待验签数据进行验签。
 *  hDev            [IN] 连接设备时返回的设备句柄
 *  pRSAPubKeyBlob  [IN] RSA公钥数据结构
 *  pbData          [IN] 待验证签名的数据
 *  ulDataLen       [IN] 数据长度，应不大于公钥模长-11
 *  pbSignature     [IN] 待验证的签名值
 *  ulSigLen        [IN] 签名值长度，必须为公钥模长
 */
DEVAPI extern "C" ULONG SKF_RSAVerify(
    IN DEVHANDLE            hDev,
    IN RSAPUBLICKEYBLOB*    pRSAPubKeyBlob,
    IN BYTE*                pbData,
    IN ULONG                ulDataLen,
    IN BYTE*                pbSignature,
    IN ULONG                ulSigLen
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  生成会话密钥并用外部公钥加密输出。
 *  hContainer      [IN] 容器句柄
 *  ulAlgID         [IN] 会话密钥的算法标识
 *  pPubKey         [IN] 加密会话密钥的RSA公钥数据结构
 *  pbData          [OUT] 导出的加密会话密钥密文，按照PKCS#1v1.5的要求封装
 *  pulDataLen      [OUT] 返回导出数据长度
 *  phSessionKey    [OUT] 导出的密钥句柄
 */
DEVAPI extern "C" ULONG SKF_RSAExportSessionKey(
    IN HCONTAINER hContainer,
    IN ULONG ulAlgID,
    IN RSAPUBLICKEYBLOB* pPubKey,
    OUT BYTE* pbData,
    OUT ULONG* pulDataLen,
    OUT HANDLE* phSessionKey
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  使用外部传入的RSA公钥对输入数据做公钥运算并输出结果
 *  hDev            [IN] 设备句柄
 *  pRSAPubKeyBlob  [IN] RSA公钥数据结构
 *  pbInput         [IN] 指向待运算的原始数据缓冲区
 *  ulInputLen      [IN] 待运算原始数据的长度，必须为公钥模长
 *  pbOutput        [OUT] 指向RSA公钥运算结果缓冲区，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
 *  pulOutputLen    [OUT] 调用前表示pbOutput缓冲区的长度，返回RSA公钥运算结果的实际长度
 */
DEVAPI extern "C" ULONG SKF_ExtRSAPubKeyOperation(
    IN DEVHANDLE hDev,
    IN RSAPUBLICKEYBLOB* pRSAPubKeyBlob,
    IN BYTE* pbInput,
    IN ULONG ulInputLen,
    OUT BYTE* pbOutput,
    OUT ULONG* pulOutputLen
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  直接使用外部传入的RSA私钥对输入数据做私钥运算并输出结果
 *  hDev            [IN] 设备句柄
 *  pRSAPriKeyBlob  [IN] RSA私钥数据结构
 *  pbInput         [IN] 指向待运算数据缓冲区
 *  ulInputLen      [IN] 待运算数据的长度，必须为公钥模长
 *  pbOutput        [OUT] RSA私钥运算结果，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
 *  pulOutputLen    [OUT] 调用前表示pbOutput缓冲区的长度，返回RSA私钥运算结果的实际长度
 */
DEVAPI extern "C" ULONG SKF_ExtRSAPriKeyOperation(
    IN DEVHANDLE hDev,
    IN RSAPRIVATEKEYBLOB* pRSAPriKeyBlob,
    IN BYTE* pbInput,
    IN ULONG ulInputLen,
    OUT BYTE* pbOutput,
    OUT ULONG* pulOutputLen
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  生成ECC签名密钥对并输出签名公钥。
 *  hContainer      [IN] 容器句柄
 *  ulBitsLen       [IN] 密钥模长
 *  pBlob           [OUT] 返回ECC公钥数据结构
 */
DEVAPI extern "C" ULONG SKF_GenECCKeyPair(
    IN HCONTAINER hContainer,
    IN ULONG ulAlgId,
    OUT ECCPUBLICKEYBLOB *pBlob
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_GenECCKeyPair response;
    Req_SKF_GenECCKeyPair request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hcontainer()->set_u32value((long)hContainer);
            request.mutable_ulalgid()->set_u32value(ulAlgId);
            if(NULL != pBlob)
            {
                request.mutable_pblob()->mutable_bitlen()->set_u32value(pBlob->BitLen);
                if(NULL != pBlob->XCoordinate)
                {
                    request.mutable_pblob()->set_xcoordinate(pBlob->XCoordinate, sizeof(pBlob->XCoordinate));
                }
                if(NULL != pBlob->YCoordinate)
                {
                    request.mutable_pblob()->set_ycoordinate(pBlob->YCoordinate, sizeof(pBlob->YCoordinate));
                }
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_pblob() && NULL != pBlob)
            {
                if(response.mutable_pblob()->has_bitlen())
                {
                    pBlob->BitLen = response.mutable_pblob()->mutable_bitlen()->u32value();
                }
                if(response.mutable_pblob()->xcoordinate().size() && NULL != pBlob->XCoordinate)
                {
                    memset(pBlob->XCoordinate, 0, sizeof(pBlob->XCoordinate));
                    memcpy(pBlob->XCoordinate, response.mutable_pblob()->xcoordinate().data(), response.mutable_pblob()->xcoordinate().size());
                }
                if(response.mutable_pblob()->ycoordinate().size() && NULL != pBlob->YCoordinate)
                {
                    memset(pBlob->YCoordinate, 0, sizeof(pBlob->YCoordinate));
                    memcpy(pBlob->YCoordinate, response.mutable_pblob()->ycoordinate().data(), response.mutable_pblob()->ycoordinate().size());
                }
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  导入ECC公私钥对
 *  hContainer      [IN] 容器句柄
 *  pbWrapedData    [IN] 加密保护的ECC加密公私钥对密文
 *  ulWrapedLen     [IN] 数据长度
 */
DEVAPI extern "C" ULONG SKF_ImportECCKeyPair(
    IN HCONTAINER hContainer,
    IN PENVELOPEDKEYBLOB pEnvelopedKeyBlob
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ImportECCKeyPair response;
    Req_SKF_ImportECCKeyPair request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hcontainer()->set_u32value((long)hContainer);
            if(NULL != pEnvelopedKeyBlob)
            {
                request.mutable_penvelopedkeyblob()->mutable_version()->set_u32value(pEnvelopedKeyBlob->Version);
                request.mutable_penvelopedkeyblob()->mutable_ulsymmalgid()->set_u32value(pEnvelopedKeyBlob->ulSymmAlgID);
                request.mutable_penvelopedkeyblob()->mutable_ulbits()->set_u32value(pEnvelopedKeyBlob->ulBits);
                request.mutable_penvelopedkeyblob()->set_cbencryptedprikey(pEnvelopedKeyBlob->cbEncryptedPriKey, sizeof(pEnvelopedKeyBlob->cbEncryptedPriKey));

                {
                    request.mutable_penvelopedkeyblob()->mutable_pubkey()->mutable_bitlen()->set_u32value(pEnvelopedKeyBlob->PubKey.BitLen);
                    {
                        request.mutable_penvelopedkeyblob()->mutable_pubkey()->set_xcoordinate(pEnvelopedKeyBlob->PubKey.XCoordinate, sizeof(pEnvelopedKeyBlob->PubKey.XCoordinate));
                    }
                    {
                        request.mutable_penvelopedkeyblob()->mutable_pubkey()->set_ycoordinate(pEnvelopedKeyBlob->PubKey.YCoordinate, sizeof(pEnvelopedKeyBlob->PubKey.YCoordinate));
                    }
                }

                {
                    {
                        request.mutable_penvelopedkeyblob()->mutable_ecccipherblob()->set_xcoordinate(pEnvelopedKeyBlob->ECCCipherBlob.XCoordinate, sizeof(pEnvelopedKeyBlob->ECCCipherBlob.XCoordinate));
                    }
                    {
                        request.mutable_penvelopedkeyblob()->mutable_ecccipherblob()->set_ycoordinate(pEnvelopedKeyBlob->ECCCipherBlob.YCoordinate, sizeof(pEnvelopedKeyBlob->ECCCipherBlob.YCoordinate));
                    }
                    {
                        request.mutable_penvelopedkeyblob()->mutable_ecccipherblob()->set_hash(pEnvelopedKeyBlob->ECCCipherBlob.HASH, sizeof(pEnvelopedKeyBlob->ECCCipherBlob.HASH));
                    }
                    {
                        request.mutable_penvelopedkeyblob()->mutable_ecccipherblob()->set_cipher(pEnvelopedKeyBlob->ECCCipherBlob.Cipher, pEnvelopedKeyBlob->ECCCipherBlob.CipherLen);
                    }
                    request.mutable_penvelopedkeyblob()->mutable_ecccipherblob()->mutable_cipherlen()->set_u32value(pEnvelopedKeyBlob->ECCCipherBlob.CipherLen);
                }
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  ECC数字签名。采用ECC算法和指定私钥hKey，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名值的长度
 *  hContainer      [IN] 用来签名的私钥所在容器句柄
 *  pbData          [IN] 被签名的数据
 *  ulDataLen       [IN] 待签名数据长度，必须小于密钥模长
 *  pbSignature     [OUT] 签名值，为NULL时用于获得签名值的长度
 *  pulSigLen       [IN,OUT] 返回签名值长度的指针
 */
DEVAPI extern "C" ULONG SKF_ECCSignData(
    IN HANDLE hContainer,
    IN BYTE *pbData,
    IN ULONG ulDataLen,
    OUT PECCSIGNATUREBLOB pSignature
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ECCSignData response;
    Req_SKF_ECCSignData request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hcontainer()->set_u32value((long)hContainer);
            if(NULL != pbData)
            {
                request.set_pbdata(pbData, ulDataLen);
            }
            request.mutable_uldatalen()->set_u32value(ulDataLen);
            if(NULL != pSignature)
            {
                if(NULL != pSignature->r)
                {
                    request.mutable_psignature()->set_r(pSignature->r, sizeof(pSignature->r));
                }
                if(NULL != pSignature->s)
                {
                    request.mutable_psignature()->set_s(pSignature->s, sizeof(pSignature->s));
                }
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_psignature() && NULL != pSignature)
            {
                if(response.mutable_psignature()->r().size() && NULL != pSignature->r)
                {
                    memset(pSignature->r, 0, sizeof(pSignature->r));
                    memcpy(pSignature->r, response.mutable_psignature()->r().data(), response.mutable_psignature()->r().size());
                }
                if(response.mutable_psignature()->s().size() && NULL != pSignature->s)
                {
                    memset(pSignature->s, 0, sizeof(pSignature->s));
                    memcpy(pSignature->s, response.mutable_psignature()->s().data(), response.mutable_psignature()->s().size());
                }
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  用ECC公钥对数据进行验签
 *  hDev            [IN] 设备句柄
 *  pECCPubKeyBlob  [IN] ECC公钥数据结构
 *  pbData          [IN] 待验证签名的数据
 *  ulDataLen       [IN] 数据长度
 *  pbSignature     [IN] 待验证的签名值
 *  ulSigLen        [IN] 签名值长度
 */
DEVAPI extern "C" ULONG SKF_ECCVerify(
    IN DEVHANDLE            hDev,
    IN ECCPUBLICKEYBLOB*    pECCPubKeyBlob,
    IN BYTE*                pbData,
    IN ULONG                ulDataLen,
    IN PECCSIGNATUREBLOB pSignature
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ECCVerify response;
    Req_SKF_ECCVerify request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != pECCPubKeyBlob)
            {
                request.mutable_peccpubkeyblob()->mutable_bitlen()->set_u32value(pECCPubKeyBlob->BitLen);
                if(NULL != pECCPubKeyBlob->XCoordinate)
                {
                    request.mutable_peccpubkeyblob()->set_xcoordinate(pECCPubKeyBlob->XCoordinate, sizeof(pECCPubKeyBlob->XCoordinate));
                }
                if(NULL != pECCPubKeyBlob->YCoordinate)
                {
                    request.mutable_peccpubkeyblob()->set_ycoordinate(pECCPubKeyBlob->YCoordinate, sizeof(pECCPubKeyBlob->YCoordinate));
                }
            }
            if(NULL != pbData)
            {
                request.set_pbdata(pbData, ulDataLen);
            }
            request.mutable_uldatalen()->set_u32value(ulDataLen);
            if(NULL != pSignature)
            {
                if(NULL != pSignature->r)
                {
                    request.mutable_psignature()->set_r(pSignature->r, sizeof(pSignature->r));
                }
                if(NULL != pSignature->s)
                {
                    request.mutable_psignature()->set_s(pSignature->s, sizeof(pSignature->s));
                }
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  生成会话密钥并用外部公钥加密输出。
 *  hContainer      [IN] 容器句柄
 *  ulAlgID         [IN] 会话密钥的算法标识
 *  pPubKey         [IN] 外部输入的公钥结构
 *  pbData          [OUT] 导出的加密会话密钥密文
 *  phSessionKey    [OUT] 会话密钥句柄
 */
DEVAPI extern "C" ULONG SKF_ECCExportSessionKey(
    IN HCONTAINER hContainer,
    IN ULONG ulAlgID,
    IN ECCPUBLICKEYBLOB* pPubKey,
    OUT PECCCIPHERBLOB pData,
    OUT HANDLE* phSessionKey
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ECCExportSessionKey response;
    Req_SKF_ECCExportSessionKey request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hcontainer()->set_u32value((long)hContainer);
            request.mutable_ulalgid()->set_u32value(ulAlgID);
            if(NULL != pPubKey)
            {
                request.mutable_ppubkey()->mutable_bitlen()->set_u32value(pPubKey->BitLen);
                if(NULL != pPubKey->XCoordinate)
                {
                    request.mutable_ppubkey()->set_xcoordinate(pPubKey->XCoordinate, sizeof(pPubKey->XCoordinate));
                }
                if(NULL != pPubKey->YCoordinate)
                {
                    request.mutable_ppubkey()->set_ycoordinate(pPubKey->YCoordinate, sizeof(pPubKey->YCoordinate));
                }
            }
            //pcipherblob
            if(NULL != pData)
            {
                if(NULL != pData->XCoordinate)
                {
                    request.mutable_pdata()->set_xcoordinate(pData->XCoordinate, sizeof(pData->XCoordinate));
                }
                if(NULL != pData->YCoordinate)
                {
                    request.mutable_pdata()->set_ycoordinate(pData->YCoordinate, sizeof(pData->YCoordinate));
                }
                if(NULL != pData->HASH)
                {
                    request.mutable_pdata()->set_hash(pData->HASH, sizeof(pData->HASH));
                }
                if(0 != pData->CipherLen)
                {
                    request.mutable_pdata()->set_cipher(pData->Cipher, pData->CipherLen);
                }
                request.mutable_pdata()->mutable_cipherlen()->set_u32value(pData->CipherLen);
            }
            if(NULL != phSessionKey)
            {
                request.mutable_phsessionkey()->set_u32value(*(UINT32*)phSessionKey);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_pdata() && NULL != pData)
            {
                if(response.pdata().xcoordinate().size() && NULL != pData->XCoordinate)
                {
                    memset(pData->XCoordinate, 0, sizeof(pData->XCoordinate));
                    memcpy(pData->XCoordinate, response.pdata().xcoordinate().data(), response.pdata().xcoordinate().size());
                }
                if(response.pdata().ycoordinate().size() && NULL != pData->YCoordinate)
                {
                    memset(pData->YCoordinate, 0, sizeof(pData->YCoordinate));
                    memcpy(pData->YCoordinate, response.pdata().ycoordinate().data(), response.pdata().ycoordinate().size());
                }
                if(response.pdata().hash().size() && NULL != pData->HASH)
                {
                    memset(pData->HASH, 0, sizeof(pData->HASH));
                    memcpy(pData->HASH, response.pdata().hash().data(), response.pdata().hash().size());
                }
                if(response.pdata().cipher().size() && 0 != pData->CipherLen)
                {
                    memset(pData->Cipher, 0, sizeof(pData->Cipher));
                    memcpy(pData->Cipher, response.pdata().cipher().data(), response.pdata().cipher().size());
                }
                if(response.pdata().has_cipherlen())
                {
                    pData->CipherLen = response.pdata().cipherlen().u32value();
                }
            }
            if(response.has_phsessionkey() && (phSessionKey != NULL))
            {
                *phSessionKey = (HANDLE)response.phsessionkey().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  使用外部传入的ECC公钥对输入数据做加密运算并输出结果
 *  hDev            [IN] 设备句柄
 *  pECCPubKeyBlob  [IN] ECC公钥数据结构
 *  pbPlainText     [IN] 待加密的明文数据
 *  ulPlainTextLen  [IN] 待加密明文数据的长度
 *  pbCipherText    [OUT] 指向密文数据缓冲区，如果该参数为NULL，则由pulCipherTextLen返回密文数据的实际长度
 *  pulCipherTextLen[OUT] 调用前表示pbCipherText缓冲区的长度，返回密文数据的实际长度
 */
DEVAPI extern "C" ULONG SKF_ExtECCEncrypt(
    IN DEVHANDLE hDev,
    IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
    IN BYTE* pbPlainText,
    IN ULONG ulPlainTextLen,
    OUT PECCCIPHERBLOB pbCipherText
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ExtECCEncrypt response;
    Req_SKF_ExtECCEncrypt request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != pECCPubKeyBlob)
            {
                request.mutable_peccpubkeyblob()->mutable_bitlen()->set_u32value(pECCPubKeyBlob->BitLen);
                if(NULL != pECCPubKeyBlob->XCoordinate)
                {
                    request.mutable_peccpubkeyblob()->set_xcoordinate(pECCPubKeyBlob->XCoordinate, sizeof(pECCPubKeyBlob->XCoordinate));
                }
                if(NULL != pECCPubKeyBlob->YCoordinate)
                {
                    request.mutable_peccpubkeyblob()->set_ycoordinate(pECCPubKeyBlob->YCoordinate, sizeof(pECCPubKeyBlob->YCoordinate));
                }
            }
            if(NULL != pbPlainText)
            {
                request.set_pbplaintext(pbPlainText, ulPlainTextLen);
            }
            request.mutable_ulplaintextlen()->set_u32value(ulPlainTextLen);
            //pcipherblob
            if(NULL != pbCipherText)
            {
                if(NULL != pbCipherText->XCoordinate)
                {
                    request.mutable_pbciphertext()->set_xcoordinate(pbCipherText->XCoordinate, sizeof(pbCipherText->XCoordinate));
                }
                if(NULL != pbCipherText->YCoordinate)
                {
                    request.mutable_pbciphertext()->set_ycoordinate(pbCipherText->YCoordinate, sizeof(pbCipherText->YCoordinate));
                }
                if(NULL != pbCipherText->HASH)
                {
                    request.mutable_pbciphertext()->set_hash(pbCipherText->HASH, sizeof(pbCipherText->HASH));
                }
                if(0 != pbCipherText->CipherLen)
                {
                    request.mutable_pbciphertext()->set_cipher(pbCipherText->Cipher, pbCipherText->CipherLen);
                }
                request.mutable_pbciphertext()->mutable_cipherlen()->set_u32value(pbCipherText->CipherLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_pbciphertext() && NULL != pbCipherText)
            {
                if(response.pbciphertext().xcoordinate().size() && NULL != pbCipherText->XCoordinate)
                {
                    memset(pbCipherText->XCoordinate, 0, sizeof(pbCipherText->XCoordinate));
                    memcpy(pbCipherText->XCoordinate, response.pbciphertext().xcoordinate().data(), response.pbciphertext().xcoordinate().size());
                }
                if(response.pbciphertext().ycoordinate().size() && NULL != pbCipherText->YCoordinate)
                {
                    memset(pbCipherText->YCoordinate, 0, sizeof(pbCipherText->YCoordinate));
                    memcpy(pbCipherText->YCoordinate, response.pbciphertext().ycoordinate().data(), response.pbciphertext().ycoordinate().size());
                }
                if(response.pbciphertext().hash().size() && NULL != pbCipherText->HASH)
                {
                    memset(pbCipherText->HASH, 0, sizeof(pbCipherText->HASH));
                    memcpy(pbCipherText->HASH, response.pbciphertext().hash().data(), response.pbciphertext().hash().size());
                }
                if(response.pbciphertext().cipher().size() && 0 != pbCipherText->CipherLen)
                {
                    memset(pbCipherText->Cipher, 0, sizeof(pbCipherText->Cipher));
                    memcpy(pbCipherText->Cipher, response.pbciphertext().cipher().data(), response.pbciphertext().cipher().size());
                }
                if(response.pbciphertext().has_cipherlen())
                {
                    pbCipherText->CipherLen = response.pbciphertext().cipherlen().u32value();
                }
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  使用外部传入的ECC私钥对输入数据做解密运算并输出结果
 *  hDev            [IN] 设备句柄
 *  pRSAPriKeyBlob  [IN] ECC私钥数据结构
 *  pbInput         [IN] 待解密的密文数据
 *  ulInputLen      [IN] 待解密密文数据的长度
 *  pbOutput        [OUT] 返回明文数据，如果该参数为NULL，则由pulPlainTextLen返回明文数据的实际长度
 *  pulOutputLen    [OUT] 调用前表示pbPlainText缓冲区的长度，返回明文数据的实际长度
 */
DEVAPI extern "C" ULONG SKF_ExtECCDecrypt(
    IN DEVHANDLE hDev,
    IN ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
    IN PECCCIPHERBLOB pbCipherText,
    OUT BYTE* pbPlainText,
    OUT ULONG* pulPlainTextLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ExtECCDecrypt response;
    Req_SKF_ExtECCDecrypt request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != pECCPriKeyBlob)
            {
                request.mutable_peccprikeyblob()->mutable_bitlen()->set_u32value(pECCPriKeyBlob->BitLen);
                if(NULL != pECCPriKeyBlob->PrivateKey)
                {
                    request.mutable_peccprikeyblob()->set_privatekey(pECCPriKeyBlob->PrivateKey, sizeof(pECCPriKeyBlob->PrivateKey));
                }
            }
            if(NULL != pbCipherText)
            {
                if(NULL != pbCipherText->XCoordinate)
                {
                    request.mutable_pbciphertext()->set_xcoordinate(pbCipherText->XCoordinate, sizeof(pbCipherText->XCoordinate));
                }
                if(NULL != pbCipherText->YCoordinate)
                {
                    request.mutable_pbciphertext()->set_ycoordinate(pbCipherText->YCoordinate, sizeof(pbCipherText->YCoordinate));
                }
                if(NULL != pbCipherText->HASH)
                {
                    request.mutable_pbciphertext()->set_hash(pbCipherText->HASH, sizeof(pbCipherText->HASH));
                }
                if(0 != pbCipherText->CipherLen)
                {
                    request.mutable_pbciphertext()->set_cipher(pbCipherText->Cipher, pbCipherText->CipherLen);
                }
                request.mutable_pbciphertext()->mutable_cipherlen()->set_u32value(pbCipherText->CipherLen);
            }
            if(NULL != pulPlainTextLen)
            {
                if(NULL != pbPlainText)
                {
                    request.set_pbplaintext(pbPlainText, *pulPlainTextLen);
                }
                request.mutable_pulplaintextlen()->set_u32value(*pulPlainTextLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.pbplaintext().size() && (pbPlainText != NULL))
            {
                memcpy(pbPlainText, response.pbplaintext().data(), response.pbplaintext().size());
            }
            if(response.has_pulplaintextlen() && (pulPlainTextLen != NULL))
            {
                *pulPlainTextLen = response.pulplaintextlen().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}


/*
 *  使用外部传入的ECC私钥对输入数据做签名运算并输出结果。
 *  hDev            [IN] 设备句柄
 *  pRSAPriKeyBlob  [IN] ECC私钥数据结构
 *  pbData          [IN] 待签名数据
 *  ulDataLen       [IN] 待签名数据的长度
 *  pbSignature     [OUT] 签名值，如果该参数为NULL，则由pulSignatureLen返回签名结果的实际长度
 *  pulSignatureLen [OUT] 调用前表示pbSignature缓冲区的长度，返回签名结果的实际长度
 */
DEVAPI extern "C" ULONG SKF_ExtECCSign(
    IN DEVHANDLE hDev,
    IN ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
    IN BYTE* pbData,
    IN ULONG ulDataLen,
    OUT PECCSIGNATUREBLOB pSignature
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ExtECCSign response;
    Req_SKF_ExtECCSign request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != pECCPriKeyBlob)
            {
                request.mutable_peccprikeyblob()->mutable_bitlen()->set_u32value(pECCPriKeyBlob->BitLen);
                if(NULL != pECCPriKeyBlob->PrivateKey)
                {
                    request.mutable_peccprikeyblob()->set_privatekey(pECCPriKeyBlob->PrivateKey, sizeof(pECCPriKeyBlob->PrivateKey));
                }
            }
            if(NULL != pbData)
            {
                request.set_pbdata(pbData, ulDataLen);
            }
            request.mutable_uldatalen()->set_u32value(ulDataLen);
            if(NULL != pSignature)
            {
                if(NULL != pSignature->r)
                {
                    request.mutable_psignature()->set_r(pSignature->r, sizeof(pSignature->r));
                }
                if(NULL != pSignature->s)
                {
                    request.mutable_psignature()->set_s(pSignature->s, sizeof(pSignature->s));
                }
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_psignature() && NULL != pSignature)
            {
                if(response.mutable_psignature()->r().size() && NULL != pSignature->r)
                {
                    memset(pSignature->r, 0, sizeof(pSignature->r));
                    memcpy(pSignature->r, response.mutable_psignature()->r().data(), response.mutable_psignature()->r().size());
                }
                if(response.mutable_psignature()->s().size() && NULL != pSignature->s)
                {
                    memset(pSignature->s, 0, sizeof(pSignature->s));
                    memcpy(pSignature->s, response.mutable_psignature()->s().data(), response.mutable_psignature()->s().size());
                }
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  外部使用传入的ECC公钥做签名验证
 *  hDev            [IN] 设备句柄
 *  pECCPubKeyBlob  [IN] ECC公钥数据结构
 *  pbData          [IN] 待验证数据
 *  ulDataLen       [IN] 待验证数据的长度
 *  pbSignature     [OUT] 签名值
 *  ulSignLen       [OUT] 签名值的长度
 */
DEVAPI extern "C" ULONG SKF_ExtECCVerify(
    IN DEVHANDLE hDev,
    IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
    IN BYTE* pbData,
    IN ULONG ulDataLen,
    IN PECCSIGNATUREBLOB pSignature
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ExtECCVerify response;
    Req_SKF_ExtECCVerify request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != pECCPubKeyBlob)
            {
                request.mutable_peccpubkeyblob()->mutable_bitlen()->set_u32value(pECCPubKeyBlob->BitLen);
                if(NULL != pECCPubKeyBlob->XCoordinate)
                {
                    request.mutable_peccpubkeyblob()->set_xcoordinate(pECCPubKeyBlob->XCoordinate, sizeof(pECCPubKeyBlob->XCoordinate));
                }
                if(NULL != pECCPubKeyBlob->YCoordinate)
                {
                    request.mutable_peccpubkeyblob()->set_ycoordinate(pECCPubKeyBlob->YCoordinate, sizeof(pECCPubKeyBlob->YCoordinate));
                }
            }
            if(NULL != pbData)
            {
                request.set_pbdata(pbData, ulDataLen);
            }
            request.mutable_uldatalen()->set_u32value(ulDataLen);
            if(NULL != pSignature)
            {
                if(NULL != pSignature->r)
                {
                    request.mutable_psignature()->set_r(pSignature->r, sizeof(pSignature->r));
                }
                if(NULL != pSignature->s)
                {
                    request.mutable_psignature()->set_s(pSignature->s, sizeof(pSignature->s));
                }
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  使用ECC密钥协商算法，为计算会话密钥而产生协商参数，返回临时ECC密钥对的公钥及协商句柄
 *  hContainer      [IN] 容器句柄
 *  ulAlgId         [IN] 会话密钥算法标识
 *  pTempECCPubKeyBlob  [OUT] 发起方临时ECC公钥
 *  pbID            [IN] 发起方的ID
 *  ulIDLen         [IN] 发起方ID的长度，不大于32
 *  phAgreementHandle   [OUT] 返回的密钥协商句柄
 */
DEVAPI extern "C" ULONG SKF_GenerateAgreementDataWithECC(
    IN HCONTAINER hContainer,
    IN ULONG ulAlgId,
    OUT ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
    IN BYTE* pbID,
    IN ULONG ulIDLen,
    OUT HANDLE *phAgreementHandle
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  使用ECC密钥协商算法，产生协商参数并计算会话密钥，输出临时ECC密钥对公钥，并返回产生的密钥句柄
 *  hContainer                  [IN] 容器句柄
 *  ulAlgId                     [IN] 会话密钥算法标识
 *  pSponsorECCPubKeyBlob       [IN] 发起方的ECC公钥
 *  pSponsorTempECCPubKeyBlob   [IN] 发起方的临时ECC公钥
 *  pTempECCPubKeyBlob          [OUT] 响应方的临时ECC公钥
 *  pbID                        [IN] 响应方的ID
 *  ulIDLen                     [IN] 响应方ID的长度，不大于32
 *  pbSponsorID                 [IN] 发起方的ID
 *  ulSponsorIDLen              [IN] 发起方ID的长度，不大于32
 *  phKeyHandle                 [OUT] 返回的对称算法密钥句柄
 */
DEVAPI extern "C" ULONG SKF_GenerateAgreementDataAndKeyWithECC(
    IN HANDLE hContainer,
    IN ULONG ulAlgId,
    IN ECCPUBLICKEYBLOB* pSponsorECCPubKeyBlob,
    IN ECCPUBLICKEYBLOB* pSponsorTempECCPubKeyBlob,
    OUT ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
    IN BYTE* pbID,
    IN ULONG ulIDLen,
    IN BYTE *pbSponsorID,
    IN ULONG ulSponsorIDLen,
    OUT HANDLE *phKeyHandle
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥，同时返回会话密钥句柄
 *  hAgreementHandle            [IN] 密钥协商句柄
 *  pECCPubKeyBlob              [IN] 外部输入的响应方ECC公钥
 *  pTempECCPubKeyBlob          [IN] 外部输入的响应方临时ECC公钥
 *  pbID                        [IN] 响应方的ID
 *  ulIDLen                     [IN] 响应方ID的长度，不大于32
 *  phKeyHandle                 [OUT] 返回的密钥句柄
 */
DEVAPI extern "C" ULONG SKF_GenerateKeyWithECC(
    IN HANDLE hAgreementHandle,
    IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
    IN ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
    IN BYTE* pbID,
    IN ULONG ulIDLen,
    OUT HANDLE *phKeyHandle
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  导出容器中的签名公钥或者加密公钥
 *  hContainer      [IN] 容器句柄
 *  bSignFlag       [IN] TRUE表示导出签名公钥，FALSE表示导出加密公钥
 *  pbBlob          [OUT] 指向RSA公钥结构（RSAPUBLICKEYBLOB）或者ECC公钥结构（ECCPUBLICKEYBLOB），如果此参数为NULL时，由pulBlobLen返回pbBlob的长度
 *  pulBlobLen      [IN,OUT] 调用时表示pbBlob的长度，返回导出公钥结构的大小
 */
DEVAPI extern "C" ULONG SKF_ExportPublicKey(
    IN HCONTAINER hContainer,
    IN BOOL bSignFlag,
    OUT BYTE* pbBlob,
    OUT ULONG* pulBlobLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ExportPublicKey response;
    Req_SKF_ExportPublicKey request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hcontainer()->set_u32value((long)hContainer);
            request.mutable_bsignflag()->set_boolvalue(bSignFlag);
            if(NULL != pulBlobLen)
            {
                if(NULL != pbBlob)
                {
                    request.set_pbblob(pbBlob, *pulBlobLen);
                }
                request.mutable_pulbloblen()->set_u32value(*pulBlobLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.pbblob().size() && (pbBlob != NULL))
            {
                memcpy(pbBlob, response.pbblob().data(), response.pbblob().size());
            }
            if(response.has_pulbloblen() && (pulBlobLen != NULL))
            {
                *pulBlobLen = response.pulbloblen().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  导入会话密钥
 *  hContainer      [IN] 容器句柄
 *  ulAlgID         [IN] 会话密钥的算法标识
 *  pbWrapedData    [IN] 要导入的数据
 *  ulWrapedLen     [IN] 数据长度
 *  phKey           [OUT] 返回会话密钥句柄
 */
DEVAPI extern "C" ULONG SKF_ImportSessionKey(
    IN HCONTAINER hContainer,
    IN ULONG ulAlgID,
    IN BYTE *pbWrapedData,
    IN ULONG ulWrapedLen,
    OUT HANDLE* phKey
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ImportSessionKey response;
    Req_SKF_ImportSessionKey request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hcontainer()->set_u32value((long)hContainer);
            request.mutable_ulalgid()->set_u32value(ulAlgID);
            if(NULL != pbWrapedData)
            {
                request.set_pbwrappeddata(pbWrapedData, ulWrapedLen);
            }
            request.mutable_ulwrappedlen()->set_u32value(ulWrapedLen);
            request.mutable_phkey()->set_u32value(*(UINT32*)phKey);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_phkey() && (phKey != NULL))
            {
                *phKey = (HANDLE)response.phkey().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  设置明文对称密钥，返回密钥句柄
 *  hContainer      [IN] 容器句柄
 *  pbKey           [IN] 指向会话密钥值的缓冲区
 *  ulAlgID         [IN] 会话密钥的算法标识
 *  phKey           [OUT] 返回会话密钥句柄
 */
DEVAPI extern "C" ULONG SKF_SetSymmKey(
    IN DEVHANDLE hDev,
    IN BYTE* pbKey,
    IN ULONG ulAlgID,
    OUT HANDLE* phKey
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_SetSymmKey response;
    Req_SKF_SetSymmKey request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != pbKey)
            {
                request.set_pbkey(pbKey, 16);
            }
            request.mutable_ulalgid()->set_u32value(ulAlgID);
            request.mutable_phkey()->set_u32value(*(UINT32*)phKey);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_phkey() && (phKey != NULL))
            {
                *phKey = (HANDLE)response.phkey().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  数据加密初始化。设置数据加密的算法相关参数。
 *  hKey            [IN] 加密密钥句柄
 *  EncryptParam    [IN] 分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
 */
DEVAPI extern "C" ULONG SKF_EncryptInit(
    IN HANDLE hKey,
    IN BLOCKCIPHERPARAM EncryptParam
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_EncryptInit response;
    Req_SKF_EncryptInit request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hkey()->set_u32value((long)hKey);
            {
                {
                    request.mutable_encryptparam()->set_iv(EncryptParam.IV, sizeof(EncryptParam.IV));
                }
                request.mutable_encryptparam()->mutable_ivlen()->set_u32value(EncryptParam.IVLen);
                request.mutable_encryptparam()->mutable_paddingtype()->set_u32value(EncryptParam.PaddingType);
                request.mutable_encryptparam()->mutable_feedbitlen()->set_u32value(EncryptParam.FeedBitLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  单一分组数据的加密操作。
    用指定加密密钥对指定数据进行加密，被加密的数据只包含一个分组，加密后的密文保存到指定的缓冲区中。
    SKF_Encrypt只对单个分组数据进行加密，在调用SKF_Encrypt之前，必须调用SKF_EncryptInit初始化加密操作。
    SKF_Encypt等价于先调用SKF_EncryptUpdate再调用SKF_EncryptFinal。
 *  hKey            [IN] 加密密钥句柄
 *  pbData          [IN] 待加密数据
 *  ulDataLen       [IN] 待加密数据长度
 *  pbEncryptedData [OUT] 加密后的数据缓冲区指针
 *  pulEncryptedLen [IN,OUT] 输入，给出的缓冲区大小；输出，返回加密后的数据
长度
 *  成功: SAR_OK
 *  失败: SAR_FAIL SAR_MEMORYERR SAR_UNKNOWNERR  SAR_INVALIDPARAMERR SAR_BUFFER_TOO_SMALL
 */
DEVAPI extern "C" ULONG SKF_Encrypt(
    HANDLE  hKey,
    BYTE*       pbData,
    ULONG       ulDataLen,
    BYTE*       pbEncryptedData,
    ULONG*  pulEncryptedLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_Encrypt response;
    Req_SKF_Encrypt request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hkey()->set_u32value((long)hKey);
            if(NULL != pbData)
            {
                request.set_pbdata(pbData, ulDataLen);
            }
            request.mutable_uldatalen()->set_u32value(ulDataLen);
            if(NULL != pulEncryptedLen)
            {
                if(NULL != pbEncryptedData)
                {
                    request.set_pbencrypteddata(pbEncryptedData, *pulEncryptedLen);
                }
                request.mutable_pulencryptedlen()->set_u32value(*pulEncryptedLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.pbencrypteddata().size() && (pbEncryptedData != NULL))
            {
                memcpy(pbEncryptedData, response.pbencrypteddata().data(), response.pbencrypteddata().size());
            }
            if(response.has_pulencryptedlen() && (pulEncryptedLen != NULL))
            {
                *pulEncryptedLen = response.pulencryptedlen().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  多个分组数据的加密操作。
    用指定加密密钥对指定数据进行加密，被加密的数据包含多个分组，加密后的密文保存到指定的缓冲区中。
    SKF_EncryptUpdate对多个分组数据进行加密，在调用SKF_EncryptUpdate之前，必须调用SKF_EncryptInit初始化加密操作；
    在调用SKF_EncryptUpdate之后，必须调用SKF_EncryptFinal结束加密操作。
 *  hKey            [IN] 加密密钥句柄
 *  pbData          [IN] 待加密数据
 *  ulDataLen       [IN] 待加密数据长度
 *  pbEncryptedData [OUT] 加密后的数据缓冲区指针
 *  pulEncryptedLen [OUT] 返回加密后的数据长度
 */
DEVAPI extern "C" ULONG SKF_EncryptUpdate(
    IN HANDLE       hKey,
    IN BYTE*        pbData,
    IN ULONG        ulDataLen,
    OUT BYTE*       pbEncryptedData,
    OUT ULONG*  pulEncryptedLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_EncryptUpdate response;
    Req_SKF_EncryptUpdate request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hkey()->set_u32value((long)hKey);
            if(NULL != pbData)
            {
                request.set_pbdata(pbData, ulDataLen);
            }
            request.mutable_uldatalen()->set_u32value(ulDataLen);
            if(NULL != pulEncryptedLen)
            {
                if(NULL != pbEncryptedData)
                {
                    request.set_pbencrypteddata(pbEncryptedData, *pulEncryptedLen);
                }
                request.mutable_pulencryptedlen()->set_u32value(*pulEncryptedLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.pbencrypteddata().size() && (pbEncryptedData != NULL))
            {
                memcpy(pbEncryptedData, response.pbencrypteddata().data(), response.pbencrypteddata().size());
            }
            if(response.has_pulencryptedlen() && (pulEncryptedLen != NULL))
            {
                *pulEncryptedLen = response.pulencryptedlen().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  结束多个分组数据的加密，返回剩余加密结果。
    先调用SKF_EncryptInit初始化加密操作，
    再调用SKF_EncryptUpdate对多个分组数据进行加密，
    最后调用SKF_EncryptFinal结束多个分组数据的加密。
 *  hKey            [IN] 加密密钥句柄
 *  pbEncryptedData [OUT] 加密结果的缓冲区
 *  pulEncryptedDataLen [OUT] 加密结果的长度
 */
DEVAPI extern "C" ULONG SKF_EncryptFinal(
    IN HANDLE hKey,
    OUT BYTE *pbEncryptedData,
    OUT ULONG *pulEncryptedDataLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_EncryptFinal response;
    Req_SKF_EncryptFinal request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hkey()->set_u32value((long)hKey);
            if(NULL != pulEncryptedDataLen)
            {
                if(NULL != pbEncryptedData)
                {
                    request.set_pbencrypteddata(pbEncryptedData, *pulEncryptedDataLen);
                }
                request.mutable_pulencrypteddatalen()->set_u32value(*pulEncryptedDataLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.pbencrypteddata().size() && (pbEncryptedData != NULL))
            {
                memcpy(pbEncryptedData, response.pbencrypteddata().data(), response.pbencrypteddata().size());
            }
            if(response.has_pulencrypteddatalen() && (pulEncryptedDataLen != NULL))
            {
                *pulEncryptedDataLen = response.pulencrypteddatalen().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  数据解密初始化，设置解密密钥相关参数。
    调用SKF_DecryptInit之后，可以调用SKF_Decrypt对单个分组数据进行解密，
    也可以多次调用SKF_DecryptUpdate之后再调用SKF_DecryptFinal完成对多个分组数据的解密。
 *  hKey [IN] 解密密钥句柄
 *  DecryptParam [IN] 分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
 */
DEVAPI extern "C" ULONG SKF_DecryptInit(
    IN HANDLE hKey,
    IN BLOCKCIPHERPARAM DecryptParam
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_DecryptInit response;
    Req_SKF_DecryptInit request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hkey()->set_u32value((long)hKey);
            {
                {
                    request.mutable_decryptparam()->set_iv(DecryptParam.IV, sizeof(DecryptParam.IV));
                }
                request.mutable_decryptparam()->mutable_ivlen()->set_u32value(DecryptParam.IVLen);
                request.mutable_decryptparam()->mutable_paddingtype()->set_u32value(DecryptParam.PaddingType);
                request.mutable_decryptparam()->mutable_feedbitlen()->set_u32value(DecryptParam.FeedBitLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  单个分组数据的解密操作
    用指定解密密钥对指定数据进行解密，被解密的数据只包含一个分组，解密后的明文保存到指定的缓冲区中
    SKF_Decrypt只对单个分组数据进行解密，在调用SKF_Decrypt之前，必须调用SKF_DecryptInit初始化解密操作
    SKF_Decypt等价于先调用SKF_DecryptUpdate再调用SKF_DecryptFinal
 *  hKey            [IN] 解密密钥句柄
 *  pbEncryptedData [IN] 待解密数据
 *  ulEncryptedLen  [IN] 待解密数据长度
 *  pbData          [OUT] 指向解密后的数据缓冲区指针，当为NULL时可获得解密后的数据长度
 *  pulDataLen      [IN，OUT] 返回解密后的数据长度
 */
DEVAPI extern "C" ULONG SKF_Decrypt(
    IN HANDLE hKey,
    IN BYTE*    pbEncryptedData,
    IN ULONG    ulEncryptedLen,
    OUT BYTE* pbData,
    OUT ULONG* pulDataLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_Decrypt response;
    Req_SKF_Decrypt request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hkey()->set_u32value((long)hKey);
            if(NULL != pbEncryptedData)
            {
                request.set_pbencrypteddata(pbEncryptedData, ulEncryptedLen);
            }
            request.mutable_ulencryptedlen()->set_u32value(ulEncryptedLen);
            if(NULL != pulDataLen)
            {
                if(NULL != pbData)
                {
                    request.set_pbdata(pbData, *pulDataLen);
                }
                request.mutable_puldatalen()->set_u32value(*(UINT32*)pulDataLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.pbdata().size() && (pbData != NULL))
            {
                memcpy(pbData, response.pbdata().data(), response.pbdata().size());
            }
            if(response.has_puldatalen() && (pulDataLen != NULL))
            {
                *pulDataLen = response.puldatalen().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
*   多个分组数据的解密操作。
    用指定解密密钥对指定数据进行解密，被解密的数据包含多个分组，解密后的明文保存到指定的缓冲区中。
    SKF_DecryptUpdate对多个分组数据进行解密，在调用SKF_DecryptUpdate之前，必须调用SKF_DecryptInit初始化解密操作；
    在调用SKF_DecryptUpdate之后，必须调用SKF_DecryptFinal结束解密操作。
 *  hKey            [IN] 解密密钥句柄
 *  pbEncryptedData [IN] 待解密数据
 *  ulEncryptedLen  [IN] 待解密数据长度
 *  pbData          [OUT] 指向解密后的数据缓冲区指针
 *  pulDataLen      [IN，OUT] 返回解密后的数据长度
 */
DEVAPI extern "C" ULONG SKF_DecryptUpdate(
    IN HANDLE hKey,
    IN BYTE*    pbEncryptedData,
    IN ULONG    ulEncryptedLen,
    OUT BYTE* pbData,
    OUT ULONG* pulDataLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_DecryptUpdate response;
    Req_SKF_DecryptUpdate request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hkey()->set_u32value((long)hKey);
            if(NULL != pbEncryptedData)
            {
                request.set_pbencrypteddata(pbEncryptedData, ulEncryptedLen);
            }
            request.mutable_ulencryptedlen()->set_u32value(ulEncryptedLen);
            if(NULL != pulDataLen)
            {
                if(NULL != pbData)
                {
                    request.set_pbdata(pbData, *pulDataLen);
                }
                request.mutable_puldatalen()->set_u32value(*(UINT32*)pulDataLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.pbdata().size() && (pbData != NULL))
            {
                memcpy(pbData, response.pbdata().data(), response.pbdata().size());
            }
            if(response.has_puldatalen() && (pulDataLen != NULL))
            {
                *pulDataLen = response.puldatalen().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  结束多个分组数据的解密。
 *  hKey                [IN] 解密密钥句柄
 *  pbPlainText         [OUT] 指向解密结果的缓冲区，如果此参数为NULL时，由pulPlainTextLen返回解密结果的长度
 *  pulDecyptedDataLen  [IN，OUT] 调用时表示pbPlainText缓冲区的长度，返回解密结果的长度
 */
DEVAPI extern "C" ULONG SKF_DecryptFinal(
    IN HANDLE hKey,
    OUT BYTE *pbPlainText,
    OUT ULONG *pulPlainTextLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_DecryptFinal response;
    Req_SKF_DecryptFinal request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hkey()->set_u32value((long)hKey);
            if(NULL != pulPlainTextLen)
            {
                if(NULL != pbPlainText)
                {
                    request.set_pbplaintext(pbPlainText, *pulPlainTextLen);
                }
                request.mutable_pulplaintextlen()->set_u32value(*pulPlainTextLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.pbplaintext().size() && (pbPlainText != NULL))
            {
                memcpy(pbPlainText, response.pbplaintext().data(), response.pbplaintext().size());
            }
            if(response.has_pulplaintextlen() && (pulPlainTextLen != NULL))
            {
                *pulPlainTextLen = response.pulplaintextlen().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  初始化消息杂凑计算操作，指定计算消息杂凑的算法。
 *  hDev            [IN] 连接设备时返回的设备句柄
 *  ulAlgID         [IN] 杂凑算法标识
 *  phHash          [OUT] 杂凑对象句柄
 */
DEVAPI extern "C" ULONG SKF_DigestInit(
    IN DEVHANDLE    hDev,
    IN ULONG        ulAlgID,
    IN ECCPUBLICKEYBLOB *pPubKey,
    IN unsigned char *pucID,
    IN ULONG ulIDLen,
    OUT HANDLE* phHash
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_DigestInit response;
    Req_SKF_DigestInit request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            request.mutable_ulalgid()->set_u32value(ulAlgID);
            if(NULL != pPubKey)
            {
                request.mutable_ppubkey()->mutable_bitlen()->set_u32value(pPubKey->BitLen);
                if(NULL != pPubKey->XCoordinate)
                {
                    request.mutable_ppubkey()->set_xcoordinate(pPubKey->XCoordinate, sizeof(pPubKey->XCoordinate));
                }
                if(NULL != pPubKey->YCoordinate)
                {
                    request.mutable_ppubkey()->set_ycoordinate(pPubKey->YCoordinate, sizeof(pPubKey->YCoordinate));
                }
            }
            if(NULL != pucID)
            {
                request.set_pucid(pucID, ulIDLen);
            }
            request.mutable_ulidlen()->set_u32value(ulIDLen);
            request.mutable_phhash()->set_u32value(*(UINT32*)phHash);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_phhash() && (phHash != NULL))
            {
                *phHash = (HANDLE)response.phhash().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  对单一分组的消息进行杂凑计算。
 *  hHash           [IN] 杂凑对象句柄
 *  pbData          [IN] 指向消息数据的缓冲区
 *  ulDataLen       [IN] 消息数据的长度
 *  pbHashData      [OUT] 杂凑数据缓冲区指针，当此参数为NULL时，由pulHashLen返回杂凑结果的长度
 *  pulHashLen      [IN，OUT] 调用时表示pbHashData缓冲区的长度，返回杂凑结果的长度
 */
DEVAPI extern "C" ULONG SKF_Digest(
    IN HANDLE hHash,
    IN BYTE *pbData,
    IN ULONG ulDataLen,
    OUT BYTE *pbHashData,
    OUT ULONG *pulHashLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_Digest response;
    Req_SKF_Digest request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hhash()->set_u32value((long)hHash);
            if(NULL != pbData)
            {
                request.set_pbdata(pbData, ulDataLen);
            }
            request.mutable_uldatalen()->set_u32value(ulDataLen);
            if(NULL != pulHashLen)
            {
                if(NULL != pbHashData)
                {
                    request.set_pbhashdata(pbHashData, *pulHashLen);
                }
                request.mutable_pulhashlen()->set_u32value(*pulHashLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.pbhashdata().size() && (pbHashData != NULL))
            {
                memcpy(pbHashData, response.pbhashdata().data(), response.pbhashdata().size());
            }
            if(response.has_pulhashlen() && (pulHashLen != NULL))
            {
                *pulHashLen = response.pulhashlen().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  对多个分组的消息进行杂凑计算。
 *  hHash           [IN] 杂凑对象句柄
 *  pbPart          [IN] 指向消息数据的缓冲区
 *  ulPartLen       [IN] 消息数据的长度
 */
DEVAPI extern "C" ULONG SKF_DigestUpdate(
    IN HANDLE hHash,
    IN BYTE *pbData,
    IN ULONG ulDataLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_DigestUpdate response;
    Req_SKF_DigestUpdate request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hhash()->set_u32value((long)hHash);
            if(NULL != pbData)
            {
                request.set_pbdata(pbData, ulDataLen);
            }
            request.mutable_uldatalen()->set_u32value(ulDataLen);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  结束多个分组消息的杂凑计算操作，将杂凑保存到指定的缓冲区。
 *  hHash           [IN] 哈希对象句柄
 *  pHashData       [OUT] 返回的杂凑数据缓冲区指针，如果此参数NULL时，由pulHashLen返回杂凑结果的长度
 *  pulHashLen      [IN，OUT] 调用时表示杂凑结果的长度，返回杂凑数据的长度
 */
DEVAPI extern "C" ULONG SKF_DigestFinal(
    IN HANDLE hHash,
    OUT BYTE *pHashData,
    OUT ULONG *pulHashLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_DigestFinal response;
    Req_SKF_DigestFinal request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hhash()->set_u32value((long)hHash);
            if(NULL != pulHashLen)
            {
                if(NULL != pHashData)
                {
                    request.set_phashdata(pHashData, *pulHashLen);
                }
                request.mutable_pulhashlen()->set_u32value(*pulHashLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.phashdata().size() && (pHashData != NULL))
            {
                memcpy(pHashData, response.phashdata().data(), response.phashdata().size());
            }
            if(response.has_pulhashlen() && (pulHashLen != NULL))
            {
                *pulHashLen = response.pulhashlen().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  初始化消息认证码计算操作，设置计算消息认证码的密钥参数，并返回消息认证码句柄。
 *  hKey            [IN] 计算消息认证码的密钥句柄
 *  MacParam        [IN] 消息认证计算相关参数，包括初始向量、初始向量长度、填充方法等
 *  phMac           [OUT] 消息认证码对象句柄
 */
DEVAPI extern "C" ULONG SKF_MacInit(
    IN HANDLE hKey,
    IN BLOCKCIPHERPARAM* MacParam,
    OUT HANDLE *phMac
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  SKF_Mac计算单一分组数据的消息认证码。
 *  hMac            [IN] 消息认证码句柄
 *  pbData          [IN] 指向待计算数据的缓冲区
 *  ulDataLen       [IN] 待计算数据的长度
 *  pbMacData       [OUT] 指向计算后的Mac结果，如果此参数为NULL时，由pulMacLen返回计算后Mac结果的长度
 *  pulMacLen       [IN，OUT] 调用时表示pbMacData缓冲区的长度，返回计算Mac结果的长度
 */
DEVAPI extern "C" ULONG SKF_Mac(
    IN HANDLE hMac,
    IN BYTE * pbData,
    IN ULONG ulDataLen,
    OUT BYTE *pbMacData,
    OUT ULONG *pulMacLen
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  计算多个分组数据的消息认证码。
 *  hMac            [IN] 消息认证码句柄
 *  pbData          [IN] 指向待计算数据的缓冲区
 *  plDataLen       [IN] 待计算数据的长度
 */
DEVAPI extern "C" ULONG SKF_MacUpdate(
    IN HANDLE hMac,
    IN BYTE*    pbData,
    IN ULONG    ulDataLen
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  结束多个分组数据的消息认证码计算操作
 *  hMac            [IN] 消息认证码句柄
 *  pbMacData       [OUT] 指向消息认证码的缓冲区，当此参数为NULL时，由pulMacDataLen返回消息认证码返回的长度
 *  pulMacDataLen   [OUT] 调用时表示消息认证码缓冲区的最大长度，返回消息认证码的长度
 */
DEVAPI extern "C" ULONG SKF_MacFinal(
    IN HANDLE hMac,
    OUT BYTE*   pbMacData,
    OUT ULONG* pulMacDataLen
)
{
    return SAR_NOTSUPPORTYETERR;
}

/*
 *  关闭会话密钥、杂凑、消息认证码句柄。
 *  hHandle         [IN] 要关闭的对象句柄
 */
DEVAPI extern "C" ULONG SKF_CloseHandle(
    IN HANDLE hHandle
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_CloseHandle response;
    Req_SKF_CloseHandle request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hhandle()->set_u32value((long)hHandle);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  将命令直接发送给设备，并返回结果
 *  hDev            [IN] 设备句柄
 *  pbCommand       [IN] 设备命令
 *  ulCommandLen    [IN] 命令长度
 *  pbData          [OUT] 返回结果数据
 *  pulDataLen      [OUT] 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度
 */
DEVAPI extern "C" ULONG SKF_Transmit(
    IN DEVHANDLE hDev,
    IN BYTE* pbCommand,
    IN ULONG ulCommandLen,
    OUT BYTE* pbData,
    OUT ULONG* pulDataLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_Transmit response;
    Req_SKF_Transmit request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hdev()->set_u32value((long)hDev);
            if(NULL != pbCommand)
            {
                request.set_pbcommand(pbCommand, ulCommandLen);
            }
            request.mutable_ulcommandlen()->set_u32value(ulCommandLen);
            if(NULL != pulDataLen)
            {
                if(NULL != pbData)
                {
                    request.set_pbdata(pbData, *pulDataLen);
                }
                request.mutable_puldatalen()->set_u32value(*pulDataLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.pbdata().size() && (pbData != NULL))
            {
                memcpy(pbData, response.pbdata().data(), response.pbdata().size());
            }
            if(response.has_puldatalen() && (pulDataLen != NULL))
            {
                *pulDataLen = response.puldatalen().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  往容器中导入签名证书或者加密证书
 *  hContainer      [IN] 容器句柄
 *  bSignFlag       [IN] TRUE表示导入签名证书，FALSE表示导入加密证书
 *  pbCert          [IN] 指向证书数据的缓冲区
 *  ulCertLen       [IN] 证书数据的长度
 */
DEVAPI extern "C" ULONG SKF_ImportCertificate(
    IN HCONTAINER hContainer,
    IN BOOL bSignFlag,
    IN BYTE* pbCert,
    IN ULONG ulCertLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ImportCertificate response;
    Req_SKF_ImportCertificate request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hcontainer()->set_u32value((long)hContainer);
            request.mutable_bsignflag()->set_boolvalue(bSignFlag);
            if(NULL != pbCert)
            {
                request.set_pbcert(pbCert, ulCertLen);
            }
            request.mutable_ulcertlen()->set_u32value(ulCertLen);
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  导出容器中的签名证书或者加密证书
 *  hContainer      [IN] 容器句柄
 *  bSignFlag       [IN] TRUE表示导出签名证书，FALSE表示导出加密证书
 *  pbCert          [OUT] 指向证书数据的缓冲区
 *  pulCertLen      [IN,OUT] 调用时表示pbCert的长度，返回导出证书的大小
 */
DEVAPI extern "C" ULONG SKF_ExportCertificate(
    IN HCONTAINER hContainer,
    IN BOOL bSignFlag,
    OUT BYTE* pbCert,
    IN OUT ULONG* pulCertLen
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_ExportCertificate response;
    Req_SKF_ExportCertificate request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hcontainer()->set_u32value((long)hContainer);
            request.mutable_bsignflag()->set_boolvalue(bSignFlag);
            if(NULL != pulCertLen)
            {
                if(NULL != pbCert)
                {
                    request.set_pbcert(pbCert, *pulCertLen);
                }
                request.mutable_pulcertlen()->set_u32value(*pulCertLen);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.pbcert().size() && (pbCert != NULL))
            {
                memcpy(pbCert, response.pbcert().data(), response.pbcert().size());
            }
            if(response.has_pulcertlen() && (pulCertLen != NULL))
            {
                *pulCertLen = response.pulcertlen().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}

/*
 *  获取容器的属性
 *  hContainer      [IN] 容器句柄
 *  pulConProperty  [OUT] 获得的容器属性。指针指向的值为0表示未知、尚未分配属性或者为空容器，为1表示为RSA容器，为2表示为ECC容器。
 */
DEVAPI extern "C" ULONG SKF_GetContainerProperty(
    IN HCONTAINER hContainer,
    OUT ULONG *pulConProperty
)
{
    int rv = 0;
    string szFunctionName = __FUNCTION__;
    string szOutMsg;
    string szInMsg;
    Rsp_SKF_GetContainerProperty response;
    Req_SKF_GetContainerProperty request;
    RemoteCall* pRemoteCall = NULL;
    ResponsePack responsePack;

    ///TODO0
    do
    {
        {
            ////TODO1_imp
            ///build request msg
            request.mutable_hcontainer()->set_u32value((long)hContainer);
            if(NULL != pulConProperty)
            {
                request.mutable_pulconproperty()->set_u32value(*pulConProperty);
            }
            LOGI(tag,"build request msg success,%s",__FUNCTION__);

            ///serialize request msg to string
            if(!request.SerializeToString(&szOutMsg))
            {
                ///TODO1_ERROR00
                break;
            }
            LOGI(tag,"serialize  request msg success");

            ////TODO101
        }

        {
            ////TODO2_01
            ///build remote call object
            pRemoteCall = new RemoteCall(pClient);

            ////TODO2_02
            ///run remote procedure call
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
            if(0 != rv)
            {
                LOGE(tag,"pRemoteCall->PutRequest, rv = %d", rv);
                ////TODO2_ERROR
            }
            LOGI(tag,"send request msg success");

            ////TODO2_03
            ///wait remote procedure call result
            rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
            if(0 != rv)
            {
                LOGI(tag,"pRemoteCall->WaitForResponse, rv = %d", rv);
                ////TODO2_ERROR03
                break;
            }
            LOGI(tag,"get response msg success");

            ////TODO2_04
        }

        {

            ///parse response msg
            if(!responsePack.ParseFromString(szInMsg))
            {
                ///TODO3_ERROR00
                break;
            }
            rv = responsePack.ret();
            if(!responsePack.has_content())
            {
                ///TODO3_ERROR01
                break;
            }
            if(!response.ParseFromString(responsePack.content()))
            {
                LOGE(tag,"parse response msg error");
                ///TODO3_ERROR02
                break;
            }
            LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);

            ///TODO3_imp
            if(response.has_pulconproperty() && (pulConProperty != NULL))
            {
                *pulConProperty = response.pulconproperty().u32value();
            }
        }
    }while(0);

    ////TODO4
    //free the memory
    delete pRemoteCall;
    pRemoteCall = NULL;

    return rv;
}
