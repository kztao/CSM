#include <iostream>
#include <set>
#include "cryptoki.h"
#include "log.h"

#pragma GCC visibility push(hidden)

#include "Export.h"
#include "Return.pb.h"
#include "RemoteCall.h"
#include "ReturnCode.h"
#include "pkcs11.pb.h"
#include "GetPackageName.h"
#include "LocalSocketClient.h"
#include "ucm.h"
#include "BinderClient.h"
#pragma pragma GCC visibility pop

using std::string;
using std::set;
using namespace com::weston::pkcs11;
using namespace com::westone::returncode;
#define OPERATION_TIMEOUT 10000
#define TRAINING_TIME  10000
#define DESTROY_TIME  20000

#define CLIENT_VERSION "3.1.8"


static int CommStatus = CLIENT_DISCONNECTED;
static NotifyFunc g_notifyserverstatus = NULL;
static bool p11InitFlg = false;

CK_FUNCTION_LIST functionList = {0};

EXPORT CK_RV Register_Exception_Notify_Callback(NotifyFunc notifyfunc){
	
	g_notifyserverstatus = notifyfunc;
	return CKR_OK;
}


static void CommClientStatus(int status){
	if(g_notifyserverstatus){	
		g_notifyserverstatus(status);
	}
}

//static CommunicationClient *pClient = new LocalSocketClient((char*)LOCAL_SOCKET_SERVER_NAME,CommClientStatus);
//static CommunicationClient *pClient = ((BinderClient::getInstance("com.westone.csm.CSM") == NULL) ? new BinderClient("com.westone.csm.CSM",CommClientStatus):BinderClient::getInstance("com.westone.csm.CSM"));
static CommunicationClient *pClient = NULL;
static set<register_status_callback_func> g_callbackFuncs;

static const char *tag = "csm_p11Client";

////////////////////////////////////////////////////////////////////////
///global callback function 
int CallbackMsgFunc(const string funcName,const string szInMsg)
{
	int rv = 0;
	ResponsePack responsePack;
	///TODO0

    LOGI(tag,"C_Extend_Status_Callback_Func 1");

	do{
		
		if(funcName == "C_Extend_Register_Status_Callback_Func")
		{			
			Rsp_Status_Callback_Func response;
			///parse response msg
			if(!responsePack.ParseFromString(szInMsg))
			{
				break;
			} 
			response.ParseFromString(responsePack.content());
			LOGI(tag,"parse response msg success %s,ret is %d",__FUNCTION__,rv);
		
			
			//search callback table and invoke 
				
			set<register_status_callback_func>::iterator itr =  g_callbackFuncs.begin();
			for(; itr != g_callbackFuncs.end(); itr++)
			{
				if(*itr)
				{
					CK_STATUS_ENUM status = (CK_STATUS_ENUM)response.status();
					LOGI(tag,"callback, slotid is %d, status id %d",response.slotid(),status);
               		(*itr)(response.slotid(),status);
				}
				else
				{
					LOGI(tag,"itr is null");
				}
			}
			
		}
	
	}while(0);

	LOGI(tag, "%s OUT",__FUNCTION__);
	return rv;
}

static CK_RV PackageNameCheck(){
	RemoteCall * remoteCall = new RemoteCall(pClient,log_proxy);
	ResponsePack pack;
    GetPackageName *getPackageName = new GetPackageName();
	string packageName = getPackageName->GetName();
	LOGI(tag, "%s OUT packageName = %s",__FUNCTION__,packageName.data());
	string out;
	string &rout = out;
	int ret = remoteCall->PutRequest("PackageNameCheck",packageName);
	if(0 != ret)
	{
		LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%x", ret);

		delete(remoteCall);
		remoteCall = NULL;
    	delete(getPackageName);
		getPackageName = NULL;
	
		return ret;
	}
	
	ret = remoteCall->WaitForResponse(OPERATION_TIMEOUT,rout);
	
	
    delete(remoteCall);
	remoteCall = NULL;
    delete(getPackageName);
	getPackageName = NULL;

	if(ret != 0){
		return ret;
	}

    if(pack.ParseFromString(out)){
        CK_RV returnCode = pack.ret();
        return returnCode;
    }

	return CKR_OK;
}


////////////////////////////////////////////////////////////////////////


/* C_Initialize initializes the Cryptoki library. */
EXPORT CK_RV C_Initialize(
  CK_VOID_PTR   pInitArgs  /* if this is not NULL_PTR, it gets
                            * cast to CK_C_INITIALIZE_ARGS_PTR
                            * and dereferenced
                            */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Initialize response;
	Req_C_Initialize request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0
    RemoteCall::SetRemoteResponseParseFunc(CallbackMsgFunc);

	const char * filename = "csmproxylog.txt";
	const char * defaultRecordPath = "/sdcard/csmproxylog.txt";

    initPlog(filename, defaultRecordPath);
	LOGI(tag,"p11 client version: %s",CLIENT_VERSION);

	if(NULL == pClient){
		pClient = getInstance((char *)"com.westone.csm.CSM");
	}

	rv = PackageNameCheck();
	if(rv != CKR_OK){
		return rv;
	}

	do{
		{
			///build request msg
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			////TODO1_imp
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
            rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
		}
		
		/*{
			///register global callback fucntion
			rv = 0;
			//rv = RemoteCall::RemoteCallInit(C_Extend_Status_Callback_Func);
			if(0 != rv)
			{
				////TODO_ERROR04
				break;
			}
		}*/

	}while(0);

	if(rv == 0){
		p11InitFlg = true;
	}

	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	return rv;
}

/* C_Finalize indicates that an application is done with the
 * Cryptoki library.
 */
EXPORT CK_RV C_Finalize(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Finalize response;
	Req_C_Finalize request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			////TODO1_imp
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}



/* C_GetInfo returns general information about Cryptoki. */
EXPORT CK_RV C_GetInfo(
  CK_INFO_PTR   pInfo  /* location that receives information */ 
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GetInfo response;
	Req_C_GetInfo request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	if(NULL==pInfo)
	{
		return CKR_ARGUMENTS_BAD;
	}

	do{
		{
			///build request msg
			
			request.mutable_pinfo()->set_manufacturerid(pInfo->manufacturerID, 32);
			request.mutable_pinfo()->set_flags(pInfo->flags);
			request.mutable_pinfo()->set_librarydescription(pInfo->libraryDescription, 32);
			request.mutable_pinfo()->mutable_cryptokiversion()->set_major(pInfo->cryptokiVersion.major);
			request.mutable_pinfo()->mutable_cryptokiversion()->set_minor(pInfo->cryptokiVersion.minor);
			request.mutable_pinfo()->mutable_libraryversion()->set_major(pInfo->libraryVersion.major);
			request.mutable_pinfo()->mutable_libraryversion()->set_minor(pInfo->libraryVersion.minor);
			
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			////TODO1_imp
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pinfo())
			{
				pInfo->cryptokiVersion.major = response.pinfo().cryptokiversion().major();
				pInfo->cryptokiVersion.minor = response.pinfo().cryptokiversion().minor();
				memcpy(pInfo->manufacturerID, response.pinfo().manufacturerid().data(), response.pinfo().manufacturerid().size());
				pInfo->flags = response.pinfo().flags();
//				memcpy(pInfo->libraryDescription, response.pinfo().librarydescription().data(), response.pinfo().librarydescription().size());
				pInfo->libraryVersion.major = response.pinfo().libraryversion().major();
				pInfo->libraryVersion.minor = response.pinfo().libraryversion().minor();

				memset(pInfo->libraryDescription,0,sizeof(pInfo->libraryDescription));
                memcpy(pInfo->libraryDescription,CLIENT_VERSION,strlen(CLIENT_VERSION));

			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_GetFunctionList returns the function list. */
EXPORT CK_RV C_GetFunctionList(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
                                            * function list
                                            */
){
	CK_RV rv = CKR_OK;

	if(ppFunctionList == NULL)
	{
		return CKR_ARGUMENTS_BAD;
	}
	

	do{	
		{
            functionList.C_Initialize = C_Initialize;

			functionList.C_Initialize = C_Initialize;
			functionList.C_Finalize = C_Finalize;
			functionList.C_GetInfo = C_GetInfo;
			functionList.C_GetFunctionList = C_GetFunctionList;
			functionList.C_GetSlotList = C_GetSlotList;
			functionList.C_GetSlotInfo = C_GetSlotInfo;
			functionList.C_GetTokenInfo = C_GetTokenInfo;
			functionList.C_GetMechanismList = C_GetMechanismList;
			functionList.C_GetMechanismInfo = C_GetMechanismInfo;
			functionList.C_InitToken = C_InitToken;
			functionList.C_InitPIN = C_InitPIN;
			functionList.C_SetPIN = C_SetPIN;
			functionList.C_OpenSession = C_OpenSession;
			functionList.C_CloseSession = C_CloseSession;
			functionList.C_CloseAllSessions = C_CloseAllSessions;
			functionList.C_GetSessionInfo = C_GetSessionInfo;
			functionList.C_GetOperationState = C_GetOperationState;
			functionList.C_SetOperationState = C_SetOperationState;
			functionList.C_Login = C_Login;
			functionList.C_Logout = C_Logout;
			functionList.C_CreateObject = C_CreateObject;
			functionList.C_CopyObject = C_CopyObject;
			functionList.C_DestroyObject = C_DestroyObject;
			functionList.C_GetObjectSize = C_GetObjectSize;
			functionList.C_GetAttributeValue = C_GetAttributeValue;
			functionList.C_SetAttributeValue = C_SetAttributeValue;
			functionList.C_FindObjectsInit = C_FindObjectsInit;
			functionList.C_FindObjects = C_FindObjects;
			functionList.C_FindObjectsFinal = C_FindObjectsFinal;
			functionList.C_EncryptInit = C_EncryptInit;
			functionList.C_Encrypt = C_Encrypt;
			functionList.C_EncryptUpdate = C_EncryptUpdate;
			functionList.C_EncryptFinal = C_EncryptFinal;
			functionList.C_DecryptInit = C_DecryptInit;
			functionList.C_Decrypt = C_Decrypt;
			functionList.C_DecryptUpdate = C_DecryptUpdate;
			functionList.C_DecryptFinal = C_DecryptFinal;
			functionList.C_DigestInit = C_DigestInit;
			functionList.C_Digest = C_Digest;
			functionList.C_DigestUpdate = C_DigestUpdate;
			functionList.C_DigestKey = C_DigestKey;
			functionList.C_DigestFinal = C_DigestFinal;
			functionList.C_SignInit = C_SignInit;
			functionList.C_Sign = C_Sign;
			functionList.C_SignUpdate = C_SignUpdate;
			functionList.C_SignFinal = C_SignFinal;
			functionList.C_SignRecoverInit = C_SignRecoverInit;
			functionList.C_SignRecover = C_SignRecover;
			functionList.C_VerifyInit = C_VerifyInit;
			functionList.C_Verify = C_Verify;
			functionList.C_VerifyUpdate = C_VerifyUpdate;
			functionList.C_VerifyFinal = C_VerifyFinal;
			functionList.C_VerifyRecoverInit = C_VerifyRecoverInit;
			functionList.C_VerifyRecover = C_VerifyRecover;
			functionList.C_DigestEncryptUpdate = C_DigestEncryptUpdate;
			functionList.C_DecryptDigestUpdate = C_DecryptDigestUpdate;
			functionList.C_SignEncryptUpdate = C_SignEncryptUpdate;
			functionList.C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
			functionList.C_GenerateKey = C_GenerateKey;
			functionList.C_GenerateKeyPair = C_GenerateKeyPair;
			functionList.C_WrapKey = C_WrapKey;
			functionList.C_UnwrapKey = C_UnwrapKey;
			functionList.C_DeriveKey = C_DeriveKey;
			functionList.C_SeedRandom = C_SeedRandom;
			functionList.C_GenerateRandom = C_GenerateRandom;
			functionList.C_GetFunctionStatus = C_GetFunctionStatus;
			functionList.C_CancelFunction = C_CancelFunction;
			functionList.C_WaitForSlotEvent = C_WaitForSlotEvent;


			functionList.Register_Exception_Notify_Callback = Register_Exception_Notify_Callback;
			functionList.C_Extend_GetPinRemainCount = C_Extend_GetPinRemainCount;
			functionList.C_Extend_GetStatus = C_Extend_GetStatus;
			functionList.C_Extend_Register_Callback = C_Extend_Register_Callback;
			functionList.C_Extend_Unregister_Callback = C_Extend_Unregister_Callback;
			functionList.C_Extend_GetExchangeSessionKey = C_Extend_GetExchangeSessionKey;
			functionList.C_Extend_Destroy = C_Extend_Destroy;
			functionList.C_Extend_Reset_Pin_With_OTP = C_Extend_Reset_Pin_With_OTP;
			functionList.C_Extend_Reset_OTP = C_Extend_Reset_OTP;
			functionList.C_Extend_Get_OTP_Unlock_Count = C_Extend_Get_OTP_Unlock_Count;
			functionList.C_Extend_Get_OTP_Remain_Count = C_Extend_Get_OTP_Remain_Count;
			functionList.C_Extend_DeriveSessionKey = C_Extend_DeriveSessionKey;
			functionList.C_Extend_EncryptInit = C_Extend_EncryptInit;
			functionList.C_Extend_DecryptInit = C_Extend_DecryptInit;
			functionList.C_Extend_EncryptUpdate = C_Extend_EncryptUpdate;
			functionList.C_Extend_DecryptUpdate = C_Extend_DecryptUpdate;
			functionList.C_Extend_EncryptFinalize = C_Extend_EncryptFinalize;
			functionList.C_Extend_DecryptFinalize = C_Extend_DecryptFinalize;
			functionList.C_Extend_PointMultiply = C_Extend_PointMultiply;
	        functionList.C_Extend_Reset_TT = C_Extend_Reset_TT;
	        functionList.C_Extend_Reset_BK = C_Extend_Reset_BK;
	        functionList.C_Extend_Get_Special_Object_Version = C_Extend_Get_Special_Object_Version;
			functionList.C_Extend_DestroyCard = C_Extend_DestroyCard;
			functionList.C_Extend_MonopolizeEnable = C_Extend_MonopolizeEnable;
			functionList.C_Extend_MonopolizeDisable = C_Extend_MonopolizeDisable;
			functionList.C_Extend_GetDevInfo = C_Extend_GetDevInfo;
			functionList.C_Extend_DevSign = C_Extend_DevSign;
			functionList.C_Extend_Set_DestroyKey = C_Extend_Set_DestroyKey;
			functionList.C_Extend_Get_ExchangePubKey = C_Extend_Get_ExchangePubKey;

			*ppFunctionList = &functionList;
		}

	}while(0);


	return rv;
}



/* Slot and token management */

/* C_GetSlotList obtains a list of slots in the system. */
EXPORT CK_RV C_GetSlotList(
  CK_BBOOL       tokenPresent,  /* only slots with tokens */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GetSlotList response;
	Req_C_GetSlotList request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			////TODO1_imp
			request.set_tokenprespent(tokenPresent);
			if(NULL != pulCount)
			{
				if(NULL != pSlotList)
				{
					for(int i = 0; i < *pulCount; ++i)
					{
						request.add_pslotlist(pSlotList[i]);
					}
				}
				request.set_pulcount(*pulCount);
			}
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(pSlotList!=NULL)
			{
				for(int index = 0; index < response.pslotlist_size(); index++)
				{
					pSlotList[index] = response.pslotlist(index);
				}
			}
			
			if(response.has_pulcount() && (pulCount != NULL))
			{
				*pulCount = response.pulcount();
                LOGD(tag,"response.pulCount = %ld",*pulCount);
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_GetSlotInfo obtains information about a particular slot in
 * the system.
 */
EXPORT CK_RV C_GetSlotInfo(
  CK_SLOT_ID       slotID,  /* the ID of the slot */
  CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GetSlotInfo response;
	Req_C_GetSlotInfo request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	if(NULL==pInfo)
	{
		return CKR_ARGUMENTS_BAD;
	}

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);
			
			request.mutable_pinfo()->set_flags(pInfo->flags);
			request.mutable_pinfo()->set_slotdescription(pInfo->slotDescription, 64);
			request.mutable_pinfo()->set_manufacturerid(pInfo->manufacturerID, 32);
			request.mutable_pinfo()->mutable_hardwareversion()->set_major(pInfo->hardwareVersion.major);
			request.mutable_pinfo()->mutable_hardwareversion()->set_minor(pInfo->hardwareVersion.minor);
			request.mutable_pinfo()->mutable_firmwareversion()->set_major(pInfo->firmwareVersion.major);
			request.mutable_pinfo()->mutable_firmwareversion()->set_minor(pInfo->firmwareVersion.minor);

			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pinfo())
			{
				memcpy(pInfo->slotDescription, response.pinfo().slotdescription().data(), response.pinfo().slotdescription().size());
				memcpy(pInfo->manufacturerID, response.pinfo().manufacturerid().data(), response.pinfo().manufacturerid().size());
				pInfo->flags = response.pinfo().flags();
				pInfo->hardwareVersion.major = response.pinfo().hardwareversion().major();
				pInfo->hardwareVersion.minor = response.pinfo().hardwareversion().minor();
				pInfo->firmwareVersion.major = response.pinfo().firmwareversion().major();
				pInfo->firmwareVersion.minor = response.pinfo().firmwareversion().minor();
			}
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_GetTokenInfo obtains information about a particular token
 * in the system.
 */
EXPORT CK_RV C_GetTokenInfo(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GetTokenInfo response;
	Req_C_GetTokenInfo request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	if(NULL==pInfo)
	{
		return CKR_ARGUMENTS_BAD;
	}

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);
			
			request.mutable_pinfo()->set_labe(pInfo->label, 32);
			request.mutable_pinfo()->set_manufacturerid(pInfo->manufacturerID, 32);
			request.mutable_pinfo()->set_model(pInfo->model, 16);
			request.mutable_pinfo()->set_serialnumber(pInfo->serialNumber, 16);
			request.mutable_pinfo()->set_flags(pInfo->flags);
			request.mutable_pinfo()->set_ulmaxsessioncount(pInfo->ulMaxSessionCount);
			request.mutable_pinfo()->set_ulsessioncount(pInfo->ulSessionCount);
			request.mutable_pinfo()->set_ulmaxrwsessioncount(pInfo->ulMaxRwSessionCount);
			request.mutable_pinfo()->set_ulrwsessioncount(pInfo->ulRwSessionCount);
			request.mutable_pinfo()->set_ulmaxpinlen(pInfo->ulMaxPinLen);
			request.mutable_pinfo()->set_ulminpinlen(pInfo->ulMinPinLen);
			request.mutable_pinfo()->set_ultotalpublicmemory(pInfo->ulTotalPublicMemory);
			request.mutable_pinfo()->set_ulfreepublicmemory(pInfo->ulFreePublicMemory);
			request.mutable_pinfo()->set_ultotalprivatememory(pInfo->ulTotalPrivateMemory);
			request.mutable_pinfo()->set_ulfreeprivatememory(pInfo->ulFreePrivateMemory);
			request.mutable_pinfo()->mutable_hardwareversion()->set_major(pInfo->hardwareVersion.major);
			request.mutable_pinfo()->mutable_hardwareversion()->set_minor(pInfo->hardwareVersion.minor);
			request.mutable_pinfo()->mutable_firmwareversion()->set_major(pInfo->firmwareVersion.major);
			request.mutable_pinfo()->mutable_firmwareversion()->set_minor(pInfo->firmwareVersion.minor);
			request.mutable_pinfo()->set_utctime(pInfo->utcTime, 16);

			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pinfo())
			{
				memcpy(pInfo->label, response.pinfo().labe().data(), response.pinfo().labe().size());
				memcpy(pInfo->manufacturerID, response.pinfo().manufacturerid().data(), response.pinfo().manufacturerid().size());
				memcpy(pInfo->model, response.pinfo().model().data(), response.pinfo().model().size());
				memcpy(pInfo->serialNumber, response.pinfo().serialnumber().data(), response.pinfo().serialnumber().size());
				pInfo->flags = response.pinfo().flags();
				pInfo->ulMaxSessionCount = response.pinfo().ulmaxsessioncount();
				pInfo->ulSessionCount = response.pinfo().ulsessioncount();
				pInfo->ulMaxRwSessionCount = response.pinfo().ulmaxrwsessioncount();
				pInfo->ulRwSessionCount = response.pinfo().ulrwsessioncount();
				pInfo->ulMaxPinLen = response.pinfo().ulmaxpinlen();
				pInfo->ulMinPinLen = response.pinfo().ulminpinlen();
				pInfo->ulTotalPublicMemory = response.pinfo().ultotalpublicmemory();
				pInfo->ulFreePublicMemory = response.pinfo().ulfreepublicmemory();
				pInfo->ulTotalPrivateMemory = response.pinfo().ultotalprivatememory();
				pInfo->ulFreePrivateMemory = response.pinfo().ulfreeprivatememory();
				pInfo->hardwareVersion.major = response.pinfo().hardwareversion().major();
				pInfo->hardwareVersion.minor = response.pinfo().hardwareversion().minor();
				pInfo->firmwareVersion.major = response.pinfo().firmwareversion().major();
				pInfo->firmwareVersion.minor = response.pinfo().firmwareversion().minor();
				memcpy(pInfo->utcTime, response.pinfo().utctime().data(), response.pinfo().utctime().size());
			}
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_GetMechanismList obtains a list of mechanism types
 * supported by a token.
 */
EXPORT CK_RV C_GetMechanismList(
  CK_SLOT_ID            slotID,          /* ID of token's slot */
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GetMechanismList response;
	Req_C_GetMechanismList request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);
			if(NULL != pulCount)
			{
				if(NULL != pMechanismList)
				{
					for(int i = 0; i < *pulCount; ++i)
					{
						request.add_pmechanismlist(pMechanismList[i]);
					}
				}
				request.set_pulcount(*pulCount);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(pMechanismList != NULL)
			{
				for(int index = 0; index < response.pmechanismlist_size(); index++)
				{
					pMechanismList[index] = response.pmechanismlist(index);
				}
			}
			
			if(response.has_pulcount() && (pulCount != NULL))
			{
				*pulCount = response.pulcount();
			}
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token.
 */
EXPORT CK_RV C_GetMechanismInfo(
  CK_SLOT_ID            slotID,  /* ID of the token's slot */
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GetMechanismInfo response;
	Req_C_GetMechanismInfo request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	if(NULL == pInfo)
	{
		return CKR_ARGUMENTS_BAD;
	}

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);
			request.set_type(type);
			
			request.mutable_pinfo()->set_ulminkeysize(pInfo->ulMinKeySize);
			request.mutable_pinfo()->set_ulmaxkeysize(pInfo->ulMaxKeySize);
			request.mutable_pinfo()->set_flags(pInfo->flags);
			
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pinfo())
			{
				pInfo->ulMinKeySize = response.pinfo().ulminkeysize();
				pInfo->ulMaxKeySize = response.pinfo().ulmaxkeysize();
				pInfo->flags = response.pinfo().flags();
			}
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_InitToken initializes a token. */
EXPORT CK_RV C_InitToken(
  CK_SLOT_ID      slotID,    /* ID of the token's slot */
  CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
  CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
  CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_InitToken response;
	Req_C_InitToken request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);
			if(NULL != pPin)
			{
				request.set_ppin(pPin, ulPinLen);
			}
			request.set_ulpinlen(ulPinLen);
			if(NULL != pLabel)
			{
				request.set_plabel(pLabel, 32);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_InitPIN initializes the normal user's PIN. */
EXPORT CK_RV C_InitPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_InitPIN response;
	Req_C_InitPIN request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pPin)
			{
				request.set_ppin(pPin, ulPinLen);
			}
			request.set_ulpinlen(ulPinLen);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_SetPIN modifies the PIN of the user who is logged in. */
EXPORT CK_RV C_SetPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_SetPIN response;
	Req_C_SetPIN request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pOldPin)
			{
				request.set_poldpin(pOldPin, ulOldLen);
			}
			request.set_uloldlen(ulOldLen);
			if(NULL != pNewPin)
			{
				request.set_pnewpin(pNewPin, ulNewLen);
			}
			request.set_ulnewlen(ulNewLen);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
		
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}



/* Session management */

/* C_OpenSession opens a session between an application and a
 * token.
 */
EXPORT CK_RV C_OpenSession(
  CK_SLOT_ID            slotID,        /* the slot's ID */
  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
  CK_VOID_PTR           pApplication,  /* passed to callback */
  CK_NOTIFY             Notify,        /* callback function */
  CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_OpenSession response;
	Req_C_OpenSession request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	if(NULL == phSession)
	{
		return CKR_ARGUMENTS_BAD;
	}

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);
			request.set_flags(flags);
			
			request.set_phsession(*phSession);
			
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_phsession())
			{
				*phSession = response.phsession();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_CloseSession closes a session between an application and a
 * token.
 */
EXPORT CK_RV C_CloseSession(
  CK_SESSION_HANDLE hSession  /* the session's handle */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_CloseSession response;
	Req_C_CloseSession request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_CloseAllSessions closes all sessions with a token. */
EXPORT CK_RV C_CloseAllSessions(
  CK_SLOT_ID     slotID  /* the token's slot */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_CloseAllSessions response;
	Req_C_CloseAllSessions request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_GetSessionInfo obtains information about the session. */
EXPORT CK_RV C_GetSessionInfo(
  CK_SESSION_HANDLE   hSession,  /* the session's handle */
  CK_SESSION_INFO_PTR pInfo      /* receives session info */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GetSessionInfo response;
	Req_C_GetSessionInfo request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	if(NULL==pInfo)
	{
		return CKR_ARGUMENTS_BAD;
	}

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			
			request.mutable_pinfo()->set_slotid(pInfo->slotID);
			request.mutable_pinfo()->set_state(pInfo->state);
			request.mutable_pinfo()->set_flags(pInfo->flags);
			request.mutable_pinfo()->set_uldeviceerror(pInfo->ulDeviceError);
		
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pinfo())
			{
				pInfo->slotID = response.pinfo().slotid();
				pInfo->state = response.pinfo().state();
				pInfo->flags = response.pinfo().flags();
				pInfo->ulDeviceError = response.pinfo().uldeviceerror();
			}

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_GetOperationState obtains the state of the cryptographic operation
 * in a session.
 */
EXPORT CK_RV C_GetOperationState(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GetOperationState response;
	Req_C_GetOperationState request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pulOperationStateLen)
			{
				if(NULL != pOperationState)
				{
					request.set_poperationstate(pOperationState, *pulOperationStateLen);
				}
				request.set_puloperationstatelen(*pulOperationStateLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(pOperationState!=NULL)
			{
				if(response.has_poperationstate())
				{
					memcpy(pOperationState, response.poperationstate().data(), response.poperationstate().size());
				}
			}
			if(response.has_puloperationstatelen()&&(pulOperationStateLen != NULL))
			{
				*pulOperationStateLen = response.puloperationstatelen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_SetOperationState restores the state of the cryptographic
 * operation in a session.
 */
EXPORT CK_RV C_SetOperationState(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_SetOperationState response;
	Req_C_SetOperationState request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pOperationState)
			{
				request.set_poperationstate(pOperationState, ulOperationStateLen);
			}
			request.set_uloperationstatelen(ulOperationStateLen);
			request.set_hencryptionkey(hEncryptionKey);
			request.set_hauthenticationkey(hAuthenticationKey);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_Login logs a user into a token. */
EXPORT CK_RV C_Login(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Login response;
	Req_C_Login request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			request.set_usertype(userType);
			if(NULL != pPin)
			{
				request.set_ppin(pPin, ulPinLen);
			}
			request.set_ulpinlen(ulPinLen);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT+TRAINING_TIME, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success %s", __FUNCTION__);
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	LOGI(tag,"%s OUT", __FUNCTION__);
	return rv;
}


/* C_Logout logs a user out from a token. */
EXPORT CK_RV C_Logout(
  CK_SESSION_HANDLE hSession  /* the session's handle */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Logout response;
	Req_C_Logout request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}



/* Object management */

/* C_CreateObject creates a new object. */
EXPORT CK_RV C_CreateObject(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_CreateObject response;
	Req_C_CreateObject request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pTemplate)
			{
				for(int index = 0; index < ulCount; index++)
				{
					PRO_Attribute* pAttribute = request.add_ptemplate();
					pAttribute->set_type(pTemplate[index].type);
					if(NULL != pTemplate[index].pValue)
					{
						pAttribute->set_value(pTemplate[index].pValue, pTemplate[index].ulValueLen);
					}
					pAttribute->set_ulvaluelen(pTemplate[index].ulValueLen);
				}
			}
			request.set_ulcount(ulCount);
			if(NULL != phObject)
			{
				request.set_phobject(*phObject);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_phobject() && (phObject != NULL))
			{
				*phObject = response.phobject();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_CopyObject copies an object, creating a new object for the
 * copy.
 */
EXPORT CK_RV C_CopyObject(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_OBJECT_HANDLE     hObject,     /* the object's handle */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
  CK_ULONG             ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_CopyObject response;
	Req_C_CopyObject request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			request.set_hobject(hObject);
			if(NULL != pTemplate)
			{
				for(int index = 0; index < ulCount; index++)
				{
					PRO_Attribute* pAttribute = request.add_ptemplate();
					
					pAttribute->set_type(pTemplate[index].type);
					if(NULL != pTemplate[index].pValue)
					{
						pAttribute->set_value(pTemplate[index].pValue, pTemplate[index].ulValueLen);
					}
					pAttribute->set_ulvaluelen(pTemplate[index].ulValueLen);
				}
			}
			request.set_ulcount(ulCount);
			if(NULL != phNewObject)
			{
				request.set_phnewobject(*phNewObject);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_phnewobject() && (phNewObject != NULL))
			{
				*phNewObject = response.phnewobject();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_DestroyObject destroys an object. */
EXPORT CK_RV C_DestroyObject(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_DestroyObject response;
	Req_C_DestroyObject request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			////TODO1_imp
			request.set_hsession(hSession);
			request.set_hobject(hObject);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_GetObjectSize gets the size of an object in bytes. */
EXPORT CK_RV C_GetObjectSize(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GetObjectSize response;
	Req_C_GetObjectSize request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	if(NULL == pulSize)
	{
		return CKR_ARGUMENTS_BAD;
	}

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			request.set_hobject(hObject);
			
			request.set_pulsize(*pulSize);
			
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pulsize())
			{
				*pulSize = response.pulsize();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_GetAttributeValue obtains the value of one or more object
 * attributes.
 */
EXPORT CK_RV C_GetAttributeValue(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs{ gets vals */
  CK_ULONG          ulCount     /* attributes in template */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GetAttributeValue response;
	Req_C_GetAttributeValue request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	if(NULL == pTemplate)
	{
		return CKR_ARGUMENTS_BAD;
	}

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			request.set_hobject(hObject);
			
			for(int index = 0; index < ulCount; index++)
			{
				PRO_Attribute* pAttribute = request.add_ptemplate();
				pAttribute->set_type(pTemplate[index].type);
				if(NULL != pTemplate[index].pValue)
				{
					pAttribute->set_value(pTemplate[index].pValue, pTemplate[index].ulValueLen);
				}
				pAttribute->set_ulvaluelen(pTemplate[index].ulValueLen);
			}
		
			request.set_ulcount(ulCount);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			for(int index = 0; index < response.ptemplate_size(); index++)
			{
				pTemplate[index].type = response.ptemplate(index).type();
				if(response.ptemplate(index).has_value())
				{					
					memcpy(pTemplate[index].pValue, response.ptemplate(index).value().data(), response.ptemplate(index).value().size());
				}
				pTemplate[index].ulValueLen = response.ptemplate(index).ulvaluelen();
			}
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_SetAttributeValue modifies the value of one or more object
 * attributes.
 */
EXPORT CK_RV C_SetAttributeValue(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_SetAttributeValue response;
	Req_C_SetAttributeValue request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			request.set_hobject(hObject);
			if(NULL != pTemplate)
			{
				for(int index = 0; index < ulCount; index++)
				{
					PRO_Attribute* pAttribute = request.add_ptemplate();
					pAttribute->set_type(pTemplate[index].type);
					if(NULL != pTemplate[index].pValue)
					{
						pAttribute->set_value(pTemplate[index].pValue, pTemplate[index].ulValueLen);
					}
					pAttribute->set_ulvaluelen(pTemplate[index].ulValueLen);
				}
			}
			request.set_ulcount(ulCount);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template.
 */
EXPORT CK_RV C_FindObjectsInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_FindObjectsInit response;
	Req_C_FindObjectsInit request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pTemplate)
			{
				for(int index = 0; index < ulCount; index++)
				{
					PRO_Attribute* pAttribute = request.add_ptemplate();
					
					pAttribute->set_type(pTemplate[index].type);
					if(NULL != pTemplate[index].pValue)
					{
						pAttribute->set_value(pTemplate[index].pValue, pTemplate[index].ulValueLen);
					}
					pAttribute->set_ulvaluelen(pTemplate[index].ulValueLen);
				}
			}
			request.set_ulcount(ulCount);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,rv = %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles.
 */
EXPORT CK_RV C_FindObjects(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_FindObjects response;
	Req_C_FindObjects request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != phObject)
			{
				for(CK_ULONG i = 0; i < ulMaxObjectCount;i ++ ){
					request.add_phobject(phObject[i]);
				}
			}
			request.set_ulmaxobjectcount(ulMaxObjectCount);
			if(NULL != pulObjectCount)
			{
				request.set_pulobjectcount(*pulObjectCount);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			LOGI(tag,"serialize request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(phObject != NULL)
			{
				for(int index = 0; index < response.phobject_size(); index++)
				{
					phObject[index] = response.phobject(index);
				}
			}
			if(response.has_pulobjectcount() && (pulObjectCount != NULL))
			{
				*pulObjectCount = response.pulobjectcount();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_FindObjectsFinal finishes a search for token and session
 * objects.
 */
EXPORT CK_RV C_FindObjectsFinal(
  CK_SESSION_HANDLE hSession  /* the session's handle */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_FindObjectsFinal response;
	Req_C_FindObjectsFinal request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}



/* Encryption and decryption */

/* C_EncryptInit initializes an encryption operation. */
EXPORT CK_RV C_EncryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_EncryptInit response;
	Req_C_EncryptInit request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
				request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
				request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
				if(pMechanism->pParameter){
					request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
				}
			}
			request.set_hkey(hKey);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_Encrypt encrypts single-part data. */
EXPORT CK_RV C_Encrypt(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Encrypt response;
	Req_C_Encrypt request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pData)
			{
				request.set_pdata(pData, ulDataLen);
			}
			request.set_uldatalen(ulDataLen);
			if(NULL != pulEncryptedDataLen)
			{
				if(NULL != pEncryptedData)
				{
					request.set_pencrypteddata(pEncryptedData, *pulEncryptedDataLen);
				}
				request.set_pulencrypteddatalen(*pulEncryptedDataLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pencrypteddata() && (pEncryptedData != NULL))
			{
				memcpy(pEncryptedData, response.pencrypteddata().data(), response.pencrypteddata().size());
			}
			if(response.has_pulencrypteddatalen() && (pulEncryptedDataLen != NULL))
			{
				*pulEncryptedDataLen = response.pulencrypteddatalen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_EncryptUpdate continues a multiple-part encryption
 * operation.
 */
EXPORT CK_RV C_EncryptUpdate(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_EncryptUpdate response;
	Req_C_EncryptUpdate request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pPart)
			{
				request.set_ppart(pPart, ulPartLen);
			}
			request.set_ulpartlen(ulPartLen);
			if(NULL != pulEncryptedPartLen)
			{
				if(NULL != pEncryptedPart)
				{
					request.set_pencryptedpart(pEncryptedPart, *pulEncryptedPartLen);
				}
				request.set_pulencryptedpartlen(*pulEncryptedPartLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pencryptedpart() && (pEncryptedPart != NULL))
			{
				memcpy(pEncryptedPart, response.pencryptedpart().data(), response.pencryptedpart().size());
			}
			if(response.has_pulencryptedpartlen() && (pulEncryptedPartLen != NULL))
			{
				*pulEncryptedPartLen = response.pulencryptedpartlen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_EncryptFinal finishes a multiple-part encryption
 * operation.
 */
EXPORT CK_RV C_EncryptFinal(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_EncryptFinal response;
	Req_C_EncryptFinal request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pulLastEncryptedPartLen)
			{
				if(NULL != pLastEncryptedPart)
				{
					request.set_plastencryptedpart(pLastEncryptedPart, *pulLastEncryptedPartLen);
				}
				request.set_pullastencryptedpartlen(*pulLastEncryptedPartLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			
			if(response.has_plastencryptedpart() && (pLastEncryptedPart != NULL))
			{
				memcpy(pLastEncryptedPart, response.plastencryptedpart().data(), response.plastencryptedpart().size());
			}
			if(response.has_pullastencryptedpartlen() && (pulLastEncryptedPartLen != NULL))
			{
				*pulLastEncryptedPartLen = response.pullastencryptedpartlen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_DecryptInit initializes a decryption operation. */
EXPORT CK_RV C_DecryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_DecryptInit response;
	Req_C_DecryptInit request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			request.set_hkey(hKey);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_Decrypt decrypts encrypted data in a single part. */
EXPORT CK_RV C_Decrypt(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Decrypt response;
	Req_C_Decrypt request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pEncryptedData)
			{
				request.set_pencrypteddata(pEncryptedData, ulEncryptedDataLen);
			}
			request.set_ulencrypteddatalen(ulEncryptedDataLen);
			if(NULL != pulDataLen)
			{
				if(NULL != pData)
				{
					request.set_pdata(pData, *pulDataLen);
				}
				request.set_puldatalen(*pulDataLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pdata() && (pData != NULL))
			{
				memcpy(pData, response.pdata().data(), response.pdata().size());
			}
			if(response.has_puldatalen() && (pulDataLen != NULL))
			{
				*pulDataLen = response.puldatalen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_DecryptUpdate continues a multiple-part decryption
 * operation.
 */
EXPORT CK_RV C_DecryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_DecryptUpdate response;
	Req_C_DecryptUpdate request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pEncryptedPart)
			{
				request.set_pencryptedpart(pEncryptedPart, ulEncryptedPartLen);
			}
			request.set_ulencryptedpartlen(ulEncryptedPartLen);
			if(NULL != pulPartLen)
			{
				if(NULL != pPart)
				{
					request.set_ppart(pPart, *pulPartLen);
				}
				request.set_pulpartlen(*pulPartLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3
			if(response.has_ppart() && (pPart != NULL))
			{
				memcpy(pPart, response.ppart().data(), response.ppart().size());
			}
			if(response.has_pulpartlen() && (pulPartLen != NULL))
			{
				*pulPartLen = response.pulpartlen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_DecryptFinal finishes a multiple-part decryption
 * operation.
 */
EXPORT CK_RV C_DecryptFinal(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_DecryptFinal response;
	Req_C_DecryptFinal request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pulLastPartLen)
			{
				if(NULL != pLastPart)
				{
					request.set_plastpart(pLastPart, *pulLastPartLen);
				}
				request.set_pullastpartlen(*pulLastPartLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp				
			if((response.has_plastpart()) && (pLastPart != NULL))
			{
				memcpy(pLastPart, response.plastpart().data(), response.plastpart().size());
			}
			
			if(response.has_pullastpartlen() && (pulLastPartLen != NULL))
			{
				*pulLastPartLen = response.pullastpartlen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}



/* Message digesting */

/* C_DigestInit initializes a message-digesting operation. */
EXPORT CK_RV C_DigestInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_DigestInit response;
	Req_C_DigestInit request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_Digest digests data in a single part. */
EXPORT CK_RV C_Digest(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Digest response;
	Req_C_Digest request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pData)
			{
				request.set_pdata(pData, ulDataLen);
			}
			request.set_uldatalen(ulDataLen);
			if(NULL != pulDigestLen)
			{
				if(NULL != pDigest)
				{
					request.set_pdigest(pDigest, *pulDigestLen);
				}
				request.set_puldigestlen(*pulDigestLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pdigest() && (pDigest != NULL))
			{
				memcpy(pDigest, response.pdigest().data(), response.pdigest().size());
			}
			if(response.has_puldigestlen() && (pulDigestLen != NULL))
			{
				*pulDigestLen = response.puldigestlen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_DigestUpdate continues a multiple-part message-digesting
 * operation.
 */
EXPORT CK_RV C_DigestUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_DigestUpdate response;
	Req_C_DigestUpdate request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pPart)
			{
				request.set_ppart(pPart, ulPartLen);
			}
			request.set_ulpartlen(ulPartLen);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested.
 */
EXPORT CK_RV C_DigestKey(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_DigestKey response;
	Req_C_DigestKey request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			request.set_hkey(hKey);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_DigestFinal finishes a multiple-part message-digesting
 * operation.
 */
EXPORT CK_RV C_DigestFinal(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_DigestFinal response;
	Req_C_DigestFinal request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pulDigestLen)
			{
				if(NULL != pDigest)
				{
					request.set_pdigest(pDigest, *pulDigestLen);
				}
				request.set_puldigestlen(*pulDigestLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pdigest() && (pDigest != NULL))
			{
				memcpy(pDigest, response.pdigest().data(), response.pdigest().size());
			}
			if(response.has_puldigestlen() && (pulDigestLen != NULL))
			{
				*pulDigestLen = response.puldigestlen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}



/* Signing and MACing */

/* C_SignInit initializes a signature (private key encryption)
 * operation, where the signature is (will be) an appendix to
 * the data, and plaintext cannot be recovered from the
 * signature.
 */
EXPORT CK_RV C_SignInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signature key */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_SignInit response;
	Req_C_SignInit request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			request.set_hkey(hKey);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);

			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_Sign signs (encrypts with private key) data in a single
 * part, where the signature is (will be) an appendix to the
 * data, and plaintext cannot be recovered from the signature.
 */
EXPORT CK_RV C_Sign(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
){

	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Sign response;
	Req_C_Sign request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pData)
			{
				request.set_pdata(pData, ulDataLen);
			}
			request.set_uldatalen(ulDataLen);
			if(NULL != pulSignatureLen)
			{
				LOGI(tag,"pulSignatureLen = %d,pSignature = %p",*pulSignatureLen,pSignature);
				if(NULL != pSignature)
				{
					request.set_psignature(pSignature, *pulSignatureLen);
				}
				request.set_pulsignaturelen(*pulSignatureLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_psignature() && (pSignature != NULL))
			{
				memcpy(pSignature, response.psignature().data(), response.psignature().size());
			}
			if(response.has_pulsignaturelen() && (pulSignatureLen != NULL))
			{
				*pulSignatureLen = response.pulsignaturelen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_SignUpdate continues a multiple-part signature operation,
 * where the signature is (will be) an appendix to the data,
 * and plaintext cannot be recovered from the signature.
 */
EXPORT CK_RV C_SignUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_SignUpdate response;
	Req_C_SignUpdate request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pPart)
			{
				request.set_ppart(pPart, ulPartLen);
			}
			request.set_ulpartlen(ulPartLen);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_SignFinal finishes a multiple-part signature operation,
 * returning the signature.
 */
EXPORT CK_RV C_SignFinal(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_SignFinal response;
	Req_C_SignFinal request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pulSignatureLen)
			{
				if(NULL != pSignature)
				{
					request.set_psignature(pSignature, *pulSignatureLen);
				}
				request.set_pulsignaturelen(*pulSignatureLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_psignature() && (pSignature != NULL))
			{
				memcpy(pSignature, response.psignature().data(), response.psignature().size());
			}
			if(response.has_pulsignaturelen() && (pulSignatureLen != NULL))
			{
				*pulSignatureLen = response.pulsignaturelen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature.
 */
EXPORT CK_RV C_SignRecoverInit
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_SignRecoverInit response;
	Req_C_SignRecoverInit request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			request.set_hkey(hKey);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature.
 */
EXPORT CK_RV C_SignRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_SignRecover response;
	Req_C_SignRecover request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pData)
			{
				request.set_pdata(pData, ulDataLen);
			}
			request.set_uldatalen(ulDataLen);
			
			if(NULL != pulSignatureLen)
			{
				if(NULL != pSignature)
				{
					request.set_psignature(pSignature, *pulSignatureLen);
				}
				request.set_pulsignaturelen(*pulSignatureLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_psignature() && (pSignature != NULL))
			{
				memcpy(pSignature, response.psignature().data(), response.psignature().size());
			}
			if(response.has_pulsignaturelen() && (pulSignatureLen != NULL))
			{
				*pulSignatureLen = response.pulsignaturelen();
			}
			

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}



/* Verifying signatures and MACs */

/* C_VerifyInit initializes a verification operation, where the
 * signature is an appendix to the data, and plaintext cannot
 * cannot be recovered from the signature (e.g. DSA).
 */
EXPORT CK_RV C_VerifyInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_VerifyInit response;
	Req_C_VerifyInit request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			request.set_hkey(hKey);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_Verify verifies a signature in a single-part operation,
 * where the signature is an appendix to the data, and plaintext
 * cannot be recovered from the signature.
 */
EXPORT CK_RV C_Verify(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Verify response;
	Req_C_Verify request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pData)
			{
				request.set_pdata(pData, ulDataLen);
			}
			request.set_uldatalen(ulDataLen);
			if(NULL != pSignature)
			{
				request.set_psignature(pSignature, ulSignatureLen);
			}
			request.set_ulsignaturelen(ulSignatureLen);
			
			
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_VerifyUpdate continues a multiple-part verification
 * operation, where the signature is an appendix to the data,
 * and plaintext cannot be recovered from the signature.
 */
EXPORT CK_RV C_VerifyUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_VerifyUpdate response;
	Req_C_VerifyUpdate request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pPart)
			{
				request.set_ppart(pPart, ulPartLen);
			}
			request.set_ulpartlen(ulPartLen);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_VerifyFinal finishes a multiple-part verification
 * operation, checking the signature.
 */
EXPORT CK_RV C_VerifyFinal(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_VerifyFinal response;
	Req_C_VerifyFinal request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pSignature)
			{
				request.set_psignature(pSignature, ulSignatureLen);
			}
			request.set_ulsignaturelen(ulSignatureLen);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature.
 */
EXPORT CK_RV C_VerifyRecoverInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_VerifyRecoverInit response;
	Req_C_VerifyRecoverInit request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			request.set_hkey(hKey);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature.
 */
EXPORT CK_RV C_VerifyRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_VerifyRecover response;
	Req_C_VerifyRecover request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pSignature)
			{
				request.set_psignature(pSignature, ulSignatureLen);
			}
			request.set_ulsignaturelen(ulSignatureLen);
			if(NULL != pulDataLen)
			{
				if(NULL != pData)
				{
					request.set_pdata(pData, *pulDataLen);
				}
				request.set_puldatalen(*pulDataLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pdata() && (pData!=NULL))
			{
				memcpy(pData, response.pdata().data(), response.pdata().size());
			}
			if(response.has_puldatalen() && (pulDataLen != NULL))
			{
				*pulDataLen = response.puldatalen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}



/* Dual-function cryptographic operations */

/* C_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation.
 */
EXPORT CK_RV C_DigestEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_DigestEncryptUpdate response;
	Req_C_DigestEncryptUpdate request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pPart)
			{
				request.set_ppart(pPart, ulPartLen);
			}
			request.set_ulpartlen(ulPartLen);
			if(NULL != pulEncryptedPartLen)
			{
				if(NULL != pEncryptedPart)
				{
					request.set_pencryptedpart(pEncryptedPart, *pulEncryptedPartLen);
				}
				request.set_pulencryptedpartlen(*pulEncryptedPartLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pencryptedpart() && (pEncryptedPart != NULL))
			{
				memcpy(pEncryptedPart, response.pencryptedpart().data(), response.pencryptedpart().size());
			}
			if(response.has_pulencryptedpartlen() && (pulEncryptedPartLen != NULL))
			{
				*pulEncryptedPartLen = response.pulencryptedpartlen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation.
 */
EXPORT CK_RV C_DecryptDigestUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_DecryptDigestUpdate response;
	Req_C_DecryptDigestUpdate request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pEncryptedPart)
			{
				request.set_pencryptedpart(pEncryptedPart, ulEncryptedPartLen);
			}
			request.set_ulencryptedpartlen(ulEncryptedPartLen);
			if(NULL != pulPartLen)
			{
				if(NULL != pPart)
				{
					request.set_ppart(pPart, *pulPartLen);
				}
				request.set_pulpartlen(*pulPartLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_ppart() && (pPart != NULL))
			{
				memcpy(pPart, response.ppart().data(), response.ppart().size());
			}
			if(response.has_pulpartlen() && (pulPartLen != NULL))
			{
				*pulPartLen = response.pulpartlen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation.
 */
EXPORT CK_RV C_SignEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_SignEncryptUpdate response;
	Req_C_SignEncryptUpdate request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pPart)
			{
				request.set_ppart(pPart, ulPartLen);
			}
			request.set_ulpartlen(ulPartLen);
			if(NULL != pulEncryptedPartLen)
			{
				if(NULL != pEncryptedPart)
				{
					request.set_pencryptedpart(pEncryptedPart, *pulEncryptedPartLen);
				}
				request.set_pulencryptedpartlen(*pulEncryptedPartLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pencryptedpart() && (pEncryptedPart != NULL))
			{
				memcpy(pEncryptedPart, response.pencryptedpart().data(), response.pencryptedpart().size());
			}
			if(response.has_pulencryptedpartlen() && (pulEncryptedPartLen != NULL))
			{
				*pulEncryptedPartLen = response.pulencryptedpartlen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation.
 */
EXPORT CK_RV C_DecryptVerifyUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_DecryptVerifyUpdate response;
	Req_C_DecryptVerifyUpdate request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pEncryptedPart)
			{
				request.set_pencryptedpart(pEncryptedPart, ulEncryptedPartLen);
			}
			request.set_ulencryptedpartlen(ulEncryptedPartLen);
			if(NULL != pulPartLen)
			{
				if(NULL != pPart)
				{
					request.set_ppart(pPart, *pulPartLen);
				}
				request.set_pulpartlen(*pulPartLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_ppart() && (pPart != NULL))
			{
				memcpy(pPart, response.ppart().data(), response.ppart().size());
			}
			if(response.has_pulpartlen() && (pulPartLen!=NULL))
			{
				*pulPartLen = response.pulpartlen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}



/* Key management */

/* C_GenerateKey generates a secret key, creating a new key
 * object.
 */
EXPORT CK_RV C_GenerateKey(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GenerateKey response;
	Req_C_GenerateKey request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			
			if(NULL != pTemplate)
			{
				for(int index = 0; index < ulCount; index++)
				{
					PRO_Attribute* pAttribute = request.add_ptemplate();
					
					pAttribute->set_type(pTemplate[index].type);
					if(NULL != pTemplate[index].pValue)
					{
						pAttribute->set_value(pTemplate[index].pValue, pTemplate[index].ulValueLen);
					}
					pAttribute->set_ulvaluelen(pTemplate[index].ulValueLen);
				}
			}
			request.set_ulcount(ulCount);
			if(NULL != phKey)
			{
				request.set_phkey(*phKey);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_phkey() && (phKey != NULL))
			{
				*phKey = response.phkey();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_GenerateKeyPair generates a public-key/private-key pair,
 * creating new key objects.
 */
EXPORT CK_RV C_GenerateKeyPair(
  CK_SESSION_HANDLE    hSession,                    /* session handle */
  CK_MECHANISM_PTR     pMechanism,                  /* key-gen mech. */
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template for pub. key */
  CK_ULONG             ulPublicKeyAttributeCount,   /* # pub. attrs. */
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template for priv. key */
  CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.  attrs. */
  CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
  CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets priv. key handle */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GenerateKeyPair response;
	Req_C_GenerateKeyPair request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			if(NULL != pPublicKeyTemplate)
			{
				for(int indexPubKeyAttr = 0; indexPubKeyAttr < ulPublicKeyAttributeCount; indexPubKeyAttr++)
				{
					PRO_Attribute* pAttribute = request.add_ppublickeytemplate();
					
					pAttribute->set_type(pPublicKeyTemplate[indexPubKeyAttr].type);
					if(NULL != pPublicKeyTemplate[indexPubKeyAttr].pValue)
					{
						pAttribute->set_value(pPublicKeyTemplate[indexPubKeyAttr].pValue, pPublicKeyTemplate[indexPubKeyAttr].ulValueLen);
					}
					pAttribute->set_ulvaluelen(pPublicKeyTemplate[indexPubKeyAttr].ulValueLen);
				}
			}
			request.set_ulpublickeyattributecount(ulPublicKeyAttributeCount);
			if(NULL != pPrivateKeyTemplate)
			{
				for(int indexPriKeyAttr = 0; indexPriKeyAttr < ulPrivateKeyAttributeCount; indexPriKeyAttr++)
				{
					PRO_Attribute* pAttribute = request.add_pprivatekeytemplate();
					
					pAttribute->set_type(pPrivateKeyTemplate[indexPriKeyAttr].type);
					if(NULL != pPrivateKeyTemplate[indexPriKeyAttr].pValue)
					{
						pAttribute->set_value(pPrivateKeyTemplate[indexPriKeyAttr].pValue, pPrivateKeyTemplate[indexPriKeyAttr].ulValueLen);
					}
					pAttribute->set_ulvaluelen(pPrivateKeyTemplate[indexPriKeyAttr].ulValueLen);
				}
			}
			request.set_ulprivatekeyattributecount(ulPrivateKeyAttributeCount);
			if(NULL != phPublicKey)
			{
				request.set_phpublickey(*phPublicKey);
			}
			if(NULL != phPrivateKey)
			{
				request.set_phprivatekey(*phPrivateKey);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_phpublickey() && (phPublicKey != NULL))
			{
				*phPublicKey = response.phpublickey();
			}
			if(response.has_phprivatekey() && (phPrivateKey != NULL))
			{
				*phPrivateKey = response.phprivatekey();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_WrapKey wraps (i.e., encrypts) a key. */
EXPORT CK_RV C_WrapKey(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_WrapKey response;
	Req_C_WrapKey request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism )
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			request.set_hwrappingkey(hWrappingKey);
			request.set_hkey(hKey);
			if(NULL != pulWrappedKeyLen)
			{
				if(NULL != pWrappedKey)
				{
					request.set_pwrappedkey(pWrappedKey, *pulWrappedKeyLen);
				}
				request.set_pulwrappedkeylen(*pulWrappedKeyLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pwrappedkey() && (pWrappedKey != NULL))
			{
				memcpy(pWrappedKey, response.pwrappedkey().data(), response.pwrappedkey().size());
			}
			if(response.has_pulwrappedkeylen() && (pulWrappedKeyLen != NULL))
			{
				*pulWrappedKeyLen = response.pulwrappedkeylen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object.
 */
EXPORT CK_RV C_UnwrapKey(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_UnwrapKey response;
	Req_C_UnwrapKey request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			request.set_hunwrappingkey(hUnwrappingKey);
			if(NULL != pWrappedKey)
			{
				request.set_pwrappedkey(pWrappedKey, ulWrappedKeyLen);
			}
			request.set_ulwrappedkeylen(ulWrappedKeyLen);
			if(NULL != pTemplate)
			{
				for(int index = 0; index < ulAttributeCount; index++)
				{
					PRO_Attribute* pAttribute = request.add_ptemplate();
					
					pAttribute->set_type(pTemplate[index].type);
					if(NULL != pTemplate[index].pValue)
					{
						pAttribute->set_value(pTemplate[index].pValue, pTemplate[index].ulValueLen);
					}
					pAttribute->set_ulvaluelen(pTemplate[index].ulValueLen);
				}
			}
			request.set_ulattributecount(ulAttributeCount);
			if(phKey)
			{				
				request.set_phkey(*phKey);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_phkey() && (phKey != NULL))
			{
				*phKey = response.phkey();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_DeriveKey derives a key from a base key, creating a new key
 * object.
 */
EXPORT CK_RV C_DeriveKey(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_DeriveKey response;
	Req_C_DeriveKey request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			request.set_hbasekey(hBaseKey);
			if(NULL != pTemplate)
			{
				for(int index = 0; index < ulAttributeCount; index++)
				{
					PRO_Attribute* pAttribute = request.add_ptemplate();
					
					pAttribute->set_type(pTemplate[index].type);
					if(NULL != pTemplate[index].pValue)
					{
						pAttribute->set_value(pTemplate[index].pValue, pTemplate[index].ulValueLen);
					}
					pAttribute->set_ulvaluelen(pTemplate[index].ulValueLen);
				}
			}
			request.set_ulattributecount(ulAttributeCount);
			if(NULL != phKey)
			{
				request.set_phkey(*phKey);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_phkey() && (phKey != NULL))
			{
				*phKey = response.phkey();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}



/* Random number generation */

/* C_SeedRandom mixes additional seed material into the token's
 * random number generator.
 */
EXPORT CK_RV C_SeedRandom(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_SeedRandom response;
	Req_C_SeedRandom request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pSeed)
			{
				request.set_pseed(pSeed, ulSeedLen);
			}
			request.set_ulseedlen(ulSeedLen);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_GenerateRandom generates random data. */
EXPORT CK_RV C_GenerateRandom(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_BYTE_PTR       RandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GenerateRandom response;
	Req_C_GenerateRandom request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != RandomData)
			{
				request.set_randomdata(RandomData, ulRandomLen);
			}
			request.set_ulrandomlen(ulRandomLen);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_randomdata() && RandomData)
			{
				memcpy(RandomData, response.randomdata().data(), response.randomdata().size());
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}



/* Parallel function management */

/* C_GetFunctionStatus is a legacy function{ it obtains an
 * updated status of a function running in parallel with an
 * application.
 */
EXPORT CK_RV C_GetFunctionStatus(
  CK_SESSION_HANDLE hSession  /* the session's handle */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_GetFunctionStatus response;
	Req_C_GetFunctionStatus request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_CancelFunction is a legacy function{ it cancels a function
 * running in parallel.
 */
EXPORT CK_RV C_CancelFunction(
  CK_SESSION_HANDLE hSession  /* the session's handle */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_CancelFunction response;
	Req_C_CancelFunction request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/* C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur.
 */
EXPORT CK_RV C_WaitForSlotEvent(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_WaitForSlotEvent response;
	Req_C_WaitForSlotEvent request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			////TODO1_imp
			request.set_flags(flags);
			if(NULL != pSlot)
			{
				request.set_pslot(*pSlot);
			}
			if(NULL != pRserved)
			{
				///d0 nothing
			}
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pslot() && pSlot)
			{
				*pSlot = response.pslot();
			}
			if(response.has_prserved())
			{
				///d0 nothing
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


/////////////////////////////////////////////////////////////////////////////////////////////

/********************************
 *获取口令剩余尝试次数
*/
EXPORT CK_RV C_Extend_GetPinRemainCount(
	CK_SESSION_HANDLE hSession,
	CK_ULONG_PTR pUiRemainCount
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_GetPinRemainCount response;
	Req_C_Extend_GetPinRemainCount request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0
	

	do{
		{
			///build request msg
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pUiRemainCount)
			{
				request.set_puiremaincount(*pUiRemainCount);
			}
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_puiremaincount() && pUiRemainCount)
			{
				*pUiRemainCount = response.puiremaincount();
			}
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *获取密码卡状态
*/
EXPORT CK_RV C_Extend_GetStatus(
	CK_SLOT_ID slotID,
	CK_STATUS_ENUM_PTR pStatus
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_GetStatus response;
	Req_C_Extend_GetStatus request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);
			if(NULL != pStatus)
			{
				request.set_pstatus(*pStatus);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pstatus() && pStatus)
			{
				*pStatus = (CK_STATUS_ENUM)response.pstatus();
			}
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *注册密码卡状态回调函数
*/
EXPORT CK_RV C_Extend_Register_Callback(
	register_status_callback_func func
){
    if(p11InitFlg == false){
        LOGI(tag,"Not permission call any function such as [%s] before C_Initialize",__FUNCTION__);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_Register_Callback response;
	Req_C_Extend_Register_Callback request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0
	
	if(func == NULL_PTR)
	{
		LOGI(tag, "register null func");
		return rv;
	}

	do
	{
		if(!request.SerializeToString(&szOutMsg))
		{
			///TODO1_ERROR00
			break;
		}
		LOGI(tag,"serialize  request msg success,C_Extend_Register_Callback");

		///build remote call object
		pRemoteCall = new RemoteCall(pClient,log_proxy);

		///run remote procedure call
		rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
		if(0 != rv)
		{
			LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
			////TODO2_ERROR
			break;
		}

		//LOGI(tag,"send request msg success");
		////TODO2_03
		///wait remote procedure call result
		rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
		if(0 != rv)
		{
			LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
			////TODO2_ERROR03
			break;
		}
		//LOGI(tag,"get response msg success");
		////TODO2_04

		///parse response msg
		if(!responsePack.ParseFromString(szInMsg))
		{
			///TODO3_ERROR00
			break;
		}
		rv = responsePack.ret();
		if(!responsePack.has_content())
		{
			LOGI(tag,"no response msg");
			///TODO3_ERROR01
			break;
		}
		if(!response.ParseFromString(responsePack.content()))
		{
			LOGE(tag,"parse response msg error");
			///TODO3_ERROR02
			break;
		}
		LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
		///TODO3_imp
		if(rv == CKR_OK){
			g_callbackFuncs.insert(func);
		}

}while(0);

	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	return rv;
}

/********************************
 *注销密码卡状态回调函数
*/
EXPORT CK_RV C_Extend_Unregister_Callback(
	register_status_callback_func func
){
    if(p11InitFlg == false){
        LOGI(tag,"Not permission call any function such as [%s] before C_Initialize",__FUNCTION__);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_Unregister_Callback response;
	Req_C_Extend_Unregister_Callback request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0
	do
	{
		if(!request.SerializeToString(&szOutMsg))
		{
			///TODO1_ERROR00
			break;
		}
		//LOGI(tag,"serialize  request msg success");

		///build remote call object
		pRemoteCall = new RemoteCall(pClient,log_proxy);

		///run remote procedure call
		rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
		if(0 != rv)
		{
			LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
			////TODO2_ERROR
			break;
		}

		//LOGI(tag,"send request msg success");
		////TODO2_03
		///wait remote procedure call result
		rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
		if(0 != rv)
		{
			LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
			////TODO2_ERROR03
			break;
		}
		//LOGI(tag,"get response msg success");
		////TODO2_04

		///parse response msg
		if(!responsePack.ParseFromString(szInMsg))
		{
			///TODO3_ERROR00
			break;
		}
		rv = responsePack.ret();
		if(!responsePack.has_content())
		{
			LOGI(tag,"no response msg");
			///TODO3_ERROR01
			break;
		}
		if(!response.ParseFromString(responsePack.content()))
		{
			LOGE(tag,"parse response msg error");
			///TODO3_ERROR02
			break;
		}
		LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
		///TODO3_imp
		if(rv == CKR_OK){
			g_callbackFuncs.erase(func);
		}

	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *使用监听公钥导出协商密钥
*/
EXPORT CK_RV C_Extend_GetExchangeSessionKey(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hKey,
	CK_BYTE_PTR pEncryptedData,
	CK_ULONG_PTR pulEncryptedDataLen
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_GetExchangeSessionKey response;
	Req_C_Extend_GetExchangeSessionKey request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			request.set_hkey(hKey);
			if(NULL != pulEncryptedDataLen)
			{
				if(NULL != pEncryptedData)
				{
					request.set_pencrypteddata(pEncryptedData, *pulEncryptedDataLen);
				}
				request.set_pulencrypteddatalen(*pulEncryptedDataLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pencrypteddata() && pEncryptedData)
			{
				memcpy(pEncryptedData, response.pencrypteddata().data(), response.pencrypteddata().size());
			}
			if(response.has_pulencrypteddatalen() && pulEncryptedDataLen)
			{
				*pulEncryptedDataLen = response.pulencrypteddatalen();
			}
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *参数注销
*/
EXPORT CK_RV C_Extend_Destroy(
	CK_SLOT_ID slotID,
	CK_BYTE_PTR containerName
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_Destroy response;
	Req_C_Extend_Destroy request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);
			if(NULL != containerName)
			{
				request.set_containername(containerName, strlen((const char*)containerName));
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *重设用户口令
*/
EXPORT CK_RV C_Extend_Reset_Pin_With_OTP(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pbOTPPIN,
	CK_ULONG ulOTPPINLen,
	CK_BYTE_PTR pbNewUserPIN,
	CK_ULONG ulNewUserPINLen
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_Reset_Pin_With_OTP response;
	Req_C_Extend_Reset_Pin_With_OTP request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pbOTPPIN)
			{
				request.set_pbotppin(pbOTPPIN, ulOTPPINLen);
			}
			request.set_ulotppinlen(ulOTPPINLen);
			if(NULL != pbNewUserPIN)
			{
				request.set_pbnewuserpin(pbNewUserPIN, ulNewUserPINLen);
			}
			request.set_ulnewuserpinlen(ulNewUserPINLen);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *重设OTP口令
*/
EXPORT CK_RV C_Extend_Reset_OTP(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pbOTPMpk,
	CK_ULONG ulMpkLen,
	CK_BYTE_PTR pbMpkIV,
	CK_ULONG ulMpkIVLen
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_Reset_OTP response;
	Req_C_Extend_Reset_OTP request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pbOTPMpk)
			{
				request.set_pbotpmpk(pbOTPMpk, ulMpkLen);
			}
			request.set_ulmpklen(ulMpkLen);
			if(NULL != pbMpkIV)
			{
				request.set_pbmpkiv(pbMpkIV, ulMpkIVLen);
			}
			request.set_ulmpkivlen(ulMpkIVLen);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *获取剩余OTP解锁次数
*/
EXPORT CK_RV C_Extend_Get_OTP_Unlock_Count(
	CK_SESSION_HANDLE hSession,
	CK_ULONG_PTR pulCount
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_Get_OTP_Unlock_Count response;
	Req_C_Extend_Get_OTP_Unlock_Count request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pulCount)
			{
				request.set_pulcount(*pulCount);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pulcount() && (pulCount != NULL))
			{
				*pulCount = response.pulcount();
			}
			
		}
	}while(0);

	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *获取剩余OTP尝试次数
*/
EXPORT CK_RV C_Extend_Get_OTP_Remain_Count(
	CK_SESSION_HANDLE hSession,
	CK_ULONG_PTR pulCount
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_Get_OTP_Remain_Count response;
	Req_C_Extend_Get_OTP_Remain_Count request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pulCount)
			{
				request.set_pulcount(*pulCount);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pulcount() && (pulCount != NULL))
			{
				*pulCount = response.pulcount();
			}
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *协商会话密钥加密初始化
*/
EXPORT CK_RV C_Extend_DeriveSessionKey(
   CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR pMechanism,
   CK_OBJECT_HANDLE hLocalKey,
   CK_OBJECT_HANDLE hRemoteKey,
   CK_ATTRIBUTE_PTR pTemplate,
   CK_ULONG ulAttributeCount,
   CK_OBJECT_HANDLE_PTR phKey,
   CK_BYTE_PTR pExchangeIV,
   CK_ULONG_PTR pExchangeIVLen
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_DeriveSessionKey response;
	Req_C_Extend_DeriveSessionKey request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			request.set_hlocalkey(hLocalKey);
			request.set_hremotekey(hRemoteKey);
			if(NULL != pTemplate)
			{
				for(int index = 0; index < ulAttributeCount; index++)
				{
					PRO_Attribute* pAttribute = request.add_ptemplate();
					
					pAttribute->set_type(pTemplate[index].type);
					if(NULL != pTemplate[index].pValue)
					{
						pAttribute->set_value(pTemplate[index].pValue, pTemplate[index].ulValueLen);
					}
					pAttribute->set_ulvaluelen(pTemplate[index].ulValueLen);
				}
			}
			request.set_ulattributecount(ulAttributeCount);
			if(NULL != phKey)
			{
				request.set_phkey(*phKey);
			}
			if(NULL != pExchangeIVLen)
			{
				if(NULL != pExchangeIV)
				{
					request.set_pexchangeiv(pExchangeIV, *pExchangeIVLen);
				}
				request.set_pexchangeivlen(*pExchangeIVLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);	
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_phkey() && (phKey != NULL))
			{
				*phKey = response.phkey();
			}
			if(response.has_pexchangeiv() && (pExchangeIV != NULL))
			{
				memcpy(pExchangeIV, response.pexchangeiv().data(), response.pexchangeiv().size());
			}
			if(response.has_pexchangeivlen() && (pExchangeIVLen != NULL))
			{
				*pExchangeIVLen = response.pexchangeivlen();
			}
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *协商会话密钥加密初始化
*/
EXPORT CK_RV C_Extend_EncryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_EncryptInit response;
	Req_C_Extend_EncryptInit request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			for(int index = 0; index < ulAttributeCount; index++)
			{
				PRO_Attribute* pAttribute = request.add_ptemplate();
				pAttribute->set_type(pTemplate[index].type);
				if(NULL != pTemplate[index].pValue)
				{
					pAttribute->set_value(pTemplate[index].pValue, pTemplate[index].ulValueLen);
				}
				pAttribute->set_ulvaluelen(pTemplate[index].ulValueLen);
			}
			request.set_ulattributecount(ulAttributeCount);
			LOGD(tag,"build request msg success");
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/******************************
 *协商会话密钥解密初始化
*/
EXPORT CK_RV C_Extend_DecryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_DecryptInit response;
	Req_C_Extend_DecryptInit request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			for(int index = 0; index < ulAttributeCount; index++)
			{
				PRO_Attribute* pAttribute = request.add_ptemplate();
				pAttribute->set_type(pTemplate[index].type);
				if(NULL != pTemplate[index].pValue)
				{
					pAttribute->set_value(pTemplate[index].pValue, pTemplate[index].ulValueLen);
				}
				pAttribute->set_ulvaluelen(pTemplate[index].ulValueLen);
			}
			request.set_ulattributecount(ulAttributeCount);
			LOGD(tag,"build request msg success");
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *协商会话密钥分步加密
*/
EXPORT CK_RV C_Extend_EncryptUpdate(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pIv,                /* encrypted iv */
  CK_ULONG          ulIvLen,            /* encrypted iv len */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_EncryptUpdate response;
	Req_C_Extend_EncryptUpdate request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pIv)
			{
				request.set_piv(pIv, ulIvLen);
			}
			request.set_ulivlen(ulIvLen);
			if(NULL != pPart)
			{
				request.set_ppart(pPart, ulPartLen);
			}
			request.set_ulpartlen(ulPartLen);
			if(NULL != pulEncryptedPartLen)
			{
				if(NULL != pEncryptedPart)
				{
					request.set_pencryptedpart(pEncryptedPart, *pulEncryptedPartLen);
				}
				request.set_pulencryptedpartlen(*pulEncryptedPartLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pencryptedpart() && (pEncryptedPart != NULL))
			{
				memcpy(pEncryptedPart, response.pencryptedpart().data(), response.pencryptedpart().size());
			}
			if(response.has_pulencryptedpartlen() && (pulEncryptedPartLen != NULL))
			{
				*pulEncryptedPartLen = response.pulencryptedpartlen();
			}
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *协商会话密钥分步解密
*/
EXPORT CK_RV C_Extend_DecryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pIv,                /* decrypted iv */
  CK_ULONG          ulIvLen,            /* decrypted iv len */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_DecryptUpdate response;
	Req_C_Extend_DecryptUpdate request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pIv)
			{
				request.set_piv(pIv, ulIvLen);
			}
			request.set_ulivlen(ulIvLen);
			if(NULL != pEncryptedPart)
			{
				request.set_pencryptedpart(pEncryptedPart, ulEncryptedPartLen);
			}
			request.set_ulencryptedpartlen(ulEncryptedPartLen);
			if(NULL != pulPartLen)
			{
				if(NULL != pPart)
				{
					request.set_ppart(pPart, *pulPartLen);
				}
				request.set_pulpartlen(*pulPartLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_ppart() && (pPart != NULL))
			{
				memcpy(pPart, response.ppart().data(), response.ppart().size());
			}
			if(response.has_pulpartlen() && (pulPartLen != NULL))
			{
				*pulPartLen = response.pulpartlen();
			}
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *协商会话密钥分步加密结束
*/
EXPORT CK_RV C_Extend_EncryptFinalize(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_EncryptFinalize response;
	Req_C_Extend_EncryptFinalize request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pulLastEncryptedPartLen)
			{
				if(NULL != pLastEncryptedPart)
				{
					request.set_plastencryptedpart(pLastEncryptedPart, *pulLastEncryptedPartLen);
				}
				request.set_pullastencryptedpartlen(*pulLastEncryptedPartLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_plastencryptedpart() && (pLastEncryptedPart != NULL))
			{
				memcpy(pLastEncryptedPart, response.plastencryptedpart().data(), response.plastencryptedpart().size());
			}
			if(response.has_pullastencryptedpartlen() && (pulLastEncryptedPartLen != NULL))
			{
				*pulLastEncryptedPartLen = response.pullastencryptedpartlen();
			}
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *协商会话密钥分步解密结束
*/
EXPORT CK_RV C_Extend_DecryptFinalize(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_DecryptFinalize response;
	Req_C_Extend_DecryptFinalize request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pulLastPartLen)
			{
				if(NULL != pLastPart)
				{
					request.set_plastpart(pLastPart, *pulLastPartLen);
				}
				request.set_pullastpartlen(*pulLastPartLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_plastpart() && (pLastPart != NULL))
			{
				memcpy(pLastPart, response.plastpart().data(), response.plastpart().size());
			}
			if(response.has_pullastpartlen() && (pulLastPartLen != NULL))
			{
				*pulLastPartLen = response.pullastpartlen();
			}
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *SM2点乘
*/
EXPORT CK_RV C_Extend_PointMultiply(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey,
  CK_BYTE_PTR pOutData,
  CK_ULONG_PTR pOutLen
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_PointMultiply response;
	Req_C_Extend_PointMultiply request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pMechanism)
			{
                request.mutable_pmechanism()->set_mechanism(pMechanism->mechanism);
                request.mutable_pmechanism()->set_ulvaluelen(pMechanism->ulParameterLen);
                if(pMechanism->pParameter){
                    request.mutable_pmechanism()->set_pparameter(pMechanism->pParameter, pMechanism->ulParameterLen);
                }
			}
			request.set_hkey(hKey);
			if(NULL != pOutLen)
			{
				if(NULL != pOutData)
				{
					request.set_poutdata(pOutData, *pOutLen);
				}
				request.set_pulcount(*pOutLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_poutdata() && (pOutData != NULL))
			{
				memcpy(pOutData, response.poutdata().data(), response.poutdata().size());
			}
			if(response.has_pulcount() && (pOutLen != NULL))
			{
				*pOutLen = response.pulcount();
			}
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *重设TT口令
*/
EXPORT CK_RV C_Extend_Reset_TT(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pbTTMpk,
	CK_ULONG ulMpkLen,
	CK_BYTE_PTR pbMpkIV,
	CK_ULONG ulMpkIVLen
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_Reset_TT response;
	Req_C_Extend_Reset_TT request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pbTTMpk)
			{
				request.set_pbttmpk(pbTTMpk, ulMpkLen);
			}
			request.set_ulmpklen(ulMpkLen);
			if(NULL != pbMpkIV)
			{
				request.set_pbmpkiv(pbMpkIV, ulMpkIVLen);
			}
			request.set_ulmpkivlen(ulMpkIVLen);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

/********************************
 *重设BK口令
*/
EXPORT CK_RV C_Extend_Reset_BK(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pbBKMpk,
	CK_ULONG ulMpkLen,
	CK_BYTE_PTR pbMpkIV,
	CK_ULONG ulMpkIVLen
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_Reset_BK response;
	Req_C_Extend_Reset_BK request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pbBKMpk)
			{
				request.set_pbbkmpk(pbBKMpk, ulMpkLen);
			}
			request.set_ulmpklen(ulMpkLen);
			if(NULL != pbMpkIV)
			{
				request.set_pbmpkiv(pbMpkIV, ulMpkIVLen);
			}
			request.set_ulmpkivlen(ulMpkIVLen);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}




EXPORT CK_RV C_Extend_Get_Special_Object_Version(
		CK_SESSION_HANDLE            hSession,
		CK_OBJECT_CLASS 	  objectClass,
		CK_BYTE_PTR pVersion,
		CK_ULONG_PTR pUlLen

){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;

    Rsp_C_Extend_Get_Special_Object_Version response;
	Req_C_Extend_Get_Special_Object_Version request;

	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
	        request.set_hsession(hSession);
            request.set_objectclass(objectClass);
            if(NULL != pUlLen){
                request.set_pullen(*pUlLen);
                if(NULL != pVersion){
                    request.set_pversion(pVersion,*pUlLen);
                }
            }


			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}

            if(response.has_pullen()){
                if(pUlLen != NULL){
                    *pUlLen = response.pullen();
                }
            }

            if(response.has_pversion()){
                if(pVersion != NULL){
                    memcpy(pVersion,response.pversion().data(),response.pversion().size());
                }
            }

			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}

EXPORT CK_RV C_Extend_DestroyCard
(
	CK_SLOT_ID slotID,
	CK_BYTE_PTR prandomIn,
	CK_ULONG randomInLen,
	CK_BYTE_PTR prandomOut,
	CK_ULONG_PTR prandomOutLen
)
{
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_DestroyCard response;
	Req_C_Extend_DestroyCard request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);
			if(NULL != prandomIn)
			{
				request.set_prandomin(prandomIn, randomInLen);
			}
			request.set_randominlen(randomInLen);
			if(NULL != prandomOutLen)
			{
				if(NULL != prandomOut)
				{
					request.set_prandomout(prandomOut, *prandomOutLen);
				}
				request.set_prandomoutlen(*prandomOutLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT+DESTROY_TIME, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_prandomout() && (prandomOut != NULL))
			{
				memcpy(prandomOut, response.prandomout().data(), response.prandomout().size());
			}
			if(response.has_prandomoutlen() && (prandomOutLen != NULL))
			{
				*prandomOutLen = response.prandomoutlen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
	
}


/******************************
 *独占
*/

EXPORT CK_RV C_Extend_MonopolizeEnable(
  CK_SLOT_ID            slotID        /* the slot's ID */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_MonopolizeEnable response;
	Req_C_Extend_MonopolizeEnable request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}



EXPORT CK_RV C_Extend_MonopolizeDisable(
		CK_SLOT_ID            slotID        /* the slot's ID */
){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_MonopolizeDisable response;
	Req_C_Extend_MonopolizeDisable request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);

			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);

			///run remote procedure call
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}

			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}
	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;

	return rv;

}


EXPORT CK_RV C_Extend_GetDevInfo
(
	CK_SLOT_ID slotID,
	const char *userName,         
 	CK_IP_PARAMS_PTR ipparam,   
	CK_BYTE_PTR pDevInfo,
	CK_ULONG_PTR pUlDevInfoLen
)
{
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_GetDevInfo response;
	Req_C_Extend_GetDevInfo request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);

			if(NULL != userName)
			{
				request.set_username(userName,strlen(userName));
			}

			if(NULL != ipparam)
			{
				request.mutable_ipparam()->set_ip(ipparam->ip, CK_MAX_IP_SIZE);
				request.mutable_ipparam()->set_owayport(ipparam->oWayPort);
				request.mutable_ipparam()->set_twayport(ipparam->tWayPort);
			}

			if(NULL != pDevInfo)
			{				
				request.set_pdevinfo(pDevInfo, *pUlDevInfoLen);
			}
			
			if(NULL != pUlDevInfoLen)
			{
				request.set_puldevinfolen(*pUlDevInfoLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pdevinfo() && (pDevInfo != NULL))
			{
				LOGI(tag, "copy devinfo");
				memcpy(pDevInfo, response.pdevinfo().data(), response.pdevinfo().size());
				
			}
			if(response.has_puldevinfolen() && (pUlDevInfoLen != NULL))
			{
				*pUlDevInfoLen = response.puldevinfolen();
			}
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;

}


EXPORT CK_RV C_Extend_DevSign
(
	CK_SLOT_ID slotID,
	CK_BYTE_PTR       pData,           /* the data to sign */
	CK_ULONG          ulDataLen,       /* count of bytes to sign */
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_DevSign response;
	Req_C_Extend_DevSign request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_slotid(slotID);
			if(NULL != pData)
			{
				request.set_pdata(pData, ulDataLen);
			}
			request.set_uldatalen(ulDataLen);
			if(NULL != pulSignatureLen)
			{
				if(NULL != pSignature)
				{
					request.set_psignature(pSignature, *pulSignatureLen);
				}
				request.set_pulsignaturelen(*pulSignatureLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_psignature() && (pSignature != NULL))
			{
				memcpy(pSignature, response.psignature().data(), response.psignature().size());
			}
			if(response.has_pulsignaturelen() && (pulSignatureLen != NULL))
			{
				*pulSignatureLen = response.pulsignaturelen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
	
}


EXPORT CK_RV C_Extend_Set_DestroyKey
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pDestroyKeyMpk,
	CK_ULONG ulMpkLen,
	CK_BYTE_PTR pbMpkIV,
	CK_ULONG ulMpkIVLen

)
{	
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_Set_DestroyKey response;
	Req_C_Extend_Set_DestroyKey request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pDestroyKeyMpk)
			{
				request.set_pdestroykeympk(pDestroyKeyMpk, ulMpkLen);
			}
			request.set_ulmpklen(ulMpkLen);
			if(NULL != pbMpkIV)
			{
				request.set_pbmpkiv(pbMpkIV, ulMpkIVLen);
			}
			request.set_ulmpkivlen(ulMpkIVLen);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101
		}
		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
				LOGI(tag,"no response msg");
				///TODO3_ERROR01
				break;
			}
			if(!response.ParseFromString(responsePack.content()))
			{
				LOGE(tag,"parse response msg error");
				///TODO3_ERROR02
				break;
			}
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			
		}
	}while(0);

	
	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}

EXPORT CK_RV C_Extend_Get_ExchangePubKey
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR 	  pExchangePubKeyValue,	  
	CK_ULONG_PTR	  pulKeyLen  
)
{
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_C_Extend_Get_ExchangePubKey response;
	Req_C_Extend_Get_ExchangePubKey request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_hsession(hSession);
			if(NULL != pulKeyLen)
			{
				if(NULL != pExchangePubKeyValue)
				{
					request.set_pexchangepubkeyvalue(pExchangePubKeyValue, *pulKeyLen);
				}
				request.set_pulkeylen(*pulKeyLen);
			}
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			if(response.has_pexchangepubkeyvalue() && (pExchangePubKeyValue != NULL))
			{
				memcpy(pExchangePubKeyValue, response.pexchangepubkeyvalue().data(), response.pexchangepubkeyvalue().size());
			}
			if(response.has_pulkeylen() && (pulKeyLen != NULL))
			{
				*pulKeyLen = response.pulkeylen();
			}
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;
}


#ifdef SOFT_CARD_EXTERN_INTERFACE

EXPORT CK_RV softCreateCipherCard(string token, string userName, string licSesrverAddr, string csppAddr){
	const char * filename = "csmproxylog.txt";
	const char * defaultRecordPath = "/sdcard/csmproxylog.txt";

	initPlog(filename, defaultRecordPath);

	LOGI(tag, "%s IN,client",__FUNCTION__);

	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_softCreateCipherCard response;
	Req_softCreateCipherCard request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0


	do{
		{
			///build request msg
			////TODO1_imp
			request.set_token(token);
			request.set_username(userName);
			request.set_licsesrveraddr(licSesrverAddr);
			request.set_csppaddr(csppAddr);
			LOGI(tag,"build request msg success,%s",__FUNCTION__);
			
			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}

		{
			
			if(NULL == pClient){
				pClient = getInstance((char *)"com.westone.csm.CSM");
			}

			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);
			
			///run remote procedure call 
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}
			
			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp
			
		}

	}while(0);


	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;
	
	return rv;                
}

EXPORT CK_RV DestroyCipherCard(){
	CK_RV rv = CKR_OK;
	string szFunctionName = __FUNCTION__;
	string szOutMsg;
	string szInMsg;
	Rsp_DestroyCipherCard response;
	Req_DestroyCipherCard request;
	RemoteCall* pRemoteCall = NULL;
	ResponsePack responsePack;
	///TODO0

	do{
		{
			///build request msg
			////TODO1_imp

			///serialize request msg to string
			if(!request.SerializeToString(&szOutMsg))
			{
				///TODO1_ERROR00
				break;
			}
			//LOGI(tag,"serialize  request msg success");
			////TODO101

		}
		LOGI(tag,"build request msg success,%s",__FUNCTION__);

		{
			if(NULL == pClient){
				pClient = getInstance((char *)"com.westone.csm.CSM");
			}
			///build remote call object
			pRemoteCall = new RemoteCall(pClient,log_proxy);

			///run remote procedure call
			rv = pRemoteCall->PutRequest(szFunctionName, szOutMsg);
			if(0 != rv)
			{
				LOGE(tag,"pRemoteCall->PutRequest, rv = 0x%08lx", rv);
				////TODO2_ERROR
				break;
			}

			//LOGI(tag,"send request msg success");
			////TODO2_03
			///wait remote procedure call result
			rv = pRemoteCall->WaitForResponse(OPERATION_TIMEOUT, szInMsg);
			if(0 != rv)
			{
				LOGI(tag,"pRemoteCall->WaitForResponse, rv = 0x%08lx", rv);
				////TODO2_ERROR03
				break;
			}
			//LOGI(tag,"get response msg success");
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
			LOGI(tag,"parse response msg success %s,ret is %lu",__FUNCTION__,rv);
			///TODO3_imp

		}

	}while(0);

	////TODO4
	//free the memory
	delete pRemoteCall;
	pRemoteCall = NULL;

	return rv;
}

#endif

