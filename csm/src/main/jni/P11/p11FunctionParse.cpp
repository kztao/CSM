#include "logserver.h"
#include "ReturnCode.h"
#include "Return.pb.h"
#include "p11FunctionParse.h"
#include "pkcs11.pb.h"
#include "P11Mapping.h"

#include "P11Adapter.h"
#include <iostream>

static const char *tag = "csm_p11server";
using namespace google::protobuf;
using namespace com::weston::pkcs11;
using namespace com::westone::returncode;

#define FREE(tmp) {\
	free(tmp); \
	tmp = NULL; \
}

static FunctionParse *pGlobeFunctionParse = NULL;
static P11Mapping p11Table;
void clearmono(string clientname)
{
	LOGSERVERI(tag,"clearmono");
	if(pGlobeFunctionParse->gloMonopolizePackageName == clientname)
	{
		pGlobeFunctionParse->gloMonopolizePackageName = "";
	}	
}


static unsigned long int  responsePack(CK_RV ret, string rspObjString, string &dst)
{
    ResponsePack responsePack;
    responsePack.set_ret(ret);
    responsePack.set_content(rspObjString);
    if(!responsePack.SerializeToString(&dst))
    {
        return RETURN_CODE_ERROR_PROTOCOL;
    }

    return 0;
}

CK_RV C_Extend_Status_Callback(CK_SLOT_ID slotID,CK_STATUS_ENUM status)
{
	Rsp_Status_Callback_Func rspObj;
	string rspObjString;

	LOGSERVERI(tag, "%s, slotid is 0x%lx, status is %u",__FUNCTION__,slotID,status);
	rspObj.Clear();

	rspObj.set_slotid(slotID);
	rspObj.set_status(status);

	rspObj.SerializeToString(&rspObjString);

	 string out;
	 string &rout = out;

	 responsePack(CKR_OK, rspObjString, rout);

	pGlobeFunctionParse->BroadCast("C_Extend_Register_Status_Callback_Func", out);
	return 0;
}

P11FunctionParse::P11FunctionParse()
{
	pGlobeFunctionParse = this;
	mapFuncList["C_Initialize"] = (FunctionParse::funcType)&P11FunctionParse::C_Initialize;
	mapFuncList["C_Finalize"] = (FunctionParse::funcType)&P11FunctionParse::C_Finalize;
	mapFuncList["C_GetInfo"] = (FunctionParse::funcType)&P11FunctionParse::C_GetInfo;
	mapFuncList["C_GetFunctionList"] = (FunctionParse::funcType)&P11FunctionParse::C_GetFunctionList;
	mapFuncList["C_GetSlotList"] = (FunctionParse::funcType)&P11FunctionParse::C_GetSlotList;
	mapFuncList["C_GetSlotInfo"] = (FunctionParse::funcType)&P11FunctionParse::C_GetSlotInfo;
	mapFuncList["C_GetTokenInfo"] = (FunctionParse::funcType)&P11FunctionParse::C_GetTokenInfo;
	mapFuncList["C_GetMechanismList"] = (FunctionParse::funcType)&P11FunctionParse::C_GetMechanismList;
	mapFuncList["C_GetMechanismInfo"] = (FunctionParse::funcType)&P11FunctionParse::C_GetMechanismInfo;
	mapFuncList["C_InitToken"] = (FunctionParse::funcType)&P11FunctionParse::C_InitToken;
	mapFuncList["C_InitPIN"] = (FunctionParse::funcType)&P11FunctionParse::C_InitPIN;
	mapFuncList["C_SetPIN"] = (FunctionParse::funcType)&P11FunctionParse::C_SetPIN;
	mapFuncList["C_OpenSession"] = (FunctionParse::funcType)&P11FunctionParse::C_OpenSession;
	mapFuncList["C_CloseSession"] = (FunctionParse::funcType)&P11FunctionParse::C_CloseSession;
	mapFuncList["C_CloseAllSessions"] = (FunctionParse::funcType)&P11FunctionParse::C_CloseAllSessions;
	mapFuncList["C_GetSessionInfo"] = (FunctionParse::funcType)&P11FunctionParse::C_GetSessionInfo;
	mapFuncList["C_GetOperationState"] = (FunctionParse::funcType)&P11FunctionParse::C_GetOperationState;
	mapFuncList["C_SetOperationState"] = (FunctionParse::funcType)&P11FunctionParse::C_SetOperationState;
	mapFuncList["C_Login"] = (FunctionParse::funcType)&P11FunctionParse::C_Login;
	mapFuncList["C_Logout"] = (FunctionParse::funcType)&P11FunctionParse::C_Logout;
	mapFuncList["C_CreateObject"] = (FunctionParse::funcType)&P11FunctionParse::C_CreateObject;
	mapFuncList["C_CopyObject"] = (FunctionParse::funcType)&P11FunctionParse::C_CopyObject;
	mapFuncList["C_DestroyObject"] = (FunctionParse::funcType)&P11FunctionParse::C_DestroyObject;
	mapFuncList["C_GetObjectSize"] = (FunctionParse::funcType)&P11FunctionParse::C_GetObjectSize;
	mapFuncList["C_GetAttributeValue"] = (FunctionParse::funcType)&P11FunctionParse::C_GetAttributeValue;
	mapFuncList["C_SetAttributeValue"] = (FunctionParse::funcType)&P11FunctionParse::C_SetAttributeValue;
	mapFuncList["C_FindObjectsInit"] = (FunctionParse::funcType)&P11FunctionParse::C_FindObjectsInit;
	mapFuncList["C_FindObjects"] = (FunctionParse::funcType)&P11FunctionParse::C_FindObjects;
	mapFuncList["C_FindObjectsFinal"] = (FunctionParse::funcType)&P11FunctionParse::C_FindObjectsFinal;
	mapFuncList["C_EncryptInit"] = (FunctionParse::funcType)&P11FunctionParse::C_EncryptInit;
	mapFuncList["C_Encrypt"] = (FunctionParse::funcType)&P11FunctionParse::C_Encrypt;
	mapFuncList["C_EncryptUpdate"] = (FunctionParse::funcType)&P11FunctionParse::C_EncryptUpdate;
	mapFuncList["C_EncryptFinal"] = (FunctionParse::funcType)&P11FunctionParse::C_EncryptFinal;
	mapFuncList["C_DecryptInit"] = (FunctionParse::funcType)&P11FunctionParse::C_DecryptInit;
	mapFuncList["C_Decrypt"] = (FunctionParse::funcType)&P11FunctionParse::C_Decrypt;
	mapFuncList["C_DecryptUpdate"] = (FunctionParse::funcType)&P11FunctionParse::C_DecryptUpdate;
	mapFuncList["C_DecryptFinal"] = (FunctionParse::funcType)&P11FunctionParse::C_DecryptFinal;
	mapFuncList["C_DigestInit"] = (FunctionParse::funcType)&P11FunctionParse::C_DigestInit;
	mapFuncList["C_Digest"] = (FunctionParse::funcType)&P11FunctionParse::C_Digest;
	mapFuncList["C_DigestUpdate"] = (FunctionParse::funcType)&P11FunctionParse::C_DigestUpdate;
	mapFuncList["C_DigestKey"] = (FunctionParse::funcType)&P11FunctionParse::C_DigestKey;
	mapFuncList["C_DigestFinal"] = (FunctionParse::funcType)&P11FunctionParse::C_DigestFinal;
	mapFuncList["C_SignInit"] = (FunctionParse::funcType)&P11FunctionParse::C_SignInit;
	mapFuncList["C_Sign"] = (FunctionParse::funcType)&P11FunctionParse::C_Sign;
	mapFuncList["C_SignUpdate"] = (FunctionParse::funcType)&P11FunctionParse::C_SignUpdate;
	mapFuncList["C_SignFinal"] = (FunctionParse::funcType)&P11FunctionParse::C_SignFinal;
	mapFuncList["C_SignRecoverInit"] = (FunctionParse::funcType)&P11FunctionParse::C_SignRecoverInit;
	mapFuncList["C_SignRecover"] = (FunctionParse::funcType)&P11FunctionParse::C_SignRecover;
	mapFuncList["C_VerifyInit"] = (FunctionParse::funcType)&P11FunctionParse::C_VerifyInit;
	mapFuncList["C_Verify"] = (FunctionParse::funcType)&P11FunctionParse::C_Verify;
	mapFuncList["C_VerifyUpdate"] = (FunctionParse::funcType)&P11FunctionParse::C_VerifyUpdate;
	mapFuncList["C_VerifyFinal"] = (FunctionParse::funcType)&P11FunctionParse::C_VerifyFinal;
	mapFuncList["C_VerifyRecoverInit"] = (FunctionParse::funcType)&P11FunctionParse::C_VerifyRecoverInit;
	mapFuncList["C_VerifyRecover"] = (FunctionParse::funcType)&P11FunctionParse::C_VerifyRecover;
	mapFuncList["C_DigestEncryptUpdate"] = (FunctionParse::funcType)&P11FunctionParse::C_DigestEncryptUpdate;
	mapFuncList["C_DecryptDigestUpdate"] = (FunctionParse::funcType)&P11FunctionParse::C_DecryptDigestUpdate;
	mapFuncList["C_SignEncryptUpdate"] = (FunctionParse::funcType)&P11FunctionParse::C_SignEncryptUpdate;
	mapFuncList["C_DecryptVerifyUpdate"] = (FunctionParse::funcType)&P11FunctionParse::C_DecryptVerifyUpdate;
	mapFuncList["C_GenerateKey"] = (FunctionParse::funcType)&P11FunctionParse::C_GenerateKey;
	mapFuncList["C_GenerateKeyPair"] = (FunctionParse::funcType)&P11FunctionParse::C_GenerateKeyPair;
	mapFuncList["C_WrapKey"] = (FunctionParse::funcType)&P11FunctionParse::C_WrapKey;
	mapFuncList["C_UnwrapKey"] = (FunctionParse::funcType)&P11FunctionParse::C_UnwrapKey;
	mapFuncList["C_DeriveKey"] = (FunctionParse::funcType)&P11FunctionParse::C_DeriveKey;
	mapFuncList["C_SeedRandom"] = (FunctionParse::funcType)&P11FunctionParse::C_SeedRandom;
	mapFuncList["C_GenerateRandom"] = (FunctionParse::funcType)&P11FunctionParse::C_GenerateRandom;
	mapFuncList["C_GetFunctionStatus"] = (FunctionParse::funcType)&P11FunctionParse::C_GetFunctionStatus;
	mapFuncList["C_CancelFunction"] = (FunctionParse::funcType)&P11FunctionParse::C_CancelFunction;
	mapFuncList["C_WaitForSlotEvent"] = (FunctionParse::funcType)&P11FunctionParse::C_WaitForSlotEvent;

	mapFuncList["C_Extend_GetPinRemainCount"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_GetPinRemainCount;
	mapFuncList["C_Extend_GetStatus"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_GetStatus;
	mapFuncList["C_Extend_Register_Status_Callback_Func"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_Register_Status_Callback_Func;
	mapFuncList["C_Extend_Register_Callback"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_Register_Callback;
	mapFuncList["C_Extend_Unregister_Callback"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_Unregister_Callback;
	mapFuncList["C_Extend_GetExchangeSessionKey"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_GetExchangeSessionKey;
	mapFuncList["C_Extend_Destroy"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_Destroy;
	mapFuncList["C_Extend_Reset_Pin_With_OTP"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_Reset_Pin_With_OTP;
	mapFuncList["C_Extend_Reset_OTP"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_Reset_OTP;
	mapFuncList["C_Extend_Get_OTP_Unlock_Count"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_Get_OTP_Unlock_Count;
	mapFuncList["C_Extend_Get_OTP_Remain_Count"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_Get_OTP_Remain_Count;
	mapFuncList["C_Extend_DeriveSessionKey"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_DeriveSessionKey;
	mapFuncList["C_Extend_EncryptInit"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_EncryptInit;
	mapFuncList["C_Extend_DecryptInit"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_DecryptInit;
	mapFuncList["C_Extend_EncryptUpdate"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_EncryptUpdate;
	mapFuncList["C_Extend_DecryptUpdate"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_DecryptUpdate;
	mapFuncList["C_Extend_EncryptFinalize"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_EncryptFinalize;
	mapFuncList["C_Extend_DecryptFinalize"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_DecryptFinalize;
	mapFuncList["C_Extend_PointMultiply"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_PointMultiply;
	mapFuncList["C_Extend_Reset_TT"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_Reset_TT;
	mapFuncList["C_Extend_Reset_BK"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_Reset_BK;
	mapFuncList["C_Extend_Get_Special_Object_Version"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_Get_Special_Object_Version;
	mapFuncList["C_Extend_DestroyCard"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_DestroyCard;
	mapFuncList["C_Extend_MonopolizeEnable"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_MonopolizeEnable;
	mapFuncList["C_Extend_MonopolizeDisable"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_MonopolizeDisable;
	mapFuncList["C_Extend_GetDevInfo"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_GetDevInfo;
	mapFuncList["C_Extend_DevSign"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_DevSign;	
	mapFuncList["C_Extend_Set_DestroyKey"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_Set_DestroyKey;	
	mapFuncList["C_Extend_Get_ExchangePubKey"] = (FunctionParse::funcType)&P11FunctionParse::C_Extend_Get_ExchangePubKey;	
	mapFuncList["softCreateCipherCard"] = (FunctionParse::funcType)&P11FunctionParse::softCreateCipherCard;	
	mapFuncList["DestroyCipherCard"] = (FunctionParse::funcType)&P11FunctionParse::DestroyCipherCard;	
	
}

P11FunctionParse::~P11FunctionParse(){

}



int P11FunctionParse::C_Initialize(const string src,string &dst)
{
	Req_C_Initialize reqObj;
	Rsp_C_Initialize rspObj;
    string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_VOID_PTR pInitArgs = NULL;
	
	CK_RV ret = Adapter_C_Initialize(pInitArgs);

	rspObj.SerializeToString(&rspObjString);

	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Finalize(const string src,string &dst)
{
	Req_C_Finalize reqObj;
	Rsp_C_Finalize rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_VOID_PTR pReserved = NULL;
	getclientname(packageName);
	
	CK_RV ret = Adapter_C_Finalize(pReserved);

	rspObj.SerializeToString(&rspObjString);
	
	FREE(pReserved);
	
	return responsePack(ret, rspObjString, dst);
}

int P11FunctionParse::C_GetInfo(const string src,string &dst)
{
	LOGSERVERD(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_GetInfo reqObj;
	Rsp_C_GetInfo rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_INFO_PTR pCkInfo = NULL;

	if(reqObj.has_pinfo())
	{
		pCkInfo = (CK_INFO_PTR)malloc(sizeof(CK_INFO));
		if(pCkInfo)
		{
			pCkInfo->flags = reqObj.pinfo().flags();
			pCkInfo->cryptokiVersion.major = reqObj.pinfo().cryptokiversion().major();
			pCkInfo->cryptokiVersion.minor = reqObj.pinfo().cryptokiversion().minor();
			memcpy(pCkInfo->libraryDescription, reqObj.pinfo().librarydescription().data(), reqObj.pinfo().librarydescription().size());
			memcpy(pCkInfo->manufacturerID, reqObj.pinfo().manufacturerid().data(), reqObj.pinfo().manufacturerid().size());
			pCkInfo->libraryVersion.major = reqObj.pinfo().libraryversion().major();
			pCkInfo->libraryVersion.minor = reqObj.pinfo().libraryversion().minor();
		}
		else
		{
			LOGSERVERE(tag, "%s malloc fail",__FUNCTION__);
		}
	}
	
	CK_RV ret = Adapter_C_GetInfo(pCkInfo);

	if(pCkInfo)
	{
		rspObj.mutable_pinfo()->set_manufacturerid(pCkInfo->manufacturerID, 32);
		rspObj.mutable_pinfo()->set_flags(pCkInfo->flags);
		rspObj.mutable_pinfo()->set_librarydescription(pCkInfo->libraryDescription, 32); 
		rspObj.mutable_pinfo()->mutable_cryptokiversion()->set_major(pCkInfo->cryptokiVersion.major);
		rspObj.mutable_pinfo()->mutable_cryptokiversion()->set_minor(pCkInfo->cryptokiVersion.minor);
		rspObj.mutable_pinfo()->mutable_libraryversion()->set_major(pCkInfo->libraryVersion.major);
		rspObj.mutable_pinfo()->mutable_libraryversion()->set_minor(pCkInfo->libraryVersion.minor);
	}
	rspObj.SerializeToString(&rspObjString);

	FREE(pCkInfo);
	
	LOGSERVERD(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_GetFunctionList(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_GetFunctionList reqObj;
	Rsp_C_GetFunctionList rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_FUNCTION_LIST_PTR pFunctionList = NULL;
	
	CK_RV ret = Adapter_C_GetFunctionList(&pFunctionList);
	
	rspObj.SerializeToString(&rspObjString);
	
	FREE(pFunctionList);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_GetSlotList(const string src,string &dst)
{
	Req_C_GetSlotList reqObj;
	Rsp_C_GetSlotList rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_BBOOL tokenPresent = reqObj.tokenprespent();
	CK_SLOT_ID_PTR pSlotList = NULL;
	CK_ULONG_PTR pulCount = NULL;

	if(reqObj.pslotlist_size())
	{
		pSlotList = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID) * reqObj.pslotlist_size());
		if(pSlotList)
		{
			for(unsigned int loop = 0; loop < reqObj.pslotlist_size(); loop++)
			{
				pSlotList[loop] = reqObj.pslotlist(loop);
			}
		}
		else
		{
			LOGSERVERE(tag, "%s malloc fail",__FUNCTION__);
		}
	}

	if(reqObj.has_pulcount())
	{
		pulCount = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulCount)
		{
			*pulCount = reqObj.pulcount();
		}
		else
		{
			LOGSERVERE(tag, "%s malloc fail",__FUNCTION__);
		}
	}

	CK_RV ret = Adapter_C_GetSlotList(tokenPresent,pSlotList,pulCount);
	LOGSERVERD(tag,"pSlotList = %p,pulCount = %p",pSlotList,pulCount);
	if(NULL != pulCount){
		LOGSERVERD(tag,"pulCount = %ld",*pulCount);
	}


	if(pulCount)
	{
		LOGSERVERD(tag,"set size,pulCount = %ld",*pulCount);
		rspObj.set_pulcount(*pulCount);
	}
		
	if(pSlotList && pulCount)
	{
		if(reqObj.pslotlist_size())
		{			
			*pulCount = (*pulCount) > reqObj.pslotlist_size() ? reqObj.pslotlist_size():(*pulCount);
			LOGSERVERI(tag,"*pulCount = %ld, pslotlist_size is %d", *pulCount, reqObj.pslotlist_size());
		}
		
		for(unsigned int loop = 0;loop < *pulCount; loop++)
		{
			rspObj.add_pslotlist(pSlotList[loop]);
		}	
	}
	
	rspObj.SerializeToString(&rspObjString);
	
	FREE(pSlotList);
	FREE(pulCount);
	
	return responsePack(ret, rspObjString, dst);			
}
int P11FunctionParse::C_GetSlotInfo(const string src,string &dst)
{
	Req_C_GetSlotInfo reqObj;
	Rsp_C_GetSlotInfo rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SLOT_ID       slotID = reqObj.slotid();  
	CK_SLOT_INFO_PTR pInfo = NULL;    

	if(reqObj.has_pinfo())
	{
		pInfo = (CK_SLOT_INFO_PTR)malloc(sizeof(CK_SLOT_INFO));
	}

	CK_RV ret = Adapter_C_GetSlotInfo(slotID, pInfo);
	
	if(pInfo)
	{
		rspObj.mutable_pinfo()->set_flags(pInfo->flags);
		rspObj.mutable_pinfo()->set_slotdescription(pInfo->slotDescription, 64);
		rspObj.mutable_pinfo()->set_manufacturerid(pInfo->manufacturerID, 32);
		rspObj.mutable_pinfo()->mutable_hardwareversion()->set_major(pInfo->hardwareVersion.major);
		rspObj.mutable_pinfo()->mutable_hardwareversion()->set_minor(pInfo->hardwareVersion.minor);
		rspObj.mutable_pinfo()->mutable_firmwareversion()->set_major(pInfo->firmwareVersion.major);
		rspObj.mutable_pinfo()->mutable_firmwareversion()->set_minor(pInfo->firmwareVersion.minor);		
	}

	rspObj.SerializeToString(&rspObjString);
	
	FREE(pInfo);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_GetTokenInfo(const string src,string &dst)
{
	Req_C_GetTokenInfo reqObj;
	Rsp_C_GetTokenInfo rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SLOT_ID slotID = reqObj.slotid();
	CK_TOKEN_INFO_PTR pInfo = NULL;
	
	if(reqObj.has_pinfo())
	{
		pInfo = (CK_TOKEN_INFO_PTR)malloc(sizeof(CK_TOKEN_INFO));	
	}

	CK_RV ret = Adapter_C_GetTokenInfo(slotID, pInfo);

	if(pInfo)
	{
		rspObj.mutable_pinfo()->set_labe(pInfo->label, 32);
		rspObj.mutable_pinfo()->set_manufacturerid(pInfo->manufacturerID, 32);
		rspObj.mutable_pinfo()->set_model(pInfo->model, 16);
		rspObj.mutable_pinfo()->set_serialnumber(pInfo->serialNumber, 16);
		rspObj.mutable_pinfo()->set_flags(pInfo->flags);
		rspObj.mutable_pinfo()->set_ulmaxsessioncount(pInfo->ulMaxSessionCount);
		rspObj.mutable_pinfo()->set_ulsessioncount(pInfo->ulSessionCount);
		rspObj.mutable_pinfo()->set_ulmaxrwsessioncount(pInfo->ulMaxRwSessionCount);
		rspObj.mutable_pinfo()->set_ulrwsessioncount(pInfo->ulRwSessionCount);
		rspObj.mutable_pinfo()->set_ulmaxpinlen(pInfo->ulMaxPinLen);
		rspObj.mutable_pinfo()->set_ulminpinlen(pInfo->ulMinPinLen);
		rspObj.mutable_pinfo()->set_ultotalpublicmemory(pInfo->ulTotalPublicMemory);
		rspObj.mutable_pinfo()->set_ulfreepublicmemory(pInfo->ulFreePublicMemory);
		rspObj.mutable_pinfo()->set_ultotalprivatememory(pInfo->ulTotalPrivateMemory);
		rspObj.mutable_pinfo()->set_ulfreeprivatememory(pInfo->ulFreePrivateMemory);
		rspObj.mutable_pinfo()->mutable_hardwareversion()->set_major(pInfo->hardwareVersion.major);
		rspObj.mutable_pinfo()->mutable_hardwareversion()->set_minor(pInfo->hardwareVersion.minor);
		rspObj.mutable_pinfo()->mutable_firmwareversion()->set_major(pInfo->firmwareVersion.major);
		rspObj.mutable_pinfo()->mutable_firmwareversion()->set_minor(pInfo->firmwareVersion.minor);
		rspObj.mutable_pinfo()->set_utctime(pInfo->utcTime, 16);		
	}

	rspObj.SerializeToString(&rspObjString);
	FREE(pInfo);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_GetMechanismList(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_GetMechanismList reqObj;
	Rsp_C_GetMechanismList rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_SLOT_ID slotID = reqObj.slotid();
	CK_MECHANISM_TYPE_PTR pMechanismList = NULL;
	CK_ULONG_PTR pulCount = NULL;

	if(reqObj.pmechanismlist_size())
	{
		pMechanismList = (CK_MECHANISM_TYPE_PTR)malloc(reqObj.pmechanismlist_size() * sizeof(CK_MECHANISM_TYPE));	
	}
	if(reqObj.has_pulcount())
	{
		pulCount = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulCount)
		{
			*pulCount = reqObj.pulcount();
		}		
	}
	
	CK_RV ret = Adapter_C_GetMechanismList(slotID, pMechanismList,pulCount);

	if((pMechanismList != NULL) && (pulCount != NULL))
	{
		for(unsigned int loop = 0; loop < *pulCount; loop++)
		{
			rspObj.add_pmechanismlist(pMechanismList[loop]);
		}
	}
	if(pulCount)
	{
		rspObj.set_pulcount(*pulCount);
	}

	rspObj.SerializeToString(&rspObjString);
	
	FREE(pMechanismList);
	FREE(pulCount);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_GetMechanismInfo(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_GetMechanismInfo reqObj;
	Rsp_C_GetMechanismInfo rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_SLOT_ID            slotID = reqObj.slotid();  /* ID of the token's slot */
	CK_MECHANISM_TYPE     type = reqObj.type();    /* type of mechanism */
	CK_MECHANISM_INFO_PTR pInfo = NULL;    /* receives mechanism info */

	if(reqObj.has_pinfo())
	{
		pInfo = (CK_MECHANISM_INFO_PTR)malloc(sizeof(CK_MECHANISM_INFO));	
	}

	CK_RV ret = Adapter_C_GetMechanismInfo(slotID, type, pInfo);

	if(pInfo)
	{
		rspObj.mutable_pinfo()->set_ulminkeysize(pInfo->ulMinKeySize);
		rspObj.mutable_pinfo()->set_ulmaxkeysize(pInfo->ulMaxKeySize);
		rspObj.mutable_pinfo()->set_flags(pInfo->flags);		
	}

	rspObj.SerializeToString(&rspObjString);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_InitToken(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_InitToken reqObj;
	Rsp_C_InitToken rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_SLOT_ID      slotID = reqObj.slotid();   /* ID of the token's slot */
	CK_UTF8CHAR_PTR pPin = NULL;      /* the SO's initial PIN */
	CK_ULONG        ulPinLen = reqObj.ppin().size();  /* length in bytes of the PIN */
	CK_UTF8CHAR_PTR pLabel = NULL;     /* 32-byte token label (blank padded) */

	if(reqObj.has_ppin())
	{
		pPin = (CK_UTF8CHAR_PTR)reqObj.ppin().data();
	}
	if(reqObj.has_plabel())
	{
		pLabel = (CK_UTF8CHAR_PTR)reqObj.plabel().data();
	}

	CK_RV ret = Adapter_C_InitToken(slotID, pPin, ulPinLen, pLabel);

	rspObj.SerializeToString(&rspObjString);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_InitPIN(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_InitPIN reqObj;
	Rsp_C_InitPIN rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();  /* the session's handle */
	CK_UTF8CHAR_PTR   pPin = NULL;      /* the normal user's PIN */
	CK_ULONG          ulPinLen = reqObj.ppin().size();   /* length in bytes of the PIN */

	if(reqObj.has_ppin())
	{
		pPin = new unsigned char[reqObj.ppin().size()];
		memcpy(pPin,reqObj.ppin().data(),reqObj.ppin().size());
	}
	
	CK_RV ret = Adapter_C_InitPIN(hSession, pPin, ulPinLen);
	
	rspObj.SerializeToString(&rspObjString);

	delete[] pPin;
	pPin = NULL;
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");

	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_SetPIN(const string src,string &dst)
{
	Req_C_SetPIN reqObj;
	Rsp_C_SetPIN rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_SESSION_HANDLE hSession = reqObj.hsession();  /* the session's handle */
	CK_UTF8CHAR_PTR   pOldPin = NULL;   /* the old PIN */
	CK_ULONG          ulOldLen = reqObj.uloldlen();  /* length of the old PIN */
	CK_UTF8CHAR_PTR   pNewPin = NULL;   /* the new PIN */
	CK_ULONG          ulNewLen = reqObj.ulnewlen();   /* length of the new PIN */

	if(reqObj.has_poldpin())
	{
		pOldPin = (unsigned char*)reqObj.poldpin().data();
	}
	if(reqObj.has_pnewpin())
	{
		pNewPin = (unsigned char*)reqObj.pnewpin().data();
	}
	CK_RV ret = Adapter_C_SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
	

	rspObj.SerializeToString(&rspObjString);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_OpenSession(const string src,string &dst)
{
	Req_C_OpenSession reqObj;
	Rsp_C_OpenSession rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_SLOT_ID            slotID = reqObj.slotid();      /* the slot's ID */
	CK_FLAGS              flags = reqObj.flags();         /* from CK_SESSION_INFO */
	CK_VOID_PTR           pApplication = NULL;  /* passed to callback */
	CK_NOTIFY             Notify = NULL;        /* callback function */
	CK_SESSION_HANDLE_PTR phSession = NULL;      /* gets session handle */

	if(reqObj.has_phsession())
	{
		phSession = (CK_SESSION_HANDLE_PTR)malloc(sizeof(CK_SESSION_HANDLE));
	}

	getclientname(packageName);
		
	CK_RV ret = Adapter_C_OpenSession(slotID, flags, pApplication, Notify, phSession);

	if(phSession)
	{
		rspObj.set_phsession(*phSession);	
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(phSession);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_CloseSession(const string src,string &dst)
{
	Req_C_CloseSession reqObj;
	Rsp_C_CloseSession rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_SESSION_HANDLE hSession = reqObj.hsession();  /* the session's handle */
	getclientname(packageName);
	
	CK_RV ret = Adapter_C_CloseSession(hSession);
	
	rspObj.SerializeToString(&rspObjString);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_CloseAllSessions(const string src,string &dst)
{
	Req_C_CloseAllSessions reqObj;
	Rsp_C_CloseAllSessions rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_SLOT_ID     slotID = reqObj.slotid();  /* the token's slot */
	CK_RV ret = Adapter_C_CloseAllSessions(slotID);
	
	rspObj.SerializeToString(&rspObjString);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_GetSessionInfo(const string src,string &dst)
{
	Req_C_GetSessionInfo reqObj;
	Rsp_C_GetSessionInfo rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_SESSION_HANDLE   hSession = reqObj.hsession();  /* the session's handle */
	CK_SESSION_INFO_PTR pInfo = NULL;      /* receives session info */

	if(reqObj.has_pinfo())
	{
		pInfo = (CK_SESSION_INFO_PTR)malloc(sizeof(CK_SESSION_INFO));
	}
	
	CK_RV ret = Adapter_C_GetSessionInfo(hSession, pInfo);

	if(pInfo)
	{
		rspObj.mutable_pinfo()->set_slotid(pInfo->slotID);
		rspObj.mutable_pinfo()->set_state(pInfo->state);
		rspObj.mutable_pinfo()->set_flags(pInfo->flags);
		rspObj.mutable_pinfo()->set_uldeviceerror(pInfo->ulDeviceError);	
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pInfo);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_GetOperationState(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_GetOperationState reqObj;
	Rsp_C_GetOperationState rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_SESSION_HANDLE hSession =  reqObj.hsession();            /* session's handle */
	CK_BYTE_PTR       pOperationState = reqObj.has_poperationstate() ? (CK_BYTE_PTR)reqObj.poperationstate().data() : NULL;// reqObj.has_poperationstate() ? (CK_BYTE_PTR)reqObj.poperationstate().data() : NULL;      /* gets state */
	CK_ULONG_PTR      pulOperationStateLen = NULL; /* gets state length */

	if(reqObj.has_puloperationstatelen())
	{
		pulOperationStateLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulOperationStateLen)
		{
			*pulOperationStateLen = reqObj.puloperationstatelen();
		}		
	}

		CK_RV ret = Adapter_C_GetOperationState(hSession, pOperationState, pulOperationStateLen);

	if(pOperationState && pulOperationStateLen)
	{
		rspObj.set_poperationstate(pOperationState, *pulOperationStateLen);
		rspObj.set_puloperationstatelen(*pulOperationStateLen);
	}
		
	rspObj.SerializeToString(&rspObjString);
	
	FREE(pulOperationStateLen);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_SetOperationState(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_SetOperationState reqObj;
	Rsp_C_SetOperationState rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_SESSION_HANDLE hSession = reqObj.hsession();            /* session's handle */
	CK_BYTE_PTR      pOperationState = NULL;     /* holds state */
	CK_ULONG         ulOperationStateLen = reqObj.uloperationstatelen();  /* holds state length */
	CK_OBJECT_HANDLE hEncryptionKey = reqObj.hencryptionkey();       /* en/decryption key */
	CK_OBJECT_HANDLE hAuthenticationKey = reqObj.hauthenticationkey();    /* sign/verify key */

	if(reqObj.has_poperationstate())
	{
		pOperationState = (unsigned char*)reqObj.poperationstate().data();
	}
	CK_RV ret = Adapter_C_SetOperationState(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey);
	
	rspObj.SerializeToString(&rspObjString);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Login(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_Login reqObj;
	Rsp_C_Login rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	  CK_UTF8CHAR_PTR   pPin = NULL;     /* the user's PIN */

	  if(reqObj.has_ppin())
	  {
	  	pPin = (unsigned char*)reqObj.ppin().data();
	  }

	CK_RV ret = Adapter_C_Login(reqObj.hsession(), reqObj.usertype(), pPin, reqObj.ppin().size());
	

	rspObj.SerializeToString(&rspObjString);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Logout(const string src,string &dst)
{
	Req_C_Logout reqObj;
	Rsp_C_Logout rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_RV ret = Adapter_C_Logout(reqObj.hsession());
	

	rspObj.SerializeToString(&rspObjString);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_CreateObject(const string src,string &dst)
{
	Req_C_CreateObject reqObj;
	Rsp_C_CreateObject rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	CK_OBJECT_HANDLE_PTR phObject = NULL;
	CK_ATTRIBUTE_PTR pTemplate = NULL;
	if(reqObj.ptemplate_size())
	{
		pTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * reqObj.ptemplate_size());

		if(pTemplate)
		{
			for(unsigned int loop = 0; loop < reqObj.ptemplate_size(); loop++)
			{
				pTemplate[loop].type = reqObj.ptemplate(loop).type();
				pTemplate[loop].pValue = reqObj.ptemplate(loop).has_value() ? (CK_VOID_PTR)(reqObj.ptemplate(loop).value().data()) : NULL;
				pTemplate[loop].ulValueLen = reqObj.ptemplate(loop).value().size();
			}	
		}
			
	}
	if(reqObj.has_phobject())
	{
		phObject = (CK_OBJECT_HANDLE_PTR)malloc(sizeof(CK_OBJECT_HANDLE));
		if(phObject)
		{
			*phObject = reqObj.phobject();
		}
		
	}
	
	getclientname(packageName);
	CK_RV ret = CKR_TEMPLATE_INCOMPLETE;
	if(pTemplate)
	{
		ret = Adapter_C_CreateObject(reqObj.hsession(), pTemplate, reqObj.ulcount(), phObject);
	}	
	else
	{
		LOGSERVERE(tag, "%s, template empty!",__FUNCTION__);
	}

	if(phObject)
	{
		rspObj.set_phobject(*phObject);
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(phObject);
	FREE(pTemplate);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_CopyObject(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_CopyObject reqObj;
	Rsp_C_CopyObject rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	CK_OBJECT_HANDLE_PTR phNewObject = NULL;
	CK_ATTRIBUTE_PTR pTemplate = NULL;
	if(reqObj.ptemplate_size())
	{
		pTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * reqObj.ptemplate_size());
		if(pTemplate)
		{
			for(unsigned int loop = 0; loop < reqObj.ptemplate_size(); loop++)
			{
				pTemplate[loop].type = reqObj.ptemplate(loop).type();
				pTemplate[loop].pValue = reqObj.ptemplate(loop).has_value() ? (CK_VOID_PTR)(reqObj.ptemplate(loop).value().data()) : NULL;
				pTemplate[loop].ulValueLen = reqObj.ptemplate(loop).value().size();
			}
		}
	}
	if(reqObj.has_phnewobject())
	{
		phNewObject = (CK_OBJECT_HANDLE_PTR)malloc(sizeof(CK_OBJECT_HANDLE));
		if(phNewObject)
		{
			*phNewObject  = reqObj.phnewobject();
		}
		
	}
	

	CK_RV ret = Adapter_C_CopyObject(reqObj.hsession(), reqObj.hobject(), pTemplate, reqObj.ptemplate_size(), phNewObject);

	if(phNewObject)
	{
		rspObj.set_phnewobject(*phNewObject);
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(phNewObject);
	FREE(pTemplate);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_DestroyObject(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_DestroyObject reqObj;
	Rsp_C_DestroyObject rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_RV ret = Adapter_C_DestroyObject(reqObj.hsession(), reqObj.hobject());
	
	rspObj.SerializeToString(&rspObjString);

	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_GetObjectSize(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_GetObjectSize reqObj;
	Rsp_C_GetObjectSize rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_ULONG_PTR pulSize = NULL;
	if(reqObj.has_pulsize())
	{
		pulSize = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulSize)
		{
			*pulSize = reqObj.pulsize();
		}	
	}
	
	CK_RV ret = Adapter_C_GetObjectSize(reqObj.hsession(), reqObj.hobject(), pulSize);
	if(pulSize)
	{
		rspObj.set_pulsize(*pulSize);
	}
	

	rspObj.SerializeToString(&rspObjString);


	FREE(pulSize);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_GetAttributeValue(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_GetAttributeValue reqObj;
	Rsp_C_GetAttributeValue rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_ATTRIBUTE_PTR pTemplate = NULL;
	if(reqObj.ptemplate_size())
	{
		pTemplate = new CK_ATTRIBUTE[reqObj.ptemplate_size()];
		for(int index = 0; index < reqObj.ptemplate_size(); index++)
		{
			pTemplate[index].type = reqObj.ptemplate(index).type();
			pTemplate[index].pValue = NULL;
			if(reqObj.ptemplate(index).has_value())
			{				
				pTemplate[index].pValue = (CK_VOID_PTR)new CK_BYTE[reqObj.ptemplate(index).value().size()];
				memcpy(pTemplate[index].pValue, reqObj.ptemplate(index).value().data(), reqObj.ptemplate(index).value().size());
			}
			pTemplate[index].ulValueLen = (CK_ULONG)reqObj.ptemplate(index).ulvaluelen();
		}
		
	}

	CK_RV ret = Adapter_C_GetAttributeValue(reqObj.hsession(), reqObj.hobject(), pTemplate, reqObj.ulcount());
	
	if(pTemplate)
	{
		for(unsigned int loop = 0; loop < reqObj.ulcount(); loop++)
		{
			PRO_Attribute *pro_attribute = rspObj.add_ptemplate();
			
			pro_attribute->set_type(pTemplate[loop].type);
			
			if((pTemplate[loop].pValue != NULL) && ((int)pTemplate[loop].ulValueLen>0))
			{
				pro_attribute->set_value(pTemplate[loop].pValue, pTemplate[loop].ulValueLen);
			}
			pro_attribute->set_ulvaluelen(pTemplate[loop].ulValueLen);
		}
	}
		
	rspObj.SerializeToString(&rspObjString);
	if(pTemplate)
	{
		for(int index = 0; index < reqObj.ulcount(); index++)
		{		
			if(pTemplate[index].pValue != NULL)
			{
				delete[]((CK_BYTE_PTR)pTemplate[index].pValue);
				pTemplate[index].pValue = NULL;
			}	
			
		}
	}
	
	delete[] pTemplate;
	pTemplate = NULL;

	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_SetAttributeValue(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_SetAttributeValue reqObj;
	Rsp_C_SetAttributeValue rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_OBJECT_HANDLE  hObject = reqObj.hobject();
	CK_ATTRIBUTE_PTR  pTemplate = NULL;
	CK_ULONG          ulCount = reqObj.ptemplate_size();

	if(reqObj.ptemplate_size())
	{
		pTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * reqObj.ptemplate_size());
		if(pTemplate)
		{
			for(int loop = 0; loop < reqObj.ptemplate_size(); ++loop)
			{
				pTemplate[loop].type = reqObj.ptemplate(loop).type();
				pTemplate[loop].pValue = reqObj.ptemplate(loop).has_value() ? (CK_VOID_PTR)(reqObj.ptemplate(loop).value().data()) : NULL;
				pTemplate[loop].ulValueLen = reqObj.ptemplate(loop).value().size();
			}	
		}
	}


	CK_RV ret = Adapter_C_SetAttributeValue(hSession, hObject, pTemplate, ulCount);
		
	rspObj.SerializeToString(&rspObjString);

	FREE(pTemplate);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_FindObjectsInit(const string src,string &dst)
{
	Req_C_FindObjectsInit reqObj;
	Rsp_C_FindObjectsInit rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_ATTRIBUTE_PTR  pTemplate = NULL;
	CK_ULONG          ulCount = reqObj.ptemplate_size();

	if(reqObj.ptemplate_size())
	{
		pTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * reqObj.ptemplate_size());
		if(pTemplate)
		{
			for(int loop = 0; loop < reqObj.ptemplate_size(); loop++)
			{
				pTemplate[loop].type = reqObj.ptemplate(loop).type();
				pTemplate[loop].pValue = reqObj.ptemplate(loop).has_value() ? (CK_VOID_PTR)(reqObj.ptemplate(loop).value().data()) : NULL;
				pTemplate[loop].ulValueLen = reqObj.ptemplate(loop).ulvaluelen();
			}	
		}
	}
	
	getclientname(packageName);
	CK_RV ret = CKR_FUNCTION_FAILED;
	ret = Adapter_C_FindObjectsInit(hSession, pTemplate, ulCount);
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pTemplate);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_FindObjects(const string src,string &dst)
{
	Req_C_FindObjects reqObj;
	Rsp_C_FindObjects rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE    hSession = reqObj.hsession();
	CK_OBJECT_HANDLE_PTR phObject = NULL;
	CK_ULONG             ulMaxObjectCount = reqObj.ulmaxobjectcount();
	CK_ULONG_PTR 	         pulObjectCount = NULL;

	if(reqObj.phobject_size() > 0){
		phObject = new CK_OBJECT_HANDLE[reqObj.phobject_size()];
		for(int i = 0 ; i < reqObj.phobject_size();i++){
			phObject[i] = reqObj.phobject(i);
		}
	}

	if(reqObj.has_pulobjectcount())
	{
		pulObjectCount = new CK_ULONG();
		*pulObjectCount = reqObj.pulobjectcount();
	}

	CK_RV ret = Adapter_C_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);

	if(phObject && pulObjectCount)
	{
		for(int index = 0; index < *pulObjectCount; index++)
		{
			LOGSERVERD(tag,"[%s] objHandle[%d] = %ld",__FUNCTION__,index,phObject[index]);
			rspObj.add_phobject(phObject[index]);
		}		
	}
	if(pulObjectCount)
	{
		rspObj.set_pulobjectcount(*pulObjectCount);
	}
	
	rspObj.SerializeToString(&rspObjString);

	delete[] phObject;
    delete pulObjectCount;

	phObject = NULL;
	pulObjectCount = NULL;
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_FindObjectsFinal(const string src,string &dst)
{
	Req_C_FindObjectsFinal reqObj;
	Rsp_C_FindObjectsFinal rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();

	CK_RV ret = Adapter_C_FindObjectsFinal(hSession);
		
	rspObj.SerializeToString(&rspObjString);

	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_EncryptInit(const string src,string &dst)
{
	Req_C_EncryptInit reqObj;
	Rsp_C_EncryptInit rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_MECHANISM_PTR 	  pMechanism = NULL;
	CK_OBJECT_HANDLE  hKey = reqObj.hkey();

	if(reqObj.has_pmechanism())
	{
		pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
		{
			pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
			pMechanism->pParameter = NULL;
			if(reqObj.pmechanism().has_pparameter())
			{
				pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
			}
		}							
	}

	
	CK_RV ret = Adapter_C_EncryptInit(hSession, pMechanism, hKey);
		
	rspObj.SerializeToString(&rspObjString);

	FREE(pMechanism);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Encrypt(const string src,string &dst)
{
	Req_C_Encrypt reqObj;
	Rsp_C_Encrypt rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pData = reqObj.has_pdata() ? (CK_BYTE_PTR)reqObj.pdata().data() : NULL;
	CK_ULONG          ulDataLen = reqObj.pdata().size();
	CK_BYTE_PTR       pEncryptedData = NULL;
	CK_ULONG_PTR	      pulEncryptedDataLen = NULL;
	if(reqObj.has_pulencrypteddatalen())
	{
		pulEncryptedDataLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulEncryptedDataLen)
		{			
			*pulEncryptedDataLen = reqObj.pulencrypteddatalen();
		}
	}

	if(reqObj.has_pencrypteddata() && pulEncryptedDataLen)
	{
		pEncryptedData = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.pencrypteddata().size());
	}
		
	CK_RV ret = Adapter_C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
	if(pEncryptedData)
		Print_Data_Server((char *)tag,pEncryptedData,*pulEncryptedDataLen);
	
	if(pulEncryptedDataLen)
	{
		rspObj.set_pulencrypteddatalen(*pulEncryptedDataLen);
	}
	if(pEncryptedData && pulEncryptedDataLen)
	{
		rspObj.set_pencrypteddata(pEncryptedData, *pulEncryptedDataLen);
	}	
	
	rspObj.SerializeToString(&rspObjString);


	FREE(pEncryptedData);
	FREE(pulEncryptedDataLen);
	
	return responsePack(ret, rspObjString, dst);
}

int P11FunctionParse::C_EncryptUpdate(const string src,string &dst)
{
	Req_C_EncryptUpdate reqObj;
	Rsp_C_EncryptUpdate rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pPart = reqObj.has_ppart() ? (CK_BYTE_PTR)reqObj.ppart().data() : NULL;
	CK_ULONG          ulPartLen = reqObj.ppart().size();
	CK_BYTE_PTR       pEncryptedPart = NULL;
	CK_ULONG_PTR 	      pulEncryptedPartLen = NULL;
	if(reqObj.has_pulencryptedpartlen())
	{
		pulEncryptedPartLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulEncryptedPartLen)
		{
			*pulEncryptedPartLen = reqObj.pulencryptedpartlen();
		}	
	}
	if(reqObj.has_pencryptedpart()&&pulEncryptedPartLen)
	{
		pEncryptedPart = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.pencryptedpart().size());	
	}

	CK_RV ret = Adapter_C_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	

	if(pulEncryptedPartLen)
	{
		rspObj.set_pulencryptedpartlen(*pulEncryptedPartLen);
	}
	
	if(pEncryptedPart && pulEncryptedPartLen)
	{
		rspObj.set_pencryptedpart(pEncryptedPart, *pulEncryptedPartLen);
	}

	
	rspObj.SerializeToString(&rspObjString);


	FREE(pulEncryptedPartLen);
	FREE(pEncryptedPart);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_EncryptFinal(const string src,string &dst)
{
	Req_C_EncryptFinal reqObj;
	Rsp_C_EncryptFinal rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pLastEncryptedPart = NULL;      /* last c-text */
	CK_ULONG_PTR      pulLastEncryptedPartLen = NULL;  /* gets last size */

	if(reqObj.has_pullastencryptedpartlen())
	{
		pulLastEncryptedPartLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulLastEncryptedPartLen)
		{			
			*pulLastEncryptedPartLen = reqObj.pullastencryptedpartlen();
		}
	}

	if(reqObj.has_plastencryptedpart())
	{
		pLastEncryptedPart = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.plastencryptedpart().size());
	}
	CK_RV ret = Adapter_C_EncryptFinal(hSession, pLastEncryptedPart, pulLastEncryptedPartLen);
	

	if(pulLastEncryptedPartLen)
	{
		rspObj.set_pullastencryptedpartlen(*pulLastEncryptedPartLen);
	}
	if(pLastEncryptedPart && pulLastEncryptedPartLen)
	{
		rspObj.set_plastencryptedpart(pLastEncryptedPart, *pulLastEncryptedPartLen);
	}

	rspObj.SerializeToString(&rspObjString);


	FREE(pLastEncryptedPart);
	FREE(pulLastEncryptedPartLen);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_DecryptInit(const string src,string &dst)
{
	Req_C_DecryptInit reqObj;
	Rsp_C_DecryptInit rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_MECHANISM_PTR 	  pMechanism = NULL;
	CK_OBJECT_HANDLE  hKey = reqObj.hkey();

    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
		{
			pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
	        pMechanism->pParameter = NULL;
	        if(reqObj.pmechanism().has_pparameter())
	        {
	            pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
	        }
		}
       

    }
	
	CK_RV ret = Adapter_C_DecryptInit(hSession, pMechanism, hKey);	
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pMechanism);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Decrypt(const string src,string &dst)
{
	Req_C_Decrypt reqObj;
	Rsp_C_Decrypt rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pEncryptedData = reqObj.has_pencrypteddata() ? (CK_BYTE_PTR)reqObj.pencrypteddata().data() : NULL;
	CK_ULONG          ulEncryptedDataLen = reqObj.pencrypteddata().size();
	CK_BYTE_PTR       pData = NULL;
	CK_ULONG_PTR	      pulDataLen = NULL;
	if(reqObj.has_puldatalen())
	{
		pulDataLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulDataLen)
		{
			*pulDataLen = reqObj.puldatalen();
		}
	}
	if(reqObj.has_pdata() && pulDataLen)
	{
		pData = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * *pulDataLen);
	}
		
	CK_RV ret = Adapter_C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
	

	if(pulDataLen)
	{
		rspObj.set_puldatalen(*pulDataLen);
	}
	if(pData && pulDataLen)
	{
		rspObj.set_pdata(pData, *pulDataLen);
	}

	
	
	rspObj.SerializeToString(&rspObjString);


	FREE(pData);
	FREE(pulDataLen);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_DecryptUpdate(const string src,string &dst)
{
	Req_C_DecryptUpdate reqObj;
	Rsp_C_DecryptUpdate rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pEncryptedPart = reqObj.has_pencryptedpart() ? (CK_BYTE_PTR)reqObj.pencryptedpart().data() : NULL;
	CK_ULONG          ulEncryptedPartLen = reqObj.pencryptedpart().size();
	CK_BYTE_PTR       pPart = NULL;
	CK_ULONG_PTR 	      pulPartLen = NULL;
	if(reqObj.has_pulpartlen())
	{
		pulPartLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulPartLen)
		{
			*pulPartLen = reqObj.pulpartlen();
		}
	}
	if(reqObj.has_ppart() && (pulPartLen!=NULL))
	{
		pPart = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * *pulPartLen);
	}

	CK_RV ret = Adapter_C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	

	if(pPart && pulPartLen)
	{
		rspObj.set_ppart(pPart, *pulPartLen);
	}
	if(pulPartLen)
	{
		rspObj.set_pulpartlen(*pulPartLen);
	}
	
	
	rspObj.SerializeToString(&rspObjString);


	FREE(pulPartLen);
	FREE(pPart);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_DecryptFinal(const string src,string &dst)
{
	Req_C_DecryptFinal reqObj;
	Rsp_C_DecryptFinal rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pLastPart = NULL;      /* last c-text */
	CK_ULONG_PTR      pulLastPartLen = NULL;  /* gets last size */

	if(reqObj.has_plastpart())
	{
		pLastPart = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.plastpart().size());
	}
	if(reqObj.has_pullastpartlen())
	{
		pulLastPartLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulLastPartLen)
		{
			*pulLastPartLen = reqObj.pullastpartlen();
		}
	}
	CK_RV ret = Adapter_C_DecryptFinal(hSession, pLastPart, pulLastPartLen);
	

	if(pulLastPartLen)
	{
		rspObj.set_pullastpartlen(*pulLastPartLen);
	}
	if(pLastPart && pulLastPartLen)
	{
		rspObj.set_plastpart(pLastPart, *pulLastPartLen);
	}

	rspObj.SerializeToString(&rspObjString);


	FREE(pLastPart);
	FREE(pulLastPartLen);	
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_DigestInit(const string src,string &dst)
{
	Req_C_DigestInit reqObj;
	Rsp_C_DigestInit rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_MECHANISM_PTR 	  pMechanism = NULL;
    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
		{
	        pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
	        pMechanism->pParameter = NULL;
	        if(reqObj.pmechanism().has_pparameter())
	        {
	            pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
	        }
		}

    }

	CK_RV ret = Adapter_C_DigestInit(hSession, pMechanism);
		
	rspObj.SerializeToString(&rspObjString);
	FREE(pMechanism);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Digest(const string src,string &dst)
{
	Req_C_Digest reqObj;
	Rsp_C_Digest rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pData = reqObj.has_pdata() ? (CK_BYTE_PTR)reqObj.pdata().data() : NULL;
	CK_ULONG          ulDataLen = reqObj.pdata().size();
	CK_BYTE_PTR       pDigest = NULL;
	CK_ULONG_PTR          pulDigestLen = NULL;//reqObj.puldigestlen();
	if(reqObj.has_pdigest())
	{
		pDigest = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.pdigest().size());
	}
	if(reqObj.has_puldigestlen())
	{
		pulDigestLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulDigestLen)
		{
			*pulDigestLen = reqObj.puldigestlen();
		}
	}
	CK_RV ret = Adapter_C_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
	

	if(pDigest && pulDigestLen)
	{
		rspObj.set_pdigest(pDigest, *pulDigestLen);
	}
	if(pulDigestLen)
	{
		rspObj.set_puldigestlen(*pulDigestLen);
	}
	
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pDigest);
	FREE(pulDigestLen);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_DigestUpdate(const string src,string &dst)
{
	Req_C_DigestUpdate reqObj;
	Rsp_C_DigestUpdate rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pPart = reqObj.has_ppart() ? (CK_BYTE_PTR)reqObj.ppart().data() : NULL;
	CK_ULONG          ulPartLen = reqObj.ppart().size();

	CK_RV ret = Adapter_C_DigestUpdate(hSession, pPart, ulPartLen);
	

	rspObj.SerializeToString(&rspObjString);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_DigestKey(const string src,string &dst)
{
	Req_C_DigestKey reqObj;
	Rsp_C_DigestKey rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_OBJECT_HANDLE  hKey = reqObj.hkey();
  
	CK_RV ret = Adapter_C_DigestKey(hSession, hKey);
		
	rspObj.SerializeToString(&rspObjString);
	
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_DigestFinal(const string src,string &dst)
{
	Req_C_DigestFinal reqObj;
	Rsp_C_DigestFinal rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pDigest = NULL;
	CK_ULONG_PTR 	      pulDigestLen = NULL;//reqObj.puldigestlen();
	if(reqObj.has_pdigest())
	{
		pDigest = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.pdigest().size());
	}

	if(reqObj.has_puldigestlen())
	{
		pulDigestLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulDigestLen)
		{
			*pulDigestLen = reqObj.puldigestlen();
		}
	}
	CK_RV ret = Adapter_C_DigestFinal(hSession, pDigest, pulDigestLen);
	

	if(pDigest && pulDigestLen)
	{
		rspObj.set_pdigest(pDigest, *pulDigestLen);
	}
	if(pulDigestLen)
	{
		rspObj.set_puldigestlen(*pulDigestLen);
	}
	
	rspObj.SerializeToString(&rspObjString);


	FREE(pDigest);
	FREE(pulDigestLen);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_SignInit(const string src,string &dst)
{
	Req_C_SignInit reqObj;
	Rsp_C_SignInit rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}
	
	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_MECHANISM_PTR 	  pMechanism = NULL;
	CK_OBJECT_HANDLE  hKey = reqObj.hkey();
    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
        {
		    pMechanism->mechanism = reqObj.pmechanism().mechanism();
		    pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
		    pMechanism->pParameter = NULL;
		    if(reqObj.pmechanism().has_pparameter())
		    {
		        pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
		    }
		}
    }
		
	CK_RV ret = Adapter_C_SignInit(hSession, pMechanism, hKey);
		
	rspObj.SerializeToString(&rspObjString);
	FREE(pMechanism);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Sign(const string src,string &dst)
{
	Req_C_Sign reqObj;
	Rsp_C_Sign rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pData = reqObj.has_pdata() ? (CK_BYTE_PTR)reqObj.pdata().data() : NULL;
	CK_ULONG          ulDataLen = reqObj.pdata().size();
	CK_BYTE_PTR       pSignature = NULL;
	CK_ULONG_PTR 	      pulSignatureLen = NULL;//reqObj.pulsignaturelen();
	if(reqObj.has_psignature())
	{
		pSignature = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.psignature().size());
	}
	if(reqObj.has_pulsignaturelen())
	{
		pulSignatureLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulSignatureLen)
		{
			*pulSignatureLen = reqObj.pulsignaturelen();
		}
	}

	CK_RV ret = Adapter_C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
	

	if(pSignature && pulSignatureLen)
	{
		rspObj.set_psignature(pSignature, *pulSignatureLen);
		rspObj.set_pulsignaturelen(*pulSignatureLen);
	}
	if(pulSignatureLen)
	{
		rspObj.set_pulsignaturelen(*pulSignatureLen);
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pSignature);
	FREE(pulSignatureLen);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_SignUpdate(const string src,string &dst)
{
	Req_C_SignUpdate reqObj;
	Rsp_C_SignUpdate rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pPart = reqObj.has_ppart() ? (CK_BYTE_PTR)reqObj.ppart().data() : NULL;
	CK_ULONG          ulPartLen = reqObj.ppart().size();

	CK_RV ret = Adapter_C_SignUpdate(hSession, pPart, ulPartLen);
		
	rspObj.SerializeToString(&rspObjString);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_SignFinal(const string src,string &dst)
{
	Req_C_SignFinal reqObj;
	Rsp_C_SignFinal rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pSignature = NULL;
	CK_ULONG_PTR	      pulSignatureLen = NULL;//reqObj.pulsignaturelen();
	if(reqObj.has_psignature())
	{
		pSignature = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.psignature().size());
	}
	if(reqObj.has_pulsignaturelen())
	{
		pulSignatureLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG_PTR));
		if(pulSignatureLen)
		{
			*pulSignatureLen = reqObj.pulsignaturelen();
		}
	}
	CK_RV ret = Adapter_C_SignFinal(hSession, pSignature, pulSignatureLen);
	

	if(pSignature && pulSignatureLen)
	{
		rspObj.set_psignature(pSignature, *pulSignatureLen);
		rspObj.set_pulsignaturelen(*pulSignatureLen);
	}
	
	if(pulSignatureLen)
	{
		rspObj.set_pulsignaturelen(*pulSignatureLen);
	}
	
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pSignature);	
	FREE(pulSignatureLen);	
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_SignRecoverInit(const string src,string &dst)
{
	Req_C_SignRecoverInit reqObj;
	Rsp_C_SignRecoverInit rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}
	
	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_MECHANISM_PTR 	  pMechanism = NULL;
	CK_OBJECT_HANDLE  hKey = reqObj.hkey();

    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
        {
	        pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
	        pMechanism->pParameter = NULL;
	        if(reqObj.pmechanism().has_pparameter())
	        {
	            pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
	        }
		}
    }

	CK_RV ret = Adapter_C_SignRecoverInit(hSession, pMechanism, hKey);
	
	rspObj.SerializeToString(&rspObjString);
	FREE(pMechanism);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_SignRecover(const string src,string &dst)
{
	Req_C_SignRecover reqObj;
	Rsp_C_SignRecover rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pData = reqObj.has_pdata() ? (CK_BYTE_PTR)reqObj.pdata().data() : NULL;
	CK_ULONG          ulDataLen = reqObj.pdata().size();
	CK_BYTE_PTR       pSignature = NULL;
	CK_ULONG_PTR	      pulSignatureLen = NULL;
	if(reqObj.has_psignature())
	{
		pSignature = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.psignature().size());
	}

	if(reqObj.has_pulsignaturelen())
	{
		pulSignatureLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulSignatureLen)
		{
			*pulSignatureLen = reqObj.pulsignaturelen();
		}
	}
	CK_RV ret = Adapter_C_SignRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
	

	if(pSignature && pulSignatureLen)
	{
		rspObj.set_psignature(pSignature, *pulSignatureLen);
		rspObj.set_pulsignaturelen(*pulSignatureLen);
	}
	if(pulSignatureLen)
	{
		rspObj.set_pulsignaturelen(*pulSignatureLen);
	}
	
		
	rspObj.SerializeToString(&rspObjString);

	FREE(pSignature);
	FREE(pulSignatureLen);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_VerifyInit(const string src,string &dst)
{
	Req_C_VerifyInit reqObj;
	Rsp_C_VerifyInit rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_MECHANISM_PTR 	  pMechanism = NULL;
	CK_OBJECT_HANDLE  hKey = reqObj.hkey();

    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
        {
	        pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
	        pMechanism->pParameter = NULL;
	        if(reqObj.pmechanism().has_pparameter())
	        {
	            pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
	        }
		}
    }


	CK_RV ret = Adapter_C_VerifyInit(hSession, pMechanism, hKey);
		
	rspObj.SerializeToString(&rspObjString);

	FREE(pMechanism);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Verify(const string src,string &dst)
{
	Req_C_Verify reqObj;
	Rsp_C_Verify rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pData  = reqObj.has_pdata() ? (CK_BYTE_PTR)reqObj.pdata().data() : NULL;/*= reqObj.pdata().data()*/;
	CK_ULONG          ulDataLen = reqObj.uldatalen();
	CK_BYTE_PTR       pSignature = reqObj.has_psignature() ? (CK_BYTE_PTR)reqObj.psignature().data() : NULL;
	CK_ULONG          ulSignatureLen = reqObj.ulsignaturelen();

	CK_RV ret = Adapter_C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
	
	rspObj.SerializeToString(&rspObjString);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_VerifyUpdate(const string src,string &dst)
{
	Req_C_VerifyUpdate reqObj;
	Rsp_C_VerifyUpdate rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pPart = reqObj.has_ppart() ? (CK_BYTE_PTR)reqObj.ppart().data() : NULL;
	CK_ULONG          ulPartLen = reqObj.ppart().size();

	CK_RV ret = Adapter_C_VerifyUpdate(hSession, pPart, ulPartLen);
	
	rspObj.SerializeToString(&rspObjString);

	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_VerifyFinal(const string src,string &dst)
{

	Req_C_VerifyFinal reqObj;
	Rsp_C_VerifyFinal rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pSignature = reqObj.has_psignature() ? (CK_BYTE_PTR)reqObj.psignature().data() : NULL;
	CK_ULONG          ulSignatureLen = reqObj.psignature().size();

	CK_RV ret = Adapter_C_VerifyFinal(hSession, pSignature, ulSignatureLen);
	
	
	rspObj.SerializeToString(&rspObjString);

	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_VerifyRecoverInit(const string src,string &dst)
{
	Req_C_VerifyRecoverInit reqObj;
	Rsp_C_VerifyRecoverInit rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_MECHANISM_PTR	  pMechanism = NULL;
	CK_OBJECT_HANDLE  hKey = reqObj.hkey();
    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		
		if(pMechanism)
        {
	        pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
	        pMechanism->pParameter = NULL;
	        if(reqObj.pmechanism().has_pparameter())
	        {
	            pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
	        }
		}
    }

	CK_RV ret = Adapter_C_VerifyRecoverInit(hSession, pMechanism, hKey);
		
	rspObj.SerializeToString(&rspObjString);
	FREE(pMechanism);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_VerifyRecover(const string src,string &dst)
{
	Req_C_VerifyRecover reqObj;
	Rsp_C_VerifyRecover rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pSignature = reqObj.has_psignature() ? (CK_BYTE_PTR)reqObj.psignature().data() : NULL;
	CK_ULONG          ulSignatureLen = reqObj.psignature().size();
	CK_BYTE_PTR       pData = NULL;
	CK_ULONG_PTR     	  pulDataLen = NULL;//
	if(reqObj.has_pdata())
	{
		pData = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.pdata().size());
	}
	if(reqObj.has_puldatalen())
	{
		pulDataLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulDataLen)
		{
			*pulDataLen = reqObj.puldatalen();
		}
	}
	CK_RV ret = Adapter_C_VerifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
	

	if(pData && pulDataLen)
	{
		rspObj.set_pdata(pData, *pulDataLen);
		rspObj.set_puldatalen(*pulDataLen);
	}
	if(pulDataLen)
	{
		rspObj.set_puldatalen(*pulDataLen);
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pData);
	FREE(pulDataLen);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_DigestEncryptUpdate(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_DigestEncryptUpdate reqObj;
	Rsp_C_DigestEncryptUpdate rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pPart = reqObj.has_ppart() ? (CK_BYTE_PTR)reqObj.ppart().data() : NULL;
	CK_ULONG          ulPartLen = reqObj.ppart().size();
	CK_BYTE_PTR       pEncryptedPart = NULL;
	CK_ULONG_PTR 	      pulEncryptedPartLen = NULL;//reqObj.pulencryptedpartlen();
	if(reqObj.has_pencryptedpart())
	{
		pEncryptedPart = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.pencryptedpart().size());
	}

	if(reqObj.has_pulencryptedpartlen())
	{
		pulEncryptedPartLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulEncryptedPartLen)
		{
			*pulEncryptedPartLen = reqObj.pulencryptedpartlen();
		}	
	}
	CK_RV ret = Adapter_C_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	

	if(pEncryptedPart && pulEncryptedPartLen)
	{
		rspObj.set_pencryptedpart(pEncryptedPart, *pulEncryptedPartLen);
		rspObj.set_pulencryptedpartlen(*pulEncryptedPartLen);
		
	}
	
	if(pulEncryptedPartLen)
	{
		rspObj.set_pulencryptedpartlen(*pulEncryptedPartLen);	
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pEncryptedPart);
	FREE(pulEncryptedPartLen);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_DecryptDigestUpdate(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_DecryptDigestUpdate reqObj;
	Rsp_C_DecryptDigestUpdate rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pEncryptedPart = reqObj.has_pencryptedpart() ? (CK_BYTE_PTR)reqObj.pencryptedpart().data() : NULL;
	CK_ULONG          ulEncryptedPartLen = reqObj.pencryptedpart().size();
	CK_BYTE_PTR       pPart = NULL;
	CK_ULONG_PTR 	      pulPartLen = NULL;
	if(reqObj.has_ppart())
	{
		pPart = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.ppart().size());
	}

	if(reqObj.has_pulpartlen())
	{
		pulPartLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulPartLen)
		{
			*pulPartLen = reqObj.pulpartlen();
		}
	}
	
	CK_RV ret = Adapter_C_DecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	

	if(pPart && pulPartLen)
	{
		rspObj.set_ppart(pPart, *pulPartLen);
		rspObj.set_pulpartlen(*pulPartLen);
	}
	if(pulPartLen)
	{
		rspObj.set_pulpartlen(*pulPartLen);
	}
	
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pPart);
	FREE(pulPartLen);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_SignEncryptUpdate(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_SignEncryptUpdate reqObj;
	Rsp_C_SignEncryptUpdate rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pPart = reqObj.has_ppart() ? (CK_BYTE_PTR)reqObj.ppart().data() : NULL;
	CK_ULONG          ulPartLen = reqObj.ppart().size();
	CK_BYTE_PTR       pEncryptedPart = NULL;
	CK_ULONG_PTR 	      pulEncryptedPartLen = NULL;//reqObj.pulencryptedpartlen();
	if(reqObj.has_pencryptedpart())
	{
		pEncryptedPart = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.pencryptedpart().size());
	}
	if(reqObj.has_pulencryptedpartlen())
	{
		pulEncryptedPartLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulEncryptedPartLen)
		{
			*pulEncryptedPartLen = reqObj.pulencryptedpartlen();
		}
	}
	CK_RV ret = Adapter_C_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	

	if(pEncryptedPart && pulEncryptedPartLen)
	{
		rspObj.set_pencryptedpart(pEncryptedPart, *pulEncryptedPartLen);
		rspObj.set_pulencryptedpartlen(*pulEncryptedPartLen);
	}
	if(pulEncryptedPartLen)
	{
		rspObj.set_pulencryptedpartlen(*pulEncryptedPartLen);
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pEncryptedPart);
	FREE(pulEncryptedPartLen);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_DecryptVerifyUpdate(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_DecryptVerifyUpdate reqObj;
	Rsp_C_DecryptVerifyUpdate rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pEncryptedPart = reqObj.has_pencryptedpart() ? (CK_BYTE_PTR)reqObj.pencryptedpart().data() : NULL;
	CK_ULONG          ulEncryptedPartLen = reqObj.pencryptedpart().size();
	CK_BYTE_PTR       pPart = NULL;
	CK_ULONG_PTR 	      pulPartLen = NULL;//reqObj.pulpartlen();
	if(reqObj.has_ppart())
	{
		pPart = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.ppart().size());
	}
	if(reqObj.has_pulpartlen())
	{
		pulPartLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulPartLen)
		{
			*pulPartLen = reqObj.pulpartlen();
		}	
	}
	CK_RV ret = Adapter_C_DecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	

	if(pPart && pulPartLen)
	{
		rspObj.set_ppart(pPart, *pulPartLen);
		rspObj.set_pulpartlen(*pulPartLen);
	}
	if(pulPartLen)
	{
		rspObj.set_pulpartlen(*pulPartLen);
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pPart);
	FREE(pulPartLen);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_GenerateKey(const string src,string &dst)
{
	Req_C_GenerateKey reqObj;
	Rsp_C_GenerateKey rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE    hSession = reqObj.hsession();
	CK_MECHANISM_PTR 	     pMechanism = NULL;
	CK_ATTRIBUTE_PTR     pTemplate = NULL;
	CK_ULONG             ulCount = reqObj.ptemplate_size();
	CK_OBJECT_HANDLE_PTR  	 phKey = NULL;
    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
		{
	       	pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
	        pMechanism->pParameter = NULL;
	        if(reqObj.pmechanism().has_pparameter())
	        {
	            pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
	        }
		}

    }

	if(reqObj.ptemplate_size())
	{
		pTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * reqObj.ptemplate_size());
		if(pTemplate)
		{
			for(int loop = 0; loop < reqObj.ptemplate_size(); ++loop)
			{
				pTemplate[loop].type = reqObj.ptemplate(loop).type();
				pTemplate[loop].pValue = reqObj.ptemplate(loop).has_value() ? (CK_VOID_PTR)(reqObj.ptemplate(loop).value().data()) : NULL;
				pTemplate[loop].ulValueLen = reqObj.ptemplate(loop).value().size();
			}		
		}
	}

	if(reqObj.has_phkey())
	{
		phKey = (CK_OBJECT_HANDLE_PTR)malloc(sizeof(CK_OBJECT_HANDLE));
		if(phKey)
		{
			*phKey = reqObj.phkey();
		}		
	}

	getclientname(packageName);

	CK_RV ret = Adapter_C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
	
	if(phKey)
	{
		rspObj.set_phkey(*phKey);
	}
	
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pMechanism);
	FREE(pTemplate);
	FREE(phKey);	
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_GenerateKeyPair(const string src,string &dst)
{
	Req_C_GenerateKeyPair reqObj;
	Rsp_C_GenerateKeyPair rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE    hSession = reqObj.hsession();
	CK_MECHANISM_PTR 	     pMechanism = NULL;
	CK_ATTRIBUTE_PTR     pPublicKeyTemplate = NULL;
	CK_ULONG             ulPublicKeyAttributeCount = reqObj.ppublickeytemplate_size();
	CK_ATTRIBUTE_PTR     pPrivateKeyTemplate = NULL;
	CK_ULONG             ulPrivateKeyAttributeCount = reqObj.pprivatekeytemplate_size();
	CK_OBJECT_HANDLE_PTR 	 phPublicKey = NULL;
	CK_OBJECT_HANDLE_PTR 	 phPrivateKey = NULL;
    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
		{			
			pMechanism->mechanism = reqObj.pmechanism().mechanism();
			pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
			pMechanism->pParameter = NULL;
			if(reqObj.pmechanism().has_pparameter())
			{
			  pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
			}
		}
      
    }
	if(reqObj.ppublickeytemplate_size())
	{
		pPublicKeyTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * ulPublicKeyAttributeCount);
		if(pPublicKeyTemplate)
		{
			for(int loop = 0; loop < ulPublicKeyAttributeCount; ++loop)
			{
				pPublicKeyTemplate[loop].type = reqObj.ppublickeytemplate(loop).type();
				pPublicKeyTemplate[loop].pValue = reqObj.ppublickeytemplate(loop).has_value() ? (CK_VOID_PTR)(reqObj.ppublickeytemplate(loop).value().data()) : NULL;
				pPublicKeyTemplate[loop].ulValueLen = reqObj.ppublickeytemplate(loop).value().size();
			}
		}
	}
	if(reqObj.pprivatekeytemplate_size())
	{
		pPrivateKeyTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * ulPrivateKeyAttributeCount);
		if(pPrivateKeyTemplate)
		{
			for(int loop = 0; loop < ulPrivateKeyAttributeCount; ++loop)
			{
				pPrivateKeyTemplate[loop].type = reqObj.pprivatekeytemplate(loop).type();
				pPrivateKeyTemplate[loop].pValue = reqObj.pprivatekeytemplate(loop).has_value() ? (CK_VOID_PTR)(reqObj.pprivatekeytemplate(loop).value().data()) : NULL;
				pPrivateKeyTemplate[loop].ulValueLen = reqObj.pprivatekeytemplate(loop).value().size();
			}	
		}
	}
	if(reqObj.has_phpublickey())
	{
		phPublicKey = (CK_OBJECT_HANDLE_PTR)malloc(sizeof(CK_OBJECT_HANDLE));
		if(phPublicKey)
		{
			*phPublicKey = reqObj.phpublickey();
		}		
	}
	if(reqObj.has_phprivatekey())
	{
		phPrivateKey = (CK_OBJECT_HANDLE_PTR)malloc(sizeof(CK_OBJECT_HANDLE));
		if(phPrivateKey)
		{
			*phPrivateKey = reqObj.phprivatekey();
		}
	}

	CK_RV ret = Adapter_C_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
	
	if(phPublicKey && phPrivateKey)
	{
		rspObj.set_phpublickey(*phPublicKey);
		rspObj.set_phprivatekey(*phPrivateKey);		
	}

	
	rspObj.SerializeToString(&rspObjString);


	FREE(pMechanism);
	FREE(pPublicKeyTemplate);
	FREE(pPrivateKeyTemplate);
	FREE(phPublicKey);
	FREE(phPrivateKey);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_WrapKey(const string src,string &dst)
{
	Req_C_WrapKey reqObj;
	Rsp_C_WrapKey rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_MECHANISM_PTR	  pMechanism = NULL;
	CK_OBJECT_HANDLE  hWrappingKey = reqObj.hwrappingkey();
	CK_OBJECT_HANDLE  hKey = reqObj.hkey();
	CK_BYTE_PTR       pWrappedKey = NULL;
	CK_ULONG_PTR 	      pulWrappedKeyLen = NULL;//reqObj.pulwrappedkeylen();
    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
		{
			pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
	        pMechanism->pParameter = NULL;
	        if(reqObj.pmechanism().has_pparameter())
	        {
	            pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
	        }
		}
    }

	if(reqObj.has_pwrappedkey())
	{
		pWrappedKey = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.pwrappedkey().size());
	}

	if(reqObj.has_pulwrappedkeylen())
	{
		pulWrappedKeyLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulWrappedKeyLen)
		{
			*pulWrappedKeyLen = reqObj.pulwrappedkeylen();
		}
	}
	
	CK_RV ret = Adapter_C_WrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
	
	if(pWrappedKey && pulWrappedKeyLen)
	{
		LOGSERVERD(tag,"%s, pulWrappedKeyLen is %lu",__FUNCTION__,*pulWrappedKeyLen);
		rspObj.set_pwrappedkey(pWrappedKey, *pulWrappedKeyLen);
		rspObj.set_pulwrappedkeylen(*pulWrappedKeyLen);
	}
	if(pulWrappedKeyLen)
	{
		rspObj.set_pulwrappedkeylen(*pulWrappedKeyLen);
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pMechanism);
	FREE(pWrappedKey);
	FREE(pulWrappedKeyLen);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_UnwrapKey(const string src,string &dst)
{
	Req_C_UnwrapKey reqObj;
	Rsp_C_UnwrapKey rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE    hSession = reqObj.hsession();
	CK_MECHANISM_PTR     	 pMechanism = NULL;
	CK_OBJECT_HANDLE     hUnwrappingKey = reqObj.hunwrappingkey();
	CK_BYTE_PTR          pWrappedKey = reqObj.has_pwrappedkey() ? (CK_BYTE_PTR)reqObj.pwrappedkey().data() : NULL;
	CK_ULONG             ulWrappedKeyLen = reqObj.pwrappedkey().size();
	CK_ATTRIBUTE_PTR     pTemplate = NULL;
	CK_ULONG             ulAttributeCount = reqObj.ptemplate_size();
	CK_OBJECT_HANDLE_PTR	 phKey = NULL;
    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
		{
	        pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
	        pMechanism->pParameter = NULL;
	        if(reqObj.pmechanism().has_pparameter())
	        {
	            pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
	        }
		}

    }

	if(reqObj.ptemplate_size())
	{
		pTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * reqObj.ptemplate_size());
		if(pTemplate)
		{
			for(int loop = 0; loop < reqObj.ptemplate_size(); ++loop)
			{
				pTemplate[loop].type = reqObj.ptemplate(loop).type();
				pTemplate[loop].pValue = reqObj.ptemplate(loop).has_value() ? (CK_VOID_PTR)(reqObj.ptemplate(loop).value().data()) : NULL;
				pTemplate[loop].ulValueLen = reqObj.ptemplate(loop).value().size();
			}		
		}		
	}
	if(reqObj.has_phkey())
	{
		phKey = (CK_OBJECT_HANDLE_PTR)malloc(sizeof(CK_OBJECT_HANDLE));
		if(phKey)
		{
			*phKey = reqObj.phkey();
		}
		
	}
		
	getclientname(packageName);
	CK_RV ret = Adapter_C_UnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
	
	if(phKey)
	{
		rspObj.set_phkey(*phKey);
	}
	
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pMechanism);
	FREE(pTemplate);	
	FREE(phKey);	
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_DeriveKey(const string src,string &dst)
{
	Req_C_DeriveKey reqObj;
	Rsp_C_DeriveKey rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE    hSession = reqObj.hsession();
	CK_MECHANISM_PTR pMechanism = NULL;
	CK_OBJECT_HANDLE     hBaseKey = reqObj.hbasekey();
	CK_ATTRIBUTE_PTR     pTemplate = NULL;
	CK_ULONG             ulAttributeCount = reqObj.ptemplate_size();
	CK_OBJECT_HANDLE_PTR phKey = NULL;

    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
		{
			pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
	        pMechanism->pParameter = NULL;
	        if(reqObj.pmechanism().has_pparameter())
	        {
	            pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
	        }
		}       
    }

	if(reqObj.ptemplate_size())
	{
		pTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * reqObj.ptemplate_size());
		if(pTemplate)
		{
			for(int loop = 0; loop < reqObj.ptemplate_size(); ++loop)
			{
				pTemplate[loop].type = reqObj.ptemplate(loop).type();
				pTemplate[loop].pValue = reqObj.ptemplate(loop).has_value() ? (CK_VOID_PTR)(reqObj.ptemplate(loop).value().data()) : NULL;
				pTemplate[loop].ulValueLen = reqObj.ptemplate(loop).value().size();
			}		
		}	
	}

	if(reqObj.has_phkey())
	{
		phKey = (CK_OBJECT_HANDLE_PTR)malloc(sizeof(CK_OBJECT_HANDLE));
		if(phKey)
		{
			*phKey = reqObj.phkey();
		}		
	}

	CK_RV ret = Adapter_C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
	
	if(phKey)
	{
		rspObj.set_phkey(*phKey);
	}
	
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pMechanism);
	FREE(pTemplate);
	FREE(phKey);	
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_SeedRandom(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_SeedRandom reqObj;
	Rsp_C_SeedRandom rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pSeed = reqObj.has_pseed() ? (CK_BYTE_PTR)reqObj.pseed().data() : NULL;
	CK_ULONG          ulSeedLen = reqObj.pseed().size();

	CK_RV ret = Adapter_C_SeedRandom(hSession, pSeed, ulSeedLen);
	

	rspObj.SerializeToString(&rspObjString);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_GenerateRandom(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_GenerateRandom reqObj;
	Rsp_C_GenerateRandom rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       RandomData = NULL;
	CK_ULONG          ulRandomLen = reqObj.ulrandomlen();
	if(reqObj.has_randomdata())
	{
		RandomData = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * ulRandomLen);
	}
	

	CK_RV ret = Adapter_C_GenerateRandom(hSession, RandomData, ulRandomLen);
	
	if(RandomData)
	{
		rspObj.set_randomdata(RandomData, ulRandomLen);
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(RandomData);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_GetFunctionStatus(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_GetFunctionStatus reqObj;
	Rsp_C_GetFunctionStatus rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();

	CK_RV ret = Adapter_C_GetFunctionStatus(hSession);
		
	rspObj.SerializeToString(&rspObjString);
	
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_CancelFunction(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_CancelFunction reqObj;
	Rsp_C_CancelFunction rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();

	CK_RV ret = Adapter_C_CancelFunction(hSession);
	
	rspObj.SerializeToString(&rspObjString);

	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_WaitForSlotEvent(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_WaitForSlotEvent reqObj;
	Rsp_C_WaitForSlotEvent rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_FLAGS flags = reqObj.flags();
	CK_SLOT_ID_PTR pSlot = NULL;
	CK_VOID_PTR pRserved = NULL;

	if(reqObj.has_pslot())
	{
		pSlot = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID));
		if(pSlot)
		{
			*pSlot = reqObj.pslot();
		}
	}

	CK_RV ret = Adapter_C_WaitForSlotEvent(flags, pSlot, pRserved);
	
	if(pSlot)
	{
		rspObj.set_pslot(*pSlot);
	}
	
	
	rspObj.SerializeToString(&rspObjString);


	FREE(pSlot);
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}


int P11FunctionParse::C_Extend_GetPinRemainCount(const string src,string &dst)
{
	Req_C_Extend_GetPinRemainCount reqObj;
	Rsp_C_Extend_GetPinRemainCount rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_ULONG_PTR pUiRemainCount = NULL ;

	if(reqObj.has_puiremaincount())
	{
		pUiRemainCount = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pUiRemainCount)
		{
			*pUiRemainCount = reqObj.puiremaincount();
		}
	}
	CK_RV ret = Adapter_C_Extend_GetPinRemainCount(hSession, pUiRemainCount);
	
	if(pUiRemainCount)
	{
		rspObj.set_puiremaincount(*pUiRemainCount);
	}
	
	
	rspObj.SerializeToString(&rspObjString);


	FREE(pUiRemainCount);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_GetStatus(const string src,string &dst)
{
	Req_C_Extend_GetStatus reqObj;
	Rsp_C_Extend_GetStatus rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SLOT_ID slotID = reqObj.slotid();
	CK_STATUS_ENUM_PTR pStatus = NULL;

	if(reqObj.has_pstatus())
	{
		pStatus = (CK_STATUS_ENUM_PTR)malloc(sizeof(CK_STATUS_ENUM));
		if(pStatus)
		{
			*pStatus = (CK_STATUS_ENUM)reqObj.pstatus();
		}
	}
	CK_RV ret = Adapter_C_Extend_GetStatus(slotID, pStatus);
	
	if(pStatus)
	{
		rspObj.set_pstatus(*pStatus);
	}
	

	rspObj.SerializeToString(&rspObjString);

	FREE(pStatus);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_Register_Status_Callback_Func(const string src,string &dst)
{
	Rsp_Status_Callback_Func rspObj;
	string rspObjString;

	CK_RV ret = 0;
	rspObj.SerializeToString(&rspObjString); 
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_Register_Callback(const string src,string &dst)
{
	Req_C_Extend_Register_Callback reqObj;
	Rsp_C_Extend_Register_Callback rspObj;
	string rspObjString;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_RV ret = Adapter_C_Extend_Register_Callback(C_Extend_Status_Callback);
	rspObj.SerializeToString(&rspObjString);
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_Unregister_Callback(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_Extend_Unregister_Callback reqObj;
	Rsp_C_Extend_Unregister_Callback rspObj;
	string rspObjString;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_RV ret = Adapter_C_Extend_Unregister_Callback(C_Extend_Status_Callback);
		
	rspObj.SerializeToString(&rspObjString);

	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_GetExchangeSessionKey(const string src,string &dst)
{
	Req_C_Extend_GetExchangeSessionKey reqObj;
	Rsp_C_Extend_GetExchangeSessionKey rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_OBJECT_HANDLE hkey = reqObj.hkey();
	CK_BYTE_PTR pEncryptedData = NULL;
	CK_ULONG_PTR pulEncryptedDataLen = NULL; //reqObj.pulencrypteddatalen();
	if(reqObj.has_pencrypteddata())
	{
		pEncryptedData = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.pencrypteddata().size());
	}
	if(reqObj.has_pulencrypteddatalen())
	{
		pulEncryptedDataLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulEncryptedDataLen)
		{
			*pulEncryptedDataLen = reqObj.pulencrypteddatalen();
		}
	}
    CK_RV ret = 0;
	ret = Adapter_C_Extend_GetExchangeSessionKey(hSession,hkey,pEncryptedData, pulEncryptedDataLen);
	

	if(pEncryptedData && pulEncryptedDataLen)
	{
		rspObj.set_pencrypteddata(pEncryptedData, *pulEncryptedDataLen);
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pEncryptedData);	
	FREE(pulEncryptedDataLen);	
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_Destroy(const string src,string &dst)
{
	Req_C_Extend_Destroy reqObj;
	Rsp_C_Extend_Destroy rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SLOT_ID slotID = reqObj.slotid();
	CK_BYTE_PTR containerName = reqObj.has_containername() ? (CK_BYTE_PTR)reqObj.containername().data() : NULL;

	CK_RV ret = Adapter_C_Extend_Destroy(slotID, containerName);
	
	rspObj.SerializeToString(&rspObjString);

	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_Reset_Pin_With_OTP(const string src,string &dst)
{
	Req_C_Extend_Reset_Pin_With_OTP reqObj;
	Rsp_C_Extend_Reset_Pin_With_OTP rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR pbOTPPIN = reqObj.has_pbotppin() ? (CK_BYTE_PTR)reqObj.pbotppin().data() : NULL;
	CK_ULONG ulOTPPINLen = reqObj.ulotppinlen();
	CK_BYTE_PTR pbNewUserPIN = reqObj.has_pbnewuserpin() ? (CK_BYTE_PTR)reqObj.pbnewuserpin().data() : NULL;
	CK_ULONG ulNewUserPINLen = reqObj.ulnewuserpinlen();

	CK_RV ret = 0;
	
	if(ulOTPPINLen>0xFF)
	{
		ret = CKR_ARGUMENTS_BAD;
	}
	else
	{		
		ret = Adapter_C_Extend_Reset_Pin_With_OTP(hSession, pbOTPPIN, ulOTPPINLen, pbNewUserPIN, ulNewUserPINLen);
	}

	
	rspObj.SerializeToString(&rspObjString);

	return responsePack(ret, rspObjString, dst);
}

int P11FunctionParse::C_Extend_Reset_OTP(const string src,string &dst)
{
	Req_C_Extend_Reset_OTP reqObj;
	Rsp_C_Extend_Reset_OTP rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR pbOTPMpk = reqObj.has_pbotpmpk() ? (CK_BYTE_PTR)reqObj.pbotpmpk().data() : NULL;
	CK_ULONG ulMpkLen = reqObj.ulmpklen();
	CK_BYTE_PTR pbMpkIV = reqObj.has_pbmpkiv() ? (CK_BYTE_PTR)reqObj.pbmpkiv().data() : NULL;
	CK_ULONG ulMpkIVLen = reqObj.ulmpkivlen();

	CK_RV ret = Adapter_C_Extend_Reset_OTP(hSession, pbOTPMpk, ulMpkLen, pbMpkIV, ulMpkIVLen);
		
	rspObj.SerializeToString(&rspObjString);
	
	return responsePack(ret, rspObjString, dst);
}

int P11FunctionParse::C_Extend_Get_OTP_Unlock_Count(const string src,string &dst)
{
	Req_C_Extend_Get_OTP_Unlock_Count reqObj;
	Rsp_C_Extend_Get_OTP_Unlock_Count rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_ULONG_PTR pulCount = NULL;

	if(reqObj.has_pulcount())
	{
		pulCount = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulCount)
		{
			*pulCount = reqObj.pulcount();
		}
	}
	CK_RV ret = Adapter_C_Extend_Get_OTP_Unlock_Count(hSession, pulCount);
	
	if(pulCount)
	{
		rspObj.set_pulcount(*pulCount);
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pulCount);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_Get_OTP_Remain_Count(const string src,string &dst)
{
	Req_C_Extend_Get_OTP_Remain_Count reqObj;
	Rsp_C_Extend_Get_OTP_Remain_Count rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_ULONG_PTR pulCount = NULL;

	if(reqObj.has_pulcount())
	{
		pulCount = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulCount)
		{
			*pulCount = reqObj.pulcount();
		}
	}

	CK_RV ret = Adapter_C_Extend_Get_OTP_Remain_Count(hSession, pulCount);
	
	if(pulCount)
	{
		rspObj.set_pulcount(*pulCount);
	}
	
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pulCount);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_DeriveSessionKey(const string src,string &dst)
{
	Req_C_Extend_DeriveSessionKey reqObj;
	Rsp_C_Extend_DeriveSessionKey rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_MECHANISM_PTR pMechanism = NULL;
	CK_OBJECT_HANDLE hLocalKey = reqObj.hlocalkey();
	CK_OBJECT_HANDLE hRemoteKey = reqObj.hremotekey();
	CK_ATTRIBUTE_PTR pTemplate = NULL;
	CK_ULONG ulAttributeCount = reqObj.ptemplate_size();
	CK_OBJECT_HANDLE_PTR phKey = NULL;
	CK_BYTE_PTR pExchangeIV = NULL;
	CK_ULONG_PTR pExchangeIVLen = NULL;

    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
		{
	        pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
	        pMechanism->pParameter = NULL;
	        if(reqObj.pmechanism().has_pparameter())
	        {
	            pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
	        }
		}

    }

	if(reqObj.ptemplate_size())
	{
		pTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * reqObj.ptemplate_size());
		if(pTemplate)
		{
			for(int loop = 0; loop < reqObj.ptemplate_size(); loop++)
			{
				pTemplate[loop].type = reqObj.ptemplate(loop).type();
				pTemplate[loop].pValue = reqObj.ptemplate(loop).has_value() ? (CK_VOID_PTR)(reqObj.ptemplate(loop).value().data()) : NULL;
				pTemplate[loop].ulValueLen = reqObj.ptemplate(loop).value().size();
			}	
		}
	}

	if(reqObj.has_phkey())
	{
		phKey = (CK_OBJECT_HANDLE_PTR)malloc(sizeof(CK_OBJECT_HANDLE));
		if(phKey)
		{
			*phKey = reqObj.phkey();
		}
	}
	if(reqObj.has_pexchangeiv())
	{
		pExchangeIV = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.pexchangeiv().size());
	}

	if(reqObj.has_pexchangeivlen())
	{
		pExchangeIVLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pExchangeIVLen)
		{
			*pExchangeIVLen = reqObj.pexchangeivlen();
		}
	}
	
	CK_RV ret = Adapter_C_Extend_DeriveSessionKey(hSession, pMechanism, hLocalKey, hRemoteKey, pTemplate, ulAttributeCount, phKey, pExchangeIV, pExchangeIVLen);

	if(phKey)
	{
		rspObj.set_phkey(*phKey);
	}
	
	
	if(pExchangeIV && pExchangeIVLen)
	{
		rspObj.set_pexchangeiv(pExchangeIV, *pExchangeIVLen);
		rspObj.set_pexchangeivlen(*pExchangeIVLen);
	}
	
	
	rspObj.SerializeToString(&rspObjString);
	
	FREE(pMechanism);
	FREE(pTemplate);
	FREE(phKey);
	FREE(pExchangeIV);
	FREE(pExchangeIVLen);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_EncryptInit(const string src,string &dst)
{
	Req_C_Extend_EncryptInit reqObj;
	Rsp_C_Extend_EncryptInit rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_MECHANISM_PTR  pMechanism = NULL;
	CK_ATTRIBUTE_PTR pTemplate = NULL;
	CK_ULONG ulAttributeCount = reqObj.ulattributecount();
    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
		{
	        pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
	        pMechanism->pParameter = NULL;
	        if(reqObj.pmechanism().has_pparameter())
	        {
	            pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
	        }
		}

    }

	if(reqObj.ptemplate_size())
	{
		pTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * reqObj.ptemplate_size());
		if(pTemplate)
		{
			for(unsigned int loop = 0; loop < reqObj.ptemplate_size(); loop++)
			{
				pTemplate[loop].type =  reqObj.ptemplate(loop).type();
				if(reqObj.ptemplate(loop).has_value())
				{
					pTemplate[loop].pValue = (CK_VOID_PTR)reqObj.ptemplate(loop).value().data();
				}
				
				pTemplate[loop].ulValueLen = reqObj.ptemplate(loop).ulvaluelen();
			}
		}
	}

	CK_RV ret = Adapter_C_Extend_EncryptInit(hSession, pMechanism, pTemplate,ulAttributeCount);
	

	rspObj.SerializeToString(&rspObjString);

	FREE(pMechanism);
	FREE(pTemplate);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_DecryptInit(const string src,string &dst)
{
	Req_C_Extend_DecryptInit reqObj;
	Rsp_C_Extend_DecryptInit rspObj;
	string rspObjString;
	
	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}
	
	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_MECHANISM_PTR  pMechanism = NULL;
	CK_ATTRIBUTE_PTR pTemplate = NULL;
	CK_ULONG ulAttributeCount = reqObj.ulattributecount();
    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
		{
	        pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
	        pMechanism->pParameter = NULL;
	        if(reqObj.pmechanism().has_pparameter())
	        {
	            pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
	        }
		}
    }

	if(reqObj.ptemplate_size())
	{
		pTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * reqObj.ptemplate_size());
		if(pTemplate)
		{
			for(unsigned int loop = 0; loop < reqObj.ptemplate_size(); loop++)
			{
				pTemplate[loop].type =  reqObj.ptemplate(loop).type();
				if(reqObj.ptemplate(loop).has_value())
				{
					pTemplate[loop].pValue = (CK_VOID_PTR)reqObj.ptemplate(loop).value().data();
				}
				pTemplate[loop].ulValueLen = reqObj.ptemplate(loop).ulvaluelen();
			}
		}
		
	}
	
	CK_RV ret = Adapter_C_Extend_DecryptInit(hSession, pMechanism, pTemplate,ulAttributeCount);
	

	rspObj.SerializeToString(&rspObjString);

	FREE(pMechanism);
	FREE(pTemplate);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_EncryptUpdate(const string src,string &dst)
{
	Req_C_Extend_EncryptUpdate reqObj;
	Rsp_C_Extend_EncryptUpdate rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pIv = reqObj.has_piv() ? (CK_BYTE_PTR)reqObj.piv().data() : NULL;
	CK_ULONG          ulIvLen = reqObj.piv().size();
	CK_BYTE_PTR       pPart = reqObj.has_ppart() ? (CK_BYTE_PTR)reqObj.ppart().data() : NULL;
	CK_ULONG          ulPartLen = reqObj.ppart().size();
	CK_BYTE_PTR       pEncryptedPart = NULL;
	CK_ULONG_PTR      pulEncryptedPartLen  = NULL;//reqObj.pulencryptedpartlen();

	if(reqObj.has_pulencryptedpartlen())
  	{
  		pulEncryptedPartLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulEncryptedPartLen)
		{
  			*pulEncryptedPartLen = reqObj.pulencryptedpartlen();
		}
  	}
		
  	if(reqObj.has_pencryptedpart()&&pulEncryptedPartLen)
  	{  
  		pEncryptedPart = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.pencryptedpart().size());
  	}
  	
	CK_RV ret = Adapter_C_Extend_EncryptUpdate(hSession, pIv, ulIvLen, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	
	if(pulEncryptedPartLen)
	{
		rspObj.set_pulencryptedpartlen(*pulEncryptedPartLen);
	}
	

	if(pEncryptedPart && pulEncryptedPartLen)
	{
		rspObj.set_pencryptedpart(pEncryptedPart, *pulEncryptedPartLen);
	}
	
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pEncryptedPart);
	FREE(pulEncryptedPartLen);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_DecryptUpdate(const string src,string &dst)
{
	Req_C_Extend_DecryptUpdate reqObj;
	Rsp_C_Extend_DecryptUpdate rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pIv = reqObj.has_piv() ? (CK_BYTE_PTR)reqObj.piv().data() : NULL;
	CK_ULONG          ulIvLen = reqObj.piv().size();
	CK_BYTE_PTR       pEncryptedPart = reqObj.has_pencryptedpart() ? (CK_BYTE_PTR)reqObj.pencryptedpart().data() : NULL;
	CK_ULONG          ulEncryptedPartLen = reqObj.pencryptedpart().size();
	CK_BYTE_PTR       pPart = NULL;
	CK_ULONG_PTR      pulPartLen = NULL;//reqObj.pulpartlen();
	if(reqObj.has_ppart())
	{
		pPart = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.ppart().size());
	}

	if(reqObj.has_pulpartlen())
	{
		pulPartLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulPartLen)
		{
			*pulPartLen = reqObj.pulpartlen();
		}	
	}

	CK_RV ret = Adapter_C_Extend_DecryptUpdate(hSession, pIv, ulIvLen, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	LOGSERVERI(tag,"%s, *pulPartLen is %lu",__FUNCTION__,*pulPartLen);


	if(pPart && pulPartLen)
	{
		rspObj.set_ppart(pPart, *pulPartLen);
		rspObj.set_pulpartlen(*pulPartLen);
	}

	if(pulPartLen)
	{
		rspObj.set_pulpartlen(*pulPartLen);
	}
	

	rspObj.SerializeToString(&rspObjString);

	FREE(pPart);
	FREE(pulPartLen);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_EncryptFinalize(const string src,string &dst)
{
	Req_C_Extend_EncryptFinalize reqObj;
	Rsp_C_Extend_EncryptFinalize rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
    CK_BYTE_PTR       pLastEncryptedPart = NULL;
    CK_ULONG_PTR     pulLastEncryptedPartLen = NULL;//reqObj.pullastencryptedpartlen();
	
	if(reqObj.has_plastencryptedpart())
	{
		pLastEncryptedPart = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.plastencryptedpart().size());
	}

	if(reqObj.has_pullastencryptedpartlen())
	{
		pulLastEncryptedPartLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulLastEncryptedPartLen)
		{
			*pulLastEncryptedPartLen = reqObj.pullastencryptedpartlen();
		}
	}
	CK_RV ret = Adapter_C_Extend_EncryptFinalize(hSession, pLastEncryptedPart, pulLastEncryptedPartLen);

	if(pLastEncryptedPart && pulLastEncryptedPartLen)
	{
		rspObj.set_plastencryptedpart(pLastEncryptedPart, *pulLastEncryptedPartLen);
		rspObj.set_pullastencryptedpartlen(*pulLastEncryptedPartLen);
	}
	if(pulLastEncryptedPartLen)
	{
		rspObj.set_pullastencryptedpartlen(*pulLastEncryptedPartLen);
	}
	

	rspObj.SerializeToString(&rspObjString);

	FREE(pLastEncryptedPart);
	FREE(pulLastEncryptedPartLen);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_DecryptFinalize(const string src,string &dst)
{
	Req_C_Extend_DecryptFinalize reqObj;
	Rsp_C_Extend_DecryptFinalize rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR pLastPart = NULL;
	CK_ULONG_PTR pulLastPartLen = NULL;//reqObj.pullastpartlen();
	if(reqObj.has_plastpart())
	{
		pLastPart = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.plastpart().size());
	}
	if(reqObj.has_pullastpartlen())
	{
		pulLastPartLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulLastPartLen)
		{
			*pulLastPartLen = reqObj.pullastpartlen();
		}	
	}
	CK_RV ret = Adapter_C_Extend_DecryptFinalize(hSession, pLastPart, pulLastPartLen);
	

	if(pLastPart && pulLastPartLen)
	{
		rspObj.set_plastpart(pLastPart, *pulLastPartLen);
		rspObj.set_pullastpartlen(*pulLastPartLen);
	}
	if(pulLastPartLen)
	{
		rspObj.set_pullastpartlen(*pulLastPartLen);
	}
	
	rspObj.SerializeToString(&rspObjString);


	FREE(pLastPart);
	FREE(pulLastPartLen);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_PointMultiply(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_Extend_PointMultiply reqObj;
	Rsp_C_Extend_PointMultiply rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_MECHANISM_PTR pMechanism = NULL;
	CK_OBJECT_HANDLE hKey = reqObj.hkey();
	CK_BYTE_PTR pOutData = NULL;
	CK_ULONG_PTR pulCount = NULL;//reqObj.pulcount();

    if(reqObj.has_pmechanism())
    {
        pMechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
		if(pMechanism)
		{
			pMechanism->mechanism = reqObj.pmechanism().mechanism();
	        pMechanism->ulParameterLen = reqObj.pmechanism().ulvaluelen();
	        pMechanism->pParameter = NULL;
	        if(reqObj.pmechanism().has_pparameter())
	        {
	            pMechanism->pParameter = (CK_VOID_PTR)reqObj.pmechanism().pparameter().data();
	        }
		}

    }
	if(reqObj.has_poutdata())
	{
		pOutData = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.poutdata().size());
	}

	if(reqObj.has_pulcount())
	{
		pulCount = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulCount)
		{
			*pulCount = reqObj.pulcount();
		}
	}
	CK_RV ret = Adapter_C_Extend_PointMultiply(hSession, pMechanism, hKey, pOutData, pulCount);


	if(pOutData && pulCount)
	{
		rspObj.set_poutdata(pOutData, *pulCount);
		rspObj.set_pulcount(*pulCount);
	}
		
	rspObj.SerializeToString(&rspObjString);

	FREE(pMechanism);
	FREE(pOutData);
	FREE(pulCount);
	
	return responsePack(ret, rspObjString, dst);
}


int P11FunctionParse::C_Extend_Reset_TT(const string src,string &dst)
{
	Req_C_Extend_Reset_TT reqObj;
	Rsp_C_Extend_Reset_TT rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return RETURN_CODE_ERROR_PROTOCOL;
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR pbTTMpk = reqObj.has_pbttmpk() ? (CK_BYTE_PTR)reqObj.pbttmpk().data() : NULL;
	CK_ULONG ulMpkLen = reqObj.ulmpklen();
	CK_BYTE_PTR pbMpkIV = reqObj.has_pbmpkiv() ? (CK_BYTE_PTR)reqObj.pbmpkiv().data() : NULL;
	CK_ULONG ulMpkIVLen = reqObj.ulmpkivlen();

	CK_RV ret = Adapter_C_Extend_Reset_TT(hSession, pbTTMpk, ulMpkLen, pbMpkIV, ulMpkIVLen);
		
	rspObj.SerializeToString(&rspObjString);
	
	return responsePack(ret, rspObjString, dst);
}

int P11FunctionParse::C_Extend_Reset_BK(const string src,string &dst)
{
	Req_C_Extend_Reset_BK reqObj;
	Rsp_C_Extend_Reset_BK rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return RETURN_CODE_ERROR_PROTOCOL;
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR pbBKMpk = reqObj.has_pbbkmpk() ? (CK_BYTE_PTR)reqObj.pbbkmpk().data() : NULL;
	CK_ULONG ulMpkLen = reqObj.ulmpklen();
	CK_BYTE_PTR pbMpkIV = reqObj.has_pbmpkiv() ? (CK_BYTE_PTR)reqObj.pbmpkiv().data() : NULL;
	CK_ULONG ulMpkIVLen = reqObj.ulmpkivlen();

	CK_RV ret = Adapter_C_Extend_Reset_BK(hSession, pbBKMpk, ulMpkLen, pbMpkIV, ulMpkIVLen);
		
	rspObj.SerializeToString(&rspObjString);
	
	return responsePack(ret, rspObjString, dst);
}



int P11FunctionParse::C_Extend_Get_Special_Object_Version(const string src, string &dst) 
{
	Req_C_Extend_Get_Special_Object_Version reqObj;
	Rsp_C_Extend_Get_Special_Object_Version rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return RETURN_CODE_ERROR_PROTOCOL;
	}

	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_OBJECT_CLASS objectClass = reqObj.objectclass();
	CK_BYTE_PTR pVersion = NULL;
	CK_ULONG_PTR pLen = NULL;

	if(reqObj.has_pullen()){
		pLen = new CK_ULONG[1];
		*pLen = reqObj.pullen();
	}

	if(reqObj.has_pversion()){
		pVersion = new CK_BYTE[reqObj.pversion().size()];
		memcpy(pVersion,reqObj.pversion().data(),reqObj.pversion().size());
	}

	CK_RV ret = Adapter_C_Extend_Get_Special_Object_Version(hSession,objectClass,pVersion,pLen);

	if(NULL != pLen){
		rspObj.set_pullen(*pLen);
		
		if(NULL != pVersion){
			rspObj.set_pversion(pVersion,*pLen);
		}
	}

	rspObj.SerializeToString(&rspObjString);

	delete[] pLen;
	delete[] pVersion;

	pLen = NULL;
	pVersion = NULL;
	
	return responsePack(ret, rspObjString, dst);
}

int P11FunctionParse::C_Extend_DestroyCard(const string src,string &dst)
{
	Req_C_Extend_DestroyCard reqObj;
	Rsp_C_Extend_DestroyCard rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SLOT_ID slotID = reqObj.slotid();
	CK_BYTE_PTR       prandomIn = reqObj.has_prandomin() ? (CK_BYTE_PTR)reqObj.prandomin().data() : NULL;
	CK_ULONG          randomInLen = reqObj.prandomin().size();
	CK_BYTE_PTR       prandomOut = NULL;
	CK_ULONG_PTR	      prandomOutLen = NULL;
	if(reqObj.has_prandomoutlen())
	{
		prandomOutLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(prandomOutLen)
		{
			*prandomOutLen = reqObj.prandomoutlen();
		}
	}

	if(reqObj.has_prandomout() && prandomOutLen)
	{
		prandomOut = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.prandomout().size());
	}
		
	CK_RV ret = Adapter_C_Extend_DestroyCard(slotID,prandomIn,randomInLen,prandomOut,prandomOutLen);
	
	if(prandomOutLen)
	{
		rspObj.set_prandomoutlen(*prandomOutLen);
	}
	if(prandomOut && prandomOutLen)
	{
		rspObj.set_prandomout(prandomOut, *prandomOutLen);
	}	
	
	rspObj.SerializeToString(&rspObjString);

	FREE(prandomOut);
	FREE(prandomOutLen);
	
	return responsePack(ret, rspObjString, dst);
}


int P11FunctionParse::C_Extend_MonopolizeEnable(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_Extend_MonopolizeEnable reqObj;
	Rsp_C_Extend_MonopolizeEnable rspObj;
	string rspObjString;
		
	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}
	 
	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	CK_SLOT_ID slotID = reqObj.slotid();	

	slotIDServer server;
		
	p11Table.GetSlot(slotID,&server);
	CK_RV ret = CKR_FUNCTION_NOT_SUPPORTED;

	if(server.des != "sc"){
		FunctionParse::gloMonopolizePackageName = packageName;
	}
	
	
	ret = Adapter_C_Extend_MonopolizeEnable(slotID);
	

	rspObj.SerializeToString(&rspObjString);	
	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_MonopolizeDisable(const string src,string &dst)
{
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"IN");

	Req_C_Extend_MonopolizeDisable reqObj;
	Rsp_C_Extend_MonopolizeDisable rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
    }
 
	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SLOT_ID slotID = reqObj.slotid();

	slotIDServer server;
		
	p11Table.GetSlot(slotID,&server);
	CK_RV ret = CKR_FUNCTION_NOT_SUPPORTED;

	if(server.des != "sc"){
		FunctionParse::gloMonopolizePackageName = "";
	}

	ret = Adapter_C_Extend_MonopolizeDisable(slotID);
	

	rspObj.SerializeToString(&rspObjString);

	
	LOGSERVERI(tag,"[%s] %s",__FUNCTION__,"OUT");
	return responsePack(ret, rspObjString, dst);
}




int P11FunctionParse::C_Extend_GetDevInfo(const string src,string &dst)
{
	Req_C_Extend_GetDevInfo reqObj;
	Rsp_C_Extend_GetDevInfo rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SLOT_ID slotID = reqObj.slotid();
	char *userName = NULL;         
 	CK_IP_PARAMS *ipparam = NULL;  
	CK_BYTE_PTR pDevInfo = NULL;
	CK_ULONG_PTR pUlDevInfoLen = NULL;//reqObj.pullastpartlen();
	
	if(reqObj.has_pdevinfo())
	{
		pDevInfo = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.pdevinfo().size());
	}

	if(reqObj.has_username())
	{
		userName = (char*)reqObj.username().data();
	}

	if(reqObj.has_ipparam())
	{		
        ipparam = (CK_IP_PARAMS *)malloc(sizeof(CK_IP_PARAMS));
		if(ipparam)
		{
			memcpy(ipparam->ip,reqObj.ipparam().ip().data(),reqObj.ipparam().ip().size());
	        ipparam->oWayPort= reqObj.ipparam().owayport();
			ipparam->tWayPort= reqObj.ipparam().twayport();
		}
	}
	
	if(reqObj.has_puldevinfolen())
	{
		pUlDevInfoLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pUlDevInfoLen)
		{
			*pUlDevInfoLen = reqObj.puldevinfolen();
		}
	}
	CK_RV ret = Adapter_C_Extend_GetDevInfo(slotID, (const char *)userName, ipparam,pDevInfo, pUlDevInfoLen);
	
	if(pDevInfo && pUlDevInfoLen)
	{
		rspObj.set_pdevinfo(pDevInfo,*pUlDevInfoLen);	
	}

	
	if(pUlDevInfoLen)
	{		
		rspObj.set_puldevinfolen(*pUlDevInfoLen);
	}
	
	rspObj.SerializeToString(&rspObjString);
		
	FREE(pDevInfo);
	FREE(pUlDevInfoLen);
	FREE(ipparam);
	
	return responsePack(ret, rspObjString, dst);
}
int P11FunctionParse::C_Extend_DevSign(const string src,string &dst)
{
	Req_C_Extend_DevSign reqObj;
	Rsp_C_Extend_DevSign rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SLOT_ID slotID = reqObj.slotid();
	CK_BYTE_PTR       pData = reqObj.has_pdata() ? (CK_BYTE_PTR)reqObj.pdata().data() : NULL;
	CK_ULONG          ulDataLen = reqObj.pdata().size();
	CK_BYTE_PTR       pSignature = NULL;
	CK_ULONG_PTR	      pulSignatureLen = NULL;
	if(reqObj.has_pulsignaturelen())
	{
		pulSignatureLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulSignatureLen)
		{
			*pulSignatureLen = reqObj.pulsignaturelen();
		}
	}

	if(reqObj.has_psignature() && pulSignatureLen)
	{
		pSignature = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.psignature().size());
	}
		
	CK_RV ret = Adapter_C_Extend_DevSign(slotID,pData,ulDataLen,pSignature,pulSignatureLen);
	
	if(pulSignatureLen)
	{
		rspObj.set_pulsignaturelen(*pulSignatureLen);
	}
	if(pSignature && pulSignatureLen)
	{
		rspObj.set_psignature(pSignature, *pulSignatureLen);
	}	
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pSignature);
	FREE(pulSignatureLen);
	
	return responsePack(ret, rspObjString, dst);
}



int P11FunctionParse::C_Extend_Set_DestroyKey(const string src,string &dst)
{
	Req_C_Extend_Set_DestroyKey reqObj;
	Rsp_C_Extend_Set_DestroyKey rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return RETURN_CODE_ERROR_PROTOCOL;
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR pDestroyKeyMpk = reqObj.has_pdestroykeympk() ? (CK_BYTE_PTR)reqObj.pdestroykeympk().data() : NULL;
	CK_ULONG ulMpkLen = reqObj.ulmpklen();
	CK_BYTE_PTR pbMpkIV = reqObj.has_pbmpkiv() ? (CK_BYTE_PTR)reqObj.pbmpkiv().data() : NULL;
	CK_ULONG ulMpkIVLen = reqObj.ulmpkivlen();

	CK_RV ret = Adapter_C_Extend_Set_DestroyKey(hSession, pDestroyKeyMpk, ulMpkLen, pbMpkIV, ulMpkIVLen);
		
	rspObj.SerializeToString(&rspObjString);
	
	return responsePack(ret, rspObjString, dst);
}

int P11FunctionParse::C_Extend_Get_ExchangePubKey(const string src,string &dst)
{
	Req_C_Extend_Get_ExchangePubKey reqObj;
	Rsp_C_Extend_Get_ExchangePubKey rspObj;
	string rspObjString;

	if(FunctionParse::gloMonopolizePackageName != "" && FunctionParse::gloMonopolizePackageName != packageName)
	{
		return responsePack(RETURN_CODE_ERROR_MONOPOLIZE_ALREADY, rspObjString, dst);
	}

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}
	
	CK_SESSION_HANDLE hSession = reqObj.hsession();
	CK_BYTE_PTR       pExchangePubKeyValue = NULL;      /* last c-text */
	CK_ULONG_PTR      pulKeyLen = NULL;  /* gets last size */

	if(reqObj.has_pexchangepubkeyvalue())
	{
		pExchangePubKeyValue = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * reqObj.pexchangepubkeyvalue().size());
	}
	if(reqObj.has_pulkeylen())
	{
		pulKeyLen = (CK_ULONG_PTR)malloc(sizeof(CK_ULONG));
		if(pulKeyLen)
		{
			*pulKeyLen = reqObj.pulkeylen();
		}
	}
	CK_RV ret = Adapter_C_Extend_Get_ExchangePubKey(hSession, pExchangePubKeyValue, pulKeyLen);
	

	if(pulKeyLen)
	{
		rspObj.set_pulkeylen(*pulKeyLen);
	}
	if(pExchangePubKeyValue && pulKeyLen)
	{
		rspObj.set_pexchangepubkeyvalue(pExchangePubKeyValue, *pulKeyLen);
	}

	rspObj.SerializeToString(&rspObjString);


	FREE(pExchangePubKeyValue);
	FREE(pulKeyLen);
	
	
	return responsePack(ret, rspObjString, dst);
}

int P11FunctionParse::softCreateCipherCard(const string src, string &dst) {
    Req_softCreateCipherCard reqObj;
    Rsp_softCreateCipherCard rspObj;
    string rspObjString;
	LOGSERVERI(tag,"%s IN",__FUNCTION__);

    if(true != reqObj.ParseFromString(src))
    {
        return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
    }

    string token = reqObj.token();
    string userName = reqObj.username();
    string licSesrverAddr = reqObj.licsesrveraddr();
    string csppAddr = reqObj.csppaddr();

    CK_RV ret = Adapter_SC_CREATESC(token,userName,licSesrverAddr,csppAddr);

    rspObj.SerializeToString(&rspObjString);

    return responsePack(ret, rspObjString, dst);
}

int P11FunctionParse::DestroyCipherCard(const string src, string &dst) {
	Req_DestroyCipherCard reqObj;
    Rsp_DestroyCipherCard rspObj;
    string rspObjString;

    if(true != reqObj.ParseFromString(src))
    {
        return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
    }

 
    CK_RV ret = Adapter_SC_C_Destroy_Extend();

    rspObj.SerializeToString(&rspObjString);

    return responsePack(ret, rspObjString, dst);

}
