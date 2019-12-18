#include "logserver.h"
#include "ReturnCode.h"
#include "Return.pb.h"
#include "skf.pb.h"
#include "skf.h"
#include "skfFunctionParse.h"
#include "SkfAdapter.h"

#include <iostream>

static const char *tag = "csm_p11server";
using namespace google::protobuf;
using namespace com::westone::skf;
using namespace com::westone::returncode;

#define FREE(tmp) {\
	free(tmp); \
	tmp = NULL; \
}

static FunctionParse *pGlobeSkfFunctionParse = NULL;

static unsigned long int  responsePack(ULONG ret, string rspObjString, string &dst)
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


SkfFunctionParse::SkfFunctionParse()
{
	pGlobeSkfFunctionParse = this;
	mapFuncList["SKF_WaitForDevEvent"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_WaitForDevEvent;
	mapFuncList["SKF_CancelWaitForDevEvent"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_CancelWaitForDevEvent;
	mapFuncList["SKF_EnumDev"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_EnumDev;
	mapFuncList["SKF_ConnectDev"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ConnectDev;
	mapFuncList["SKF_DisConnectDev"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_DisConnectDev;
	mapFuncList["SKF_GetDevState"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_GetDevState;
	mapFuncList["SKF_SetLabel"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_SetLabel;
	mapFuncList["SKF_GetDevInfo"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_GetDevInfo;
	mapFuncList["SKF_LockDev"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_LockDev;
	mapFuncList["SKF_UnlockDev"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_UnlockDev;
	mapFuncList["SKF_ChangeDevAuthKey"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ChangeDevAuthKey;
	mapFuncList["SKF_DevAuth"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_DevAuth;
	mapFuncList["SKF_ChangePIN"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ChangePIN;
	mapFuncList["SKF_GetPINInfo"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_GetPINInfo;
	mapFuncList["SKF_VerifyPIN"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_VerifyPIN;
	mapFuncList["SKF_UnblockPIN"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_UnblockPIN;
	mapFuncList["SKF_ClearSecureState"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ClearSecureState;
	mapFuncList["SKF_CreateApplication"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_CreateApplication;
	mapFuncList["SKF_EnumApplication"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_EnumApplication;
	mapFuncList["SKF_DeleteApplication"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_DeleteApplication;
	mapFuncList["SKF_OpenApplication"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_OpenApplication;
	mapFuncList["SKF_CloseApplication"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_CloseApplication;
	mapFuncList["SKF_CreateFile"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_CreateFile;
	mapFuncList["SKF_DeleteFile"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_DeleteFile;
	mapFuncList["SKF_EnumFiles"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_EnumFiles;
	mapFuncList["SKF_GetFileInfo"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_GetFileInfo;
	mapFuncList["SKF_ReadFile"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ReadFile;
	mapFuncList["SKF_WriteFile"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_WriteFile;
	mapFuncList["SKF_CreateContainer"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_CreateContainer;
	mapFuncList["SKF_DeleteContainer"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_DeleteContainer;
	mapFuncList["SKF_OpenContainer"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_OpenContainer;
	mapFuncList["SKF_CloseContainer"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_CloseContainer;
	mapFuncList["SKF_EnumContainer"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_EnumContainer;
	mapFuncList["SKF_GetContainerType"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_GetContainerType;
	mapFuncList["SKF_GenRandom"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_GenRandom;
	mapFuncList["SKF_GenExtRSAKey"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_GenExtRSAKey;
	mapFuncList["SKF_GenRSAKeyPair"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_GenRSAKeyPair;
	mapFuncList["SKF_ImportRSAKeyPair"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ImportRSAKeyPair;
	mapFuncList["SKF_RSASignData"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_RSASignData;
	mapFuncList["SKF_RSAVerify"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_RSAVerify;
	mapFuncList["SKF_RSAExportSessionKey"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_RSAExportSessionKey;
	mapFuncList["SKF_ExtRSAPubKeyOperation"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ExtRSAPubKeyOperation;
	mapFuncList["SKF_ExtRSAPriKeyOperation"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ExtRSAPriKeyOperation;
	mapFuncList["SKF_GenECCKeyPair"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_GenECCKeyPair;
	mapFuncList["SKF_ImportECCKeyPair"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ImportECCKeyPair;
	mapFuncList["SKF_ECCSignData"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ECCSignData;
	mapFuncList["SKF_ECCVerify"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ECCVerify;
	mapFuncList["SKF_ECCExportSessionKey"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ECCExportSessionKey;
	mapFuncList["SKF_ExtECCEncrypt"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ExtECCEncrypt;
	mapFuncList["SKF_ExtECCDecrypt"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ExtECCDecrypt;
	mapFuncList["SKF_ExtECCSign"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ExtECCSign;
	mapFuncList["SKF_ExtECCVerify"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ExtECCVerify;
	mapFuncList["SKF_GenerateAgreementDataWithECC"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_GenerateAgreementDataWithECC;
	mapFuncList["SKF_GenerateAgreementDataAndKeyWithECC"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_GenerateAgreementDataAndKeyWithECC;
	mapFuncList["SKF_GenerateKeyWithECC"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_GenerateKeyWithECC;
	mapFuncList["SKF_ExportPublicKey"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ExportPublicKey;
	mapFuncList["SKF_ImportSessionKey"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ImportSessionKey;
	mapFuncList["SKF_SetSymmKey"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_SetSymmKey;
	mapFuncList["SKF_EncryptInit"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_EncryptInit;
	mapFuncList["SKF_Encrypt"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_Encrypt;
	mapFuncList["SKF_EncryptUpdate"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_EncryptUpdate;
	mapFuncList["SKF_EncryptFinal"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_EncryptFinal;
	mapFuncList["SKF_DecryptInit"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_DecryptInit;
	mapFuncList["SKF_Decrypt"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_Decrypt;
	mapFuncList["SKF_DecryptUpdate"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_DecryptUpdate;
	mapFuncList["SKF_DecryptFinal"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_DecryptFinal;
	mapFuncList["SKF_DigestInit"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_DigestInit;
	mapFuncList["SKF_Digest"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_Digest;
	mapFuncList["SKF_DigestUpdate"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_DigestUpdate;
	mapFuncList["SKF_DigestFinal"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_DigestFinal;
	mapFuncList["SKF_MacInit"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_MacInit;
	mapFuncList["SKF_Mac"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_Mac;
	mapFuncList["SKF_MacUpdate"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_MacUpdate;
	mapFuncList["SKF_MacFinal"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_MacFinal;
	mapFuncList["SKF_CloseHandle"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_CloseHandle;
	mapFuncList["SKF_Transmit"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_Transmit;
	mapFuncList["SKF_ImportCertificate"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ImportCertificate;
	mapFuncList["SKF_ExportCertificate"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_ExportCertificate;
	mapFuncList["SKF_GetContainerProperty"] = (FunctionParse::funcType)&SkfFunctionParse::SKF_GetContainerProperty;
}

SkfFunctionParse::~SkfFunctionParse(){

}

/*
void SkfFunctionParse::initCard(JavaVM *javaVMIn, jint versionIn, jobject telephonyManager)
{
    Adapter_SKF_Native_Init(javaVMIn, versionIn, telephonyManager);
}
*/

ULONG SkfFunctionParse::SKF_WaitForDevEvent(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_WaitForDevEvent reqObj;
	Rsp_SKF_WaitForDevEvent rspObj;
	string rspObjString;
	LPSTR szNameList = NULL;
	ULONG* pulSize = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	rspObj.SerializeToString(&rspObjString);

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}


ULONG SkfFunctionParse::SKF_CancelWaitForDevEvent(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_CancelWaitForDevEvent reqObj;
	Rsp_SKF_CancelWaitForDevEvent rspObj;
	string rspObjString;
	LPSTR szNameList = NULL;
	ULONG* pulSize = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	rspObj.SerializeToString(&rspObjString);

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}


ULONG SkfFunctionParse::SKF_EnumDev(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_EnumDev reqObj;
	Rsp_SKF_EnumDev rspObj;
    string rspObjString;
	LPSTR szNameList = NULL;
	ULONG* pulSize = NULL;

	if(true != reqObj.ParseFromString(src)) {
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	BOOL present = reqObj.has_bpresent();
	if(!present) {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	present = reqObj.bpresent().boolvalue();

	if(reqObj.has_pulsize()){
		pulSize = (ULONG*)malloc(sizeof(ULONG));
		if(pulSize) {
			*pulSize = reqObj.pulsize().u32value();
		}
		else{
			return responsePack(SAR_FAIL, rspObjString, dst);
		}
	}else{
        return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	// buffer length inconsistent with pulSize
	if(*pulSize != reqObj.sznamelist().size()){
		FREE(pulSize);
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}
	
	if(reqObj.sznamelist().size())
	{
		szNameList = (LPSTR)malloc(sizeof(unsigned char) * reqObj.sznamelist().size());
		if (szNameList) {
			memset(szNameList, 0, reqObj.sznamelist().size());
		}
	}

	ULONG ret = Adapter_SKF_EnumDev(present, szNameList, pulSize);
	

	if(pulSize){
		rspObj.mutable_pulsize()->set_u32value(*pulSize);
	}
	
	if(szNameList && pulSize){
		rspObj.set_sznamelist(szNameList, *pulSize);
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pulSize);
	FREE(szNameList);
	
	return responsePack(ret, rspObjString, dst);

}


ULONG SkfFunctionParse::SKF_ConnectDev(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ConnectDev reqObj;
	Rsp_SKF_ConnectDev rspObj;
	string rspObjString;
	DEVHANDLE * phDev = NULL;
	LPSTR szName = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.szname().size()) {
		szName = (LPSTR)malloc(reqObj.szname().size());
		if (szName) {
			memcpy(szName, reqObj.szname().data(), reqObj.szname().size());
		}
	}
		

	if(reqObj.has_phdev()){
		phDev = (DEVHANDLE*)malloc(sizeof(DEVHANDLE));
		if(phDev){
			*phDev = (DEVHANDLE)reqObj.phdev().u32value();
		}
		else{
			FREE(szName);
			return responsePack(SAR_FAIL, rspObjString, dst);
		}
	}else{
		FREE(szName);
        return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	ULONG ret = Adapter_SKF_ConnectDev(szName, phDev);

	if(phDev){
		rspObj.mutable_phdev()->set_u32value((uint32)(*phDev));
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(phDev);
	FREE(szName);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_DisConnectDev(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_DisConnectDev reqObj;
	Rsp_SKF_DisConnectDev rspObj;
	string rspObjString;
	DEVHANDLE hDev = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	ULONG ret = Adapter_SKF_DisConnectDev(hDev);

	rspObj.SerializeToString(&rspObjString);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_GetDevState(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_GetDevState reqObj;
	Rsp_SKF_GetDevState rspObj;
	string rspObjString;
	ULONG* pulDevState = NULL;
	LPSTR szDevName = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.szdevname().size()) {
		szDevName = (LPSTR)malloc(reqObj.szdevname().size());
		if (szDevName) {
			memcpy(szDevName, reqObj.szdevname().data(), reqObj.szdevname().size());
		}
	}

	if(reqObj.has_puldevstate()){
		pulDevState = (ULONG*)malloc(sizeof(ULONG));
		if(pulDevState){
			*pulDevState = reqObj.puldevstate().u32value();
		}	
	}

	ULONG ret = Adapter_SKF_GetDevState(szDevName, pulDevState);

	if(pulDevState){
		rspObj.mutable_puldevstate()->set_u32value((uint32)(*pulDevState));
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pulDevState);
	FREE(szDevName);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_SetLabel(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_SetLabel reqObj;
	Rsp_SKF_SetLabel rspObj;
	string rspObjString;
	DEVHANDLE hDev = NULL;
	LPSTR szLabel = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.szlabel().size()){
		szLabel = (LPSTR)malloc(sizeof(unsigned char) * reqObj.szlabel().size());
		memcpy(szLabel, reqObj.szlabel().data(), reqObj.szlabel().size());
	}

	ULONG ret = Adapter_SKF_SetLabel(hDev, szLabel);

	rspObj.SerializeToString(&rspObjString);

	FREE(szLabel);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_GetDevInfo(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_GetDevInfo reqObj;
	Rsp_SKF_GetDevInfo rspObj;
	string rspObjString;
	DEVHANDLE hDev = NULL;
	PDEVINFO pDevInfo = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.has_pdevinfo()){
		pDevInfo = (PDEVINFO)malloc(sizeof(DEVINFO));
		if(pDevInfo){
			memset(pDevInfo, 0, sizeof(DEVINFO));
		}
	}

	ULONG ret = Adapter_SKF_GetDevInfo(hDev, pDevInfo);

	if(pDevInfo) {
		rspObj.mutable_pdevinfo()->mutable_version()->mutable_major()->set_u32value((uint32)pDevInfo->Version.major);
		rspObj.mutable_pdevinfo()->mutable_version()->mutable_major()->set_u32value((uint32)pDevInfo->Version.minor);
		rspObj.mutable_pdevinfo()->set_manufacturer(pDevInfo->Manufacturer, 64);
		rspObj.mutable_pdevinfo()->set_issuer(pDevInfo->Issuer, 64);
		rspObj.mutable_pdevinfo()->set_label(pDevInfo->Label, 32);
		rspObj.mutable_pdevinfo()->set_serialnumber(pDevInfo->SerialNumber, 32);
		rspObj.mutable_pdevinfo()->mutable_hwversion()->mutable_major()->set_u32value((uint32)pDevInfo->HWVersion.major);
		rspObj.mutable_pdevinfo()->mutable_hwversion()->mutable_major()->set_u32value((uint32)pDevInfo->HWVersion.minor);
		rspObj.mutable_pdevinfo()->mutable_firmwareversion()->mutable_major()->set_u32value((uint32)pDevInfo->FirmwareVersion.major);
		rspObj.mutable_pdevinfo()->mutable_firmwareversion()->mutable_minor()->set_u32value((uint32)pDevInfo->FirmwareVersion.minor);
		rspObj.mutable_pdevinfo()->mutable_algsymcap()->set_u32value((uint32)pDevInfo->AlgSymCap);
		rspObj.mutable_pdevinfo()->mutable_algasymcap()->set_u32value((uint32)pDevInfo->AlgAsymCap);
		rspObj.mutable_pdevinfo()->mutable_alghashcap()->set_u32value((uint32)pDevInfo->AlgHashCap);
		rspObj.mutable_pdevinfo()->mutable_devauthalgid()->set_u32value((uint32)pDevInfo->DevAuthAlgId);
		rspObj.mutable_pdevinfo()->mutable_totalspace()->set_u32value((uint32)pDevInfo->TotalSpace);
		rspObj.mutable_pdevinfo()->mutable_freespace()->set_u32value((uint32)pDevInfo->FreeSpace);
		rspObj.mutable_pdevinfo()->mutable_maxeccbuffersize()->set_u32value((uint32)pDevInfo->MaxECCBufferSize);
		rspObj.mutable_pdevinfo()->mutable_maxbuffersize()->set_u32value((uint32)pDevInfo->MaxBufferSize);
		rspObj.mutable_pdevinfo()->set_reserved(pDevInfo->Reserved, 64);
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pDevInfo);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_LockDev(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_LockDev reqObj;
	Rsp_SKF_LockDev rspObj;
	string rspObjString;
	DEVHANDLE hDev = NULL;
	ULONG ulTimeOut = 0;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.has_ultimeout()){
		ulTimeOut = (ULONG)reqObj.ultimeout().u32value();
	}

	ULONG ret = Adapter_SKF_LockDev(hDev, ulTimeOut);

	rspObj.SerializeToString(&rspObjString);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_UnlockDev(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_UnlockDev reqObj;
	Rsp_SKF_UnlockDev rspObj;
	string rspObjString;
	DEVHANDLE hDev = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	ULONG ret = Adapter_SKF_UnlockDev(hDev);

	rspObj.SerializeToString(&rspObjString);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ChangeDevAuthKey(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ChangeDevAuthKey reqObj;
	Rsp_SKF_ChangeDevAuthKey rspObj;
	string rspObjString;
	DEVHANDLE	hDev = NULL;
	BYTE		*pbKeyValue = NULL;
	ULONG		ulKeyLen = 0;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.has_ulkeylen()){
		ulKeyLen = (ULONG)reqObj.ulkeylen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbkeyvalue().size()){
		pbKeyValue = (BYTE*)malloc(sizeof(char) * reqObj.pbkeyvalue().size());
		if(pbKeyValue){
			memcpy(pbKeyValue, reqObj.pbkeyvalue().data(), reqObj.pbkeyvalue().size());
		}
	}

	ULONG ret = Adapter_SKF_ChangeDevAuthKey(hDev, pbKeyValue, ulKeyLen);

	rspObj.SerializeToString(&rspObjString);

	FREE(pbKeyValue);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_DevAuth(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_DevAuth reqObj;
	Rsp_SKF_DevAuth rspObj;
	string rspObjString;
	DEVHANDLE	hDev = NULL;
	BYTE*		pbAuthData = NULL;
	ULONG		ulLen = 0;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.has_ullen()){
		ulLen = (ULONG)reqObj.ullen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbauthdata().size()){
		pbAuthData = (BYTE*)malloc(sizeof(char) * reqObj.pbauthdata().size());
		if(pbAuthData){
			memcpy(pbAuthData, reqObj.pbauthdata().data(), reqObj.pbauthdata().size());
		}
		else{
			return responsePack(SAR_FAIL, rspObjString, dst);
		}
	}else{
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	ULONG ret = Adapter_SKF_DevAuth(hDev, pbAuthData, ulLen);

	rspObj.SerializeToString(&rspObjString);

	FREE(pbAuthData);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ChangePIN(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ChangePIN reqObj;
	Rsp_SKF_ChangePIN rspObj;
	string rspObjString;
	HAPPLICATION hApplication = NULL;
	ULONG ulPINType = 0;
	LPSTR szOldPIN = NULL;
	LPSTR szNewPIN = NULL;
	ULONG * pulRetryCount = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	if(reqObj.has_ulpintype()){
		ulPINType = (ULONG)reqObj.ulpintype().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.szoldpin().size()){
		szOldPIN = (LPSTR)malloc(sizeof(char) * reqObj.szoldpin().size());
		if(szOldPIN){
			memcpy(szOldPIN, reqObj.szoldpin().data(), reqObj.szoldpin().size());
		}
	}

	if(reqObj.sznewpin().size())
	{
		LOGSERVERE(tag, "%s sznewpin().size():%d ", __FUNCTION__, reqObj.sznewpin().size());
		szNewPIN = (LPSTR)malloc(sizeof(char) * reqObj.sznewpin().size());
		if(szNewPIN){
			memcpy(szNewPIN, reqObj.sznewpin().data(), reqObj.sznewpin().size());
		}
	}

	if(reqObj.has_pulretrycount())
	{
		pulRetryCount = (ULONG *)malloc(sizeof(ULONG));
		if(pulRetryCount){
			*pulRetryCount = 0;
		}
	}

	ULONG ret = Adapter_SKF_ChangePIN(hApplication, ulPINType, szOldPIN, szNewPIN, pulRetryCount);

	if(pulRetryCount){
		rspObj.mutable_pulretrycount()->set_u32value((uint32)(*pulRetryCount));
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(szOldPIN);
	FREE(szNewPIN);
	FREE(pulRetryCount);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_GetPINInfo(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_GetPINInfo reqObj;
	Rsp_SKF_GetPINInfo rspObj;
	string rspObjString;
	HAPPLICATION hApplication = NULL;
	ULONG ulPINType = 0;
	ULONG * pulMaxRetryCount = NULL;
	ULONG * pulRemainRetryCount = NULL;
	BOOL * pbDefaultPin = NULL;
	
	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	if(reqObj.has_ulpintype()){
		ulPINType = (ULONG)reqObj.ulpintype().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}
	
	if(reqObj.has_pulmaxretrycount())
	{
		pulMaxRetryCount = (ULONG *)malloc(sizeof(ULONG));
		if(pulMaxRetryCount){
			*pulMaxRetryCount = (ULONG)reqObj.pulmaxretrycount().u32value();
		}
	}

	if(reqObj.has_pulremainretrycount())
	{
		pulRemainRetryCount = (ULONG *)malloc(sizeof(ULONG));
		if(pulRemainRetryCount){
			*pulRemainRetryCount = 0;
		}
	}

	if(reqObj.has_pbdefaultpin())
	{
		pbDefaultPin = (BOOL *)malloc(sizeof(BOOL));
		if(pbDefaultPin){
			*pbDefaultPin = false;
		}
	}

	ULONG ret = Adapter_SKF_GetPINInfo(hApplication, ulPINType, pulMaxRetryCount, pulRemainRetryCount, pbDefaultPin);

	if(pulMaxRetryCount){
		rspObj.mutable_pulmaxretrycount()->set_u32value((uint32)(*pulMaxRetryCount));
	}

	if(pulRemainRetryCount){
		rspObj.mutable_pulremainretrycount()->set_u32value((uint32)(*pulRemainRetryCount));
	}

	if(pbDefaultPin){
		rspObj.mutable_pbdefaultpin()->set_boolvalue((bool)(*pbDefaultPin));
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pulMaxRetryCount);
	FREE(pulRemainRetryCount);
	FREE(pbDefaultPin);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_VerifyPIN(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_VerifyPIN reqObj;
	Rsp_SKF_VerifyPIN rspObj;
	string rspObjString;
	HAPPLICATION hApplication = NULL;
	ULONG ulPINType = 0;
	LPSTR szPIN = NULL;
	ULONG * pulRetryCount = NULL;


	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	if(reqObj.has_ulpintype()){
		ulPINType = (ULONG)reqObj.ulpintype().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}
	
	if(reqObj.szpin().size())
	{
		szPIN = (LPSTR)malloc(sizeof(char *) * reqObj.szpin().size());
		if(szPIN){
			memcpy(szPIN, reqObj.szpin().data(), reqObj.szpin().size());
		}
	}

	if(reqObj.has_pulretrycount())
	{
		pulRetryCount = (ULONG *)malloc(sizeof(ULONG));
		if(pulRetryCount){
			*pulRetryCount = (ULONG)reqObj.pulretrycount().u32value();
		}
	}

	ULONG ret = Adapter_SKF_VerifyPIN(hApplication, ulPINType, szPIN, pulRetryCount);

	if(pulRetryCount){
		rspObj.mutable_pulretrycount()->set_u32value((uint32)(*pulRetryCount));
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(szPIN);
	FREE(pulRetryCount);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_UnblockPIN(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_UnblockPIN reqObj;
	Rsp_SKF_UnblockPIN rspObj;
	string rspObjString;
	HAPPLICATION hApplication = NULL;
	LPSTR szAdminPIN = NULL;
	LPSTR szNewUserPIN = NULL;
	ULONG * pulRetryCount = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	if(reqObj.szadminpin().size()){
		szAdminPIN = (LPSTR)malloc(sizeof(char *) * reqObj.szadminpin().size());
		if(szAdminPIN){
			memcpy(szAdminPIN, reqObj.szadminpin().data(), reqObj.szadminpin().size());
		}
	}

	if(reqObj.sznewuserpin().size()){
		szNewUserPIN = (LPSTR)malloc(sizeof(char *) * reqObj.sznewuserpin().size());
		if(szNewUserPIN){
			memcpy(szNewUserPIN, reqObj.sznewuserpin().data(), reqObj.sznewuserpin().size());
		}
	}

	if(reqObj.has_pulretrycount()){
		pulRetryCount = (ULONG *)malloc(sizeof(ULONG));
		if(pulRetryCount){
			*pulRetryCount = (ULONG)reqObj.pulretrycount().u32value();
		}
	}

	ULONG ret = Adapter_SKF_UnblockPIN(hApplication, szAdminPIN, szNewUserPIN, pulRetryCount);

	if(pulRetryCount){
		rspObj.mutable_pulretrycount()->set_u32value((uint32)(*pulRetryCount));
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(szAdminPIN);
	FREE(szNewUserPIN);
	FREE(pulRetryCount);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ClearSecureState(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ClearSecureState reqObj;
	Rsp_SKF_ClearSecureState rspObj;
	string rspObjString;
	HAPPLICATION hApplication = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	ULONG ret = Adapter_SKF_ClearSecureState(hApplication);

	rspObj.SerializeToString(&rspObjString);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_CreateApplication(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_CreateApplication reqObj;
	Rsp_SKF_CreateApplication rspObj;
	string rspObjString;
	DEVHANDLE hDev = NULL;
	LPSTR szAppName = NULL;
	LPSTR szAdminPIN = NULL;
	DWORD dwAdminPinRetryCount = 0;
	LPSTR szUserPIN = NULL;
	DWORD dwUserPinRetryCount = 0;
	DWORD dwCreateFileRights = 0;
	HAPPLICATION* phApplication = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.has_dwadminpinretrycount()){
		dwAdminPinRetryCount = (DWORD)reqObj.dwadminpinretrycount().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_dwuserpinretrycount()){
		dwUserPinRetryCount = (DWORD)reqObj.dwuserpinretrycount().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_dwcreatefilerights()){
		dwCreateFileRights = (DWORD)reqObj.dwcreatefilerights().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_phapplication()){
		phApplication = (HAPPLICATION *)malloc(sizeof(HAPPLICATION));
		if(phApplication){
			*phApplication = (HAPPLICATION)reqObj.phapplication().u32value();
		}
	}

	if(reqObj.szappname().size()){
		szAppName = (LPSTR)malloc(sizeof(char) * reqObj.szappname().size());
		if(szAppName){
			memcpy(szAppName, reqObj.szappname().data(), reqObj.szappname().size());
		}
	}

	if(reqObj.szadminpin().size()){
		szAdminPIN = (LPSTR)malloc(sizeof(char) * reqObj.szadminpin().size());
		if(szAdminPIN){
			memcpy(szAdminPIN, reqObj.szadminpin().data(), reqObj.szadminpin().size());
		}
	}

	if(reqObj.szuserpin().size()){
		szUserPIN = (LPSTR)malloc(sizeof(char) * reqObj.szuserpin().size());
		if(szUserPIN){
			memcpy(szUserPIN, reqObj.szuserpin().data(), reqObj.szuserpin().size());
		}
	}

	ULONG ret = Adapter_SKF_CreateApplication(hDev, szAppName, szAdminPIN, dwAdminPinRetryCount, szUserPIN, dwUserPinRetryCount, dwCreateFileRights, phApplication);

	if(phApplication){
		rspObj.mutable_phapplication()->set_u32value((uint32)(*phApplication));
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(phApplication);
	FREE(szAdminPIN);
	FREE(szAppName);
	FREE(szUserPIN);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_EnumApplication(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_EnumApplication reqObj;
	Rsp_SKF_EnumApplication rspObj;
	string rspObjString;
	DEVHANDLE hDev = NULL;
	LPSTR szAppName = NULL;
	ULONG * pulSize = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev())
	{
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.szappname().size())
	{
		szAppName = (LPSTR)malloc(sizeof(char) * reqObj.szappname().size());
		if(szAppName){
			memcpy(szAppName, reqObj.szappname().data(), reqObj.szappname().size());
		}
	}

	if(reqObj.has_pulsize())
	{
		pulSize = (ULONG *)malloc(sizeof(ULONG));
		if(pulSize){
			*pulSize = (ULONG)reqObj.pulsize().u32value();
		}
	}

	ULONG ret = Adapter_SKF_EnumApplication(hDev, szAppName, pulSize);

	if((szAppName)&&pulSize){
		rspObj.set_szappname(szAppName, *pulSize);
	}

	if(pulSize){
		rspObj.mutable_pulsize()->set_u32value((uint32)(*pulSize));
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(szAppName);
	FREE(pulSize);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_DeleteApplication(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_DeleteApplication reqObj;
	Rsp_SKF_DeleteApplication rspObj;
	string rspObjString;
	DEVHANDLE hDev = NULL;
	LPSTR szAppName = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.szappname().size()){
		szAppName = (LPSTR)malloc(sizeof(char) * reqObj.szappname().size());
		if(szAppName){
			memcpy(szAppName, reqObj.szappname().data(), reqObj.szappname().size());
		}
	}

	ULONG ret = Adapter_SKF_DeleteApplication(hDev, szAppName);
	rspObj.SerializeToString(&rspObjString);

	FREE(szAppName);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_OpenApplication(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_OpenApplication reqObj;
	Rsp_SKF_OpenApplication rspObj;
	string rspObjString;
	DEVHANDLE hDev = NULL;
	LPSTR szAppName = NULL;
	HAPPLICATION* phApplication = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}


	if(reqObj.szappname().size()){
		szAppName = (LPSTR)malloc(sizeof(char) * reqObj.szappname().size());
		if(szAppName){
			memcpy(szAppName, reqObj.szappname().data(), reqObj.szappname().size());
		}
	}

	if(reqObj.has_phapplication())
	{
		phApplication = (HAPPLICATION *)malloc(sizeof(HAPPLICATION));
		if(phApplication){
			*phApplication = (HAPPLICATION)reqObj.phapplication().u32value();
		}
	}

	ULONG ret = Adapter_SKF_OpenApplication(hDev, szAppName, phApplication);

	if(phApplication){
		rspObj.mutable_phapplication()->set_u32value((uint32)(*phApplication));
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(szAppName);
	FREE(phApplication);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_CloseApplication(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_CloseApplication reqObj;
	Rsp_SKF_CloseApplication rspObj;
	string rspObjString;
	HAPPLICATION hApplication = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	ULONG ret = Adapter_SKF_CloseApplication(hApplication);

	rspObj.SerializeToString(&rspObjString);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_CreateFile(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_CreateFile reqObj;
	Rsp_SKF_CreateFile rspObj;
	string rspObjString;
	HAPPLICATION	hApplication = NULL;
	LPSTR			szFileName = NULL;
	ULONG			ulFileSize = 0;
	ULONG			ulReadRights = 0;
	ULONG			ulWriteRights = 0;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ulfilesize()){
		ulFileSize = (ULONG)reqObj.ulfilesize().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ulreadrights()){
		ulReadRights = (ULONG)reqObj.ulreadrights().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ulwriterights()){
		ulWriteRights = (ULONG)reqObj.ulwriterights().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.szfilename().size())
	{
		szFileName = (LPSTR)malloc(reqObj.szfilename().size());
		if(szFileName){
			memcpy(szFileName, reqObj.szfilename().data(), reqObj.szfilename().size());
		}
	}

	ULONG ret = Adapter_SKF_CreateFile(hApplication, szFileName, ulFileSize, ulReadRights, ulWriteRights);

	rspObj.SerializeToString(&rspObjString);

	FREE(szFileName);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_DeleteFile(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_DeleteFile reqObj;
	Rsp_SKF_DeleteFile rspObj;
	string rspObjString;
	HAPPLICATION	hApplication = NULL;
	LPSTR			szFileName = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	if(reqObj.szfilename().size()){
		szFileName = (LPSTR)malloc(reqObj.szfilename().size());
		if(szFileName){
			memcpy(szFileName, reqObj.szfilename().data(), reqObj.szfilename().size());
		}
	}

	ULONG ret = Adapter_SKF_DeleteFile(hApplication, szFileName);

	rspObj.SerializeToString(&rspObjString);

	FREE(szFileName);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_EnumFiles(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_EnumFiles reqObj;
	Rsp_SKF_EnumFiles rspObj;
	string rspObjString;
	HAPPLICATION	hApplication = NULL;
	LPSTR			szFileName = NULL;
	ULONG*			pulSize = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	if(reqObj.szfilename().size()){
		szFileName = (LPSTR)malloc(reqObj.szfilename().size());
		if(szFileName){
			memcpy(szFileName, reqObj.szfilename().data(), reqObj.szfilename().size());
		}
	}

	if(reqObj.has_pulsize())
	{
		pulSize = (ULONG*)malloc(sizeof(ULONG));
		if(pulSize){
			*pulSize = reqObj.pulsize().u32value();
		}
	}

	ULONG ret = Adapter_SKF_EnumFiles(hApplication, szFileName, pulSize);

	if((szFileName) && (pulSize)){
		rspObj.set_szfilename(szFileName, *pulSize);
	}

	if(pulSize){
		rspObj.mutable_pulsize()->set_u32value((uint32)(*pulSize));
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(szFileName);
	FREE(pulSize);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_GetFileInfo(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_GetFileInfo reqObj;
	Rsp_SKF_GetFileInfo rspObj;
	string rspObjString;
	HAPPLICATION	hApplication = NULL;
	LPSTR			szFileName = NULL;
	FILEATTRIBUTE*	pFileInfo = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	if(reqObj.szfilename().size()){
		szFileName = (LPSTR)malloc(reqObj.szfilename().size());
		if(szFileName){
			memcpy(szFileName, reqObj.szfilename().data(), reqObj.szfilename().size());
		}
	}

	if(reqObj.has_pfileinfo()){
		pFileInfo = (FILEATTRIBUTE*)malloc(sizeof(FILEATTRIBUTE));
		if(pFileInfo){
			memset((void *)pFileInfo, 0, sizeof(FILEATTRIBUTE));
		
}
	}

	ULONG ret = Adapter_SKF_GetFileInfo(hApplication, szFileName, pFileInfo);

	if(pFileInfo) {
		rspObj.mutable_pfileinfo()->set_filename(pFileInfo->FileName, 32);
		rspObj.mutable_pfileinfo()->mutable_filesize()->set_u32value((uint32)pFileInfo->FileSize);
		rspObj.mutable_pfileinfo()->mutable_readrights()->set_u32value((uint32)pFileInfo->ReadRights);
		rspObj.mutable_pfileinfo()->mutable_writerights()->set_u32value((uint32)pFileInfo->WriteRights);
	}
	rspObj.SerializeToString(&rspObjString);

	FREE(szFileName);
	FREE(pFileInfo);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ReadFile(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ReadFile reqObj;
	Rsp_SKF_ReadFile rspObj;
	string rspObjString;
	HAPPLICATION	hApplication = NULL;
	LPSTR			szFileName = NULL;
	ULONG			ulOffset = 0;
	ULONG			ulSize = 0;
	BYTE*			pbOutData = 0;
	ULONG*			pulOutLen = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	if(reqObj.has_uloffset()){
		ulOffset = (ULONG)reqObj.uloffset().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ulsize()){
		ulSize = (ULONG)reqObj.ulsize().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.szfilename().size()){
		szFileName = (LPSTR)malloc(reqObj.szfilename().size());
		if(szFileName){
			memcpy(szFileName, reqObj.szfilename().data(), reqObj.szfilename().size());
		}
	}

	if(reqObj.pboutdata().size()){
		pbOutData = (BYTE*)malloc(reqObj.pboutdata().size());
		if(pbOutData){
			memset(pbOutData, 0, reqObj.pboutdata().size());
		}
	}

	if(reqObj.has_puloutlen())
	{
		pulOutLen = (ULONG*)malloc(sizeof(ULONG));
		if(pulOutLen){
			*pulOutLen = reqObj.puloutlen().u32value();
		}
		else{
			return responsePack(SAR_FAIL, rspObjString, dst);
		}
	}
	else {
		FREE(szFileName);
		FREE(pbOutData);
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	ULONG ret = Adapter_SKF_ReadFile(hApplication, szFileName, ulOffset, ulSize, pbOutData, pulOutLen);

	if(pbOutData) {
		rspObj.set_pboutdata(pbOutData, *pulOutLen);
	}

	if(pulOutLen){
		rspObj.mutable_puloutlen()->set_u32value((uint32)(*pulOutLen));
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(szFileName);
	FREE(pbOutData);
	FREE(pulOutLen);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_WriteFile(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_WriteFile reqObj;
	Rsp_SKF_WriteFile rspObj;
	string rspObjString;
	HAPPLICATION	hApplication = NULL;
	LPSTR			szFileName = NULL;
	ULONG			ulOffset = 0;
	BYTE*			pbData = NULL;
	ULONG			ulSize = 0;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	if(reqObj.has_uloffset()){
		ulOffset = (ULONG)reqObj.uloffset().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ulsize()){
		ulSize = (ULONG)reqObj.ulsize().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.szfilename().size())
	{
		szFileName = (LPSTR)malloc(reqObj.szfilename().size());
		if(szFileName){
			memcpy(szFileName, reqObj.szfilename().data(), reqObj.szfilename().size());
		}
	}

	if(reqObj.pbdata().size())
	{
		pbData = (BYTE*)malloc(reqObj.pbdata().size());
		if(pbData){
			memcpy(pbData, reqObj.pbdata().data(), reqObj.pbdata().size());
		}
	}

	ULONG ret = Adapter_SKF_WriteFile(hApplication, szFileName, ulOffset, pbData, ulSize);

	rspObj.SerializeToString(&rspObjString);

	FREE(szFileName);
	FREE(pbData);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_CreateContainer(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_CreateContainer reqObj;
	Rsp_SKF_CreateContainer rspObj;
	string rspObjString;
	HAPPLICATION	hApplication = NULL;
	LPSTR			szContainerName = NULL;
	HCONTAINER*		phContainer = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	if(reqObj.szcontainername().size()){
		szContainerName = (LPSTR)malloc(reqObj.szcontainername().size());
		if(szContainerName){
			memcpy(szContainerName, reqObj.szcontainername().data(), reqObj.szcontainername().size());
		}
	}

	if(reqObj.has_phcontainer()){
		phContainer = (HCONTAINER*)malloc(sizeof(HCONTAINER));
		if(phContainer){
			*phContainer = (HAPPLICATION)reqObj.phcontainer().u32value();
		}
	}

	ULONG ret = Adapter_SKF_CreateContainer(hApplication, szContainerName, phContainer);

	if(phContainer){
		rspObj.mutable_phcontainer()->set_u32value((uint32)(*phContainer));
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(szContainerName);
	FREE(phContainer);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_DeleteContainer(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_DeleteContainer reqObj;
	Rsp_SKF_DeleteContainer rspObj;
	string rspObjString;
	HAPPLICATION	hApplication = NULL;
	LPSTR			szContainerName = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	if(reqObj.szcontainername().size()){
		szContainerName = (LPSTR)malloc(reqObj.szcontainername().size());
		if(szContainerName){
			memcpy(szContainerName, reqObj.szcontainername().data(), reqObj.szcontainername().size());
		}
	}

	ULONG ret = Adapter_SKF_DeleteContainer(hApplication, szContainerName);

	rspObj.SerializeToString(&rspObjString);

	FREE(szContainerName);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_OpenContainer(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_OpenContainer reqObj;
	Rsp_SKF_OpenContainer rspObj;
	string rspObjString;
	HAPPLICATION	hApplication = NULL;
	LPSTR			szContainerName = NULL;
	HCONTAINER*		phContainer = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}

	if(reqObj.szcontainername().size()){
		szContainerName = (LPSTR)malloc(reqObj.szcontainername().size());
		if(szContainerName){
			memcpy(szContainerName, reqObj.szcontainername().data(), reqObj.szcontainername().size());
		}
	}

	if(reqObj.has_phcontainer()){
		phContainer = (HCONTAINER*)malloc(sizeof(HCONTAINER));
		if(phContainer){
			*phContainer = (HAPPLICATION)reqObj.phcontainer().u32value();
		}
	}

	ULONG ret = Adapter_SKF_OpenContainer(hApplication, szContainerName, phContainer);

	if(phContainer){
		rspObj.mutable_phcontainer()->set_u32value((uint32)(*phContainer));
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(szContainerName);
	FREE(phContainer);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_CloseContainer(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_CloseContainer reqObj;
	Rsp_SKF_CloseContainer rspObj;
	string rspObjString;
	HCONTAINER	hContainer = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hcontainer()){
		hContainer = (HCONTAINER)reqObj.hcontainer().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	ULONG ret = Adapter_SKF_CloseContainer(hContainer);

	rspObj.SerializeToString(&rspObjString);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_EnumContainer(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_EnumContainer reqObj;
	Rsp_SKF_EnumContainer rspObj;
	string rspObjString;
	HAPPLICATION	hApplication = NULL;
	LPSTR 			szContainerName = NULL;
	ULONG* 			pulSize = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_happlication()){
		hApplication = (HAPPLICATION)reqObj.happlication().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.szcontainername().size()){
		szContainerName = (LPSTR)malloc(sizeof(char) * reqObj.szcontainername().size());
		if(szContainerName){
			memcpy(szContainerName, reqObj.szcontainername().data(), reqObj.szcontainername().size());
		}
	}

	if(reqObj.has_pulsize()){
		pulSize = (ULONG *)malloc(sizeof(ULONG));
		if(pulSize){
			*pulSize = (ULONG)reqObj.pulsize().u32value();
		}
	}

	ULONG ret = Adapter_SKF_EnumContainer(hApplication, szContainerName, pulSize);

	if(pulSize){
		rspObj.mutable_pulsize()->set_u32value((uint32)(*pulSize));

		if (szContainerName){
			rspObj.set_szcontainername(szContainerName, *pulSize);
		}
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(szContainerName);
	FREE(pulSize);

	return responsePack(ret, rspObjString, dst);

	
}



ULONG SkfFunctionParse::SKF_GetContainerType(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_GetContainerType reqObj;
	Rsp_SKF_GetContainerType rspObj;
	string rspObjString;
	HCONTAINER	hContainer = NULL;
	ULONG* 		pulContainerType = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hcontainer()){
		hContainer = (HCONTAINER)reqObj.hcontainer().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_pulcontainertype()){
		pulContainerType = (ULONG*)malloc(sizeof(ULONG));
		if(pulContainerType) {
			*pulContainerType = (ULONG)reqObj.pulcontainertype().u32value();
		}
	}

	ULONG ret = Adapter_SKF_GetContainerType(hContainer, pulContainerType);

	if(pulContainerType){
		rspObj.mutable_pulcontainertype()->set_u32value((uint32)(*pulContainerType));
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pulContainerType);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_GenRandom(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_GenRandom reqObj;
	Rsp_SKF_GenRandom rspObj;
	string rspObjString;
	DEVHANDLE hDev = NULL;
	BYTE *pbRandom = NULL;
	ULONG ulRandomLen = 0;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ulrandomlen()){
		ulRandomLen = (ULONG)reqObj.ulrandomlen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbrandom().size()){
		pbRandom = (BYTE *)malloc(sizeof(char) * reqObj.pbrandom().size());
		if(pbRandom) {
			memset(pbRandom, 0, reqObj.pbrandom().size());
		}
	}

	ULONG ret = Adapter_SKF_GenRandom(hDev, pbRandom, ulRandomLen);

	if(pbRandom && ulRandomLen){
		rspObj.set_pbrandom(pbRandom, ulRandomLen);
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pbRandom);

	return responsePack(ret, rspObjString, dst);

	
}



ULONG SkfFunctionParse::SKF_GenExtRSAKey(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_GenExtRSAKey reqObj;
	Rsp_SKF_GenExtRSAKey rspObj;
	string rspObjString;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_GenRSAKeyPair(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_GenRSAKeyPair reqObj;
	Rsp_SKF_GenRSAKeyPair rspObj;
	string rspObjString;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ImportRSAKeyPair(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ImportRSAKeyPair reqObj;
	Rsp_SKF_ImportRSAKeyPair rspObj;
	string rspObjString;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_RSASignData(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_RSASignData reqObj;
	Rsp_SKF_RSASignData rspObj;
	string rspObjString;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_RSAVerify(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_RSAVerify reqObj;
	Rsp_SKF_RSAVerify rspObj;
	string rspObjString;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_RSAExportSessionKey(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_RSAExportSessionKey reqObj;
	Rsp_SKF_RSAExportSessionKey rspObj;
	string rspObjString;
	LPSTR szNameList = NULL;
	ULONG* pulSize = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ExtRSAPubKeyOperation(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ExtRSAPubKeyOperation reqObj;
	Rsp_SKF_ExtRSAPubKeyOperation rspObj;
	string rspObjString;
	LPSTR szNameList = NULL;
	ULONG* pulSize = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ExtRSAPriKeyOperation(const string src,string &dst)
{
	setCallerName(packageName);
    Req_SKF_ExtRSAPriKeyOperation reqObj;
	Rsp_SKF_ExtRSAPriKeyOperation rspObj;
	string rspObjString;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_GenECCKeyPair(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_GenECCKeyPair reqObj;
	Rsp_SKF_GenECCKeyPair rspObj;
	string rspObjString;
	HCONTAINER hContainer = NULL;
	ULONG ulAlgId = 0;
	ECCPUBLICKEYBLOB *pBlob = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hcontainer()){
		hContainer = (HCONTAINER)reqObj.hcontainer().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ulalgid()){
		ulAlgId = (ULONG)reqObj.ulalgid().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_pblob()){
		pBlob = (ECCPUBLICKEYBLOB*)malloc(sizeof(ECCPUBLICKEYBLOB));
		if(pBlob){
			memset((void *)pBlob, 0, sizeof(ECCPUBLICKEYBLOB));
		}
	}

	ULONG ret = Adapter_SKF_GenECCKeyPair(hContainer, ulAlgId, pBlob);

	if(pBlob){
		rspObj.mutable_pblob()->mutable_bitlen()->set_u32value((uint32)(pBlob->BitLen));
		rspObj.mutable_pblob()->set_xcoordinate(pBlob->XCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
		rspObj.mutable_pblob()->set_ycoordinate(pBlob->YCoordinate, ECC_MAX_YCOORDINATE_BITS_LEN/8);
	}
	
	rspObj.SerializeToString(&rspObjString);

	FREE(pBlob);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ImportECCKeyPair(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ImportECCKeyPair reqObj;
	Rsp_SKF_ImportECCKeyPair rspObj;
	string rspObjString;
	HCONTAINER hContainer = NULL;
	PENVELOPEDKEYBLOB pEnvelopedKeyBlob = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hcontainer()){
		hContainer = (HCONTAINER)reqObj.hcontainer().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_penvelopedkeyblob()){
		//if(reqObj.pbenvelopedkeyblob().has_ecccipherblob()&&reqObj.pbenvelopedkeyblob().ecccipherblob().has_cipherlen()) {
		// request memory size as reqObj.pbenvelopedkeyblob().ecccipherblob().cipher().size(), but not CipherLen as they may be inconsistent
		if(reqObj.penvelopedkeyblob().has_ecccipherblob()) {
			pEnvelopedKeyBlob = (PENVELOPEDKEYBLOB)malloc(sizeof(ENVELOPEDKEYBLOB) + reqObj.penvelopedkeyblob().ecccipherblob().cipher().size());
		}
		
		if(pEnvelopedKeyBlob){
			// clean/initialize memory as some fields of the input obj could have no value
			memset((void*)pEnvelopedKeyBlob, 0, (sizeof(ENVELOPEDKEYBLOB) + reqObj.penvelopedkeyblob().ecccipherblob().cipher().size()));
			
			if(reqObj.penvelopedkeyblob().has_version()) {
				pEnvelopedKeyBlob->Version = reqObj.penvelopedkeyblob().version().u32value();
			}
			if(reqObj.penvelopedkeyblob().has_ulsymmalgid()) {
				pEnvelopedKeyBlob->ulSymmAlgID = reqObj.penvelopedkeyblob().ulsymmalgid().u32value();
			}
			if(reqObj.penvelopedkeyblob().has_ulbits()) {
				pEnvelopedKeyBlob->ulBits = reqObj.penvelopedkeyblob().ulbits().u32value();
			}
			memcpy((void *)pEnvelopedKeyBlob->cbEncryptedPriKey, reqObj.penvelopedkeyblob().cbencryptedprikey().data(), reqObj.penvelopedkeyblob().cbencryptedprikey().size());
			if(reqObj.penvelopedkeyblob().has_pubkey()) {
				if(reqObj.penvelopedkeyblob().pubkey().has_bitlen()) {
					pEnvelopedKeyBlob->PubKey.BitLen = reqObj.penvelopedkeyblob().pubkey().bitlen().u32value();
				}
				memcpy(pEnvelopedKeyBlob->PubKey.XCoordinate, reqObj.penvelopedkeyblob().pubkey().xcoordinate().data(), reqObj.penvelopedkeyblob().pubkey().xcoordinate().size());
				memcpy(pEnvelopedKeyBlob->PubKey.YCoordinate, reqObj.penvelopedkeyblob().pubkey().ycoordinate().data(), reqObj.penvelopedkeyblob().pubkey().ycoordinate().size());
			}
			if(reqObj.penvelopedkeyblob().has_ecccipherblob()) {
				memcpy(pEnvelopedKeyBlob->ECCCipherBlob.XCoordinate, reqObj.penvelopedkeyblob().ecccipherblob().xcoordinate().data(), reqObj.penvelopedkeyblob().ecccipherblob().xcoordinate().size());
				memcpy(pEnvelopedKeyBlob->ECCCipherBlob.YCoordinate, reqObj.penvelopedkeyblob().ecccipherblob().ycoordinate().data(), reqObj.penvelopedkeyblob().ecccipherblob().ycoordinate().size());
				memcpy(pEnvelopedKeyBlob->ECCCipherBlob.HASH, reqObj.penvelopedkeyblob().ecccipherblob().hash().data(), reqObj.penvelopedkeyblob().ecccipherblob().hash().size());
				if(reqObj.penvelopedkeyblob().ecccipherblob().has_cipherlen()) {
					pEnvelopedKeyBlob->ECCCipherBlob.CipherLen = reqObj.penvelopedkeyblob().ecccipherblob().cipherlen().u32value();
				}
				memcpy(pEnvelopedKeyBlob->ECCCipherBlob.Cipher, reqObj.penvelopedkeyblob().ecccipherblob().cipher().data(), reqObj.penvelopedkeyblob().ecccipherblob().cipher().size());
			}
		}
	}

	ULONG ret = Adapter_SKF_ImportECCKeyPair(hContainer, pEnvelopedKeyBlob);

	rspObj.SerializeToString(&rspObjString);

	FREE(pEnvelopedKeyBlob);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ECCSignData(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ECCSignData reqObj;
	Rsp_SKF_ECCSignData rspObj;
	string rspObjString;
	HCONTAINER hContainer = NULL;
	BYTE *pbData = NULL;
	ULONG ulDataLen = 0;
	PECCSIGNATUREBLOB pSignature = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hcontainer()){
		hContainer = (HCONTAINER)reqObj.hcontainer().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_uldatalen()){
		ulDataLen = (ULONG)reqObj.uldatalen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbdata().size()){
		pbData = (BYTE *)malloc(reqObj.pbdata().size());
		if(pbData){
			memcpy((void *)pbData, reqObj.pbdata().data(), reqObj.pbdata().size());
		}
	}

	if(reqObj.has_psignature()){
		pSignature = (PECCSIGNATUREBLOB)malloc(sizeof(ECCSIGNATUREBLOB));
		if(pSignature){
			memset((void*)pSignature, 0, sizeof(ECCSIGNATUREBLOB));
		}
	}

	ULONG ret = Adapter_SKF_ECCSignData(hContainer, pbData, ulDataLen, pSignature);

	if(pSignature){
		rspObj.mutable_psignature()->set_r(pSignature->r, ECC_MAX_XCOORDINATE_BITS_LEN/8);
		rspObj.mutable_psignature()->set_s(pSignature->s, ECC_MAX_YCOORDINATE_BITS_LEN/8);
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pbData);
	FREE(pSignature);

	return responsePack(ret, rspObjString, dst);

	
}



ULONG SkfFunctionParse::SKF_ECCVerify(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ECCVerify reqObj;
	Rsp_SKF_ECCVerify rspObj;
	string rspObjString;
	DEVHANDLE			hDev = NULL;
	ECCPUBLICKEYBLOB*	pECCPubKeyBlob = NULL;
	BYTE*				pbData = NULL;
	ULONG				ulDataLen = 0;
	PECCSIGNATUREBLOB 	pSignature = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.has_uldatalen()){
		ulDataLen = (ULONG)reqObj.uldatalen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_peccpubkeyblob()){
		pECCPubKeyBlob = (ECCPUBLICKEYBLOB*)malloc(sizeof(ECCPUBLICKEYBLOB));
		if(pECCPubKeyBlob) {
			memset((void*)pECCPubKeyBlob, 0, sizeof(ECCPUBLICKEYBLOB));
			if(reqObj.peccpubkeyblob().has_bitlen()) {
				pECCPubKeyBlob->BitLen = reqObj.peccpubkeyblob().bitlen().u32value();
			}
			memcpy(pECCPubKeyBlob->XCoordinate, reqObj.peccpubkeyblob().xcoordinate().data(), reqObj.peccpubkeyblob().xcoordinate().size());
			memcpy(pECCPubKeyBlob->YCoordinate, reqObj.peccpubkeyblob().ycoordinate().data(), reqObj.peccpubkeyblob().ycoordinate().size());
		}
	}

	if(reqObj.pbdata().size()){
		pbData = (BYTE *)malloc(reqObj.pbdata().size());
		if(pbData){
			memcpy((void *)pbData, reqObj.pbdata().data(), reqObj.pbdata().size());
		}
	}

	if(reqObj.has_psignature()){
		pSignature = (PECCSIGNATUREBLOB)malloc(sizeof(ECCSIGNATUREBLOB));
		if(pSignature){
			memcpy((void *)pSignature->r, reqObj.psignature().r().data(), reqObj.psignature().r().size());
			memcpy((void *)pSignature->s, reqObj.psignature().s().data(), reqObj.psignature().s().size());
		}
	}

	ULONG ret = Adapter_SKF_ECCVerify(hDev, pECCPubKeyBlob, pbData, ulDataLen, pSignature);

	rspObj.SerializeToString(&rspObjString);

	FREE(pbData);
	FREE(pECCPubKeyBlob);
	FREE(pSignature);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ECCExportSessionKey(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ECCExportSessionKey reqObj;
	Rsp_SKF_ECCExportSessionKey rspObj;
	string rspObjString;
	HCONTAINER 			hContainer = NULL;
	ULONG 				ulAlgID = 0;
	ECCPUBLICKEYBLOB* 	pPubKey = NULL;
	PECCCIPHERBLOB 		pData = NULL;
	HANDLE* 			phSessionKey = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hcontainer()){
		hContainer = (HCONTAINER)reqObj.hcontainer().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ulalgid()){
		ulAlgID = (ULONG)reqObj.ulalgid().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ppubkey()){
		pPubKey = (ECCPUBLICKEYBLOB*)malloc(sizeof(ECCPUBLICKEYBLOB));
		if(pPubKey) {
			memset((void*)pPubKey, 0, sizeof(ECCPUBLICKEYBLOB));
			if(reqObj.ppubkey().has_bitlen()) {
				pPubKey->BitLen = reqObj.ppubkey().bitlen().u32value();
			}
			memcpy(pPubKey->XCoordinate, reqObj.ppubkey().xcoordinate().data(), reqObj.ppubkey().xcoordinate().size());
			memcpy(pPubKey->YCoordinate, reqObj.ppubkey().ycoordinate().data(), reqObj.ppubkey().ycoordinate().size());
		}
	}

	if(reqObj.has_pdata()) {
		pData = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB) + reqObj.pdata().cipher().size());
		if(pData) {
			// clean/initialize buffer before use
			memset((void*)pData, 0, (sizeof(ECCCIPHERBLOB) + reqObj.pdata().cipher().size()));

			memcpy(pData->XCoordinate, reqObj.pdata().xcoordinate().data(), reqObj.pdata().xcoordinate().size());
			memcpy(pData->YCoordinate, reqObj.pdata().ycoordinate().data(), reqObj.pdata().ycoordinate().size());
			memcpy(pData->HASH, reqObj.pdata().hash().data(), reqObj.pdata().hash().size());
			if(reqObj.pdata().has_cipherlen()){
				pData->CipherLen = reqObj.pdata().cipherlen().u32value();
			}
			memcpy(pData->Cipher, reqObj.pdata().cipher().data(), reqObj.pdata().cipher().size());
		}
	}

	if(reqObj.has_phsessionkey()){
		phSessionKey = (HANDLE*)malloc(sizeof(HANDLE));
		if(phSessionKey) {
			*phSessionKey = (HANDLE)reqObj.phsessionkey().u32value();
		}
	}

	if(NULL==phSessionKey){
		FREE(pPubKey);
		FREE(pData);
		FREE(phSessionKey);
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	ULONG ret = Adapter_SKF_ECCExportSessionKey(hContainer, ulAlgID, pPubKey, pData, phSessionKey);

	if(pData){
		rspObj.mutable_pdata()->set_xcoordinate(pData->XCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
		rspObj.mutable_pdata()->set_ycoordinate(pData->YCoordinate, ECC_MAX_YCOORDINATE_BITS_LEN/8);
		rspObj.mutable_pdata()->set_hash(pData->HASH, 32);
		rspObj.mutable_pdata()->mutable_cipherlen()->set_u32value(pData->CipherLen);
		rspObj.mutable_pdata()->set_cipher(pData->Cipher, pData->CipherLen);
	}

	if(phSessionKey) {
		rspObj.mutable_phsessionkey()->set_u32value((uint32)*phSessionKey);
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pPubKey);
	FREE(pData);
	FREE(phSessionKey);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ExtECCEncrypt(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ExtECCEncrypt reqObj;
	Rsp_SKF_ExtECCEncrypt rspObj;
	string rspObjString;
	DEVHANDLE 			hDev = NULL;
	ECCPUBLICKEYBLOB* 	pECCPubKeyBlob = NULL;
	BYTE* 				pbPlainText = NULL;
	ULONG 				ulPlainTextLen = 0;
	PECCCIPHERBLOB 		pbCipherText = NULL;

	if(true != reqObj.ParseFromString(src)){
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.has_ulplaintextlen()){
		ulPlainTextLen = (ULONG)reqObj.ulplaintextlen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_peccpubkeyblob()){
		pECCPubKeyBlob = (ECCPUBLICKEYBLOB*)malloc(sizeof(ECCPUBLICKEYBLOB));
		if(pECCPubKeyBlob) {
			memset((void*)pECCPubKeyBlob, 0, sizeof(ECCPUBLICKEYBLOB));
			if(reqObj.peccpubkeyblob().has_bitlen()) {
				pECCPubKeyBlob->BitLen = reqObj.peccpubkeyblob().bitlen().u32value();
			}
			memcpy(pECCPubKeyBlob->XCoordinate, reqObj.peccpubkeyblob().xcoordinate().data(), reqObj.peccpubkeyblob().xcoordinate().size());
			memcpy(pECCPubKeyBlob->YCoordinate, reqObj.peccpubkeyblob().ycoordinate().data(), reqObj.peccpubkeyblob().ycoordinate().size());
		}
	}

	if(reqObj.pbplaintext().size()) {
		pbPlainText = (BYTE*)malloc(reqObj.pbplaintext().size());
		if(pbPlainText) {
			memcpy((void*)pbPlainText, reqObj.pbplaintext().data(), reqObj.pbplaintext().size());
		}
	}

	if(reqObj.has_pbciphertext()&&reqObj.pbciphertext().has_cipherlen()) {
		pbCipherText = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB) + reqObj.pbciphertext().cipherlen().u32value());
		if(pbCipherText) {
			memset((void *)pbCipherText, 0, sizeof(ECCCIPHERBLOB) + reqObj.pbciphertext().cipherlen().u32value());
			pbCipherText->CipherLen = reqObj.pbciphertext().cipherlen().u32value();
		}
	}

	ULONG ret = Adapter_SKF_ExtECCEncrypt(hDev, pECCPubKeyBlob, pbPlainText, ulPlainTextLen, pbCipherText);

	if(pbCipherText){
		rspObj.mutable_pbciphertext()->set_xcoordinate(pbCipherText->XCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
		rspObj.mutable_pbciphertext()->set_ycoordinate(pbCipherText->YCoordinate, ECC_MAX_YCOORDINATE_BITS_LEN/8);
		rspObj.mutable_pbciphertext()->set_hash(pbCipherText->HASH, 32);
		rspObj.mutable_pbciphertext()->mutable_cipherlen()->set_u32value(pbCipherText->CipherLen);
		rspObj.mutable_pbciphertext()->set_cipher(pbCipherText->Cipher, pbCipherText->CipherLen);
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pECCPubKeyBlob);
	FREE(pbPlainText);
	FREE(pbCipherText);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ExtECCDecrypt(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ExtECCDecrypt reqObj;
	Rsp_SKF_ExtECCDecrypt rspObj;
	string rspObjString;
	DEVHANDLE 			hDev = NULL;
	ECCPRIVATEKEYBLOB* 	pECCPriKeyBlob = NULL;
	PECCCIPHERBLOB 		pbCipherText = NULL;
	BYTE* 				pbPlainText = NULL;
	ULONG* 				pulPlainTextLen = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.has_peccprikeyblob()) {
		pECCPriKeyBlob = (ECCPRIVATEKEYBLOB*)malloc(sizeof(ECCPRIVATEKEYBLOB));
		if(pECCPriKeyBlob) {
			memset((void*)pECCPriKeyBlob, 0, sizeof(ECCPRIVATEKEYBLOB));
			if(reqObj.peccprikeyblob().has_bitlen()) {
				pECCPriKeyBlob->BitLen = reqObj.peccprikeyblob().bitlen().u32value();
			}
			memcpy(pECCPriKeyBlob->PrivateKey, reqObj.peccprikeyblob().privatekey().data(), reqObj.peccprikeyblob().privatekey().size());
		}
	}

	if(reqObj.has_pbciphertext()) {
		pbCipherText = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB) + reqObj.pbciphertext().cipher().size());
		if(pbCipherText) {
			memset((void*)pbCipherText, 0, sizeof(ECCCIPHERBLOB) + reqObj.pbciphertext().cipher().size());
			if(reqObj.pbciphertext().has_cipherlen()) {
				pbCipherText->CipherLen = reqObj.pbciphertext().cipherlen().u32value();
			}
			memcpy(pbCipherText->XCoordinate, reqObj.pbciphertext().xcoordinate().data(), reqObj.pbciphertext().xcoordinate().size());
			memcpy(pbCipherText->YCoordinate, reqObj.pbciphertext().ycoordinate().data(), reqObj.pbciphertext().ycoordinate().size());
			memcpy(pbCipherText->HASH, reqObj.pbciphertext().hash().data(), reqObj.pbciphertext().hash().size());
			memcpy(pbCipherText->Cipher, reqObj.pbciphertext().cipher().data(), reqObj.pbciphertext().cipher().size());
		}
	}

	if(reqObj.pbplaintext().size()) {
		pbPlainText = (BYTE *)malloc(reqObj.pbplaintext().size());
		if(pbPlainText) {
			memcpy(pbPlainText, reqObj.pbplaintext().data(), reqObj.pbplaintext().size());
		}
	}

	if(reqObj.has_pulplaintextlen()) {
		pulPlainTextLen = (ULONG*)malloc(sizeof(ULONG));
		if(pulPlainTextLen) {
			*pulPlainTextLen = (ULONG)reqObj.pulplaintextlen().u32value();
		}
	}

	ULONG ret = Adapter_SKF_ExtECCDecrypt(hDev, pECCPriKeyBlob, pbCipherText, pbPlainText, pulPlainTextLen);

	if(pulPlainTextLen){
		rspObj.mutable_pulplaintextlen()->set_u32value(*pulPlainTextLen);
		
		if(pbPlainText){
			rspObj.set_pbplaintext(pbPlainText, *pulPlainTextLen);
		}
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pECCPriKeyBlob);
	FREE(pbCipherText);
	FREE(pbPlainText);
	FREE(pulPlainTextLen);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ExtECCSign(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ExtECCSign reqObj;
	Rsp_SKF_ExtECCSign rspObj;
	string rspObjString;
	DEVHANDLE 			hDev = NULL;
	ECCPRIVATEKEYBLOB* 	pECCPriKeyBlob = NULL;
	BYTE* 				pbData = NULL;
	ULONG 				ulDataLen = 0;
	PECCSIGNATUREBLOB 	pSignature = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.has_uldatalen()){
		ulDataLen = (ULONG)reqObj.uldatalen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_peccprikeyblob()) {
		pECCPriKeyBlob = (ECCPRIVATEKEYBLOB*)malloc(sizeof(ECCPRIVATEKEYBLOB));
		if(pECCPriKeyBlob) {
			memset((void*)pECCPriKeyBlob, 0, sizeof(ECCPRIVATEKEYBLOB));
			if(reqObj.peccprikeyblob().has_bitlen()) {
				pECCPriKeyBlob->BitLen = reqObj.peccprikeyblob().bitlen().u32value();
			}
			memcpy(pECCPriKeyBlob->PrivateKey, reqObj.peccprikeyblob().privatekey().data(), reqObj.peccprikeyblob().privatekey().size());
		}
	}

	if(reqObj.pbdata().size()){
		pbData = (BYTE *)malloc(reqObj.pbdata().size());
		if(pbData){
			memcpy((void *)pbData, reqObj.pbdata().data(), reqObj.pbdata().size());
		}
	}

	if(reqObj.has_psignature()){
		pSignature = (PECCSIGNATUREBLOB)malloc(sizeof(ECCSIGNATUREBLOB));
		if(pSignature){
			memset((void*)pSignature, 0, sizeof(ECCSIGNATUREBLOB));
		}
	}

	ULONG ret = Adapter_SKF_ExtECCSign(hDev, pECCPriKeyBlob, pbData, ulDataLen, pSignature);

	if(pSignature){
		rspObj.mutable_psignature()->set_r(pSignature->r, ECC_MAX_XCOORDINATE_BITS_LEN/8);
		rspObj.mutable_psignature()->set_s(pSignature->s, ECC_MAX_YCOORDINATE_BITS_LEN/8);
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pECCPriKeyBlob);
	FREE(pbData);
	FREE(pSignature);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ExtECCVerify(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ExtECCVerify reqObj;
	Rsp_SKF_ExtECCVerify rspObj;
	string rspObjString;
	DEVHANDLE 			hDev = NULL;
	ECCPUBLICKEYBLOB* 	pECCPubKeyBlob = NULL;
	BYTE* 				pbData = NULL;
	ULONG 				ulDataLen = 0;
	PECCSIGNATUREBLOB 	pSignature = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.has_uldatalen()){
		ulDataLen = (ULONG)reqObj.uldatalen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_peccpubkeyblob()){
		pECCPubKeyBlob = (ECCPUBLICKEYBLOB*)malloc(sizeof(ECCPUBLICKEYBLOB));
		if(pECCPubKeyBlob) {
			memset((void*)pECCPubKeyBlob, 0, sizeof(ECCPUBLICKEYBLOB));
			if(reqObj.peccpubkeyblob().has_bitlen()) {
				pECCPubKeyBlob->BitLen = reqObj.peccpubkeyblob().bitlen().u32value();
			}
			memcpy(pECCPubKeyBlob->XCoordinate, reqObj.peccpubkeyblob().xcoordinate().data(), reqObj.peccpubkeyblob().xcoordinate().size());
			memcpy(pECCPubKeyBlob->YCoordinate, reqObj.peccpubkeyblob().ycoordinate().data(), reqObj.peccpubkeyblob().ycoordinate().size());
		}
	}

	if(reqObj.pbdata().size()){
		pbData = (BYTE *)malloc(reqObj.pbdata().size());
		if(pbData){
			memcpy((void *)pbData, reqObj.pbdata().data(), reqObj.pbdata().size());
		}
	}

	if(reqObj.has_psignature()){
		pSignature = (PECCSIGNATUREBLOB)malloc(sizeof(ECCSIGNATUREBLOB));
		if(pSignature){
			memcpy((void *)pSignature->r, reqObj.psignature().r().data(), reqObj.psignature().r().size());
			memcpy((void *)pSignature->s, reqObj.psignature().s().data(), reqObj.psignature().s().size());
		}
	}

	ULONG ret = Adapter_SKF_ExtECCVerify(hDev, pECCPubKeyBlob, pbData, ulDataLen, pSignature);

	rspObj.SerializeToString(&rspObjString);

	FREE(pbData);
	FREE(pECCPubKeyBlob);
	FREE(pSignature);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_GenerateAgreementDataWithECC(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_GenerateAgreementDataWithECC reqObj;
	Rsp_SKF_GenerateAgreementDataWithECC rspObj;
	string rspObjString;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_GenerateAgreementDataAndKeyWithECC(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_GenerateAgreementDataAndKeyWithECC reqObj;
	Rsp_SKF_GenerateAgreementDataAndKeyWithECC rspObj;
	string rspObjString;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_GenerateKeyWithECC(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_GenerateKeyWithECC reqObj;
	Rsp_SKF_GenerateKeyWithECC rspObj;
	string rspObjString;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ExportPublicKey(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ExportPublicKey reqObj;
	Rsp_SKF_ExportPublicKey rspObj;
	string rspObjString;
	HCONTAINER 	hContainer = NULL;
	BOOL 		bSignFlag = false;
	BYTE* 		pbBlob = NULL;
	ULONG* 		pulBlobLen = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hcontainer()){
		hContainer = (HCONTAINER)reqObj.hcontainer().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_bsignflag()){
		bSignFlag = (BOOL)reqObj.bsignflag().boolvalue();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbblob().size()){
		pbBlob = (BYTE *)malloc(reqObj.pbblob().size());
		if(pbBlob){
			memcpy((void *)pbBlob, reqObj.pbblob().data(), reqObj.pbblob().size());
		}
	}

	if(reqObj.has_pulbloblen()) {
		pulBlobLen = (ULONG*)malloc(sizeof(ULONG));
		if(pulBlobLen) {
			*pulBlobLen = (ULONG)reqObj.pulbloblen().u32value();
		}
	}

	ULONG ret = Adapter_SKF_ExportPublicKey(hContainer, bSignFlag, pbBlob, pulBlobLen);

	if(pulBlobLen){
		rspObj.mutable_pulbloblen()->set_u32value(*pulBlobLen);
		
		if(pbBlob){
			rspObj.set_pbblob(pbBlob, *pulBlobLen);
		}
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pbBlob);
	FREE(pulBlobLen);

	return responsePack(ret, rspObjString, dst);

}



ULONG SkfFunctionParse::SKF_ImportSessionKey(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ImportSessionKey reqObj;
	Rsp_SKF_ImportSessionKey rspObj;
	string rspObjString;
	HCONTAINER 	hContainer = NULL;
	ULONG 		ulAlgID = 0;
	BYTE *		pbWrapedData = NULL;
	ULONG 		ulWrapedLen = 0;
	HANDLE* 	phKey = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hcontainer()){
		hContainer = (HCONTAINER)reqObj.hcontainer().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ulalgid()){
		ulAlgID = (ULONG)reqObj.ulalgid().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ulwrappedlen()){
		ulWrapedLen = (ULONG)reqObj.ulwrappedlen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbwrappeddata().size()){
		pbWrapedData = (BYTE *)malloc(reqObj.pbwrappeddata().size());
		memcpy(pbWrapedData, reqObj.pbwrappeddata().data(), reqObj.pbwrappeddata().size());
	}

	if(reqObj.has_phkey()){
		phKey = (HANDLE*)malloc(sizeof(HANDLE));
		if(phKey){
			*phKey = (HANDLE)reqObj.phkey().u32value();
		}
	}

	ULONG ret = Adapter_SKF_ImportSessionKey(hContainer, ulAlgID, pbWrapedData, ulWrapedLen, phKey);

	if(phKey){
		rspObj.mutable_phkey()->set_u32value((uint32)*phKey);
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pbWrapedData);
	FREE(phKey);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_SetSymmKey(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_SetSymmKey reqObj;
	Rsp_SKF_SetSymmKey rspObj;
	string rspObjString;
	DEVHANDLE 	hDev = NULL;
	BYTE* 		pbKey = NULL;
	ULONG 		ulAlgID = 0;
	HANDLE* 	phKey = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.has_ulalgid()){
		ulAlgID = (ULONG)reqObj.ulalgid().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbkey().size()){
		pbKey = (BYTE *)malloc(reqObj.pbkey().size());
		memcpy(pbKey, reqObj.pbkey().data(), reqObj.pbkey().size());
	}

	if(reqObj.has_phkey()){
		phKey = (HANDLE*)malloc(sizeof(HANDLE));
		if(phKey){
			*phKey = (HANDLE)reqObj.phkey().u32value();
		}
	}

	ULONG ret = Adapter_SKF_SetSymmKey(hDev, pbKey, ulAlgID, phKey);

	if(phKey){
		rspObj.mutable_phkey()->set_u32value((uint32)*phKey);
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pbKey);
	FREE(phKey);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_EncryptInit(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_EncryptInit reqObj;
	Rsp_SKF_EncryptInit rspObj;
	string rspObjString;
	HANDLE 				hKey = NULL;
	BLOCKCIPHERPARAM EncryptParam;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hkey()){
		hKey = (DEVHANDLE)reqObj.hkey().u32value();
	}

	if(reqObj.has_encryptparam()){
		memset((void*)&EncryptParam, 0, sizeof(EncryptParam));
		memcpy(EncryptParam.IV, reqObj.encryptparam().iv().data(), reqObj.encryptparam().iv().size());
		if(reqObj.encryptparam().has_ivlen()) {
			EncryptParam.IVLen = reqObj.encryptparam().ivlen().u32value();
		}
		if(reqObj.encryptparam().has_paddingtype()) {
			EncryptParam.PaddingType= reqObj.encryptparam().paddingtype().u32value();
		}
		if(reqObj.encryptparam().has_feedbitlen()) {
			EncryptParam.FeedBitLen= reqObj.encryptparam().feedbitlen().u32value();
		}
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	ULONG ret = Adapter_SKF_EncryptInit(hKey, EncryptParam);

	rspObj.SerializeToString(&rspObjString);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_Encrypt(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_Encrypt reqObj;
	Rsp_SKF_Encrypt rspObj;
	string rspObjString;
	HANDLE	hKey = NULL;
	BYTE*	pbData = NULL;
	ULONG	ulDataLen = 0;
	BYTE*	pbEncryptedData = NULL;
	ULONG*	pulEncryptedLen = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hkey()){
		hKey = (DEVHANDLE)reqObj.hkey().u32value();
	}

	if(reqObj.has_uldatalen()){
		ulDataLen = (ULONG)reqObj.uldatalen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbdata().size()) {
		pbData = (BYTE*)malloc(reqObj.pbdata().size());
		if(pbData) {
			memcpy((void*)pbData, reqObj.pbdata().data(), reqObj.pbdata().size());
		}
	}

	if(reqObj.pbencrypteddata().size()) {
		pbEncryptedData = (BYTE*)malloc(reqObj.pbencrypteddata().size());
		if(pbEncryptedData) {
			memcpy((void*)pbEncryptedData, reqObj.pbencrypteddata().data(), reqObj.pbencrypteddata().size());
		}
	}

	if(reqObj.has_pulencryptedlen()) {
		pulEncryptedLen = (ULONG*)malloc(sizeof(ULONG));
		if(pulEncryptedLen) {
			*pulEncryptedLen = reqObj.pulencryptedlen().u32value();
		}
	}

	ULONG ret = Adapter_SKF_Encrypt(hKey, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen);

	if(pulEncryptedLen){
		// response encrypt output len
		rspObj.mutable_pulencryptedlen()->set_u32value(*pulEncryptedLen);
		// fill encrypt output if there is buffer allocated
		if(pbEncryptedData) {
			rspObj.set_pbencrypteddata(pbEncryptedData, *pulEncryptedLen);
		}
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pbData);
	FREE(pbEncryptedData);
	FREE(pulEncryptedLen);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_EncryptUpdate(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_EncryptUpdate reqObj;
	Rsp_SKF_EncryptUpdate rspObj;
	string rspObjString;
	HANDLE		hKey = NULL;
	BYTE*		pbData = NULL;
	ULONG		ulDataLen = 0;
	BYTE*		pbEncryptedData = NULL;
	ULONG*		pulEncryptedLen = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hkey()){
		hKey = (DEVHANDLE)reqObj.hkey().u32value();
	}

	if(reqObj.has_uldatalen()){
		ulDataLen = (ULONG)reqObj.uldatalen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbdata().size()) {
		pbData = (BYTE*)malloc(reqObj.pbdata().size());
		if(pbData) {
			memcpy((void*)pbData, reqObj.pbdata().data(), reqObj.pbdata().size());
		}
	}

	if(reqObj.pbencrypteddata().size()) {
		pbEncryptedData = (BYTE*)malloc(reqObj.pbencrypteddata().size());
		if(pbEncryptedData) {
			memcpy((void*)pbEncryptedData, reqObj.pbencrypteddata().data(), reqObj.pbencrypteddata().size());
		}
	}

	if(reqObj.has_pulencryptedlen()) {
		pulEncryptedLen = (ULONG*)malloc(sizeof(ULONG));
		if(pulEncryptedLen) {
			*pulEncryptedLen = reqObj.pulencryptedlen().u32value();
		}
	}

	ULONG ret = Adapter_SKF_EncryptUpdate(hKey, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen);

	if(pulEncryptedLen){
		// response encrypt output len
		rspObj.mutable_pulencryptedlen()->set_u32value(*pulEncryptedLen);
		// fill encrypt output if there is buffer allocated
		if(pbEncryptedData) {
			rspObj.set_pbencrypteddata(pbEncryptedData, *pulEncryptedLen);
		}
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pbData);
	FREE(pbEncryptedData);
	FREE(pulEncryptedLen);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_EncryptFinal(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_EncryptFinal reqObj;
	Rsp_SKF_EncryptFinal rspObj;
	string rspObjString;
	HANDLE 	hKey = NULL;
	BYTE *	pbEncryptedData = NULL;
	ULONG *	pulEncryptedDataLen = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hkey()){
		hKey = (DEVHANDLE)reqObj.hkey().u32value();
	}

	if(reqObj.pbencrypteddata().size()) {
		pbEncryptedData = (BYTE*)malloc(reqObj.pbencrypteddata().size());
		if(pbEncryptedData) {
			memcpy((void*)pbEncryptedData, reqObj.pbencrypteddata().data(), reqObj.pbencrypteddata().size());
		}
	}

	if(reqObj.has_pulencrypteddatalen()) {
		pulEncryptedDataLen = (ULONG*)malloc(sizeof(ULONG));
		if(pulEncryptedDataLen) {
			*pulEncryptedDataLen = reqObj.pulencrypteddatalen().u32value();
		}
	}

	ULONG ret = Adapter_SKF_EncryptFinal(hKey, pbEncryptedData, pulEncryptedDataLen);

	if(pulEncryptedDataLen){
		// response encrypt output len
		rspObj.mutable_pulencrypteddatalen()->set_u32value(*pulEncryptedDataLen);
		// fill encrypt output if there is buffer allocated
		if(pbEncryptedData) {
			rspObj.set_pbencrypteddata(pbEncryptedData, *pulEncryptedDataLen);
		}
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pbEncryptedData);
	FREE(pulEncryptedDataLen);

	return responsePack(ret, rspObjString, dst);

}



ULONG SkfFunctionParse::SKF_DecryptInit(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_DecryptInit reqObj;
	Rsp_SKF_DecryptInit rspObj;
	string rspObjString;
	HANDLE hKey = NULL;
	BLOCKCIPHERPARAM DecryptParam;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hkey()){
		hKey = (DEVHANDLE)reqObj.hkey().u32value();
	}

	if(reqObj.has_decryptparam()){
		memset((void*)&DecryptParam, 0, sizeof(DecryptParam));
		memcpy(DecryptParam.IV, reqObj.decryptparam().iv().data(), reqObj.decryptparam().iv().size());
		if(reqObj.decryptparam().has_ivlen()) {
			DecryptParam.IVLen = reqObj.decryptparam().ivlen().u32value();
		}
		if(reqObj.decryptparam().has_paddingtype()) {
			DecryptParam.PaddingType= reqObj.decryptparam().paddingtype().u32value();
		}
		if(reqObj.decryptparam().has_feedbitlen()) {
			DecryptParam.FeedBitLen= reqObj.decryptparam().feedbitlen().u32value();
		}
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	ULONG ret = Adapter_SKF_EncryptInit(hKey, DecryptParam);

	rspObj.SerializeToString(&rspObjString);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_Decrypt(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_Decrypt reqObj;
	Rsp_SKF_Decrypt rspObj;
	string rspObjString;
	HANDLE 	hKey = NULL;
	BYTE*	pbEncryptedData = NULL;
	ULONG	ulEncryptedLen = 0;
	BYTE* 	pbData = NULL;
	ULONG* 	pulDataLen = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hkey()){
		hKey = (DEVHANDLE)reqObj.hkey().u32value();
	}

	if(reqObj.has_ulencryptedlen()){
		ulEncryptedLen = (ULONG)reqObj.ulencryptedlen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbencrypteddata().size()) {
		pbEncryptedData = (BYTE*)malloc(reqObj.pbencrypteddata().size());
		if(pbEncryptedData) {
			memcpy((void*)pbEncryptedData, reqObj.pbencrypteddata().data(), reqObj.pbencrypteddata().size());
		}
	}

	if(reqObj.pbdata().size()) {
		pbData = (BYTE*)malloc(reqObj.pbdata().size());
		if(pbData) {
			memcpy((void*)pbData, reqObj.pbdata().data(), reqObj.pbdata().size());
		}
	}

	if(reqObj.has_puldatalen()) {
		pulDataLen = (ULONG*)malloc(sizeof(ULONG));
		if(pulDataLen) {
			*pulDataLen = reqObj.puldatalen().u32value();
		}
	}

	ULONG ret = Adapter_SKF_Decrypt(hKey, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen);

	if(pulDataLen){
		// response decrypt output len
		rspObj.mutable_puldatalen()->set_u32value(*pulDataLen);
		// fill decrypt output if there is buffer allocated
		if(pbData) {
			rspObj.set_pbdata(pbData, *pulDataLen);
		}
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pbData);
	FREE(pbEncryptedData);
	FREE(pulDataLen);

	return responsePack(ret, rspObjString, dst);

}



ULONG SkfFunctionParse::SKF_DecryptUpdate(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_DecryptUpdate reqObj;
	Rsp_SKF_DecryptUpdate rspObj;
	string 	rspObjString;
	HANDLE 	hKey = NULL;
	BYTE*	pbEncryptedData = NULL;
	ULONG	ulEncryptedLen = 0;
	BYTE* 	pbData = NULL;
	ULONG* 	pulDataLen = NULL;
	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hkey()){
		hKey = (DEVHANDLE)reqObj.hkey().u32value();
	}

	if(reqObj.has_ulencryptedlen()){
		ulEncryptedLen = (ULONG)reqObj.ulencryptedlen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbencrypteddata().size()) {
		pbEncryptedData = (BYTE*)malloc(reqObj.pbencrypteddata().size());
		if(pbEncryptedData) {
			memcpy((void*)pbEncryptedData, reqObj.pbencrypteddata().data(), reqObj.pbencrypteddata().size());
		}
	}

	if(reqObj.pbdata().size()) {
		pbData = (BYTE*)malloc(reqObj.pbdata().size());
		if(pbData) {
			memcpy((void*)pbData, reqObj.pbdata().data(), reqObj.pbdata().size());
		}
	}

	if(reqObj.has_puldatalen()) {
		pulDataLen = (ULONG*)malloc(sizeof(ULONG));
		if(pulDataLen) {
			*pulDataLen = reqObj.puldatalen().u32value();
		}
	}

	ULONG ret = Adapter_SKF_DecryptUpdate(hKey, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen);

	if(pulDataLen){
		// response decrypt output len
		rspObj.mutable_puldatalen()->set_u32value(*pulDataLen);
		// fill decrypt output if there is buffer allocated
		if(pbData) {
			rspObj.set_pbdata(pbData, *pulDataLen);
		}
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pbData);
	FREE(pbEncryptedData);
	FREE(pulDataLen);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_DecryptFinal(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_DecryptFinal reqObj;
	Rsp_SKF_DecryptFinal rspObj;
	string 	rspObjString;
	HANDLE 	hKey = NULL;
	BYTE *	pbPlainText = NULL;
	ULONG *	pulPlainTextLen = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hkey()){
		hKey = (DEVHANDLE)reqObj.hkey().u32value();
	}

	if(reqObj.pbplaintext().size()) {
		pbPlainText = (BYTE*)malloc(reqObj.pbplaintext().size());
		if(pbPlainText) {
			memcpy((void*)pbPlainText, reqObj.pbplaintext().data(), reqObj.pbplaintext().size());
		}
	}

	if(reqObj.has_pulplaintextlen()) {
		pulPlainTextLen = (ULONG*)malloc(sizeof(ULONG));
		if(pulPlainTextLen) {
			*pulPlainTextLen = reqObj.pulplaintextlen().u32value();
		}
	}

	ULONG ret = Adapter_SKF_DecryptFinal(hKey, pbPlainText, pulPlainTextLen);

	if(pulPlainTextLen){
		// response decrypt output len
		rspObj.mutable_pulplaintextlen()->set_u32value(*pulPlainTextLen);
		// fill decrypt output if there is buffer allocated
		if(pbPlainText) {
			rspObj.set_pbplaintext(pbPlainText, *pulPlainTextLen);
		}
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pbPlainText);
	FREE(pulPlainTextLen);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_DigestInit(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_DigestInit reqObj;
	Rsp_SKF_DigestInit rspObj;
	string rspObjString;
	DEVHANDLE			hDev = NULL;
	ULONG				ulAlgID = 0;
	ECCPUBLICKEYBLOB *	pPubKey = NULL;
	unsigned char *		pucID = NULL;
	ULONG 				ulIDLen = 0;
	HANDLE*				phHash = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hdev()){
		hDev = (DEVHANDLE)reqObj.hdev().u32value();
	}

	if(reqObj.has_ulalgid()){
		ulAlgID = (ULONG)reqObj.ulalgid().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ulidlen()){
		ulIDLen = (ULONG)reqObj.ulidlen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ppubkey()) {
		pPubKey = (PECCPUBLICKEYBLOB)malloc(sizeof(ECCPUBLICKEYBLOB));
		if(pPubKey) {
			memset((void *)pPubKey, 0, sizeof(ECCPUBLICKEYBLOB));
			if(reqObj.ppubkey().has_bitlen()) {
				pPubKey->BitLen = reqObj.ppubkey().bitlen().u32value();
			}
			memcpy(pPubKey->XCoordinate, reqObj.ppubkey().xcoordinate().data(), reqObj.ppubkey().xcoordinate().size());
			memcpy(pPubKey->YCoordinate, reqObj.ppubkey().ycoordinate().data(), reqObj.ppubkey().ycoordinate().size());
		}
	}

	if(reqObj.pucid().size()) {
		pucID = (unsigned char *)malloc(reqObj.pucid().size());
		if(pucID) {
			memcpy(pucID, reqObj.pucid().data(), reqObj.pucid().size());
		}
	}

	if(reqObj.has_phhash()) {
		phHash = (HANDLE *)malloc(sizeof(HANDLE));
		if(phHash) {
			*phHash = (HANDLE)reqObj.phhash().u32value();
		}
	}

	ULONG ret = Adapter_SKF_DigestInit(hDev, ulAlgID, pPubKey, pucID, ulIDLen, phHash);

	if(phHash){
		// response output
		rspObj.mutable_phhash()->set_u32value((uint32)*phHash);
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pPubKey);
	FREE(pucID);
	FREE(phHash);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_Digest(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_Digest reqObj;
	Rsp_SKF_Digest rspObj;
	string rspObjString;
	HANDLE 	hHash = NULL;
	BYTE *	pbData = NULL;
	ULONG 	ulDataLen = 0;
	BYTE *	pbHashData = NULL;
	ULONG *	pulHashLen = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hhash()){
		hHash = (DEVHANDLE)reqObj.hhash().u32value();
	}

	if(reqObj.has_uldatalen()){
		ulDataLen = (ULONG)reqObj.uldatalen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbdata().size()) {
		pbData = (unsigned char *)malloc(reqObj.pbdata().size());
		if(pbData) {
			memcpy(pbData, reqObj.pbdata().data(), reqObj.pbdata().size());
		}
	}

	if(reqObj.pbhashdata().size()) {
		pbHashData = (unsigned char *)malloc(reqObj.pbhashdata().size());
		if(pbHashData) {
			memcpy(pbHashData, reqObj.pbhashdata().data(), reqObj.pbhashdata().size());
		}
	}

	if(reqObj.has_pulhashlen()) {
		pulHashLen = (ULONG*)malloc(sizeof(ULONG));
		if(pulHashLen) {
			*pulHashLen = reqObj.pulhashlen().u32value();
		}
	}

	ULONG ret = Adapter_SKF_Digest(hHash, pbData, ulDataLen, pbHashData, pulHashLen);

	if(pulHashLen){
		// response output len
		rspObj.mutable_pulhashlen()->set_u32value(*pulHashLen);
		// fill output if there is buffer allocated
		if(pbHashData) {
			rspObj.set_pbhashdata(pbHashData, *pulHashLen);
		}
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pbData);
	FREE(pbHashData);
	FREE(pulHashLen);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_DigestUpdate(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_DigestUpdate reqObj;
	Rsp_SKF_DigestUpdate rspObj;
	string rspObjString;
	HANDLE hHash = NULL;
	BYTE *pbData = NULL;
	ULONG ulDataLen = 0;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hhash()){
		hHash = (DEVHANDLE)reqObj.hhash().u32value();
	}

	if(reqObj.has_uldatalen()){
		ulDataLen = (ULONG)reqObj.uldatalen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbdata().size()) {
		pbData = (unsigned char *)malloc(reqObj.pbdata().size());
		if(pbData) {
			memcpy(pbData, reqObj.pbdata().data(), reqObj.pbdata().size());
		}
	}

	ULONG ret = Adapter_SKF_DigestUpdate(hHash, pbData, ulDataLen);

	rspObj.SerializeToString(&rspObjString);

	FREE(pbData);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_DigestFinal(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_DigestFinal reqObj;
	Rsp_SKF_DigestFinal rspObj;
	string rspObjString;
	HANDLE 	hHash = NULL;
	BYTE *	pHashData = NULL;
	ULONG *	pulHashLen = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hhash()){
		hHash = (DEVHANDLE)reqObj.hhash().u32value();
	}

	if(reqObj.phashdata().size()) {
		pHashData = (unsigned char *)malloc(reqObj.phashdata().size());
		if(pHashData) {
			memcpy(pHashData, reqObj.phashdata().data(), reqObj.phashdata().size());
		}
	}

	if(reqObj.has_pulhashlen()) {
		pulHashLen = (ULONG*)malloc(sizeof(ULONG));
		if(pulHashLen) {
			*pulHashLen = reqObj.pulhashlen().u32value();
		}
	}

	ULONG ret = Adapter_SKF_DigestFinal(hHash, pHashData, pulHashLen);

	if(pulHashLen){
		// response output len
		rspObj.mutable_pulhashlen()->set_u32value(*pulHashLen);
		// fill output if there is buffer allocated
		if(pHashData) {
			rspObj.set_phashdata(pHashData, *pulHashLen);
		}
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pHashData);
	FREE(pulHashLen);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_MacInit(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_MacInit reqObj;
	Rsp_SKF_MacInit rspObj;
	string rspObjString;
	LPSTR szNameList = NULL;
	ULONG* pulSize = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_Mac(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_Mac reqObj;
	Rsp_SKF_Mac rspObj;
	string rspObjString;
	LPSTR szNameList = NULL;
	ULONG* pulSize = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_MacUpdate(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_MacUpdate reqObj;
	Rsp_SKF_MacUpdate rspObj;
	string rspObjString;
	LPSTR szNameList = NULL;
	ULONG* pulSize = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_MacFinal(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_MacFinal reqObj;
	Rsp_SKF_MacFinal rspObj;
	string rspObjString;
	LPSTR szNameList = NULL;
	ULONG* pulSize = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_CloseHandle(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_CloseHandle reqObj;
	Rsp_SKF_CloseHandle rspObj;
	string rspObjString;
	HANDLE hHandle = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hhandle()){
		hHandle = (HANDLE)reqObj.hhandle().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	ULONG ret = Adapter_SKF_CloseHandle(hHandle);

	rspObj.SerializeToString(&rspObjString);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_Transmit(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_Transmit reqObj;
	Rsp_SKF_Transmit rspObj;
	string rspObjString;
	LPSTR szNameList = NULL;
	ULONG* pulSize = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	return responsePack(SAR_NOTSUPPORTYETERR, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ImportCertificate(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ImportCertificate reqObj;
	Rsp_SKF_ImportCertificate rspObj;
	string rspObjString;
	HCONTAINER 	hContainer = NULL;
	BOOL 		bSignFlag = false;
	BYTE* 		pbCert = NULL;
	ULONG 		ulCertLen = 0;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hcontainer()){
		hContainer = (HCONTAINER)reqObj.hcontainer().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_bsignflag()){
		bSignFlag = (bool)reqObj.bsignflag().boolvalue();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_ulcertlen()){
		ulCertLen = (ULONG)reqObj.ulcertlen().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbcert().size()) {
		pbCert = (unsigned char *)malloc(reqObj.pbcert().size());
		if(pbCert) {
			memcpy(pbCert, reqObj.pbcert().data(), reqObj.pbcert().size());
		}
	}

	ULONG ret = Adapter_SKF_ImportCertificate(hContainer, bSignFlag, pbCert, ulCertLen);

	rspObj.SerializeToString(&rspObjString);

	FREE(pbCert);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_ExportCertificate(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_ExportCertificate reqObj;
	Rsp_SKF_ExportCertificate rspObj;
	string rspObjString;
	LPSTR szNameList = NULL;
	HCONTAINER 	hContainer = NULL;
	BOOL 		bSignFlag = false;
	BYTE* 		pbCert = NULL;
	ULONG* 		pulCertLen = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hcontainer()){
		hContainer = (HCONTAINER)reqObj.hcontainer().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_bsignflag()){
		bSignFlag = (bool)reqObj.bsignflag().boolvalue();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.pbcert().size()) {
		pbCert = (unsigned char *)malloc(reqObj.pbcert().size());
		if(pbCert) {
			memcpy(pbCert, reqObj.pbcert().data(), reqObj.pbcert().size());
		}
	}

	if(reqObj.has_pulcertlen()) {
		pulCertLen = (ULONG*)malloc(sizeof(ULONG));
		if(pulCertLen) {
			*pulCertLen = reqObj.pulcertlen().u32value();
		}
	}

	ULONG ret = Adapter_SKF_ExportCertificate(hContainer, bSignFlag, pbCert, pulCertLen);

	if(pulCertLen){
		// response cert output len
		rspObj.mutable_pulcertlen()->set_u32value(*pulCertLen);
		// fill cert output if there is buffer allocated
		if(pbCert) {
			rspObj.set_pbcert(pbCert, *pulCertLen);
		}
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pbCert);
	FREE(pulCertLen);

	return responsePack(ret, rspObjString, dst);
}



ULONG SkfFunctionParse::SKF_GetContainerProperty(const string src,string &dst)
{
	setCallerName(packageName);
	Req_SKF_GetContainerProperty reqObj;
	Rsp_SKF_GetContainerProperty rspObj;
	string rspObjString;
	HCONTAINER 	hContainer = NULL;
	ULONG *		pulConProperty = NULL;

	if(true != reqObj.ParseFromString(src))
	{
		return responsePack(RETURN_CODE_ERROR_PROTOCOL, rspObjString, dst);
	}

	if(reqObj.has_hcontainer()){
		hContainer = (HCONTAINER)reqObj.hcontainer().u32value();
	}
	else {
		return responsePack(SAR_INVALIDPARAMERR, rspObjString, dst);
	}

	if(reqObj.has_pulconproperty()) {
		pulConProperty = (ULONG*)malloc(sizeof(ULONG));
		if(pulConProperty) {
			*pulConProperty = reqObj.pulconproperty().u32value();
		}
	}

	ULONG ret = Adapter_SKF_GetContainerProperty(hContainer, pulConProperty);

	if(pulConProperty){
		rspObj.mutable_pulconproperty()->set_u32value(*pulConProperty);
	}

	rspObj.SerializeToString(&rspObjString);

	FREE(pulConProperty);

	return responsePack(ret, rspObjString, dst);
}
