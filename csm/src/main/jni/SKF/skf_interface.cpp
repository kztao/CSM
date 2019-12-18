/******************************************************************
	*Author:Wangjunren
	*Date:2018.10.13
	*History:
		*	2018.10.13 first version by wangjunren
		*
*******************************************************************/
#ifdef WIN32
#include "skf_t.h"
#include "cryptoki.h"
#else
#include "P11Adapter.h"
#endif
#include "Record.h"
#include "skfdef.h"
#include <iostream>
#ifndef WIN32
#include <iomanip>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <set>
#include <algorithm>
#include <string.h>


#define SKF_AUTHDEV_LABEL "deviceAuthKey"
#define SM4_KEY_LEN  16
#define HASH_OUTPUT_LEN  32
#ifdef WIN32
// check SM4 mechanism
#define SGD_SMS4_MASK	0x00000400
#endif

#define SKF_LIB_VER "0.1.1"


//static bool loggerInitialized = false;
void initLogger()
{
	if (SKFGlobeData::loggerInitialized)
	{
		return;
	}

	// init logger to save 5MB * 5 files
	initLogger(DEFAULT_LOG_LEVEL, (const char*)("westone_skf_plog"), 1024*1024*5, 5);

	SKFGlobeData::loggerInitialized = true;
}

/*
logData to print specified data into file, for log/debug usage
32 bytes each line
*/
void logData(unsigned char * pData, unsigned long ulDataLen, LogSeverity level, char * inputComments = NULL)
{
	char buffer0[256] = { 0 };
	int printfRet = 0;
	int currentIdx = 0;
	unsigned int writeIdx = 0;

	if(NULL == pData || 0 == ulDataLen) {
		return;
	}

	if(inputComments) {
		if (SKFGlobeData::loggerInitialized){do{log_skf(level, __FUNCTION__, __LINE__, __FILE__, "%s", inputComments);}while(0);};
	}

	for (writeIdx = 0, currentIdx = 0; writeIdx < ulDataLen; writeIdx++)
	{
#ifdef WIN32
		printfRet = sprintf_s(buffer0 + currentIdx, sizeof(buffer0) - currentIdx, "%02x", pData[writeIdx]);
#else
		printfRet = snprintf(buffer0 + currentIdx, sizeof(buffer0) - currentIdx,"%02x", pData[writeIdx]);
#endif
		currentIdx = currentIdx + printfRet;
		// 32 bytes each line
		if (currentIdx >= 63)
		{
			//SKF_LOGV("%s", buffer0);
			if (SKFGlobeData::loggerInitialized){do{log_skf(level, __FUNCTION__, __LINE__, __FILE__, "%s", buffer0);}while(0);};
			currentIdx = 0;
			std::memset(buffer0, 0, sizeof(buffer0));
		}
	}
	if (buffer0[0])
	{
		//SKF_LOGV("%s", buffer0);
		if (SKFGlobeData::loggerInitialized){do{log_skf(level, __FUNCTION__, __LINE__, __FILE__, "%s", buffer0);}while(0);};
	}

	return;
}

ULONG Import_ECC_PublicKey(
IN DEVHANDLE hDev,
IN PECCPUBLICKEYBLOB pBlob,
OUT CK_OBJECT_HANDLE_PTR phPubKey
);

ULONG Import_ECC_PrivateKey(
IN DEVHANDLE hDev,
IN PECCPRIVATEKEYBLOB pBlob,
OUT CK_OBJECT_HANDLE_PTR phKey
);

ULONG destroyObjByTemplate(CK_SESSION_HANDLE hSession,
CK_ATTRIBUTE_PTR pAttr,
CK_ULONG ulAttrCount
);

ULONG findSingleObjByTemplate(CK_SESSION_HANDLE hSession,
CK_ATTRIBUTE_PTR pAttr,
CK_ULONG ulAttrCount,
CK_OBJECT_HANDLE_PTR phObj
);

ULONG p11Error2SkfError(ULONG p11error)
{
	ULONG skf_ret = SAR_FAIL;

	if(CKR_OK != p11error) {
		SKF_LOGD("p11Error2SkfError input p11error=0x%08x",p11error);
	}

	switch (p11error){
		case CKR_OK:
			skf_ret = SAR_OK;
			break;
		case CKR_HOST_MEMORY:
			skf_ret = SAR_MEMORYERR;
			break;
		case CKR_DEVICE_MEMORY:
			skf_ret = SAR_NO_ROOM;
			break;
		case CKR_SLOT_ID_INVALID:
		case CKR_DEVICE_ERROR:
		case CKR_DEVICE_REMOVED:
			skf_ret = SAR_DEVICE_REMOVED;
			break;
		case CKR_TOKEN_NOT_PRESENT:
		case CKR_TOKEN_NOT_RECOGNIZED:
		case CKR_TOKEN_WRITE_PROTECTED:
			skf_ret = SAR_DEVICE_REMOVED;
			break;
		case CKR_FUNCTION_NOT_SUPPORTED:
		case CKR_FUNCTION_REJECTED:
			skf_ret = SAR_NOTSUPPORTYETERR;
			break;
		case CKR_KEY_HANDLE_INVALID:
			skf_ret = SAR_KEYNOTFOUNDERR;
			break;
		case CKR_KEY_FUNCTION_NOT_PERMITTED:
		case CKR_KEY_INDIGESTIBLE:
		case CKR_KEY_NOT_WRAPPABLE:
		case CKR_KEY_UNEXTRACTABLE:
		case CKR_MECHANISM_INVALID:
		case CKR_MECHANISM_PARAM_INVALID:
			skf_ret = SAR_KEYUSAGEERR;
			break;
		case CKR_BUFFER_TOO_SMALL:
			skf_ret = SAR_BUFFER_TOO_SMALL;
			break;
		default:
			break;
	}

	return skf_ret;
}


CK_BYTE_PTR assembleKeyId(SKFHandleC_PTR hContainer, CK_BBOOL signatureFlag, CK_ULONG_PTR pKeyIdLen);

static void listSkfHandle()
{
	set<SKFHandleD_PTR>::iterator itD;
	set<SKFHandleA_PTR>::iterator itA;
	set<SKFHandleC_PTR>::iterator itC;
	set<SKFHandleF_PTR>::iterator itF;
	set<SKFHandleSYM_PTR>::iterator itSK;
	set<SKFHandleCT_PTR>::iterator itCT;

	SKFHandleD_PTR tempDeviceHandle = NULL;
	SKFHandleA_PTR tempApplicationHandle = NULL;
	SKFHandleC_PTR tempContainerHandle = NULL;
	SKFHandleF_PTR tempFileHandle = NULL;
	SKFHandleSYM_PTR tempSessionKeyHandle = NULL;
	SKFHandleCT_PTR tempCertificationHandle = NULL;

	SKF_LOGD("\ndev handle num: %d\n", SKFGlobeData::setDevHandle.size());
	for (itD = SKFGlobeData::setDevHandle.begin(); itD != SKFGlobeData::setDevHandle.end(); itD++){
		tempDeviceHandle = *itD;
		SKF_LOGD("%p(%d)  ", tempDeviceHandle, tempDeviceHandle->flg);
	}

	SKF_LOGD("\napp handle num: %d\n", SKFGlobeData::setAppHandle.size());
	for (itA = SKFGlobeData::setAppHandle.begin(); itA != SKFGlobeData::setAppHandle.end(); itA++){
		tempApplicationHandle = *itA;
		SKF_LOGD("%p(%d)->0x%x  ", tempApplicationHandle, tempApplicationHandle->flg, tempApplicationHandle->appHandle);
	}

	SKF_LOGD("\nfile handle num: %d\n", SKFGlobeData::setFileHandle.size());
	for (itF = SKFGlobeData::setFileHandle.begin(); itF != SKFGlobeData::setFileHandle.end(); itF++){
		tempFileHandle = *itF;
		SKF_LOGD("%p(%p)->0x%x  ", tempFileHandle, tempFileHandle->pAppHandle, tempFileHandle->fileHandle);
	}

	SKF_LOGD("\ncontainer handle num: %d\n", SKFGlobeData::setContainerHandle.size());
	for (itC = SKFGlobeData::setContainerHandle.begin(); itC != SKFGlobeData::setContainerHandle.end(); itC++){
		tempContainerHandle = *itC;
		SKF_LOGD("%p(%p)(%d)->0x%x  ", tempContainerHandle, tempContainerHandle->pAppHandle, tempContainerHandle->flg, tempContainerHandle->containerHandle);
	}

	SKF_LOGD("\nsession key handle num: %d\n", SKFGlobeData::setSessionKeyHandle.size());
	for (itSK = SKFGlobeData::setSessionKeyHandle.begin(); itSK != SKFGlobeData::setSessionKeyHandle.end(); itSK++){
		tempSessionKeyHandle = *itSK;
		SKF_LOGD("%p(%p)->0x%x  ", tempSessionKeyHandle, tempSessionKeyHandle->pContainerHandle, tempSessionKeyHandle->sessKeyHandle);
	}

	SKF_LOGD("\ncertification handle num: %d\n", SKFGlobeData::setCertHandle.size());
	for (itCT = SKFGlobeData::setCertHandle.begin(); itCT != SKFGlobeData::setCertHandle.end(); itCT++){
		tempCertificationHandle = *itCT;
		SKF_LOGD("%p(%p)->0x%x  ", tempCertificationHandle, tempCertificationHandle->pContainerHandle, tempCertificationHandle->certHandle);
	}
	
	return;
}


SKF_DEVAPI SKF_WaitForDevEvent(
	OUT LPSTR szDevName,
	OUT ULONG *pulDevNameLen,
	OUT ULONG *pulEvent
) 
{
	if (NULL == szDevName || NULL == pulDevNameLen || NULL == pulEvent){
		return SAR_INVALIDPARAMERR;
	}

	return SAR_NOTSUPPORTYETERR;
}
/*
*	取消等待设备的插拔事件
*/
SKF_DEVAPI SKF_CancelWaitForDevEvent()
{
	return SAR_NOTSUPPORTYETERR;
}

/*
*	获得当前系统中的设备列表
*	bPresent		[IN]为TRUE表示取当前设备状态为存在的设备列表。为FALSE表示取当前驱动支持的设备列表
*	szNameList		[OUT]设备名称列表。如果该参数为NULL，将由pulSize返回所需要的内存空间大小。每个设备的名称以单个'\0'结束，以双'\0'表示列表的结束
*	pulSize			[IN,OUT]输入参数，输入设备名称列表的缓冲区长度，输出参数，返回szNameList所需要的空间大小
*/
SKF_DEVAPI SKF_EnumDev(
IN BOOL bPresent,
OUT LPSTR szNameList,
OUT ULONG* pulSize
)
{
	if (NULL == pulSize || FALSE == bPresent){
		return SAR_INVALIDPARAMERR;
	}
	
#ifdef WIN32
	initLogger();
#endif

	//initLogger();
    // log SKF lib version for track
    SKF_LOGE("SKF lib version %s", SKF_LIB_VER);

    SKF_LOGD("%s entry", __FUNCTION__);

	SKFGlobeData::clearAll();

	CK_ULONG ret = Adapter_C_Initialize(NULL);
	if (ret != CKR_OK && ret != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		SKF_LOGF("Adapter_C_Initialize failed return 0x%x", ret);
		return p11Error2SkfError(ret);
	}

	CK_ULONG count = 0;
	CK_SLOT_ID_PTR idArray = NULL;

	ret = Adapter_C_GetSlotList(CK_TRUE, idArray, &count);
	if (ret != CKR_OK) {
		SKF_LOGF("Adapter_C_GetSlotList failed return 0x%x", ret);
		return p11Error2SkfError(ret);
	}

	if (0 == count) {
		SKF_LOGF("Adapter_C_GetSlotList find no valid slot");
		return SAR_DEVICE_REMOVED;
	}

	idArray = new CK_SLOT_ID[count];
	ret = Adapter_C_GetSlotList(CK_TRUE, idArray, &count);
	if (ret != CKR_OK || count == 0) {
		delete[] idArray;
		idArray = NULL;
		SKF_LOGF("Adapter_C_GetSlotList return 0x%x and count %d", ret, count);
		return SAR_FAIL;
	}

	set<CK_SLOT_ID > slotIdSet;

	for(unsigned int loop = 0;loop < count;loop++){
		CK_TOKEN_INFO tokenInfo;
		ret = Adapter_C_GetTokenInfo(idArray[loop],&tokenInfo);
		if(ret != CKR_OK){
			return SAR_FAIL;
		}

		if(0 != memcmp(tokenInfo.manufacturerID,"HDZB",strlen("HDZB"))){
			slotIdSet.insert(idArray[loop]);
		}
	}


	char pad[1] = { 0 };
	char slotDesc[10] = { 0 };
	string slotStr;

	for(auto it = slotIdSet.begin();it != slotIdSet.end();it++){
		SKFHandleD_PTR tmp = new SKFHandleD();
		tmp->id = *it;
		tmp->flg = SKF_FLAG_EXIST;
		SKFGlobeData::setDevHandle.insert(tmp);

		memset(slotDesc,0,sizeof(slotDesc));
#ifdef WIN32
		sprintf_s(slotDesc, sizeof(slotDesc), "%08x", *it);
#else
		snprintf(slotDesc, sizeof(slotDesc), "%08x", *it);
#endif
		slotStr.append(slotDesc);
		slotStr.append(pad, 1);
	}
	if(slotStr.size() > 0){
		slotStr.append(pad, 1);
	}

	delete[] idArray;
	idArray = NULL;

	// check if input buffer enough to hold all output
	if((szNameList) && (*pulSize < slotStr.size())) {
		SKF_LOGE("%s exit with 0x%x due input buffer len %d and required %d", __FUNCTION__, SAR_BUFFER_TOO_SMALL, *pulSize, slotStr.size());
		*pulSize = slotStr.size();
		return SAR_BUFFER_TOO_SMALL;
	}
		
	*pulSize = slotStr.size();
	
	if (szNameList != NULL) {
		memcpy(szNameList,slotStr.data(), slotStr.size());
		logData((unsigned char *)szNameList, slotStr.size(), plog_verbose, "device enum result:");
	}

	SKF_LOGD("%s exit", __FUNCTION__);
	return SAR_OK;
}

/*
*	通过设备名称连接设备，返回设备的句柄
*	szName		[IN]设备名称
*	phDev		[OUT]返回设备操作句柄
*/
SKF_DEVAPI SKF_ConnectDev(
IN LPSTR szName,
OUT DEVHANDLE* phDev
)
{
	if (NULL == szName || NULL == phDev){
		return SAR_INVALIDPARAMERR;
	}

	SKF_LOGD("%s entry with %s", __FUNCTION__, szName);
	
	CK_SLOT_ID id;
#ifdef WIN32
	sscanf_s(szName,"%08lx",&id);
#else
	sscanf(szName,"%08lx",&id);
#endif

	HandleCheck handle;
	CK_SESSION_HANDLE session;
	CK_RV ret = CKR_OK;

	set<SKFHandleD_PTR>::iterator it = SKFGlobeData::setDevHandle.begin();
	for (;it != SKFGlobeData::setDevHandle.end();it++){
		if ((*it)->id == id){
			*phDev = *it;
			if ((*it)->flg == SKF_FLAG_OPEN){
				SKF_LOGD("return OK");
				return SAR_OK;
			}
			else if ((*it)->flg == SKF_FLAG_EXIST)
			{
				(*it)->flg = SKF_FLAG_OPEN;
			}

			ret = handle.GetSession(*it, &session);
			if (ret != CKR_OK){
				SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
				return SAR_FAIL;
			}

			ret = Adapter_C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)SKF_P11_USER_PIN, strlen(SKF_P11_USER_PIN));
			if (ret != CKR_OK && ret != CKR_USER_ALREADY_LOGGED_IN){
				SKF_LOGE("check pin failed with return 0x%x", ret);
				handle.CloseSession(session);
				return SAR_DEVICE_REMOVED;
			}

			//遍历应用

			ret = handle.AppEnum(*it);
			if (ret != SAR_OK){
				SKF_LOGE("enum app failed with return 0x%x", ret);
				handle.CloseSession(session);
				return p11Error2SkfError(ret);
			}

			//遍历容器和文件
			set<SKFHandleA_PTR>::iterator itA = SKFGlobeData::setAppHandle.begin();
			for (; itA != SKFGlobeData::setAppHandle.end(); itA++){
				ret = handle.ContainerEnum(*itA);
				if (ret != SAR_OK){
					handle.CloseSession(session);
					SKF_LOGE("enum container failed with return 0x%x", ret);
					return p11Error2SkfError(ret);
				}

				ret = handle.FileEnum(*itA);
				if (ret != SAR_OK){
					handle.CloseSession(session);
					SKF_LOGE("enum file failed with return 0x%x", ret);
					return p11Error2SkfError(ret);
				}
			}

			//遍历证书和密钥
			set<SKFHandleC_PTR>::iterator itC = SKFGlobeData::setContainerHandle.begin();
			for (; itC != SKFGlobeData::setContainerHandle.end(); itC++){
				ret = handle.CertEnum(*itC);
				if (ret != SAR_OK){
					handle.CloseSession(session);
					SKF_LOGE("enum cert failed with return 0x%x", ret);
					return p11Error2SkfError(ret);
				}

				ret = handle.KeyEnum(*itC);
				if (ret != SAR_OK){
					handle.CloseSession(session);
					SKF_LOGE("enum key failed with return 0x%x", ret);
					return p11Error2SkfError(ret);
				}
			}

			handle.CloseSession(session);

			listSkfHandle();

			SKF_LOGD("%s exit SAR_OK with %p", __FUNCTION__, *phDev);

			return SAR_OK;
		}
	}

	return SAR_DEVICE_REMOVED;

	
}

/*
*	断开一个已经连接的设备，并释放句柄。
*	hDev		[IN]连接设备时返回的设备句柄
*/
SKF_DEVAPI SKF_DisConnectDev(
IN DEVHANDLE hDev
)
{
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	HandleCheck handle;

	// declaration for iterators...
	set<SKFHandleD_PTR>::iterator itD;
	set<SKFHandleA_PTR>::iterator itA;
	set<SKFHandleC_PTR>::iterator itC;
	set<SKFHandleF_PTR>::iterator itF;
	set<SKFHandleSYM_PTR>::iterator itSK;
	set<SKFHandleCT_PTR>::iterator itCT;

	SKFHandleD_PTR tempDeviceHandle = NULL;
	SKFHandleA_PTR tempApplicationHandle = NULL;
	SKFHandleC_PTR tempContainerHandle = NULL;
	SKFHandleF_PTR tempFileHandle = NULL;
	SKFHandleSYM_PTR tempSessionKeyHandle = NULL;
	SKFHandleCT_PTR tempCertificationHandle = NULL;

	SKF_LOGD("%s entry with %p", __FUNCTION__, hDev);
	
	if (NULL == hDev){
		return SAR_INVALIDPARAMERR;
	}

	// check if input hDev valid
	ret_skf = handle.Check((SKFHandleD_PTR)hDev);
	if (SAR_OK != ret_skf){
		SKF_LOGE("check handle failed with return 0x%x", ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	
	// update setDevHandle flag to SKF_FLAG_EXIST for target device
	for (itD = SKFGlobeData::setDevHandle.begin(); itD != SKFGlobeData::setDevHandle.end(); itD++){
		if (*itD == hDev){
			(*itD)->flg = SKF_FLAG_EXIST;
		}
	}

	// clean up session key information
	for (itSK = SKFGlobeData::setSessionKeyHandle.begin(); itSK != SKFGlobeData::setSessionKeyHandle.end(); ){
		if ((*itSK)->pDevHandle == hDev) {
			tempSessionKeyHandle =  *itSK;

			if (SGD_SM3 != tempSessionKeyHandle->ulAlgId) {
				// destroy session object as these shall be invalid after device disconnect
				// SM3 for hash calculation, no destroy operation
				ret_p11 = Adapter_C_DestroyObject(tempSessionKeyHandle->session, tempSessionKeyHandle->sessKeyHandle);
				if(CKR_OK != ret_p11) {
					SKF_LOGE("destroy session key failed with return 0x%x", ret_p11);
					ret_skf = SAR_FAIL;
					break;
				}
			}

			// close session bind with key
			ret_p11 = Adapter_C_CloseSession(tempSessionKeyHandle->session);
			if(CKR_OK != ret_p11) {
				SKF_LOGE("close session failed with return 0x%x", ret_p11);
				ret_skf = SAR_FAIL;
				break;
			}

			// remove handle from set
			// itSK must ++ here, cannot be put into for(;;itSK++)
			SKFGlobeData::setSessionKeyHandle.erase(itSK++);

			// release handle memory
			delete tempSessionKeyHandle;
			tempSessionKeyHandle = NULL;
		}
		else {
			itSK++;
		}
	}
	// unexpected error, return;
	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s destroy session key failed with return 0x%x", __FUNCTION__, ret_skf);
		return ret_skf;
	}

	// remove certification buffer information and release memory
	// certification buffer information shall be destroied before container information...
	for (itCT = SKFGlobeData::setCertHandle.begin(); itCT != SKFGlobeData::setCertHandle.end(); ){

		tempCertificationHandle = *itCT;

		if ((*itCT)->pContainerHandle->pAppHandle->pDevHandle == hDev){
			SKFGlobeData::setCertHandle.erase(itCT++);
			delete tempCertificationHandle;
			tempCertificationHandle = NULL;
		}
		else {
			itCT++;
		}
	}

	// remove container buffer information and release memory
	for (itC = SKFGlobeData::setContainerHandle.begin(); itC != SKFGlobeData::setContainerHandle.end(); ){
		if ((*itC)->pAppHandle->pDevHandle == hDev){

			tempContainerHandle = *itC;
			
			SKFGlobeData::setContainerHandle.erase(itC++);

			delete tempContainerHandle;
			tempContainerHandle = NULL;
		}
		else {
			itC++;
		}
	}

	// remove file buffer information and release memory
	for (itF = SKFGlobeData::setFileHandle.begin(); itF != SKFGlobeData::setFileHandle.end(); ){
		if ((*itF)->pAppHandle->pDevHandle == hDev){
			tempFileHandle = *itF;
			
			SKFGlobeData::setFileHandle.erase(itF++);

			delete tempFileHandle;
			tempFileHandle = NULL;
		}
		else {
			itF++;
		}
	}

	// remove application buffer information and release memory
	for (itA = SKFGlobeData::setAppHandle.begin(); itA != SKFGlobeData::setAppHandle.end(); ){
		if ((*itA)->pDevHandle == hDev){

			tempApplicationHandle = *itA;

			//release internal memory allocated when enum app
			if(tempApplicationHandle->appValue.soDefaultPin) {
				delete[] tempApplicationHandle->appValue.soDefaultPin;
				tempApplicationHandle->appValue.soDefaultPin = NULL;
			}

			if(tempApplicationHandle->appValue.soPin) {
				delete[] tempApplicationHandle->appValue.soPin;
				tempApplicationHandle->appValue.soPin = NULL;
			}

			if(tempApplicationHandle->appValue.usrDefaultPin) {
				delete[] tempApplicationHandle->appValue.usrDefaultPin;
				tempApplicationHandle->appValue.usrDefaultPin = NULL;
			}

			if(tempApplicationHandle->appValue.usrPin) {
				delete[] tempApplicationHandle->appValue.usrPin;
				tempApplicationHandle->appValue.usrPin = NULL;
			}

			// remove handle information in set
			SKFGlobeData::setAppHandle.erase(itA++);

			delete tempApplicationHandle;
			tempApplicationHandle = NULL;
		}
		else {
			itA++;
		}
	}

	// close all sessions opened on this device
	//----- shall NOT close all sessions in case multi-application connected with device
	//----- close all sessions will impact other application
	//ret_p11 = Adapter_C_CloseAllSessions(((SKFHandleD_PTR)hDev)->id);

	// verbose print for debug
	listSkfHandle();
	
	SKF_LOGD("%s exit with %p", __FUNCTION__, hDev);
	return SAR_OK;
}

/*
*	获取设备是否存在的状态
*	szDevName	[IN]连接名称
*	pulDevState	[OUT]返回设备状态
*/
SKF_DEVAPI SKF_GetDevState(
IN  LPSTR	 szDevName,
OUT ULONG* pulDevState
)
{
	SKF_LOGD("%s entry", __FUNCTION__);
	
	if (NULL == szDevName || NULL == pulDevState){
		SKF_LOGE("%s return 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	*pulDevState = DEV_ABSENT_STATE;
	CK_SLOT_ID id = 0;
#ifdef WIN32
	sscanf_s(szDevName,"%08lx",&id);
#else
	sscanf(szDevName,"%08lx",&id);
#endif

	set<SKFHandleD_PTR>::iterator it = SKFGlobeData::setDevHandle.begin();
	for (; it != SKFGlobeData::setDevHandle.end();it++){
		if ((*it)->id == id){
			*pulDevState = DEV_PRESENT_STATE;
			SKF_LOGD("%s exit SAR_OK with %s", __FUNCTION__, szDevName);
			return SAR_OK;
		}
	}

	SKF_LOGE("%s return 0x%x", __FUNCTION__, SAR_DEVICE_REMOVED);
	return SAR_DEVICE_REMOVED;
}

/*
*	设置设备标签
*	hDev		[IN]连接设备时返回的设备句柄
*	szLabel		[OUT]设备标签字符串。该字符串应小于32字节
*/
SKF_DEVAPI SKF_SetLabel(
IN DEVHANDLE hDev,
IN LPSTR szLabel)
{
	SKF_LOGD("%s entry with %p", __FUNCTION__, hDev);
	
	if (NULL == hDev){
		SKF_LOGE("%s return 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	HandleCheck handle;
	ULONG ret = handle.Check((SKFHandleD_PTR)hDev);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	SKF_LOGE("%s exit with 0x%x", __FUNCTION__, SAR_NOTSUPPORTYETERR);
	return SAR_NOTSUPPORTYETERR;
}

/*
*	获取设备的一些特征信息，包括设备标签、厂商信息、支持的算法等
*	hDev		[IN]连接设备时返回的设备句柄
*	pDevInfo	[OUT]返回设备信息
*/
SKF_DEVAPI SKF_GetDevInfo(
	IN DEVHANDLE	hDev,
	OUT PDEVINFO	pDevInfo
	)
{
	SKF_LOGD("%s entry with %p", __FUNCTION__, hDev);
	
	if (NULL == hDev || NULL == pDevInfo){
		SKF_LOGE("%s return 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	HandleCheck handle;
	SKFHandleD_PTR pDev = NULL;

	ULONG ret = handle.Check((SKFHandleD_PTR)hDev);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	pDev = (SKFHandleD_PTR)hDev;

	CK_TOKEN_INFO tokenInfo = { 0 };
	CK_SLOT_INFO slotInfo = { 0 };

	ret = Adapter_C_GetTokenInfo(pDev->id, &tokenInfo);

	if (ret != SAR_OK){
		SKF_LOGE("%s get 0x%x for get token infor", __FUNCTION__, ret);
		return p11Error2SkfError(ret);
	}

	ret = Adapter_C_GetSlotInfo(pDev->id, &slotInfo);

	if (ret != SAR_OK){
		SKF_LOGE("%s get 0x%x for get slot infor", __FUNCTION__, ret);
		return p11Error2SkfError(ret);
	}

	pDevInfo->AlgAsymCap = SGD_RSA | SGD_SM2_1 | SGD_SM2_2 | SGD_SM2_3;
	pDevInfo->AlgHashCap = SGD_SM3 | SGD_SHA1 | SGD_SHA256;
	pDevInfo->AlgSymCap =	SGD_SMS4_ECB | SGD_SMS4_CBC |
							SGD_SMS4_CFB | SGD_SMS4_OFB |
							SGD_SMS4_MAC | SGD_DES112_ECB;
	pDevInfo->DevAuthAlgId = SGD_SMS4_ECB;
	pDevInfo->FirmwareVersion.major = tokenInfo.firmwareVersion.major;
	pDevInfo->FirmwareVersion.minor = tokenInfo.firmwareVersion.minor;
	pDevInfo->FreeSpace = tokenInfo.ulFreePrivateMemory + tokenInfo.ulFreePublicMemory;
	pDevInfo->HWVersion.major = tokenInfo.hardwareVersion.major;
	pDevInfo->HWVersion.minor = tokenInfo.hardwareVersion.minor;
	memset(pDevInfo->Issuer, 0, sizeof(pDevInfo->Issuer));
	memset(pDevInfo->Label, 0, sizeof(pDevInfo->Label));
	
	memset(pDevInfo->Manufacturer, 0, sizeof(pDevInfo->Manufacturer));
	memcpy(pDevInfo->Manufacturer,tokenInfo.manufacturerID, sizeof(tokenInfo.manufacturerID));

	pDevInfo->MaxBufferSize = 0;
	pDevInfo->MaxECCBufferSize = 0;
	memset(pDevInfo->Reserved, 0, sizeof(pDevInfo->Reserved));
	memcpy(pDevInfo->SerialNumber,tokenInfo.serialNumber,sizeof(tokenInfo.serialNumber));
	pDevInfo->TotalSpace = tokenInfo.ulTotalPrivateMemory + tokenInfo.ulTotalPublicMemory;
	pDevInfo->Version;

	SKF_LOGD("%s exit with %p", __FUNCTION__, hDev);
	return SAR_OK;		   
}						   

/*
*	获得设备的独占使用权
*	hDev		[IN]连接设备时返回的设备句柄
*	ulTimeOut	[IN]超时时间，单位为毫秒。如果为0xFFFFFFFF表示无限等待
*/
SKF_DEVAPI SKF_LockDev(
IN DEVHANDLE	hDev,
IN ULONG ulTimeOut
)
{
	SKF_LOGD("%s entry with %p", __FUNCTION__, hDev);
	
	if (NULL == hDev){
		SKF_LOGE("%s return 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	HandleCheck handle;
	SKFHandleD_PTR pDev = NULL;

	ULONG ret = handle.Check((SKFHandleD_PTR)hDev);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	SKF_LOGD("%s exit with %p", __FUNCTION__, hDev);
#ifdef WIN32
	return SAR_OK;
#else
	return SAR_NOTSUPPORTYETERR;
#endif
}

/*
*	释放对设备的独占使用权
*	hDev		[IN]连接设备时返回的设备句柄
*/
SKF_DEVAPI SKF_UnlockDev(
IN DEVHANDLE	hDev
)
{
	SKF_LOGD("%s entry with %p", __FUNCTION__, hDev);

	if (NULL == hDev){
		return SAR_INVALIDPARAMERR;
	}

	HandleCheck handle;
	ULONG ret = handle.Check((SKFHandleD_PTR)hDev);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	SKF_LOGD("%s exit with %p", __FUNCTION__, hDev);
#ifdef WIN32
	return SAR_OK;
#else
	return SAR_NOTSUPPORTYETERR;
#endif
}


/************************************************************************/
/*  2. 访问控制				                                            */
/*	SKF_ChangeDevAuthKey												*/
/*	SKF_DevAuth															*/
/*	SKF_ChangePIN														*/
/*	SKF_GetPINInfo														*/
/*	SKF_VerifyPIN														*/
/*	SKF_UnblockPIN														*/
/*	SKF_ClearSecureState												*/
/************************************************************************/

/*
*	更改设备认证密钥
*	hDev		[IN]连接时返回的设备句柄
*	pbKeyValue	[IN]密钥值
*	ulKeyLen	[IN]密钥长度
*/
SKF_DEVAPI SKF_ChangeDevAuthKey(
IN DEVHANDLE	hDev,
IN BYTE		*pbKeyValue,
IN ULONG		ulKeyLen
)
{
	SKF_LOGD("%s entry with %p", __FUNCTION__, hDev);
	
	if (NULL == hDev || NULL == pbKeyValue || ulKeyLen != SM4_KEY_LEN){
		return SAR_INVALIDPARAMERR;
	}

	if (NULL == hDev){
		return SAR_INVALIDPARAMERR;
	}

	HandleCheck handle;
	SKFHandleD_PTR pDev = NULL;

	ULONG ret = handle.Check((SKFHandleD_PTR)hDev);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	if(SKF_FLAG_EXIST == ((SKFHandleD_PTR)hDev)->flg) {
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	if(SKF_FLAG_AUTH_DEV != ((SKFHandleD_PTR)hDev)->flg) {
		SKF_LOGE("%s return 0x%x due device is not authorized", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
		return SAR_USER_NOT_LOGGED_IN;
	}

	CK_ATTRIBUTE attributesFind[] = {
		{ CKA_LABEL, (unsigned char *)SKF_AUTHDEV_LABEL, strlen(SKF_AUTHDEV_LABEL) }
	};

	CK_SESSION_HANDLE session = 0;
	ret = handle.GetSession((SKFHandleD_PTR)hDev, &session);
	if (ret != CKR_OK){
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
		return SAR_FAIL;
	}	
	
	ret = Adapter_C_FindObjectsInit(session, attributesFind, sizeof(attributesFind) / sizeof(CK_ATTRIBUTE));
	if (ret != CKR_OK){
		handle.CloseSession(session);
		SKF_LOGE("%s find obj init get 0x%x", __FUNCTION__, ret);
		return p11Error2SkfError(ret);
	}

	CK_OBJECT_HANDLE objHandle[1] = { 0 };
	CK_ULONG findCount = 0;
	ret = Adapter_C_FindObjects(session,objHandle,1,&findCount);
	if (ret != CKR_OK || findCount == 0){
		handle.CloseSession(session);
		SKF_LOGE("%s find obj get 0x%x", __FUNCTION__, ret);
		return p11Error2SkfError(ret);
	}
	
	ret = Adapter_C_FindObjectsFinal(session);
	if (ret != CKR_OK){
		handle.CloseSession(session);
		SKF_LOGE("%s find obj final get 0x%x", __FUNCTION__, ret);
		return p11Error2SkfError(ret);
	}

	CK_ATTRIBUTE attributesKey[] = {
		{CKA_VALUE,pbKeyValue,ulKeyLen}
	};

	ret = Adapter_C_SetAttributeValue(session,objHandle[0],attributesKey,sizeof(attributesKey) / sizeof(CK_ATTRIBUTE));
	if (ret != CKR_OK){
		handle.CloseSession(session);
		SKF_LOGE("%s update obj get 0x%x", __FUNCTION__, ret);
		return SAR_WRITEFILEERR;
	}

	handle.CloseSession(session);

	SKF_LOGD("%s exit with %p", __FUNCTION__, hDev);
	return SAR_OK;
} 

/*
*	设备认证是设备对应用程序的认证
*	hDev			[IN]连接时返回的设备句柄
*	pbAuthData		[IN]认证数据
*	ulLen			[IN]认证数据的长度
*/
SKF_DEVAPI SKF_DevAuth(
IN DEVHANDLE	hDev,
IN BYTE*		pbAuthData,
IN ULONG		ulLen
)
{
	SKF_LOGD("%s entry with %p", __FUNCTION__, hDev);

	if (hDev == NULL || NULL == pbAuthData || ulLen != 16){
		SKF_LOGE("%s return 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	HandleCheck handle;
	SKFHandleD_PTR pDev = NULL;

	ULONG ret = handle.Check((SKFHandleD_PTR)hDev);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	if(SKF_FLAG_EXIST == ((SKFHandleD_PTR)hDev)->flg) {
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}
	else {
		// reset device state to OPEN
		((SKFHandleD_PTR)hDev)->flg = SKF_FLAG_OPEN;
	}


	CK_BBOOL ttrue = CK_TRUE;
	CK_ATTRIBUTE attributesFind[] = {
		{CKA_LABEL,(unsigned char *)SKF_AUTHDEV_LABEL,strlen(SKF_AUTHDEV_LABEL)},
		{CKA_TOKEN,&ttrue,sizeof(ttrue)}
	};

	CK_SESSION_HANDLE session = 0;
	ret = handle.GetSession((SKFHandleD_PTR)hDev,&session);
	if (ret != CKR_OK){
		SKF_LOGE("get session failed with return 0x%x return 0x%x", ret, SAR_DEVICE_REMOVED);
		return SAR_DEVICE_REMOVED;
	}

	ret = Adapter_C_FindObjectsInit(session, attributesFind, sizeof(attributesFind) / sizeof(CK_ATTRIBUTE));
	if (ret != CKR_OK){
		handle.CloseSession(session);
		SKF_LOGE("%s find obj init get 0x%x return 0x%x", __FUNCTION__, ret, SAR_DEVICE_REMOVED);
		return SAR_DEVICE_REMOVED;
	}

	CK_OBJECT_HANDLE objHandle[1] = { 0 };
	CK_ULONG keyCount = 0;
	ret = Adapter_C_FindObjects(session,objHandle,1,&keyCount);
	if (ret != CKR_OK){
		handle.CloseSession(session);
		SKF_LOGE("%s find obj get 0x%x return 0x%x", __FUNCTION__, ret, SAR_DEVICE_REMOVED);
		return SAR_DEVICE_REMOVED;
	}
	else {
		SKF_LOGD("%s find obj get key %d with handle 0x%x", __FUNCTION__, keyCount, objHandle[0]);
	}

	ret = Adapter_C_FindObjectsFinal(session);
	if (ret != CKR_OK){
		handle.CloseSession(session);
		SKF_LOGE("%s find obj final get 0x%x return 0x%x", __FUNCTION__, ret, SAR_DEVICE_REMOVED);
		return SAR_DEVICE_REMOVED;
	}

	//auth key has not exist & create it
	if (keyCount == 0){
		CK_KEY_TYPE keyType = CKK_SM4;
		CK_OBJECT_CLASS symmKeyClass = CKO_SECRET_KEY;
		CK_ATTRIBUTE attributesCreate[] = {
			{ CKA_CLASS, &symmKeyClass, sizeof(CK_OBJECT_CLASS) },
			{ CKA_LABEL, (unsigned char *)SKF_AUTHDEV_LABEL, strlen(SKF_AUTHDEV_LABEL) },
			{ CKA_ENCRYPT, &ttrue, sizeof(ttrue) },
			{ CKA_DECRYPT, &ttrue, sizeof(ttrue) },
			{ CKA_TOKEN, &ttrue, sizeof(ttrue) },
			{CKA_VALUE,(unsigned char *)"1234567812345678",strlen("1234567812345678")},
			{CKA_KEY_TYPE,&keyType,sizeof(keyType)}
		};

		ret = Adapter_C_CreateObject(session,attributesCreate,sizeof(attributesCreate) / sizeof(CK_ATTRIBUTE),&objHandle[0]);
		if (ret != CKR_OK){
			handle.CloseSession(session);
			SKF_LOGE("%s create obj get 0x%x return 0x%x", __FUNCTION__, ret, SAR_DEVICE_REMOVED);
			return SAR_DEVICE_REMOVED;
		}
		else {
			SKF_LOGD("%s create obj get 0x%x", __FUNCTION__, objHandle[0]);
		}
	}
	
	CK_MECHANISM mechanism = {CKM_SM4_ECB,NULL,0};
	ret = Adapter_C_DecryptInit(session, &mechanism, objHandle[0]);
	if (ret != CKR_OK) {
		handle.CloseSession(session);
		SKF_LOGE("%s auth init get 0x%x return 0x%x", __FUNCTION__, ret, SAR_DEVICE_REMOVED);
		return SAR_DEVICE_REMOVED;
	}


	CK_BYTE_PTR pOut = NULL;
	CK_ULONG ulDataLen = 0;
	ret = Adapter_C_Decrypt(session, pbAuthData, ulLen, pOut, &ulDataLen);
	if (ret != CKR_OK) {
		handle.CloseSession(session);
		SKF_LOGE("%s auth get 0x%x return 0x%x", __FUNCTION__, ret, SAR_DEVICE_REMOVED);
		return SAR_DEVICE_REMOVED;
	}

	pOut = new CK_BYTE[ulDataLen];
	ret = Adapter_C_Decrypt(session, pbAuthData, ulLen, pOut, &ulDataLen);
	if (ret != CKR_OK) {
		delete[]pOut;
		handle.CloseSession(session);
		SKF_LOGE("%s auth get 0x%x return 0x%x", __FUNCTION__, ret, SAR_DEVICE_REMOVED);
		return SAR_DEVICE_REMOVED;
	}

	if(SM4_KEY_LEN != ulDataLen) {
		delete[]pOut;
		SKF_LOGE("%s auth length error return 0x%x", __FUNCTION__, SAR_FAIL);
		return SAR_FAIL;
	}

	if(memcmp(pOut, ((SKFHandleD_PTR)hDev)->devAuthPlain, SM4_KEY_LEN)) {
		delete[]pOut;
		SKF_LOGE("%s auth error return 0x%x", __FUNCTION__, SAR_FAIL);
		return SAR_FAIL;
	}

	delete[]pOut;

	handle.CloseSession(session);

	// update device status
	((SKFHandleD_PTR)hDev)->flg = SKF_FLAG_AUTH_DEV;

	SKF_LOGD("%s exit with %p", __FUNCTION__, hDev);
	return SAR_OK;
}

/*
*	修改PIN，可以修改Admin和User的PIN，如果原PIN错误，返回剩余重试次数，当剩余次数为0时，表示PIN已经被锁死
*	hApplication	[IN]应用句柄
*	ulPINType		[IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
*	szOldPIN		[IN]原PIN值
*	szNewPIN		[IN]新PIN值
*	pulRetryCount	[OUT]出错后重试次数
*/
SKF_DEVAPI SKF_ChangePIN(
IN HAPPLICATION	hApplication,
IN ULONG			ulPINType,
IN LPSTR			szOldPIN,
IN LPSTR			szNewPIN,
OUT ULONG*		pulRetryCount
)
{
	ULONG pinVerifyRet = SAR_OK;
	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);
	
	if (NULL == hApplication || \
		NULL == szOldPIN || \
		NULL == szNewPIN || \
		NULL == pulRetryCount ){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	if (ulPINType != ADMIN_TYPE && ulPINType != USER_TYPE) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_USER_TYPE_INVALID);
		SAR_USER_TYPE_INVALID ;
	}

	HandleCheck handle;
	ULONG ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return ret;
	}

	// check if application open
	if (SKF_FLAG_EXIST == ((SKFHandleA_PTR)hApplication)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	SKF_LOGV("type %d, old %s, new %s", ulPINType, szOldPIN, szNewPIN);

	SKFHandleA_PTR tmp = (SKFHandleA_PTR)hApplication;
	if (ulPINType == ADMIN_TYPE){

		// check if PIN already locked. return directly if locked
		if (0 == tmp->appValue.soPinAlreadyCount) {
			*pulRetryCount = 0;
			SKF_LOGE("%s pin already locked exit 0x%x", __FUNCTION__, SAR_PIN_LOCKED);
			return SAR_PIN_LOCKED;
		}
		
		if (tmp->appValue.soPinlen == strlen(szOldPIN) && \
			0 == memcmp(tmp->appValue.soPin, szOldPIN, strlen(szOldPIN))){

			delete[] tmp->appValue.soPin;
			tmp->appValue.soPin = new CHAR[strlen(szNewPIN)];
			memcpy(tmp->appValue.soPin,szNewPIN, strlen(szNewPIN));
			tmp->appValue.soPinlen = strlen(szNewPIN);
			tmp->appValue.soPinAlreadyCount = tmp->appValue.soPinMaxCount;
			*pulRetryCount = tmp->appValue.soPinMaxCount;
			pinVerifyRet = SAR_OK; 
		}
		else{
			if (tmp->appValue.soPinAlreadyCount <= 1){
				tmp->appValue.soPinAlreadyCount = 0;
				*pulRetryCount = 0;
				SKF_LOGE("%s pin locked exit 0x%x", __FUNCTION__, SAR_PIN_LOCKED);
				pinVerifyRet = SAR_PIN_LOCKED;
			}
			else
			{
				tmp->appValue.soPinAlreadyCount--;
				*pulRetryCount = tmp->appValue.soPinAlreadyCount;
				SKF_LOGE("%s pin incorrect exit 0x%x", __FUNCTION__, SAR_PIN_INCORRECT);
				pinVerifyRet = SAR_PIN_INCORRECT;
			}
		}
	}
	else
	{
		// check if PIN already locked. return directly if locked
		if (0 == tmp->appValue.usrPinAlreadyCount) {
			*pulRetryCount = 0;
			SKF_LOGE("%s pin already locked exit 0x%x", __FUNCTION__, SAR_PIN_LOCKED);
			return SAR_PIN_LOCKED;
		}
		
		if (tmp->appValue.usrPinlen == strlen(szOldPIN) && \
			0 == memcmp(tmp->appValue.usrPin, szOldPIN, strlen(szOldPIN))){

			delete[] tmp->appValue.usrPin;
			tmp->appValue.usrPin = new CHAR[strlen(szNewPIN)];
			memcpy(tmp->appValue.usrPin,szNewPIN, strlen(szNewPIN));
			tmp->appValue.usrPinlen = strlen(szNewPIN);
			tmp->appValue.usrPinAlreadyCount = tmp->appValue.usrPinMaxCount;
			*pulRetryCount = tmp->appValue.usrPinMaxCount;
			pinVerifyRet = SAR_OK;
		}
		else{
			if (tmp->appValue.usrPinAlreadyCount <= 1){
				tmp->appValue.usrPinAlreadyCount = 0;
				*pulRetryCount = 0;
				SKF_LOGE("%s pin locked exit 0x%x", __FUNCTION__, SAR_PIN_LOCKED);
				pinVerifyRet = SAR_PIN_LOCKED;
			}
			else
			{
				tmp->appValue.usrPinAlreadyCount--;
				*pulRetryCount = tmp->appValue.usrPinAlreadyCount;
				SKF_LOGE("%s pin incorrect exit 0x%x", __FUNCTION__, SAR_PIN_INCORRECT);
				pinVerifyRet = SAR_PIN_INCORRECT;
			}
		}
	}

	CK_SESSION_HANDLE session = 0;
	ret = handle.GetSession((SKFHandleA_PTR)hApplication,&session);
	if (ret != SAR_OK){
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
		return SAR_FAIL;
	}

	string out;
	string &rout = out;
	SerializationSKFValueApplication(&tmp->appValue,rout);
	
	CK_ATTRIBUTE newValue[] = {
		{CKA_VALUE,(CK_VOID_PTR)out.data(),out.size()}
	};

	ret = Adapter_C_SetAttributeValue(session, tmp->appHandle, newValue, sizeof(newValue) / sizeof(CK_ATTRIBUTE));
	if (CKR_OK != ret) {
		SKF_LOGE("%s update log in infor exit 0x%x", __FUNCTION__, ret);
		return p11Error2SkfError(ret);
	}

	handle.CloseSession(session);

	SKF_LOGD("%s exit with %p", __FUNCTION__, hApplication);
	return pinVerifyRet;
}

/*
*	获取PIN码信息，包括最大重试次数、当前剩余重试次数，以及当前PIN码是否为出厂默认PIN码
*	hApplication		[IN]应用句柄
*	ulPINType			[IN]PIN类型
*	pulMaxRetryCount	[OUT]最大重试次数
*	pulRemainRetryCount	[OUT]当前剩余重试次数，当为0时表示已锁死
*	pbDefaultPin		[OUT]是否为出厂默认PIN码
*/
SKF_DEVAPI SKF_GetPINInfo(
IN HAPPLICATION	hApplication,
IN ULONG			ulPINType,
OUT ULONG*		pulMaxRetryCount,
OUT ULONG*		pulRemainRetryCount,
OUT BOOL*			pbDefaultPin
)
{
	SKF_LOGD("%s entry with %p for type %d", __FUNCTION__, hApplication, ulPINType);
	
	if (NULL == hApplication || NULL == pulMaxRetryCount  \
		|| NULL == pulRemainRetryCount || NULL == pbDefaultPin){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	if (ulPINType != ADMIN_TYPE && ulPINType != USER_TYPE) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_USER_TYPE_INVALID);
		SAR_USER_TYPE_INVALID ;
	}

	HandleCheck handle;
	ULONG ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return ret;
	}

	// check if application open
	if (SKF_FLAG_EXIST == ((SKFHandleA_PTR)hApplication)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}
	
	SKFHandleA_PTR tmp = (SKFHandleA_PTR)hApplication;
	if (ulPINType == ADMIN_TYPE){
		*pulMaxRetryCount = tmp->appValue.soPinMaxCount;
		*pulRemainRetryCount = tmp->appValue.soPinAlreadyCount;
		*pbDefaultPin = false;
		if (tmp->appValue.soDefaultPinlen == tmp->appValue.soPinlen  && \
			0 == memcmp(tmp->appValue.soDefaultPin, tmp->appValue.soPin, tmp->appValue.soPinlen)){
			*pbDefaultPin = true;
		}
	}
	else
	{
		*pulMaxRetryCount = tmp->appValue.usrPinMaxCount;
		*pulRemainRetryCount = tmp->appValue.usrPinAlreadyCount;
		*pbDefaultPin = false;
		if (tmp->appValue.usrDefaultPinlen == tmp->appValue.usrPinlen  && \
			0 == memcmp(tmp->appValue.usrPin, tmp->appValue.usrDefaultPin, tmp->appValue.usrPinlen)){
			*pbDefaultPin = true;
		}
	}

	SKF_LOGD("%s exit with %p", __FUNCTION__, hApplication);
	return SAR_OK;
}

/*
*	校验PIN码。校验成功后，会获得相应的权限，如果PIN码错误，会返回PIN码的重试次数，当重试次数为0时表示PIN码已经锁死
*	hApplication	[IN]应用句柄
*	ulPINType		[IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
*	szPIN			[IN]PIN值
*	pulRetryCount	[OUT]出错后返回的重试次数
*/
SKF_DEVAPI SKF_VerifyPIN(
IN HAPPLICATION	hApplication,
IN ULONG			ulPINType,
IN LPSTR			szPIN,
OUT ULONG*		pulRetryCount
)
{
	ULONG verifyResult = SAR_OK;

	set<SKFHandleC_PTR>::iterator itC;
	SKFHandleA_PTR tmp = (SKFHandleA_PTR)hApplication;
	SKFHandleC_PTR tempContainerHandle = NULL;

	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);
	
	if (NULL == hApplication || NULL == szPIN || NULL == pulRetryCount){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	if (ulPINType != ADMIN_TYPE && ulPINType != USER_TYPE) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_USER_TYPE_INVALID);
		return SAR_USER_TYPE_INVALID ;
	}

	HandleCheck handle;
	ULONG ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return ret;
	}

	// check if app handle is open
	if (SKF_FLAG_EXIST == tmp->flg) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// shall clear app/container history state when verify pin
	// destroy session key as well
	/*ret = SKF_ClearSecureState(hApplication);
	if(SAR_OK != ret) {
		SKF_LOGE("%s exit 0x%x due clear secure state error", __FUNCTION__, ret);
		return ret;
	}
*/
	SKF_LOGV("type %d, input %s", ulPINType, szPIN);

	if (ulPINType == ADMIN_TYPE){
		// check if PIN already locked. return directly if locked
		if (0 == tmp->appValue.soPinAlreadyCount) {
			*pulRetryCount = 0;
			SKF_LOGE("%s pin already locked exit 0x%x", __FUNCTION__, SAR_PIN_LOCKED);
			return SAR_PIN_LOCKED;
		}

		// continue to check PIN if not locked yet
		if (tmp->appValue.soPinlen == strlen(szPIN) && \
			0 == memcmp(szPIN, tmp->appValue.soPin, strlen(szPIN))){
			*pulRetryCount = tmp->appValue.soPinAlreadyCount = tmp->appValue.soPinMaxCount;
			//tmp->flg = SKF_FLAG_AUTH_ADM;
			verifyResult = SAR_OK;
		}
		else{
				verifyResult = SAR_PIN_INCORRECT;
				SKF_LOGW("%s pin incorrect exit 0x%x", __FUNCTION__, SAR_PIN_INCORRECT);
				if (tmp->appValue.soPinAlreadyCount <= 1){
					*pulRetryCount = tmp->appValue.soPinAlreadyCount = 0;
					SKF_LOGE("%s pin locked exit 0x%x", __FUNCTION__, SAR_PIN_LOCKED);
					verifyResult = SAR_PIN_LOCKED;
				}
				else {
					tmp->appValue.soPinAlreadyCount--;
					*pulRetryCount = tmp->appValue.soPinAlreadyCount;
				}				
		}
	}
	else
	{
		// check if PIN already locked. return directly if locked
		if (0 == tmp->appValue.usrPinAlreadyCount) {
			*pulRetryCount = 0;
			SKF_LOGE("%s pin already locked exit 0x%x", __FUNCTION__, SAR_PIN_LOCKED);
			return SAR_PIN_LOCKED;
		}

		// continue to check PIN if not locked yet
		if (tmp->appValue.usrPinlen == strlen(szPIN) && \
			0 == memcmp(szPIN, tmp->appValue.usrPin, strlen(szPIN))){
			*pulRetryCount = tmp->appValue.usrPinAlreadyCount = tmp->appValue.usrPinMaxCount;
			//tmp->flg = SKF_FLAG_AUTH_USR;
			verifyResult = SAR_OK;
		}
		else{
			verifyResult = SAR_PIN_INCORRECT;
			SKF_LOGW("%s pin incorrect exit 0x%x", __FUNCTION__, SAR_PIN_INCORRECT);
			if (tmp->appValue.usrPinAlreadyCount <= 1){
				*pulRetryCount = tmp->appValue.usrPinAlreadyCount = 0;
				SKF_LOGE("%s pin locked exit 0x%x", __FUNCTION__, SAR_PIN_LOCKED);
				verifyResult = SAR_PIN_LOCKED;
			}
			else {
				tmp->appValue.usrPinAlreadyCount--;
				*pulRetryCount = tmp->appValue.usrPinAlreadyCount;
			}
		}
	}

	// update buffer information and p11 data object no matter verify pass or not
	string dst;
	string &rdst = dst;
	ret = SerializationSKFValueApplication(&tmp->appValue,rdst);
	if (ret != SAR_OK){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, ret);
		return ret;
	}
	
	CK_ATTRIBUTE newValue[] = {
		{CKA_VALUE,(CK_VOID_PTR)dst.data(),dst.size()}
	};

	CK_SESSION_HANDLE session = 0;
	ret = handle.GetSession((SKFHandleA_PTR)hApplication, &session);
	if (ret != SAR_OK){
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
		return SAR_FAIL;
	}
	ret = Adapter_C_SetAttributeValue(session, tmp->appHandle, newValue, sizeof(newValue) / sizeof(CK_ATTRIBUTE));
	if (ret != SAR_OK){
		handle.CloseSession(session);
		SKF_LOGE("%s update infor error exit 0x%x", __FUNCTION__, ret);
		return p11Error2SkfError(ret);
	}
	
	handle.CloseSession(session);

	if (SAR_OK == verifyResult) {
		// verify pin succeed, update application status to authorized
		if (ulPINType == ADMIN_TYPE){
			tmp->flg = SKF_FLAG_AUTH_ADM;
		}
		else {
			tmp->flg = SKF_FLAG_AUTH_USR;
		}
		
		// update container status to AUTH
		itC = SKFGlobeData::setContainerHandle.begin();
		for (; itC != SKFGlobeData::setContainerHandle.end();){
			if ((*itC)->pAppHandle == tmp) {
				tempContainerHandle = *itC;
				tempContainerHandle->flg = tmp->flg;
			}
			itC++;
		}
	}

	SKF_LOGD("%s exit with %p", __FUNCTION__, hApplication);
	
	return verifyResult;
}

/*
*	当用户的PIN码锁死后，通过调用该函数来解锁用户PIN码。
*	解锁后，用户PIN码被设置成新值，用户PIN码的重试次数也恢复到原值。
*	hApplication	[IN]应用句柄
*	szAdminPIN		[IN]管理员PIN码
*	szNewUserPIN	[IN]新的用户PIN码
*	pulRetryCount	[OUT]管理员PIN码错误时，返回剩余重试次数
*/
SKF_DEVAPI SKF_UnblockPIN(
IN HAPPLICATION	hApplication,
IN LPSTR			szAdminPIN,
IN LPSTR			szNewUserPIN,
OUT ULONG*		pulRetryCount
)
{
	ULONG verifyResult = SAR_OK;

	set<SKFHandleC_PTR>::iterator itC;
	SKFHandleA_PTR tempAppHandle = (SKFHandleA_PTR)hApplication;
	SKFHandleC_PTR tempContHandle = NULL;
	
	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);
	
	if (NULL == hApplication || NULL == szNewUserPIN || \
		NULL == szAdminPIN || NULL == pulRetryCount){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	HandleCheck handle;
	ULONG ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return ret;
	}

	// check if app handle is open
	if (SKF_FLAG_EXIST == tempAppHandle->flg) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	SKF_LOGV("%s, %s", szAdminPIN, szNewUserPIN);

	// always reset app status before verify pin
	tempAppHandle->flg = SKF_FLAG_OPEN;
	// reset container status for current app
	itC = SKFGlobeData::setContainerHandle.begin();
	for (; itC != SKFGlobeData::setContainerHandle.end(); ){
		if ((*itC)->pAppHandle == tempAppHandle) {
			tempContHandle = *itC;
			tempContHandle->flg = SKF_FLAG_OPEN;
		}
		itC++;
	}

	// verify if admin PIN correct...
	// check if PIN already locked. return directly if locked
	if (0 == tempAppHandle->appValue.soPinAlreadyCount) {
		*pulRetryCount = 0;
		SKF_LOGE("%s admin pin already locked exit 0x%x", __FUNCTION__, SAR_PIN_LOCKED);
		return SAR_PIN_LOCKED;
	}
	// continue to check PIN if not locked yet
	if (tempAppHandle->appValue.soPinlen == strlen(szAdminPIN) && \
		0 == memcmp(szAdminPIN, tempAppHandle->appValue.soPin, strlen(szAdminPIN))){
		*pulRetryCount = tempAppHandle->appValue.soPinAlreadyCount = tempAppHandle->appValue.soPinMaxCount;
		verifyResult = SAR_OK;
	}
	else{
		verifyResult = SAR_PIN_INCORRECT;
		SKF_LOGW("%s pin incorrect exit 0x%x", __FUNCTION__, SAR_PIN_INCORRECT);
		if (tempAppHandle->appValue.soPinAlreadyCount <= 1){
			*pulRetryCount = tempAppHandle->appValue.soPinAlreadyCount = 0;
			SKF_LOGE("%s pin locked exit 0x%x", __FUNCTION__, SAR_PIN_LOCKED);
			verifyResult = SAR_PIN_LOCKED;
		}
		else {
			tempAppHandle->appValue.soPinAlreadyCount--;
			*pulRetryCount = tempAppHandle->appValue.soPinAlreadyCount;
		}				
	}
	// end of verify admin PIN

	// unblock user PIN if admin PIN check pass
	if (SAR_OK == verifyResult) {
		// free old buffer
		if (tempAppHandle->appValue.usrPin) {
			delete[] tempAppHandle->appValue.usrPin;
		}
		tempAppHandle->appValue.usrPin = new CHAR[strlen(szNewUserPIN)];
		memcpy(tempAppHandle->appValue.usrPin,szNewUserPIN, strlen(szNewUserPIN));
		tempAppHandle->appValue.usrPinlen = strlen(szNewUserPIN);
		tempAppHandle->appValue.usrPinAlreadyCount = tempAppHandle->appValue.usrPinMaxCount;
	}

	// update buffer information and p11 data object no matter verify pass or not
	string dst;
	string &rdst = dst;
	ret = SerializationSKFValueApplication(&tempAppHandle->appValue,rdst);
	if (ret != SAR_OK){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, ret);
		return ret;
	}
	
	CK_ATTRIBUTE newValue[] = {
		{CKA_VALUE,(CK_VOID_PTR)dst.data(),dst.size()}
	};

	CK_SESSION_HANDLE session = 0;
	ret = handle.GetSession((SKFHandleA_PTR)hApplication, &session);
	if (ret != SAR_OK){
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
		return SAR_FAIL;
	}
	ret = Adapter_C_SetAttributeValue(session, tempAppHandle->appHandle, newValue, sizeof(newValue) / sizeof(CK_ATTRIBUTE));
	if (ret != SAR_OK){
		handle.CloseSession(session);
		SKF_LOGE("%s update infor error exit 0x%x", __FUNCTION__, ret);
		return p11Error2SkfError(ret);
	}
	
	handle.CloseSession(session);

	SKF_LOGD("%s exit with %p", __FUNCTION__, hApplication);

	return verifyResult;
}

/*
*	清除应用当前的安全状态
*	hApplication	[IN]应用句柄
*/
SKF_DEVAPI SKF_ClearSecureState(
IN HAPPLICATION	hApplication
)
{
	// clear application login status
	// similar operation as SKF_CloseApplication except update application/container flg to SKF_FLAG_OPEN
	ULONG ret_skf = SAR_OK;
	CK_RV ret_p11 = CKR_OK;

	set<SKFHandleC_PTR>::iterator itC;
	set<SKFHandleF_PTR>::iterator itF;
	set<SKFHandleSYM_PTR>::iterator itSK;
	set<SKFHandleCT_PTR>::iterator itCT;

	SKFHandleA_PTR tempApplicationHandle = (SKFHandleA_PTR)hApplication;
	SKFHandleC_PTR tempContainerHandle = NULL;
	SKFHandleSYM_PTR tempSessionKeyHandle = NULL;
	SKFHandleCT_PTR tempCertificationHandle = NULL;
	HandleCheck handle;

	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);
	
	if (NULL == hApplication){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}
	

	CK_RV ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (ret != CKR_OK) {
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	// check if application open
	if (SKF_FLAG_EXIST == ((SKFHandleA_PTR)hApplication)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// clean up session key information created within target application scope
	// ======================== start to destroy session key information =========================
	for (itSK = SKFGlobeData::setSessionKeyHandle.begin(); itSK != SKFGlobeData::setSessionKeyHandle.end(); ){
		if (((*itSK)->pContainerHandle) && ((*itSK)->pContainerHandle->pAppHandle == tempApplicationHandle)) {
			tempSessionKeyHandle =  *itSK;
			if (SGD_SM3 != tempSessionKeyHandle->ulAlgId) {
				// destroy session object as these shall be invalid after device disconnect
				// SM3 for hash calculation, no destroy operation
				ret_p11 = Adapter_C_DestroyObject(tempSessionKeyHandle->session, tempSessionKeyHandle->sessKeyHandle);
				if(CKR_OK != ret_p11) {
					SKF_LOGE("destroy session key failed with return 0x%x", ret_p11);
					ret_skf = SAR_FAIL;
					break;
				}
			}

			// close session bind with key
			ret_p11 = Adapter_C_CloseSession(tempSessionKeyHandle->session);
			if(CKR_OK != ret_p11) {
				SKF_LOGE("close session failed with return 0x%x", ret_p11);
				ret_skf = SAR_FAIL;
				break;
			}

			// remove handle from set
			// itSK must ++ here, cannot be put into for(;;itSK++)
			SKFGlobeData::setSessionKeyHandle.erase(itSK++);

			// release handle memory
			delete tempSessionKeyHandle;
			tempSessionKeyHandle = NULL;
		}
		else {
			itSK++;
		}
	}
	// unexpected error, return;
	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s destroy session key failed with return 0x%x", __FUNCTION__, ret_skf);
		return ret_skf;
	}
	// ======================== end of destroy session key information =========================

	// ======================== update container status in target applicatoin scope =========================
	itC = SKFGlobeData::setContainerHandle.begin();
	for (; itC != SKFGlobeData::setContainerHandle.end(); ){
		if ((*itC)->pAppHandle == tempApplicationHandle) {
			tempContainerHandle = *itC;
			tempContainerHandle->flg = SKF_FLAG_OPEN;
		}
		itC++;
	}
			
	// update application status, keep application buffer information
	tempApplicationHandle->flg = SKF_FLAG_OPEN;
	
	SKF_LOGD("%s exit with %p", __FUNCTION__, hApplication);

	return SAR_OK;
}

/************************************************************************/
/*  3. 应用管理				                                            */
/*	SKF_CreateApplication												*/
/*	SKF_EnumApplication													*/
/*	SKF_DeleteApplication												*/
/*	SKF_OpenApplication													*/
/*	SKF_CloseApplication												*/
/************************************************************************/

/*
*	创建一个应用
*	hDev					[IN]连接设备时返回的设备句柄
*	szAppName				[IN]应用名称
*	szAdminPIN				[IN]管理员PIN
*	dwAdminPinRetryCount	[IN]管理员PIN最大重试次数
*	szUserPIN				[IN]用户PIN
*	dwAdminPinRetryCount	[IN]用户PIN最大重试次数
*	dwCreateFileRights		[IN]在该应用下创建文件和容器的权限
*	phApplication			[OUT]应用的句柄
*/
SKF_DEVAPI SKF_CreateApplication(
IN DEVHANDLE		hDev,
IN LPSTR			szAppName,
IN LPSTR			szAdminPIN,
IN DWORD			dwAdminPinRetryCount,
IN LPSTR			szUserPIN,
IN DWORD			dwUserPinRetryCount,
IN DWORD			dwCreateFileRights,
OUT HAPPLICATION*	phApplication
)
{
	ULONG ret_skf = SAR_OK;
	HandleCheck handle;
	string aName;
	CK_OBJECT_HANDLE appHandle = 0;

	SKF_LOGD("%s entry with %p", __FUNCTION__, hDev);
	
	if (NULL == hDev || NULL == szAppName ||
		NULL == szAdminPIN ||
		strlen(szAdminPIN) >= 0xFF ||
		dwAdminPinRetryCount >= 0xFF ||
		szUserPIN == NULL ||
		strlen(szUserPIN) >= 0xFF ||
		dwUserPinRetryCount >= 0xFF ||
		dwCreateFileRights > 0xFF ||
		NULL == phApplication){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	SKF_LOGV("name %s, pin %s(%d), pin %s(%d), right %d", szAppName, szAdminPIN, dwAdminPinRetryCount, szUserPIN, dwUserPinRetryCount, dwCreateFileRights);

	// check if device is authorized to create application
	ret_skf = SAR_INVALIDHANDLEERR;
	set<SKFHandleD_PTR>::iterator itD = SKFGlobeData::setDevHandle.begin();
	while (itD != SKFGlobeData::setDevHandle.end()){
		if ((*itD) == hDev){
			if(SKF_FLAG_AUTH_DEV == (*itD)->flg) {
				ret_skf = SAR_OK;
			}
			else if (SKF_FLAG_OPEN == (*itD)->flg) {
				SKF_LOGW("%s exit 0x%x due to dev not authorized", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
				// DevAuth not run firstly...
				ret_skf = SAR_USER_NOT_LOGGED_IN;
			}
			else {
				SKF_LOGW("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
				// device not connect yet
				ret_skf = SAR_INVALIDHANDLEERR;
			}
			
			break;
		}
		itD++;
	}

	// check device auth failed, return directly
	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, ret_skf);
		return ret_skf;
	}
	
	aName.append(szAppName);

	set<SKFHandleA_PTR>::iterator itA = SKFGlobeData::setAppHandle.begin();
	for (; itA != SKFGlobeData::setAppHandle.end();itA++){
		if ((*itA)->appName == aName && (*itA)->pDevHandle == hDev){
			SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_APPLICATION_EXISTS);
			return SAR_APPLICATION_EXISTS;
		}
	}

	CK_SESSION_HANDLE session = 0;
	CK_BBOOL ttrue = CK_TRUE, ffalse = CK_FALSE;
	CK_OBJECT_CLASS dataClass = CKO_DATA;
	CK_ATTRIBUTE attributesCreate[] = {
		{ CKA_CLASS, &dataClass, sizeof(dataClass) },
		{ CKA_APPLICATION, (unsigned char *)SKF_APP_APPLICATION_DESC, strlen(SKF_APP_APPLICATION_DESC) },
		{ CKA_LABEL, szAppName, strlen(szAppName) },
		{ CKA_TOKEN, &ttrue, sizeof(ttrue) },
		{ CKA_PRIVATE, &ttrue, sizeof(ttrue) },
		{ CKA_VALUE,NULL,0}
	};

	ret_skf = handle.GetSession((SKFHandleD_PTR)hDev, &session);
	if (SAR_OK != ret_skf){
		SKF_LOGE("get session failed with return 0x%x", ret_skf);
		return ret_skf;
	}

	ret_skf = Adapter_C_CreateObject(session, attributesCreate, sizeof(attributesCreate) / sizeof(CK_ATTRIBUTE), &appHandle);
	if (SAR_OK != ret_skf){
		handle.CloseSession(session);
		SKF_LOGE("%s create obj get 0x%x and return 0x%x", __FUNCTION__, ret_skf, SAR_OBJERR);
		return SAR_OBJERR;
	}

	SKFHandleA_PTR app = new SKFHandleA();
//	memset(app, 0, sizeof(SKFHandleA));
	app->pDevHandle = NULL;
	app->flg = 0;
	app->appName = "";
	app->appHandle = NULL;
	memset(&app->appValue,0,sizeof(SKFValueApplication));

	app->appName.append(szAppName, strlen(szAppName));
	app->pDevHandle = (SKFHandleD_PTR)hDev;
	
	app->appValue.soPinlen = strlen(szAdminPIN);
	app->appValue.soPin = (LPSTR)new CK_BYTE[app->appValue.soPinlen];
	memcpy(app->appValue.soPin,szAdminPIN, strlen(szAdminPIN));

	app->appValue.soDefaultPinlen = strlen(szAdminPIN);
	app->appValue.soDefaultPin = (LPSTR)new CK_BYTE[strlen(szAdminPIN)];
	memcpy(app->appValue.soDefaultPin,szAdminPIN, strlen(szAdminPIN));


	app->appValue.soPinMaxCount = dwAdminPinRetryCount;
	app->appValue.soPinAlreadyCount = dwAdminPinRetryCount;
	
	app->appValue.usrPinlen = strlen(szUserPIN);
	app->appValue.usrPin = (LPSTR)new CK_BYTE[app->appValue.usrPinlen];
	memcpy(app->appValue.usrPin, szUserPIN, strlen(szUserPIN));
	
	app->appValue.usrDefaultPinlen = strlen(szUserPIN);
	app->appValue.usrDefaultPin = (LPSTR)new CK_BYTE[strlen(szUserPIN)];
	memcpy(app->appValue.usrDefaultPin,szUserPIN, strlen(szUserPIN));

	app->appValue.usrPinMaxCount = dwUserPinRetryCount;
	app->appValue.usrPinAlreadyCount = dwUserPinRetryCount;
	app->appValue.rights = dwCreateFileRights;
	
	string appValue;
	string &rappValue = appValue;
	ret_skf = SerializationSKFValueApplication(&app->appValue, rappValue);
	if (SAR_OK != ret_skf){
		SKF_LOGE("%s serialize error return 0x%x", __FUNCTION__, ret_skf);
		delete[] app->appValue.soPin;
		app->appValue.soPin = NULL;

		delete[] app->appValue.soDefaultPin;
		app->appValue.soDefaultPin = NULL;

		delete[] app->appValue.usrPin;
		app->appValue.usrPin = NULL;

		delete[] app->appValue.usrDefaultPin;
		app->appValue.usrDefaultPin = NULL;

		delete app;
		handle.CloseSession(session);
		return ret_skf;
	}

	CK_ATTRIBUTE newValue[] = {
		{CKA_VALUE,(CK_VOID_PTR)appValue.data(),appValue.size()}
	};

	ret_skf = Adapter_C_SetAttributeValue(session, appHandle, newValue, sizeof(newValue) / sizeof(CK_ATTRIBUTE));
	if (SAR_OK != ret_skf){
		SKF_LOGE("%s update obj get 0x%x and return 0x%x", __FUNCTION__, ret_skf, SAR_OBJERR);
		
		delete[] app->appValue.soPin;
		app->appValue.soPin = NULL;

		delete[] app->appValue.soDefaultPin;
		app->appValue.soDefaultPin = NULL;

		delete[] app->appValue.usrPin;
		app->appValue.usrPin = NULL;

		delete[] app->appValue.usrDefaultPin;
		app->appValue.usrDefaultPin = NULL;

		delete app;
		handle.CloseSession(session);
		return SAR_OBJERR;
	}

	app->appHandle = appHandle;
	app->flg = SKF_FLAG_OPEN;
	SKFGlobeData::setAppHandle.insert(app);
	*phApplication = app;

	handle.CloseSession(session);

	SKF_LOGD("%s entry with %p", __FUNCTION__, app);
	
	return SAR_OK;
}

/*
*	枚举设备中所存在的所有应用
*	hDev			[IN]连接设备时返回的设备句柄
*	szAppName		[OUT]返回应用名称列表, 如果该参数为空，将由pulSize返回所需要的内存空间大小。
*						 每个应用的名称以单个'\0'结束，以双'\0'表示列表的结束。
*	pulSize			[IN,OUT]输入参数，输入应用名称的缓冲区长度，输出参数，返回szAppName所占用的的空间大小
*/
SKF_DEVAPI SKF_EnumApplication(
IN DEVHANDLE		hDev,
OUT LPSTR			szAppName,
OUT ULONG*		pulSize
)
{
	SKF_LOGD("%s entry with %p", __FUNCTION__, hDev);
	
	if (NULL == hDev || NULL == pulSize){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	HandleCheck handle;

	CK_RV ret = handle.Check((SKFHandleD_PTR)hDev);
	if (ret != CKR_OK) {
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}
	
#if 0
	// device shall be in OPEN or AUTH state
	if(SKF_FLAG_EXIST == (SKFHandleD_PTR)hDev->flg) {
		return SAR_INVALIDHANDLEERR;
	}
#endif

	string out;
	char pad[1] = { 0 };

	ULONG appCount = 0;

	set<SKFHandleA_PTR>::iterator it = SKFGlobeData::setAppHandle.begin();
	for (; it != SKFGlobeData::setAppHandle.end(); it++){
		if((*it)->pDevHandle == hDev) {
		out.append((*it)->appName);
		out.append(pad,1);
		appCount++;
		}
	}
	out.append(pad, 1);

	if (0 == appCount){
		*pulSize = 0;
	}
	else
	{
		// check if input buffer enough to hold all output
		if((szAppName) && (*pulSize < out.size())) {
			SKF_LOGE("%s exit with 0x%x", __FUNCTION__, SAR_BUFFER_TOO_SMALL);
			*pulSize = out.size();
			return SAR_BUFFER_TOO_SMALL;
		}
		
		*pulSize = out.size();
		if (NULL != szAppName){
			memcpy(szAppName,out.data(),out.size());
			logData((unsigned char *)szAppName, out.size(), plog_verbose, "app enum result:");
		}
	}

	listSkfHandle();
	
	SKF_LOGD("%s exit with %p", __FUNCTION__, hDev);
	return SAR_OK;
}

/*
*	删除指定的应用
*	hDev			[IN]连接设备时返回的设备句柄
*	szAppName		[IN]应用名称
*/
SKF_DEVAPI SKF_DeleteApplication(
IN DEVHANDLE		hDev,
IN LPSTR			szAppName
)
{
	ULONG ret_skf = SAR_OK;
	CK_RV ret_p11 = CKR_OK;
	//CK_SESSION_HANDLE hSession = 0;

	set<SKFHandleC_PTR>::iterator itC;
	set<SKFHandleF_PTR>::iterator itF;
	set<SKFHandleSYM_PTR>::iterator itSK;
	set<SKFHandleCT_PTR>::iterator itCT;

	SKFHandleC_PTR tempContainerHandle = NULL;
	SKFHandleF_PTR tempFileHandle = NULL;
	SKFHandleSYM_PTR tempSessionKeyHandle = NULL;
	SKFHandleCT_PTR tempCertificationHandle = NULL;

	// variables for asymmetric keypair operations
	CK_KEY_TYPE  keyType = CKK_SM2;
	CK_OBJECT_CLASS	pubkeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS prikeyClass = CKO_PRIVATE_KEY;
	CK_BYTE	m_ttrue = TRUE;
	CK_BYTE m_ffalse = FALSE;
	CK_BYTE_PTR keyID = NULL;
	CK_ULONG ulKeyIDLen = 0;

	// variables for certification operations
	CK_OBJECT_CLASS dataClass = CKO_DATA;
	string certApp;

	SKF_LOGD("%s entry with %p", __FUNCTION__, hDev);
	
	if (NULL == hDev || NULL == szAppName){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	SKF_LOGV("application to be deleted: %s", szAppName);
	
	HandleCheck handle;
	CK_SESSION_HANDLE session = 0;

	// check if device is authorized to create application
	ret_skf = SAR_INVALIDHANDLEERR;
	set<SKFHandleD_PTR>::iterator itD = SKFGlobeData::setDevHandle.begin();
	while (itD != SKFGlobeData::setDevHandle.end()){
		if ((*itD) == hDev){
			if (SKF_FLAG_AUTH_DEV == (*itD)->flg) {
				ret_skf = SAR_OK;
			}
			else {
				ret_skf = SAR_USER_NOT_LOGGED_IN;
			}
			break;
		}
		itD++;
	}

	// check device auth failed, return directly
	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, ret_skf);
		return ret_skf;
	}

	//删除应用对象
	SKFHandleA_PTR pAppToBeDeleted = NULL;

	set<SKFHandleA_PTR>::iterator itA = SKFGlobeData::setAppHandle.begin();
	for (; itA != SKFGlobeData::setAppHandle.end();){
		if ((*itA)->pDevHandle == hDev && \
			strlen(szAppName) == (*itA)->appName.size() && \
			0 == memcmp(szAppName, (*itA)->appName.data(), (*itA)->appName.size())
			)
		{
			pAppToBeDeleted = *itA;
			break;
		}
		else
		{
			itA++;
		}
	}

	if(NULL == pAppToBeDeleted) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_APPLICATION_NOT_EXISTS);
		return SAR_APPLICATION_NOT_EXISTS;
	}

	// clean up session key information
	// ======================== start to destroy session key information =========================
	SKF_LOGD("total sessionKey %d before destroy", SKFGlobeData::setSessionKeyHandle.size());
	for (itSK = SKFGlobeData::setSessionKeyHandle.begin(); itSK != SKFGlobeData::setSessionKeyHandle.end(); ){
		if (((*itSK)->pContainerHandle) && ((*itSK)->pContainerHandle->pAppHandle == pAppToBeDeleted)) {
			tempSessionKeyHandle =  *itSK;
			if (SGD_SM3 != tempSessionKeyHandle->ulAlgId) {
				// destroy session object as these shall be invalid after device disconnect
				// SM3 for hash calculation, no destroy operation
				ret_p11 = Adapter_C_DestroyObject(tempSessionKeyHandle->session, tempSessionKeyHandle->sessKeyHandle);
				if(CKR_OK != ret_p11) {
					SKF_LOGE("destroy session key failed with return 0x%x", ret_p11);
					ret_skf = p11Error2SkfError(ret_p11);
					break;
				}
			}

			// close session bind with key
			ret_p11 = Adapter_C_CloseSession(tempSessionKeyHandle->session);
			if(CKR_OK != ret_p11) {
				SKF_LOGE("close session failed with return 0x%x", ret_p11);
				ret_skf = p11Error2SkfError(ret_p11);
				break;
			}

			// remove handle from set
			// itSK must ++ here, cannot be put into for(;;itSK++)
			SKFGlobeData::setSessionKeyHandle.erase(itSK++);

			// release handle memory
			delete tempSessionKeyHandle;
			tempSessionKeyHandle = NULL;
		}
		else {
			itSK++;
		}
	}
	SKF_LOGD("total sessionKey %d before destroy", SKFGlobeData::setSessionKeyHandle.size());
	// unexpected error, return;
	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s destroy session key failed with return 0x%x", __FUNCTION__, ret_skf);
		return ret_skf;
	}
	// ======================== end of destroy session key information =========================

	//删除容器和文件对象
	// ======================== start to destroy container and container internal information =========================
	SKF_LOGD("total container %d before destroy container", SKFGlobeData::setContainerHandle.size());
		itC = SKFGlobeData::setContainerHandle.begin();
		for (; itC != SKFGlobeData::setContainerHandle.end();){
			if ((*itC)->pAppHandle == pAppToBeDeleted)
			{
				tempContainerHandle = *itC;
				
				ret_skf = handle.GetSession(tempContainerHandle, &session);
				if (SAR_OK != ret_skf) {
					SKF_LOGE("get session failed 0x%x and return 0x%x", ret_skf, SAR_INVALIDHANDLEERR);
					return SAR_INVALIDHANDLEERR;
				}

				// need destroy asymmetric keypairs and certifications in the container...
				
				// -------------------start to destroy signature keypairs-----------------------
				keyID = NULL;
				ulKeyIDLen = 0;
				keyID = assembleKeyId((SKFHandleC_PTR)tempContainerHandle, TRUE, &ulKeyIDLen);
				if(NULL == keyID || 0 == ulKeyIDLen){
					handle.CloseSession(session);
					SKF_LOGE("%s return 0x%x for assembleKeyId failure", __FUNCTION__, SAR_FAIL);
					if(keyID){
						delete[] keyID;
						keyID = NULL;
					}
					return SAR_FAIL;
				}
				CK_ATTRIBUTE findTemplateSignature[] = {
					{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
					{ CKA_ID, keyID, ulKeyIDLen },
					{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
				};
				ret_skf = destroyObjByTemplate(session, findTemplateSignature, sizeof(findTemplateSignature)/sizeof(CK_ATTRIBUTE));
				delete[] keyID;
				keyID = NULL;
				if(SAR_OK != ret_skf) {
					handle.CloseSession(session);
					SKF_LOGE("%s destroy keypair error and exit 0x%x", __FUNCTION__, ret_skf);
					return ret_skf;
				}
				// -----------------------end of destroy signature keypairs...-----------------------

				// -----------------------start to destroy signature keypairs...-----------------------
				ulKeyIDLen = 0;
				keyID = assembleKeyId((SKFHandleC_PTR)tempContainerHandle, FALSE, &ulKeyIDLen);
				if(NULL == keyID || 0 == ulKeyIDLen){
					handle.CloseSession(session);
					SKF_LOGE("%s return 0x%x for assembleKeyId failure", __FUNCTION__, SAR_FAIL);
					if(keyID){
						delete[] keyID;
						keyID = NULL;
					}
					return SAR_FAIL;
				}
				CK_ATTRIBUTE findTemplateCryp[] = {
					{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
					{ CKA_ID, keyID, ulKeyIDLen },
					{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
				};
				ret_skf = destroyObjByTemplate(session, findTemplateCryp, sizeof(findTemplateCryp)/sizeof(CK_ATTRIBUTE));
				delete[] keyID;
				keyID = NULL;
				if(SAR_OK != ret_skf) {
					handle.CloseSession(session);
					SKF_LOGE("%s destory keypair error and exit 0x%x", __FUNCTION__, ret_skf);
					return ret_skf;
				}
				// -----------------------end of destroy signature keypairs...-----------------------

				
				// -----------------------start to destroy certifications...-----------------------
				SKF_LOGD("total certification %d before destroy certification", SKFGlobeData::setCertHandle.size());
				//remove buffer information for certification if there is
				for (itCT = SKFGlobeData::setCertHandle.begin(); itCT != SKFGlobeData::setCertHandle.end(); ) {
					if((*itCT)->pContainerHandle == tempContainerHandle) {
						tempCertificationHandle = *itCT;
						ret_skf = Adapter_C_DestroyObject(session, tempCertificationHandle->certHandle);
						if(SAR_OK != ret_skf) {
							handle.CloseSession(session);
							SKF_LOGE("%s destroy cert get 0x%x and exit 0x%x", __FUNCTION__, ret_skf, SAR_OBJERR);
							return SAR_OBJERR;
						}
						SKFGlobeData::setCertHandle.erase(itCT++);

						delete tempCertificationHandle;
						tempCertificationHandle = NULL;
					}
					else {
						itCT++;
					}
				}
				SKF_LOGD("total certification %d after destroy certification", SKFGlobeData::setCertHandle.size());
				// end of remove buffer information 
#if 0
				SKF_CERT_APPLICATION_DESC(tempContainerHandle->pAppHandle->appName,
					tempContainerHandle->containerName, certApp);
				
				CK_ATTRIBUTE certFindTemplate[] = {
					{ CKA_APPLICATION, (char*)certApp.data(), certApp.size() },
					{ CKA_CLASS,&dataClass,sizeof(dataClass)},
					{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
				};

				ret_skf = destroyObjByTemplate(session, certFindTemplate, sizeof(certFindTemplate)/sizeof(CK_ATTRIBUTE));
				if(SAR_OK != ret_skf) {
					handle.CloseSession(session);
					return ret_skf;
				}
#endif
				// -----------------------end of destroy certifications...-----------------------

				// ----------------------- destroy container buffer/object -----------------------
				ret_skf = Adapter_C_DestroyObject(session, tempContainerHandle->containerHandle);
				if (SAR_OK != ret_skf) {
					handle.CloseSession(session);
					SKF_LOGE("%s destroy cont get 0x%x and exit 0x%x", __FUNCTION__, ret_skf, SAR_OBJERR);
					return SAR_OBJERR;
				}

				handle.CloseSession(session);

				SKFGlobeData::setContainerHandle.erase(itC++);

				delete tempContainerHandle;
				tempContainerHandle = NULL;
				// ----------------------- end of destroy container information -----------------------
			}
			else
			{
				itC++;
			}
		}
		SKF_LOGD("total container %d after destroy container", SKFGlobeData::setContainerHandle.size());
		// ======================== end of destroy container and container internal information =========================

		// ======================== start to destroy file information =========================
		SKF_LOGD("total file %d before destroy", SKFGlobeData::setFileHandle.size());
		itF = SKFGlobeData::setFileHandle.begin();
		for (; itF != SKFGlobeData::setFileHandle.end(); ){
			if ((*itF)->pAppHandle == pAppToBeDeleted)
			{
				tempFileHandle = *itF;
				
				ret_skf = handle.GetSession(pAppToBeDeleted, &session);
				if (SAR_OK != ret_skf) {
					SKF_LOGE("get session failed 0x%x and return 0x%x", ret_skf, SAR_INVALIDHANDLEERR);
					return SAR_INVALIDHANDLEERR;
				}

				ret_skf = Adapter_C_DestroyObject(session, tempFileHandle->fileHandle);
				if (SAR_OK != ret_skf) {
					handle.CloseSession(session);
					SKF_LOGE("%s destroy file get 0x%x and exit 0x%x", __FUNCTION__, ret_skf, SAR_OBJERR);
					return SAR_OBJERR;
				}

				handle.CloseSession(session);

				SKFGlobeData::setFileHandle.erase(itF++);

				delete tempFileHandle;
				tempFileHandle = NULL;
			}
			else
			{
				itF++;
			}
		}
		SKF_LOGD("total file %d after destroy", SKFGlobeData::setFileHandle.size());
		// ======================== end of destroy file information =========================


	// delete app information after other operations done...
	// ======================== start to destroy application information =========================
	ret_skf = handle.GetSession(pAppToBeDeleted, &session);
	if (SAR_OK != ret_skf) {
		SKF_LOGE("get session failed 0x%x and return 0x%x", ret_skf, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// destroy p11 object for app level
	ret_skf = Adapter_C_DestroyObject(session, pAppToBeDeleted->appHandle);
	if (SAR_OK != ret_skf) {
		handle.CloseSession(session);
		SKF_LOGE("%s destroy app get 0x%x and exit 0x%x", __FUNCTION__, ret_skf, SAR_OBJERR);
		return SAR_OBJERR;
	}

	handle.CloseSession(session);

	// release internal memory allocated when connect device or create app
	if(pAppToBeDeleted->appValue.soPin) {
		delete[] pAppToBeDeleted->appValue.soPin;
		pAppToBeDeleted->appValue.soPin = NULL;
	}

	if(pAppToBeDeleted->appValue.soDefaultPin) {
		delete[] pAppToBeDeleted->appValue.soDefaultPin;
		pAppToBeDeleted->appValue.soDefaultPin = NULL;
	}

	if(pAppToBeDeleted->appValue.usrDefaultPin) {
		delete[] pAppToBeDeleted->appValue.usrDefaultPin;
		pAppToBeDeleted->appValue.usrDefaultPin = NULL;
	}

	if(pAppToBeDeleted->appValue.usrPin) {
		delete[] pAppToBeDeleted->appValue.usrPin;
		pAppToBeDeleted->appValue.usrPin = NULL;
	}
	
	SKFGlobeData::setAppHandle.erase(pAppToBeDeleted);
	delete pAppToBeDeleted;
	pAppToBeDeleted = NULL;
	// ======================== end of destroy application information =========================

	SKF_LOGD("%s exit with %p, delete %s", __FUNCTION__, hDev, szAppName);
	return SAR_OK;
}

/*
*	打开指定的应用
*	hDev			[IN]连接设备时返回的设备句柄
*	szAppName		[IN]应用名称
*	phApplication	[OUT]应用的句柄
*/
SKF_DEVAPI SKF_OpenApplication(
IN DEVHANDLE		hDev,
IN LPSTR			szAppName,
OUT HAPPLICATION*	phApplication
)
{
	SKF_LOGD("%s entry with %p", __FUNCTION__, hDev);

	if (NULL == hDev || NULL == szAppName || NULL == phApplication){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	SKF_LOGV("application to be opened: %s", szAppName);

	HandleCheck handle;

	CK_RV ret = handle.Check((SKFHandleD_PTR)hDev);
	if (ret != CKR_OK) {
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	if(SKF_FLAG_EXIST == ((SKFHandleD_PTR)hDev)->flg) {
		SKF_LOGE("%s return 0x%x for device not opened yet", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	set<SKFHandleA_PTR>::iterator it = SKFGlobeData::setAppHandle.begin();
	for (; it != SKFGlobeData::setAppHandle.end(); it++){
		if ((*it)->pDevHandle == hDev && \
			strlen(szAppName) == (*it)->appName.size() && \
			0 == memcmp(szAppName, (*it)->appName.data(), (*it)->appName.size())
			)
		{
			if ((*it)->flg == SKF_FLAG_EXIST){
				(*it)->flg = SKF_FLAG_OPEN;
			}
			
			*phApplication = *it;

			SKF_LOGD("%s exit with %p, name %s", __FUNCTION__, hDev, szAppName);
			return SAR_OK;
		}
	}

	SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_APPLICATION_NOT_EXISTS);
	return SAR_APPLICATION_NOT_EXISTS;
}

/*
*	关闭应用并释放应用句柄
*	hApplication	[IN]应用的句柄
*/
SKF_DEVAPI SKF_CloseApplication(
IN HAPPLICATION	hApplication
)
{
	ULONG ret_skf = SAR_OK;
	CK_RV ret_p11 = CKR_OK;
	CK_SESSION_HANDLE hSession = 0;

	set<SKFHandleC_PTR>::iterator itC;
	set<SKFHandleF_PTR>::iterator itF;
	set<SKFHandleSYM_PTR>::iterator itSK;
	set<SKFHandleCT_PTR>::iterator itCT;

	SKFHandleA_PTR tempApplicationHandle = (SKFHandleA_PTR)hApplication;
	SKFHandleC_PTR tempContainerHandle = NULL;
	SKFHandleF_PTR tempFileHandle = NULL;
	SKFHandleSYM_PTR tempSessionKeyHandle = NULL;
	SKFHandleCT_PTR tempCertificationHandle = NULL;
	HandleCheck handle;

	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);
	
	if (NULL == hApplication){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}
	

	CK_RV ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (ret != CKR_OK) {
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	// check if application open
	if (SKF_FLAG_EXIST == ((SKFHandleA_PTR)hApplication)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// clean up session key information created within target application scope
	// ======================== start to destroy session key information =========================
	for (itSK = SKFGlobeData::setSessionKeyHandle.begin(); itSK != SKFGlobeData::setSessionKeyHandle.end(); ){
		if (((*itSK)->pContainerHandle) && ((*itSK)->pContainerHandle->pAppHandle == tempApplicationHandle)) {
			tempSessionKeyHandle =  *itSK;
			if (SGD_SM3 != tempSessionKeyHandle->ulAlgId) {
				// destroy session object as these shall be invalid after device disconnect
				// SM3 for hash calculation, no destroy operation
				ret_p11 = Adapter_C_DestroyObject(tempSessionKeyHandle->session, tempSessionKeyHandle->sessKeyHandle);
				if(CKR_OK != ret_p11) {
					SKF_LOGE("destroy session key failed with return 0x%x", ret_p11);
					ret_skf = SAR_FAIL;
					break;
				}
			}

			// close session bind with key
			ret_p11 = Adapter_C_CloseSession(tempSessionKeyHandle->session);
			if(CKR_OK != ret_p11) {
				SKF_LOGE("close session failed with return 0x%x", ret_p11);
				ret_skf = SAR_FAIL;
				break;
			}

			// remove handle from set
			// itSK must ++ here, cannot be put into for(;;itSK++)
			SKFGlobeData::setSessionKeyHandle.erase(itSK++);

			// release handle memory
			delete tempSessionKeyHandle;
			tempSessionKeyHandle = NULL;
		}
		else {
			itSK++;
		}
	}
	// unexpected error, return;
	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s destroy session key failed with return 0x%x", __FUNCTION__, ret_skf);
		return ret_skf;
	}
	// ======================== end of destroy session key information =========================

	// ======================== update container status in target applicatoin scope =========================
	itC = SKFGlobeData::setContainerHandle.begin();
	for (; itC != SKFGlobeData::setContainerHandle.end(); ){
		if ((*itC)->pAppHandle == tempApplicationHandle) {
			tempContainerHandle = *itC;
			tempContainerHandle->flg = SKF_FLAG_EXIST;
		}
		itC++;
	}
			
	// update application status, keep application buffer information
	tempApplicationHandle->flg = SKF_FLAG_EXIST;

	SKF_LOGD("%s exit with %p", __FUNCTION__, hApplication);

	return SAR_OK;
}


/************************************************************************/
/*  4. 文件管理				                                            */
/*	SKF_CreateFile														*/
/*	SKF_DeleteFile														*/
/*	SKF_EnumFiles														*/
/*	SKF_GetFileInfo														*/
/*	SKF_ReadFile														*/
/*	SKF_WriteFile														*/
/************************************************************************/

/*
*	创建一个文件。创建文件时要指定文件的名称，大小，以及文件的读写权限
*	hApplication		[IN]应用句柄
*	szFileName			[IN]文件名称，长度不得大于32个字节
*	ulFileSize			[IN]文件大小
*	ulReadRights		[IN]文件读权限
*	ulWriteRights		[IN]文件写权限
*/
SKF_DEVAPI SKF_CreateFile(
IN HAPPLICATION	hApplication,
IN LPSTR			szFileName,
IN ULONG			ulFileSize,
IN ULONG			ulReadRights,
IN ULONG			ulWriteRights
)
{
	ULONG skf_ret = SAR_OK;
	SKFHandleA_PTR hApp = (SKFHandleA_PTR)hApplication;
	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);
	
	if (NULL == hApplication || NULL == szFileName || (ulReadRights > SECURE_EVERYONE_ACCOUNT) || (ulWriteRights > SECURE_EVERYONE_ACCOUNT)){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	SKF_LOGV("file to be created: %s, %d %d %d", szFileName, ulFileSize, ulReadRights, ulWriteRights);

	HandleCheck handle;
	CK_RV ret = handle.Check(hApp);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return ret;
	}

	if(SECURE_NEVER_ACCOUNT == hApp->appValue.rights) {
		SKF_LOGE("%s exit 0x%x due app not authorized to create file", __FUNCTION__, SAR_NOTSUPPORTYETERR);
		return SAR_NOTSUPPORTYETERR;
	}

	switch (hApp->flg){
		case SKF_FLAG_EXIST:
			SKF_LOGE("%s exit 0x%x due app state error", __FUNCTION__, SAR_INVALIDHANDLEERR);
			skf_ret = SAR_INVALIDHANDLEERR;
			break;
		case SKF_FLAG_OPEN:
			// if set right to everyone, enable file creation even no log in. (refer LongMai implementation)
			if(SECURE_EVERYONE_ACCOUNT == hApp->appValue.rights) {
				skf_ret = SAR_OK;
			}
			else {
				SKF_LOGE("%s exit 0x%x due app not log in", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
				skf_ret = SAR_USER_NOT_LOGGED_IN;
			}
			break;
		case SKF_FLAG_AUTH_ADM:
			if(SECURE_ADM_ACCOUNT & hApp->appValue.rights) {
				skf_ret = SAR_OK;
			}
			else {
				SKF_LOGE("%s exit 0x%x due user not log in: required %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, hApp->appValue.rights);
				skf_ret = SAR_USER_NOT_LOGGED_IN;
			}
			break;
		case SKF_FLAG_AUTH_USR:
			if(SECURE_USER_ACCOUNT & hApp->appValue.rights) {
				skf_ret = SAR_OK;
			}
			else {
				SKF_LOGE("%s exit 0x%x due admin not log in: required %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, hApp->appValue.rights);
				skf_ret = SAR_USER_NOT_LOGGED_IN;
			}
			break;
		default:
			SKF_LOGE("%s exit 0x%x: app state error %d", __FUNCTION__, SAR_FAIL, hApp->flg);
			skf_ret = SAR_FAIL;
			break;
	}

	if(SAR_OK != skf_ret) {
		SKF_LOGE("%s exit 0x%x: error return", __FUNCTION__, skf_ret);
		return skf_ret;
	}

	string fileName;
	fileName.append(szFileName);
	
	set<SKFHandleF_PTR>::iterator it = SKFGlobeData::setFileHandle.begin();
	for (; it != SKFGlobeData::setFileHandle.end(); it++){
		if ((*it)->pAppHandle == (SKFHandleA_PTR)hApplication &&
			(*it)->fileName == fileName){
			SKF_LOGE("%s exit 0x%x for file %s", __FUNCTION__, SAR_FILE_ALREADY_EXIST, szFileName);
			return SAR_FILE_ALREADY_EXIST;
		}
	}

	string fileDesc;
	SKF_FILE_APPLICATION_DESC(((SKFHandleA_PTR)hApplication)->appName, fileDesc);

	CK_OBJECT_CLASS dataClass = CKO_DATA;
	CK_BBOOL ttrue = CK_TRUE, ffalse = CK_FALSE;
	string value;
	value.append((char*)&ulReadRights,sizeof(ULONG));
	value.append((char*)&ulWriteRights,sizeof(ULONG));
	char *pad = NULL;
	pad = new char[ulFileSize];
	memset(pad,0,ulFileSize);
	value.append(pad, ulFileSize);
	delete[] pad;
	pad = NULL;


	CK_ATTRIBUTE attributes[] = {
		{CKA_CLASS,&dataClass,sizeof(dataClass)},
		{ CKA_APPLICATION, (CK_VOID_PTR)fileDesc.data(), fileDesc.size() },
		{ CKA_LABEL, szFileName, strlen(szFileName) },
		{ CKA_TOKEN, &ttrue, sizeof(ttrue) },
		{ CKA_PRIVATE, &ttrue, sizeof(ttrue) },
		{ CKA_VALUE, (char*)value.data(), value.size() }
	};
	CK_SESSION_HANDLE session = 0;
	ret = handle.GetSession((SKFHandleA_PTR)hApplication,&session);
	if (ret != SAR_OK){
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
		return SAR_FAIL;
	}

	SKFHandleF_PTR tmp = new SKFHandleF();
	tmp->pAppHandle = (SKFHandleA_PTR)hApplication;
	tmp->fileName.append(szFileName);

	ret = Adapter_C_CreateObject(session,attributes,sizeof(attributes) / sizeof(CK_ATTRIBUTE),&tmp->fileHandle);
	if (ret != SAR_OK){
		handle.CloseSession(session);
		delete tmp;
		tmp = NULL;
		SKF_LOGE("%s create file failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_WRITEFILEERR);
		return SAR_WRITEFILEERR;
	}
	tmp->readRights = ulReadRights;
	tmp->writeRights = ulWriteRights;
	tmp->value.append(value.data() + 2 * sizeof(ULONG) ,value.size() - 2 * sizeof(ULONG));
	
	SKFGlobeData::setFileHandle.insert(tmp);
	handle.CloseSession(session);

	SKF_LOGD("%s exit with %p for file %s", __FUNCTION__, hApplication, szFileName);
	
	return SAR_OK;
}

/*
*	删除指定文件，文件删除后，文件中写入的所有信息将丢失。文件在设备中的占用的空间将被释放。
*	hApplication		[IN]要删除文件所在的应用句柄
*	szFileName			[IN]要删除文件的名称
*/
SKF_DEVAPI SKF_DeleteFile(
IN HAPPLICATION	hApplication,
IN LPSTR			szFileName
)
{
	ULONG skf_ret = SAR_OK;
	SKFHandleA_PTR hApp = (SKFHandleA_PTR)hApplication;
	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);

	if (NULL == hApplication || NULL == szFileName){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	SKF_LOGV("file to be deleted: %s", szFileName);

	HandleCheck handle;
	CK_RV ret = handle.Check(hApp);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	if(SECURE_NEVER_ACCOUNT == hApp->appValue.rights) {
		SKF_LOGE("%s exit 0x%x due app not authorized to create file", __FUNCTION__, SAR_NOTSUPPORTYETERR);
		return SAR_NOTSUPPORTYETERR;
	}

	switch (hApp->flg){
		case SKF_FLAG_EXIST:
			SKF_LOGE("%s exit 0x%x due app state error", __FUNCTION__, SAR_INVALIDHANDLEERR);
			skf_ret = SAR_INVALIDHANDLEERR;
			break;
		case SKF_FLAG_OPEN:
			// if set right to everyone, enable file creation even no log in. (refer LongMai implementation)
			if(SECURE_EVERYONE_ACCOUNT == hApp->appValue.rights) {
				skf_ret = SAR_OK;
			}
			else {
				SKF_LOGE("%s exit 0x%x due app not log in", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
				skf_ret = SAR_USER_NOT_LOGGED_IN;
			}
			break;
		case SKF_FLAG_AUTH_ADM:
			if(SECURE_ADM_ACCOUNT & hApp->appValue.rights) {
				skf_ret = SAR_OK;
			}
			else {
				SKF_LOGE("%s exit 0x%x due user not log in: required %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, hApp->appValue.rights);
				skf_ret = SAR_USER_NOT_LOGGED_IN;
			}
			break;
		case SKF_FLAG_AUTH_USR:
			if( SECURE_USER_ACCOUNT & hApp->appValue.rights) {
				skf_ret = SAR_OK;
			}
			else {
				SKF_LOGE("%s exit 0x%x due admin not log in: required %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, hApp->appValue.rights);
				skf_ret = SAR_USER_NOT_LOGGED_IN;
			}
			break;
		default:
			SKF_LOGE("%s exit 0x%x: app state error %d", __FUNCTION__, SAR_FAIL, hApp->flg);
			skf_ret = SAR_FAIL;
			break;
	}

	if(SAR_OK != skf_ret) {
		SKF_LOGE("%s exit 0x%x: error return", __FUNCTION__, skf_ret);
		return skf_ret;
	}

	string fileDesc;
	fileDesc.append(szFileName);
	CK_SESSION_HANDLE session = 0;

	ret = handle.GetSession((SKFHandleA_PTR)hApplication,&session);
	if (ret != SAR_OK){
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
		return SAR_FAIL;
	}

	set<SKFHandleF_PTR>::iterator it = SKFGlobeData::setFileHandle.begin();
	for (; it != SKFGlobeData::setFileHandle.end(); it++){
		if ((*it)->pAppHandle == (SKFHandleA_PTR)hApplication &&
			(*it)->fileName == fileDesc){
			ret = Adapter_C_DestroyObject(session,(*it)->fileHandle);
			if (ret != CKR_OK){
				handle.CloseSession(session);
				SKF_LOGE("%s exit 0x%x due delete file failure 0x%x", __FUNCTION__, SAR_FILE_NOT_EXIST, ret);
				return SAR_FILE_NOT_EXIST;
			}

			delete (*it);
			SKFGlobeData::setFileHandle.erase(it);

			handle.CloseSession(session);
			
			SKF_LOGD("%s exit with %p for file %s", __FUNCTION__, hApplication, szFileName);
			
			return SAR_OK;
		}		
	}

	handle.CloseSession(session);

	SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_FILE_NOT_EXIST);
	return SAR_FILE_NOT_EXIST;
}

/*
*	枚举一个应用下存在的所有文件
*	hApplication		[IN]应用的句柄
*	szFileList			[OUT]返回文件名称列表，该参数为空，由pulSize返回文件信息所需要的空间大小。每个文件名称以单个'\0'结束，以双'\0'表示列表的结束。
*	pulSize				[OUT]输入为数据缓冲区的大小，输出为实际文件名称的大小
*/
SKF_DEVAPI SKF_EnumFiles(
IN HAPPLICATION	hApplication,
OUT LPSTR			szFileList,
OUT ULONG*		pulSize
)
{
	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);
	
	if (NULL == hApplication || NULL == pulSize){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	HandleCheck handle;
	CK_RV ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	// check if application open
	if (SKF_FLAG_EXIST == ((SKFHandleA_PTR)hApplication)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// SKF document has no specification on whether need user log in to enum files
	// create/delete/read/write authorize depends on app and file configuration when creation
#if 0
	// check if user already logged in app
	if (SKF_FLAG_AUTH != ((SKFHandleA_PTR)hApplication)->flg) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
		return SAR_USER_NOT_LOGGED_IN;
	}
#endif

	string fileList;
	char pad[1] = { 0 };
	ULONG fileCount = 0;
	set<SKFHandleF_PTR>::iterator it = SKFGlobeData::setFileHandle.begin();
	for (;it != SKFGlobeData::setFileHandle.end();it++){
		if((*it)->pAppHandle == hApplication) {
		fileList.append((*it)->fileName);
		fileList.append(pad,1);
		fileCount++;
		}
	}

	// fill output buffer if there is file
	if (fileCount > 0){
		fileList.append(pad, 1);
		
		// check if input buffer enough to hold all output
		if((szFileList) && (*pulSize < fileList.size())) {
			SKF_LOGE("%s exit with 0x%x", __FUNCTION__, SAR_BUFFER_TOO_SMALL);
			*pulSize = fileList.size();
			return SAR_BUFFER_TOO_SMALL;
		}
		
		*pulSize = fileList.size();
		if (NULL != szFileList){
			memcpy(szFileList,fileList.data(), fileList.size());
			logData((unsigned char *)szFileList, fileList.size(), plog_verbose, "file enum result:");
		}
	}
	else {
		*pulSize = 0;
	}
		
	SKF_LOGD("%s exit with %p", __FUNCTION__, hApplication);
	return SAR_OK;
}

/*
*	获取应用文件的属性信息，例如文件的大小、权限等
*	hApplication		[IN]文件所在应用的句柄
*	szFileName			[IN]文件名称
*	pFileInfo			[OUT]文件信息，指向文件属性结构的指针
*/
SKF_DEVAPI SKF_GetFileInfo(
IN HAPPLICATION		hApplication,
IN LPSTR				szFileName,
OUT FILEATTRIBUTE*	pFileInfo
)
{
	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);
	
	if (NULL == hApplication || NULL == szFileName || NULL == pFileInfo){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	HandleCheck handle;
	CK_RV ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	// check if application open
	if (SKF_FLAG_EXIST == ((SKFHandleA_PTR)hApplication)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// get file info shall NOT check user log in or not
	// file info will indicate whether need user log in to read/write file
#if 0
	// check if user already logged in app
	if (SKF_FLAG_AUTH != ((SKFHandleA_PTR)hApplication)->flg) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
		return SAR_USER_NOT_LOGGED_IN;
	}
#endif

	string fileDesc;
	fileDesc.append(szFileName);

	set<SKFHandleF_PTR>::iterator it = SKFGlobeData::setFileHandle.begin();
	for (;it != SKFGlobeData::setFileHandle.end();it++){
		if ((*it)->pAppHandle == hApplication &&
			(*it)->fileName == fileDesc){
			memcpy(pFileInfo->FileName,fileDesc.data(), fileDesc.size());
			pFileInfo->ReadRights = (*it)->readRights;
			pFileInfo->WriteRights = (*it)->writeRights;
			pFileInfo->FileSize = (*it)->value.size();
			SKF_LOGD("%s exit with %p for %s", __FUNCTION__, hApplication, szFileName);
			return SAR_OK;
		}
	}

	SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_FILE_NOT_EXIST);
	return SAR_FILE_NOT_EXIST;
}

/*
*	读取文件内容
*	hApplication		[IN]文件所在的应用句柄
*	szFileName			[IN]文件名
*	ulOffset			[IN]文件读取偏移位置
*	ulSize				[IN]要读取的长度
*	pbOutData			[OUT]返回数据的缓冲区
*	pulOutLen			[OUT]输入表示给出的缓冲区大小；输出表示实际读取返回的数据大小
*/
SKF_DEVAPI SKF_ReadFile(
IN HAPPLICATION	hApplication,
IN LPSTR			szFileName,
IN ULONG			ulOffset,
IN ULONG			ulSize,
OUT BYTE*			pbOutData,
OUT ULONG*		pulOutLen
)
{
	ULONG maxReadLen = 0;
	
	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);
	
	if (NULL == hApplication || NULL == szFileName || NULL == pulOutLen || 0 == ulSize){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	SKF_LOGV("file to read: %s, %d %d %p %d", szFileName, ulOffset, ulSize, pbOutData, *pulOutLen);

	if(NULL == pbOutData) {
		*pulOutLen = ulSize;
		SKF_LOGD("%s exit 0x%x", __FUNCTION__, SAR_OK);
		return SAR_OK;
	}

	HandleCheck handle;
	CK_RV ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	// check if application open
	if (SKF_FLAG_EXIST == ((SKFHandleA_PTR)hApplication)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	string fileDesc;
	fileDesc.append(szFileName);

	set<SKFHandleF_PTR>::iterator it = SKFGlobeData::setFileHandle.begin();
	for (; it != SKFGlobeData::setFileHandle.end(); it++){
		if ((*it)->pAppHandle == hApplication &&
			(*it)->fileName == fileDesc){

			// check if current user can read target file
			// case nobody can read file
			if(SECURE_NEVER_ACCOUNT == (*it)->readRights) {
				SKF_LOGE("%s exit 0x%x due file cannot read", __FUNCTION__, SAR_NOTSUPPORTYETERR);
				return SAR_NOTSUPPORTYETERR;
			}

			if(SKF_FLAG_OPEN == ((SKFHandleA_PTR)hApplication)->flg) {
				if(SECURE_EVERYONE_ACCOUNT != (*it)->readRights) {
					// case required log in, but not login
					SKF_LOGE("%s exit 0x%x, app not log in. require: %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, (*it)->readRights);
					return SAR_USER_NOT_LOGGED_IN;
				}
				else {
					// app not login, but every one can read file. continue...
				}
			}
			else if (SKF_FLAG_AUTH_ADM == ((SKFHandleA_PTR)hApplication)->flg) {
				if(SECURE_USER_ACCOUNT == (*it)->readRights) {
					// case user only can read file, but admin login
					SKF_LOGE("%s exit 0x%x, user not log in. require: %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, (*it)->readRights);
					return SAR_USER_NOT_LOGGED_IN;
				}
			}
			else if (SKF_FLAG_AUTH_USR == ((SKFHandleA_PTR)hApplication)->flg) {
				if(SECURE_ADM_ACCOUNT == (*it)->readRights) {
					// case admin only can read file, but user login
					SKF_LOGE("%s exit 0x%x, admin not log in. require: %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, (*it)->readRights);
					return SAR_USER_NOT_LOGGED_IN;
				}
			}
			else {
				SKF_LOGE("%s exit 0x%x: app state %d", __FUNCTION__, SAR_FAIL, ((SKFHandleA_PTR)hApplication)->flg);
				return SAR_FAIL;
			}

			if (ulOffset >= (*it)->value.size()){
				SKF_LOGE("%s exit 0x%x due to offset more than file size", __FUNCTION__, SAR_FILEERR);
				return SAR_FILEERR;
			}

			maxReadLen = (*it)->value.size() - ulOffset;

			// input buffer enough to save all data in file
			if(maxReadLen <= (*pulOutLen)) {
				memcpy(pbOutData, (*it)->value.data() + ulOffset, maxReadLen);
				// update output mem length
				*pulOutLen = maxReadLen;
			}
			else {
				// copy required data length
				memcpy(pbOutData, (*it)->value.data() + ulOffset, *pulOutLen);
			}

			SKF_LOGD("%s exit with %p for file %s", __FUNCTION__, hApplication, szFileName);
			return SAR_OK;
		}
	}

	SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_FILE_NOT_EXIST);
	return SAR_FILE_NOT_EXIST;
}

/*
*	写数据到文件中
*	hApplication		[IN]文件所在的应用句柄
*	szFileName			[IN]文件名
*	ulOffset			[IN]写入文件的偏移量
*	pbData				[IN]写入数据缓冲区
*	ulSize				[IN]写入数据的大小
*/
SKF_DEVAPI SKF_WriteFile(
IN HAPPLICATION	hApplication,
IN LPSTR			szFileName,
IN ULONG			ulOffset,
IN BYTE*			pbData,
IN ULONG			ulSize
)
{
	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);

	if (NULL == hApplication || NULL == szFileName || NULL == pbData || 0 == ulSize){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	SKF_LOGV("file to write: %s, %d %p %d", szFileName, ulOffset, pbData, ulSize);

	HandleCheck handle;
	CK_RV ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (SAR_OK != ret){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	// check if application open
	if (SKF_FLAG_EXIST == ((SKFHandleA_PTR)hApplication)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	string fileDesc;
	fileDesc.append(szFileName);

	set<SKFHandleF_PTR>::iterator it = SKFGlobeData::setFileHandle.begin();
	for (; it != SKFGlobeData::setFileHandle.end(); it++){
		if ((*it)->pAppHandle == hApplication &&
			(*it)->fileName == fileDesc){
			// check if current user can read target file
			// case nobody can read file
			if(SECURE_NEVER_ACCOUNT == (*it)->writeRights) {
				SKF_LOGE("%s exit 0x%x due file cannot write", __FUNCTION__, SAR_NOTSUPPORTYETERR);
				return SAR_NOTSUPPORTYETERR;
			}

			if(SKF_FLAG_OPEN == ((SKFHandleA_PTR)hApplication)->flg) {
				if(SECURE_EVERYONE_ACCOUNT != (*it)->writeRights) {
					// case required log in, but not login
					SKF_LOGE("%s exit 0x%x, app not log in. require: %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, (*it)->writeRights);
					return SAR_USER_NOT_LOGGED_IN;
				}
				else {
					// app not login, but every one can read file. continue...
				}
			}
			else if (SKF_FLAG_AUTH_ADM == ((SKFHandleA_PTR)hApplication)->flg) {
				if(SECURE_USER_ACCOUNT == (*it)->writeRights) {
					// case user only can read file, but admin login
					SKF_LOGE("%s exit 0x%x, user not log in. require: %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, (*it)->writeRights);
					return SAR_USER_NOT_LOGGED_IN;
				}
			}
			else if (SKF_FLAG_AUTH_USR == ((SKFHandleA_PTR)hApplication)->flg) {
				if(SECURE_ADM_ACCOUNT == (*it)->writeRights) {
					// case admin only can read file, but user login
					SKF_LOGE("%s exit 0x%x, admin not log in. require: %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, (*it)->writeRights);
					return SAR_USER_NOT_LOGGED_IN;
				}
			}
			else {
				SKF_LOGE("%s exit 0x%x: app state %d", __FUNCTION__, SAR_FAIL, ((SKFHandleA_PTR)hApplication)->flg);
				return SAR_FAIL;
			}
			
			if (ulOffset > (*it)->value.size()){
				SKF_LOGE("%s exit 0x%x due to offset more than file size", __FUNCTION__, SAR_FILEERR);
				return SAR_FILEERR;
			}

			string newValue;
			
			newValue.append((*it)->value.data(), ulOffset);
			newValue.append((CHAR*)pbData, ulSize);
			if (ulSize < (*it)->value.size() - ulOffset){
				newValue.append((*it)->value.data() + ulOffset + ulSize, (*it)->value.size() - ulOffset - ulSize);
			}

			(*it)->value = newValue;
			
			CK_SESSION_HANDLE session = 0;
			ret = handle.GetSession((SKFHandleA_PTR)hApplication,&session);
			if (SAR_OK != ret){
				SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
				return SAR_FAIL;
			}

			string setValue;
			setValue.append((char*)&(*it)->readRights, sizeof((*it)->readRights));
			setValue.append((char*)&(*it)->writeRights, sizeof((*it)->writeRights));
			setValue.append(newValue);
			CK_ATTRIBUTE attributes[] = {
				{ CKA_VALUE, (CK_VOID_PTR)setValue.data(),setValue.size()}
			};

			ret = Adapter_C_SetAttributeValue(session, (*it)->fileHandle, attributes, sizeof(attributes)/sizeof(CK_ATTRIBUTE));
			if (SAR_OK != ret){
				handle.CloseSession(session);
				SKF_LOGE("%s exit 0x%x due to write file error 0x%x", __FUNCTION__, SAR_OBJERR, ret);
				return SAR_OBJERR;
			}

			handle.CloseSession(session);
			
			SKF_LOGD("%s exit with %p for file %s", __FUNCTION__, hApplication, szFileName);
			return SAR_OK;
		}
	}

	SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_FILE_NOT_EXIST);
	return SAR_FILE_NOT_EXIST;
}


/************************************************************************/
/*  5. 容器管理				                                            */
/*	SKF_CreateContainer													*/
/*	SKF_DeleteContainer													*/
/*	SKF_OpenContainer													*/
/*	SKF_CloseContainer													*/
/*	SKF_EnumContainer													*/
/************************************************************************/

/*
*	在应用下建立指定名称的容器并返回容器句柄
*	hApplication		[IN]应用句柄
*	szContainerName		[IN]ASCII字符串，表示所建立容器的名称，容器名称的最大长度不能超过64字节
*	phContainer			[OUT]返回所建立容器的容器句柄
*/
SKF_DEVAPI SKF_CreateContainer(
IN HAPPLICATION	hApplication,
IN LPSTR			szContainerName,
OUT HCONTAINER*	phContainer
)
{
	ULONG ret_skf = SAR_OK;
	CK_RV ret_p11 = CKR_OK;
	//CK_SESSION_HANDLE hSession = 0;

	set<SKFHandleC_PTR>::iterator itC;
	set<SKFHandleF_PTR>::iterator itF;
	set<SKFHandleSYM_PTR>::iterator itSK;
	set<SKFHandleCT_PTR>::iterator itCT;

	SKFHandleA_PTR tempApplicationHandle = (SKFHandleA_PTR)hApplication;
	SKFHandleC_PTR tempContainerHandle = NULL;
	SKFHandleF_PTR tempFileHandle = NULL;
	SKFHandleSYM_PTR tempSessionKeyHandle = NULL;
	SKFHandleCT_PTR tempCertificationHandle = NULL;
	HandleCheck handle;

	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);
	
	if (NULL == hApplication || NULL == szContainerName || NULL == phContainer){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	SKF_LOGV("container to be created: %s", szContainerName);

	CK_RV ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (ret != CKR_OK) {
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	// check if application open
	if (SKF_FLAG_EXIST == ((SKFHandleA_PTR)hApplication)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// check if user already logged in app
	if (SKF_FLAG_AUTH_USR != tempApplicationHandle->flg) {
		SKF_LOGE("%s exit 0x%x. user log in required to create container, current state %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, tempApplicationHandle->flg);
		return SAR_USER_NOT_LOGGED_IN;
	}

	string containerName;
	containerName.append(szContainerName);

	set<SKFHandleC_PTR>::iterator it = SKFGlobeData::setContainerHandle.begin();
	for (; it != SKFGlobeData::setContainerHandle.end(); it++){
		if ((*it)->pAppHandle == hApplication && (*it)->containerName == containerName){
			*phContainer = *it;
			SKF_LOGW("%s exit 0x%x for existing container", __FUNCTION__, SAR_OK);
			return SAR_OK;
		}
	}

	SKFHandleA_PTR tmp = (SKFHandleA_PTR)hApplication;
	string containerDesc;
	SKF_CONTAINER_APPLICATION_DESC(tmp->appName, containerDesc);

	CK_SESSION_HANDLE session = 0;
	ret = handle.GetSession((SKFHandleA_PTR)hApplication,&session);
	if (ret != SAR_OK){
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
		return SAR_FAIL;
	}
	
	CK_OBJECT_CLASS dataClass = CKO_DATA;
	CK_BBOOL ttrue = CK_TRUE;

	CK_ATTRIBUTE attributesCreate[] = {
		{ CKA_CLASS, &dataClass, sizeof(dataClass) },
		{ CKA_APPLICATION, (CK_VOID_PTR)containerDesc.data(), containerDesc.size() },
		{ CKA_LABEL, szContainerName, strlen(szContainerName) },
		{ CKA_TOKEN, &ttrue, sizeof(ttrue) },
		{ CKA_PRIVATE, &ttrue, sizeof(ttrue) },
		{ CKA_VALUE,NULL,0}
	};

	CK_OBJECT_HANDLE containerHandle = 0;
	ret = Adapter_C_CreateObject(session,attributesCreate,sizeof(attributesCreate) / sizeof(CK_ATTRIBUTE),&containerHandle);
	if (ret != SAR_OK){
		handle.CloseSession(session);
		SKF_LOGE("%s create cont error 0x%x", __FUNCTION__, ret);
		return p11Error2SkfError(ret);
	}

	handle.CloseSession(session);

	SKFHandleC_PTR tmpCon = new SKFHandleC();
	tmpCon->containerHandle = containerHandle;
	tmpCon->pAppHandle = (SKFHandleA_PTR)hApplication;
	tmpCon->containerName.append(szContainerName);
	tmpCon->flg = tempApplicationHandle->flg;

	SKFGlobeData::setContainerHandle.insert(tmpCon);
	
	*phContainer = tmpCon;

	SKF_LOGD("%s exit with %p and return container %p", __FUNCTION__, hApplication, tmpCon);
	
	return SAR_OK;
}

/*
*	在应用下删除指定名称的容器并释放容器相关的资源
*	hApplication		[IN]应用句柄
*	szContainerName		[IN]指向删除容器的名称
*/
SKF_DEVAPI SKF_DeleteContainer(
	IN HAPPLICATION	hApplication,
	IN LPSTR			szContainerName
	)
{
	ULONG ret_skf = SAR_OK;
	CK_RV ret_p11 = CKR_OK;

	set<SKFHandleSYM_PTR>::iterator itSK;
	set<SKFHandleCT_PTR>::iterator itCT;

	SKFHandleA_PTR tempApplicationHandle = (SKFHandleA_PTR)hApplication;
	SKFHandleSYM_PTR tempSessionKeyHandle = NULL;
	SKFHandleCT_PTR tempCertificationHandle = NULL;
	HandleCheck handle;

	// variables for asymmetric keypair operations
	CK_KEY_TYPE  keyType = CKK_SM2;
	CK_OBJECT_CLASS	pubkeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS prikeyClass = CKO_PRIVATE_KEY;
	CK_BYTE	m_ttrue = TRUE;
	CK_BYTE m_ffalse = FALSE;
	CK_BYTE_PTR keyID = NULL;
	CK_ULONG ulKeyIDLen = 0;

	// variables for certification operations
	CK_OBJECT_CLASS dataClass = CKO_DATA;
	string certApp;

	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);
	
	if (NULL == hApplication || NULL == szContainerName){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	SKF_LOGV("container to be deleted: %s", szContainerName);

	// check if app handle valid
	CK_RV ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	// check if application open
	if (SKF_FLAG_EXIST == ((SKFHandleA_PTR)hApplication)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// check if user already logged in app
	if (SKF_FLAG_AUTH_USR != tempApplicationHandle->flg) {
		SKF_LOGE("%s exit 0x%x. user log in required to delete container, current state %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, tempApplicationHandle->flg);
		return SAR_USER_NOT_LOGGED_IN;
	}

	// get container handle
	string s;
	s.append(szContainerName);
	set<SKFHandleC_PTR>::iterator it = SKFGlobeData::setContainerHandle.begin();
	SKFHandleC_PTR tmp = NULL;
	for (; it != SKFGlobeData::setContainerHandle.end(); it++){
		if ((*it)->pAppHandle == hApplication && (*it)->containerName == s){
			tmp = *it;
			break;
		}
	}

	// no valid container handle found, return error
	if (tmp == NULL){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INDATAERR);
		return SAR_INDATAERR;
	}

	// clean up session key information
	// ======================== start to destroy session key information =========================
	SKF_LOGD("total sessionKey %d before destroy", SKFGlobeData::setSessionKeyHandle.size());
	for (itSK = SKFGlobeData::setSessionKeyHandle.begin(); itSK != SKFGlobeData::setSessionKeyHandle.end(); ){
		if (((*itSK)->pContainerHandle) && ((*itSK)->pContainerHandle == tmp)) {
			tempSessionKeyHandle =  *itSK;
			if (SGD_SM3 != tempSessionKeyHandle->ulAlgId) {
				// destroy session object as these shall be invalid after device disconnect
				// SM3 for hash calculation, no destroy operation
				ret_p11 = Adapter_C_DestroyObject(tempSessionKeyHandle->session, tempSessionKeyHandle->sessKeyHandle);
				if(CKR_OK != ret_p11) {
					SKF_LOGE("destroy session key failed with return 0x%x", ret_p11);
					ret_skf = p11Error2SkfError(ret_skf);
					break;
				}
			}

			// close session bind with key
			ret_p11 = Adapter_C_CloseSession(tempSessionKeyHandle->session);
			if(CKR_OK != ret_p11) {
				SKF_LOGE("close session failed with return 0x%x", ret_p11);
				ret_skf = SAR_FAIL;
				break;
			}

			// remove handle from set
			// itSK must ++ here, cannot be put into for(;;itSK++)
			SKFGlobeData::setSessionKeyHandle.erase(itSK++);

			// release handle memory
			delete tempSessionKeyHandle;
			tempSessionKeyHandle = NULL;
		}
		else {
			itSK++;
		}
	}
	SKF_LOGD("total sessionKey %d after destroy", SKFGlobeData::setSessionKeyHandle.size());
	// unexpected error, return;
	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s destroy session key failed with return 0x%x", __FUNCTION__, ret_skf);
		return ret_skf;
	}
	// ======================== end of destroy session key information =========================

	CK_SESSION_HANDLE session = 0;
	ret = handle.GetSession((SKFHandleA_PTR)hApplication,&session);
	if (ret != SAR_OK){
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
		return SAR_FAIL;
	}
	
	// -------------------start to destroy signature keypairs-----------------------
	keyID = NULL;
	ulKeyIDLen = 0;
	keyID = assembleKeyId(tmp, TRUE, &ulKeyIDLen);
	if(NULL == keyID || 0 == ulKeyIDLen){
		handle.CloseSession(session);
		SKF_LOGE("%s return 0x%x for assembleKeyId failure", __FUNCTION__, SAR_FAIL);
		if(keyID){
			delete[] keyID;
			keyID = NULL;
		}
		return SAR_FAIL;
	}
	CK_ATTRIBUTE findTemplateSignature[] = {
		{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
		{ CKA_ID, keyID, ulKeyIDLen },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	ret_skf = destroyObjByTemplate(session, findTemplateSignature, sizeof(findTemplateSignature)/sizeof(CK_ATTRIBUTE));
	delete[] keyID;
	keyID = NULL;
	if(SAR_OK != ret_skf) {
		handle.CloseSession(session);
		SKF_LOGE("%s exit 0x%x due to destroy keypair error", __FUNCTION__, ret_skf);
		return ret_skf;
	}
	// -----------------------end of destroy signature keypairs...-----------------------
	
	// -----------------------start to destroy signature keypairs...-----------------------
	ulKeyIDLen = 0;
	keyID = assembleKeyId(tmp, FALSE, &ulKeyIDLen);
	if(NULL == keyID || 0 == ulKeyIDLen){
		handle.CloseSession(session);
		SKF_LOGE("%s return 0x%x for assembleKeyId failure", __FUNCTION__, SAR_FAIL);
		if(keyID){
			delete[] keyID;
			keyID = NULL;
		}
		return SAR_FAIL;
	}
	CK_ATTRIBUTE findTemplateCryp[] = {
		{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
		{ CKA_ID, keyID, ulKeyIDLen },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	ret_skf = destroyObjByTemplate(session, findTemplateCryp, sizeof(findTemplateCryp)/sizeof(CK_ATTRIBUTE));
	delete[] keyID;
	keyID = NULL;
	if(SAR_OK != ret_skf) {
		handle.CloseSession(session);
		SKF_LOGE("%s exit 0x%x due to destroy keypair error", __FUNCTION__, ret_skf);
		return ret_skf;
	}
	// -----------------------end of destroy signature keypairs...-----------------------
	
	
	// -----------------------start to destroy certifications...-----------------------
	SKF_LOGD("total certification %d before destroy certification", SKFGlobeData::setCertHandle.size());
	//remove buffer information for certification if there is
	for (itCT = SKFGlobeData::setCertHandle.begin(); itCT != SKFGlobeData::setCertHandle.end(); ) {
		if((*itCT)->pContainerHandle == tmp) {
			tempCertificationHandle = *itCT;
			ret_skf = Adapter_C_DestroyObject(session, tempCertificationHandle->certHandle);
			if(SAR_OK != ret_skf) {
				handle.CloseSession(session);
				SKF_LOGE("%s exit 0x%x due to destroy cert error", __FUNCTION__, ret_skf);
				return p11Error2SkfError(ret_skf);
			}
			SKFGlobeData::setCertHandle.erase(itCT++);

			delete tempCertificationHandle;
			tempCertificationHandle = NULL;
		}
		else {
			itCT++;
		}
	}
	SKF_LOGD("total certification %d after destroy certification", SKFGlobeData::setCertHandle.size());
	// end of remove buffer information 
#if 0
	SKF_CERT_APPLICATION_DESC(tmp->pAppHandle->appName,
		tmp->containerName, certApp);
	
	CK_ATTRIBUTE certFindTemplate[] = {
		{ CKA_APPLICATION, (char*)certApp.data(), certApp.size() },
		{ CKA_CLASS,&dataClass,sizeof(dataClass)},
		{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
	};
	
	ret_skf = destroyObjByTemplate(session, certFindTemplate, sizeof(certFindTemplate)/sizeof(CK_ATTRIBUTE));
	if(SAR_OK != ret_skf) {
		handle.CloseSession(session);
		return ret_skf;
	}
#endif
	// -----------------------end of destroy certifications...-----------------------
	
	ret = Adapter_C_DestroyObject(session,tmp->containerHandle);
	if (ret != SAR_OK){
		SKF_LOGE("%s exit 0x%x due to destroy cont error", __FUNCTION__, ret);
		return p11Error2SkfError(ret);
	}

	delete tmp;
	SKFGlobeData::setContainerHandle.erase(tmp);

	handle.CloseSession(session);

	SKF_LOGD("%s exit with %p and return container %s", __FUNCTION__, hApplication, szContainerName);

	return SAR_OK;
}

/*
*	获取容器句柄
*	hApplication		[IN]应用句柄
*	szContainerName		[IN]容器名称
*	phContainer			[OUT]返回所打开容器的句柄
*/
SKF_DEVAPI SKF_OpenContainer(
IN HAPPLICATION	hApplication,
IN LPSTR			szContainerName,
OUT HCONTAINER*	phContainer
)
{
	ULONG ret_skf = SAR_OK;
	CK_RV ret_p11 = CKR_OK;

	SKFHandleA_PTR tempApplicationHandle = (SKFHandleA_PTR)hApplication;
	HandleCheck handle;

	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);
	
	
	if (NULL == hApplication || NULL == szContainerName || NULL == phContainer){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	SKF_LOGV("container to be opened: %s", szContainerName);

	CK_RV ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (ret != CKR_OK) {
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	// check if application open
	if (SKF_FLAG_EXIST == ((SKFHandleA_PTR)hApplication)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

#if 0
	// check if user already logged in app
	if (SKF_FLAG_AUTH != tempApplicationHandle->flg) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
		return SAR_USER_NOT_LOGGED_IN;
	}
#endif

	string cName;
	cName.append(szContainerName);

	set<SKFHandleC_PTR>::iterator it = SKFGlobeData::setContainerHandle.begin();
	for (; it != SKFGlobeData::setContainerHandle.end(); it++){
		SKFHandleC_PTR tmp = *it;
		if (tmp->pAppHandle == (SKFHandleA_PTR)hApplication && tmp->containerName == cName){
			*phContainer = tmp;
			tmp->flg = SKF_FLAG_OPEN;
			SKF_LOGD("%s exit with input %p and existing container %p", __FUNCTION__, hApplication, tmp);
			return SAR_OK;
		}
	}

	SKF_LOGW("%s, continue read cont %s...", __FUNCTION__, szContainerName);

	if (it == SKFGlobeData::setContainerHandle.end()){
		string containerDesc;
		SKF_CONTAINER_APPLICATION_DESC(((SKFHandleA_PTR)hApplication)->appName, containerDesc);

		CK_BBOOL ttrue = CK_TRUE, ffalse = CK_FALSE;
		CK_OBJECT_CLASS dataClass = CKO_DATA;
		CK_ATTRIBUTE attributesFind[] = {
			{ CKA_CLASS, &dataClass, sizeof(dataClass) },
			{ CKA_APPLICATION, (CK_VOID_PTR)containerDesc.data(), containerDesc.size() },
			{ CKA_LABEL, szContainerName, strlen(szContainerName) },
			{ CKA_TOKEN, &ttrue, sizeof(ttrue) },
			{ CKA_PRIVATE, &ttrue, sizeof(ttrue) }
		};

		CK_SESSION_HANDLE session = 0;
		ret = handle.GetSession((SKFHandleA_PTR)hApplication, &session);
		if (ret != SAR_OK){
			SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
			return SAR_FAIL;
		}

		ret = Adapter_C_FindObjectsInit(session, attributesFind, sizeof(attributesFind) / sizeof(CK_ATTRIBUTE));
		if (ret != SAR_OK){
			handle.CloseSession(session);
			SKF_LOGE("%s find init failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
			return SAR_FAIL;
		}

		CK_OBJECT_HANDLE obj[1];
		CK_ULONG count = 0;
		ret = Adapter_C_FindObjects(session, obj, 1, &count);
		if (ret != SAR_OK){
			handle.CloseSession(session);
			SKF_LOGE("%s find failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
			return SAR_FAIL;
		}

		ret = Adapter_C_FindObjectsFinal(session);
		if (ret != SAR_OK){
			handle.CloseSession(session);
			SKF_LOGE("%s find final failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
			return SAR_FAIL;
		}
		handle.CloseSession(session);

		if (count > 0){
			SKFHandleC_PTR tmpC = new SKFHandleC();
			tmpC->containerHandle = obj[0];
			tmpC->containerName.append(szContainerName);
			tmpC->pAppHandle = (SKFHandleA_PTR)hApplication;
			*phContainer = tmpC;
			tmpC->flg = SKF_FLAG_OPEN;
			SKFGlobeData::setContainerHandle.insert(tmpC);

			SKF_LOGD("%s exit with input %p and container %p", __FUNCTION__, hApplication, tmpC);
			return SAR_OK;
		}
		else{
			SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
			return SAR_INVALIDHANDLEERR;
		}	
	}

	SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INDATAERR);
	return SAR_INDATAERR;
}

/*
*	关闭容器句柄，并释放容器句柄相关资源
*	hContainer			[OUT]容器句柄
*/
SKF_DEVAPI SKF_CloseContainer(
IN HCONTAINER hContainer
)
{
	ULONG ret_skf = SAR_OK;
	CK_RV ret_p11 = CKR_OK;

	set<SKFHandleC_PTR>::iterator itC;
	set<SKFHandleF_PTR>::iterator itF;
	set<SKFHandleSYM_PTR>::iterator itSK;
	set<SKFHandleCT_PTR>::iterator itCT;

	SKFHandleC_PTR tempContainerHandle = (SKFHandleC_PTR)hContainer;
	SKFHandleSYM_PTR tempSessionKeyHandle = NULL;
	HandleCheck handle;

	// variables for asymmetric keypair operations
	CK_KEY_TYPE  keyType = CKK_SM2;
	CK_OBJECT_CLASS	pubkeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS prikeyClass = CKO_PRIVATE_KEY;
	CK_BYTE	m_ttrue = TRUE;
	CK_BYTE m_ffalse = FALSE;
	CK_BYTE_PTR keyID = NULL;
	CK_ULONG ulKeyIDLen = 0;

	// variables for certification operations
	CK_OBJECT_CLASS dataClass = CKO_DATA;
	string certApp;

	SKF_LOGD("%s entry with %p", __FUNCTION__, hContainer);
	
	if (NULL == hContainer){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// check if app handle valid
	CK_RV ret = handle.Check(tempContainerHandle);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	// check if container open
	if (SKF_FLAG_EXIST == ((SKFHandleC_PTR)hContainer)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

#if 0
	// check if app logged in
	if (SKF_FLAG_AUTH != tempContainerHandle->pAppHandle->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
		return SAR_USER_NOT_LOGGED_IN;
	}
#endif
	
	// clean up session key information
	// ======================== start to destroy session key information =========================
	for (itSK = SKFGlobeData::setSessionKeyHandle.begin(); itSK != SKFGlobeData::setSessionKeyHandle.end(); ){
		if (((*itSK)->pContainerHandle) && ((*itSK)->pContainerHandle == tempContainerHandle)) {
			tempSessionKeyHandle =	*itSK;
			if (SGD_SM3 != tempSessionKeyHandle->ulAlgId) {
				// destroy session object as these shall be invalid after device disconnect
				// SM3 for hash calculation, no destroy operation
				ret_p11 = Adapter_C_DestroyObject(tempSessionKeyHandle->session, tempSessionKeyHandle->sessKeyHandle);
				if(CKR_OK != ret_p11) {
					SKF_LOGE("destroy session key failed with return 0x%x", ret_p11);
					ret_skf = p11Error2SkfError(ret_p11);
					break;
				}
			}
			// close session bind with key
			ret_p11 = Adapter_C_CloseSession(tempSessionKeyHandle->session);
			if(CKR_OK != ret_p11) {
				SKF_LOGE("close session failed with return 0x%x", ret_p11);
				ret_skf = SAR_FAIL;
				break;
			}
			// remove handle from set
			// itSK must ++ here, cannot be put into for(;;itSK++)
			SKFGlobeData::setSessionKeyHandle.erase(itSK++);
			// release handle memory
			delete tempSessionKeyHandle;
			tempSessionKeyHandle = NULL;
		}
		else {
			itSK++;
		}
	}
	// unexpected error, return;
	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s destroy session key failed with return 0x%x", __FUNCTION__, ret_skf);
		return ret_skf;
	}
	// ======================== end of destroy session key information =========================

	// update container status flag
	tempContainerHandle->flg = SKF_FLAG_EXIST;

	SKF_LOGD("%s exit with %p", __FUNCTION__, hContainer);
			
	return ret_skf;
}

/*
*	枚举应用下的所有容器并返回容器名称列表
*	hApplication		[IN]应用句柄
*	szContainerName		[OUT]指向容器名称列表缓冲区，如果此参数为NULL时，pulSize表示返回数据所需要缓冲区的长度，如果此参数不为NULL时，返回容器名称列表，每个容器名以单个'\0'为结束，列表以双'\0'结束
*	pulSize				[OUT]调用前表示szContainerName缓冲区的长度，返回容器名称列表的长度
*/
SKF_DEVAPI SKF_EnumContainer(
IN HAPPLICATION	hApplication,
OUT LPSTR			szContainerName,
OUT ULONG*		pulSize
)
{
	SKF_LOGD("%s entry with %p", __FUNCTION__, hApplication);

	if (NULL == hApplication || NULL == pulSize){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	HandleCheck handle;
	CK_RV ret = handle.Check((SKFHandleA_PTR)hApplication);
	if (ret != CKR_OK) {
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	// check if application open
	if (SKF_FLAG_EXIST == ((SKFHandleA_PTR)hApplication)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

#if 0
	if (SKF_FLAG_AUTH != ((SKFHandleA_PTR)hApplication)->flg) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
		return SAR_USER_NOT_LOGGED_IN;
	}
#endif

	string out;
	char pad[1] = { 0 };
	
	set<SKFHandleC_PTR>::iterator it = SKFGlobeData::setContainerHandle.begin();
	for (;it != SKFGlobeData::setContainerHandle.end();it++){
		if ((*it)->pAppHandle == hApplication) {
		out.append((*it)->containerName);
		out.append(pad,1);
		}
	}
	out.append(pad, 1);

	if (out.size() == 1){
		*pulSize = 0;
		SKF_LOGD("%s no container, exit with return 0x%x", __FUNCTION__, SAR_OK);
		return SAR_OK;
	}

	// check if input buffer enough to hold all output
	if((szContainerName) && (*pulSize < out.size())) {
		SKF_LOGE("%s exit with 0x%x", __FUNCTION__, SAR_BUFFER_TOO_SMALL);
		*pulSize = out.size();
		return SAR_BUFFER_TOO_SMALL;
	}
		
	*pulSize = out.size();

	if (NULL != szContainerName){
		memcpy(szContainerName,out.data(), *pulSize);
		logData((unsigned char *)szContainerName, out.size(), plog_verbose, "container enum result:");
	}

	SKF_LOGD("%s exit with %p", __FUNCTION__, hApplication);

	return SAR_OK;
}

/*
*	功能描述	获取容器的类型
*	hContainer	[IN]容器句柄。
*	pulContainerType	[OUT] 获得的容器类型。指针指向的值为0表示未定、尚未分配类型或者为空容器，为1表示为RSA容器，为2表示为SM2容器。
*
*/
SKF_DEVAPI SKF_GetContainerType(IN HCONTAINER hContainer,
OUT ULONG *pulContainerType)
{
	CK_OBJECT_HANDLE hPubKey = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	//CK_KEY_TYPE  keyType = CKK_SM2;
	CK_KEY_TYPE  keyType = 0;
	CK_OBJECT_CLASS pubkeyClass = CKO_PUBLIC_KEY;
	CK_BYTE m_ttrue = TRUE;
	CK_BYTE_PTR keyID = NULL;
	CK_ULONG ulKeyIDLen = 0;
	CK_ULONG objNumFound = 0;

	CK_ATTRIBUTE pubkeyTypeAttr[] = {
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	
	SKF_LOGD("%s entry with hContainer %p", __FUNCTION__, hContainer);
		
	if (NULL == hContainer){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}
	
	HandleCheck handle;
	ret_skf = handle.Check((SKFHandleC_PTR)hContainer);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	// check if container open
	if (SKF_FLAG_EXIST == ((SKFHandleC_PTR)hContainer)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

// there is no request for user log in to access this interface
#if 0
	// check if app logged in
	if (SKF_FLAG_AUTH != ((SKFHandleC_PTR)hContainer)->pAppHandle->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
		return SAR_USER_NOT_LOGGED_IN;
	}
#endif

	// set type to unkonw before check
	*pulContainerType = CONTAINER_PROPERTY_UNKNOWN;
	
	ret_p11 = Adapter_C_OpenSession(((SKFHandleC_PTR)hContainer)->pAppHandle->pDevHandle->id, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

	keyID = assembleKeyId((SKFHandleC_PTR)hContainer, TRUE, &ulKeyIDLen);
	if(NULL == keyID || 0 == ulKeyIDLen){
		SKF_LOGE("%s return 0x%x for assembleKeyId failure", __FUNCTION__, SAR_FAIL);
		if(keyID){
			delete[] keyID;
			keyID = NULL;
		}
		return SAR_FAIL;
	}

do {
	// get private key handle for signature operation in current container
	CK_ATTRIBUTE findSignPubTemplate[] = {
		{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
		{ CKA_ID, keyID, ulKeyIDLen },
		{ CKA_CLASS, &pubkeyClass, sizeof(CK_OBJECT_CLASS) }
		//{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};

	ret_p11 = Adapter_C_FindObjectsInit(hSession, findSignPubTemplate, sizeof(findSignPubTemplate)/sizeof(CK_ATTRIBUTE));
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s find init failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}

	// find object if exist
	ret_p11 = Adapter_C_FindObjects(hSession, &hPubKey, 1, &objNumFound);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s find failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}
		
	ret_p11 = Adapter_C_FindObjectsFinal(hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s find final failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}

	// no keypair yet, container type unkown
	if(0 == objNumFound) {
		*pulContainerType = CONTAINER_PROPERTY_UNKNOWN;
		ret_skf = SAR_OK;
		SKF_LOGW("%s find no keypair and return 0x%x", __FUNCTION__, SAR_OK);
		break;
	}

	ret_p11 = Adapter_C_GetAttributeValue(hSession, hPubKey, pubkeyTypeAttr, sizeof(pubkeyTypeAttr)/sizeof(CK_ATTRIBUTE));
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s read container failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}

	// current support ECC SM2 only
	if(CKK_SM2 == keyType) {
		*pulContainerType = CONTAINER_PROPERTY_ECC;
		ret_skf = SAR_OK;
		break;
	}
	else {
		*pulContainerType = CONTAINER_PROPERTY_UNKNOWN;
		SKF_LOGW("%s find unkonwn keypair and return 0x%x", __FUNCTION__, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}

} while(0);

	if (keyID) {
		delete[] keyID;
		keyID = NULL;
	}

	// close session after all p11 object destroied.
	ret_p11 = Adapter_C_CloseSession(hSession);
	
	SKF_LOGD("return 0x%x and type %d", ret_skf, *pulContainerType);

	return ret_skf;
}
/************************************************************************/
/*  6. 密码服务				                                            */
/*	SKF_GetRandom														*/
/*	SKF_GenExtRSAKey													*/
/*	SKF_GenRSAKeyPair													*/
/*	SKF_ImportRSAKeyPair												*/
/*	SKF_RSASignData														*/
/*	SKF_RSAVerify														*/
/*	SKF_RSAExportSessionKey												*/
/*	SKF_ExtRSAPubKeyOperation											*/
/*	SKF_ExtRSAPriKeyOperation											*/
/*	SKF_GenECCKeyPair													*/
/*	SKF_ImportECCKeyPair												*/
/*	SKF_ECCSignData														*/
/*	SKF_ECCVerify														*/
/*	SKF_ECCExportSessionKey												*/
/*	SKF_ExtECCEncrypt													*/
/*	SKF_ExtECCDecrypt													*/
/*	SKF_ExtECCSign														*/
/*	SKF_ExtECCVerify													*/
/*	SKF_ExportPublicKey													*/
/*	SKF_ImportSessionKey												*/
/*	SKF_SetSymmKey														*/
/*	SKF_EncryptInit														*/
/*	SKF_Encrypt															*/
/*	SKF_EncryptUpdate													*/
/*	SKF_EncryptFinal													*/
/*	SKF_DecryptInit														*/
/*	SKF_Decrypt															*/
/*	SKF_DecryptUpdate													*/
/*	SKF_DecryptFinal													*/
/*	SKF_DegistInit														*/
/*	SKF_Degist															*/
/*	SKF_DegistUpdate													*/
/*	SKF_DegistFinal														*/
/*	SKF_MACInit															*/
/*	SKF_MAC																*/
/*	SKF_MACUpdate														*/
/*	SKF_MACFinal														*/
/************************************************************************/

/*
*	产生指定长度的随机数
*	hDev			[IN] 设备句柄
*	pbRandom		[OUT] 返回的随机数
*	ulRandomLen		[IN] 随机数长度
*/
SKF_DEVAPI SKF_GenRandom(
IN DEVHANDLE hDev,
OUT BYTE *pbRandom,
IN ULONG ulRandomLen
)
{
	ULONG ret_skf = SAR_OK;
	CK_RV ret_p11 = CKR_OK;
	CK_SESSION_HANDLE hSession = 0;

	SKF_LOGD("%s entry with hDev %p and ulRandomLen 0x%lx", __FUNCTION__, hDev, ulRandomLen);
	
	if (NULL == hDev || NULL == pbRandom || 0 == ulRandomLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}
	
	HandleCheck handle;
	ret_skf = handle.Check((SKFHandleD_PTR)hDev);
	if (SAR_OK != ret_skf){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	
	ret_skf = handle.GetSession((SKFHandleD_PTR)hDev,&hSession);
	if (ret_skf != SAR_OK){
		SKF_LOGE("get session failed return 0x%x", ret_skf);
		return ret_skf;
	}

	ret_p11 = Adapter_C_GenerateRandom(hSession, pbRandom, ulRandomLen);
	if (ret_p11 != CKR_OK) {
		SKF_LOGE("%s read container failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

	// save random data for dev auth operation
	if(DEV_AUTH_RANDOM_LEN == ulRandomLen) {
		memset(((SKFHandleD_PTR)hDev)->devAuthPlain , 0,  16);
		memcpy(((SKFHandleD_PTR)hDev)->devAuthPlain, pbRandom, DEV_AUTH_RANDOM_LEN);
	}

	SKF_LOGD("%s exit", __FUNCTION__);
	logData((unsigned char *)pbRandom, ulRandomLen, plog_verbose, "Random data generated:");

	handle.CloseSession(hSession);

	return SAR_OK;
}

/*
*	由设备生成RSA密钥对并明文输出
*	hDev			[IN] 设备句柄
*	ulBitsLen		[IN] 密钥模长
*	pBlob			[OUT] 返回的私钥数据结构
*/
SKF_DEVAPI SKF_GenExtRSAKey(
IN DEVHANDLE hDev,
IN ULONG ulBitsLen,
OUT RSAPRIVATEKEYBLOB* pBlob
)
{
return SAR_NOTSUPPORTYETERR;
}

/*
*	生成RSA签名密钥对并输出签名公钥
*	hContainer		[IN] 容器句柄
*	ulBitsLen		[IN] 密钥模长
*	pBlob			[OUT] 返回的RSA公钥数据结构
*/
SKF_DEVAPI SKF_GenRSAKeyPair(
IN HCONTAINER hContainer,
IN ULONG ulBitsLen,
OUT RSAPUBLICKEYBLOB *pBlob
)
{
return SAR_NOTSUPPORTYETERR;
}

/*
*	导入RSA加密公私钥对
*	hContainer		[IN] 容器句柄
*	ulSymAlgId		[IN] 对称算法密钥标识
*	pbWrappedKey	[IN] 使用该容器内签名公钥保护的对称算法密钥
*	ulWrappedKeyLen	[IN] 保护的对称算法密钥长度
*	pbEncryptedData	[IN] 对称算法密钥保护的RSA加密私钥。私钥的格式遵循PKCS #1 v2.1: RSA Cryptography Standard中的私钥格式定义
*	ulEncryptedDataLen	[IN] 对称算法密钥保护的RSA加密公私钥对长度
*/
SKF_DEVAPI SKF_ImportRSAKeyPair(
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
*	使用hContainer指定容器的签名私钥，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名的长度
*	hContainer		[IN] 用来签名的私钥所在容器句柄
*	pbData			[IN] 被签名的数据
*	ulDataLen		[IN] 签名数据长度，应不大于RSA密钥模长-11
*	pbSignature		[OUT] 存放签名结果的缓冲区指针，如果值为NULL，用于取得签名结果长度
*	pulSigLen		[IN,OUT] 输入为签名结果缓冲区大小，输出为签名结果长度
*/
SKF_DEVAPI SKF_RSASignData(
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
*	验证RSA签名。用pRSAPubKeyBlob内的公钥值对待验签数据进行验签。
*	hDev			[IN] 连接设备时返回的设备句柄
*	pRSAPubKeyBlob	[IN] RSA公钥数据结构
*	pbData			[IN] 待验证签名的数据
*	ulDataLen		[IN] 数据长度，应不大于公钥模长-11
*	pbSignature		[IN] 待验证的签名值
*	ulSigLen		[IN] 签名值长度，必须为公钥模长
*/
SKF_DEVAPI SKF_RSAVerify(
IN DEVHANDLE			hDev,
IN RSAPUBLICKEYBLOB*	pRSAPubKeyBlob,
IN BYTE*				pbData,
IN ULONG				ulDataLen,
IN BYTE*				pbSignature,
IN ULONG				ulSigLen
)
{
return SAR_NOTSUPPORTYETERR;
}

/*
*	生成会话密钥并用外部公钥加密输出。
*	hContainer		[IN] 容器句柄
*	ulAlgID			[IN] 会话密钥的算法标识
*	pPubKey			[IN] 加密会话密钥的RSA公钥数据结构
*	pbData			[OUT] 导出的加密会话密钥密文，按照PKCS#1v1.5的要求封装
*	pulDataLen		[OUT] 返回导出数据长度
*	phSessionKey	[OUT] 导出的密钥句柄
*/
SKF_DEVAPI SKF_RSAExportSessionKey(
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
*	使用外部传入的RSA公钥对输入数据做公钥运算并输出结果
*	hDev			[IN] 设备句柄
*	pRSAPubKeyBlob	[IN] RSA公钥数据结构
*	pbInput			[IN] 指向待运算的原始数据缓冲区
*	ulInputLen		[IN] 待运算原始数据的长度，必须为公钥模长
*	pbOutput		[OUT] 指向RSA公钥运算结果缓冲区，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
*	pulOutputLen	[OUT] 调用前表示pbOutput缓冲区的长度，返回RSA公钥运算结果的实际长度
*/
SKF_DEVAPI SKF_ExtRSAPubKeyOperation(
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
*	直接使用外部传入的RSA私钥对输入数据做私钥运算并输出结果
*	hDev			[IN] 设备句柄
*	pRSAPriKeyBlob	[IN] RSA私钥数据结构
*	pbInput			[IN] 指向待运算数据缓冲区
*	ulInputLen		[IN] 待运算数据的长度，必须为公钥模长
*	pbOutput		[OUT] RSA私钥运算结果，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
*	pulOutputLen	[OUT] 调用前表示pbOutput缓冲区的长度，返回RSA私钥运算结果的实际长度
*/
SKF_DEVAPI SKF_ExtRSAPriKeyOperation(
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


ULONG Import_ECC_PublicKey(
IN DEVHANDLE hDev,
IN PECCPUBLICKEYBLOB pBlob,
OUT CK_OBJECT_HANDLE_PTR phPubKey
)
{
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_BYTE	m_ttrue = TRUE;
	CK_BYTE m_ffalse = FALSE;
	SKFHandleD_PTR pDev = (SKFHandleD_PTR)hDev;
	// public key attribute
	//CK_OBJECT_HANDLE hSm2PubKey = 0;
	CK_KEY_TYPE  keyTypeSM2 = CKK_SM2;
	CK_OBJECT_CLASS	pubkeyClass = CKO_PUBLIC_KEY;
	CK_BYTE localPubKey[ECC_MAX_XCOORDINATE_BITS_LEN/8] = {0};
	//CK_MECHANISM wrapSymmKeyMechanism = { CKM_SM2 , NULL, 0 };
	CK_ATTRIBUTE publicKeyCreatTemplate[] = {
			{ CKA_CLASS, &pubkeyClass, sizeof(CK_OBJECT_CLASS) },
			{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_ENCRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_VERIFY, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_ID, (unsigned char *)"SM2_EXTERNAL_TEMP_SKF", strlen("SM2_EXTERNAL_TEMP_SKF") },
			{ CKA_WRAP, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_KEY_TYPE, &keyTypeSM2, sizeof(keyTypeSM2) },
			{ CKA_VALUE, localPubKey, ECC_MAX_XCOORDINATE_BITS_LEN/8}
	};

	memcpy(localPubKey, pBlob->XCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, ECC_MAX_XCOORDINATE_BITS_LEN/16);
	memcpy(localPubKey + ECC_MAX_XCOORDINATE_BITS_LEN/16, pBlob->YCoordinate + ECC_MAX_YCOORDINATE_BITS_LEN/16, ECC_MAX_YCOORDINATE_BITS_LEN/16);

	ret_p11 = Adapter_C_OpenSession(pDev->id,  CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

	ret_p11 = Adapter_C_CreateObject(hSession, publicKeyCreatTemplate, sizeof(publicKeyCreatTemplate)/sizeof(CK_ATTRIBUTE), phPubKey);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s create obj failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
	}

	ret_p11 = Adapter_C_CloseSession(hSession);

	return ret_skf;
}


ULONG Import_ECC_PrivateKey(
IN DEVHANDLE hDev,
IN PECCPRIVATEKEYBLOB pBlob,
OUT CK_OBJECT_HANDLE_PTR phKey
)
{
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_BYTE	m_ttrue = TRUE;
	CK_BYTE m_ffalse = FALSE;
	SKFHandleD_PTR pDev = (SKFHandleD_PTR)hDev;
	// public key attribute
	//CK_OBJECT_HANDLE hSm2PubKey = 0;
	CK_KEY_TYPE  keyTypeSM2 = CKK_SM2;
	CK_OBJECT_CLASS	priKeyClass = CKO_PRIVATE_KEY;
	CK_BYTE localPriKey[ECC_MAX_MODULUS_BITS_LEN/16] = {0};
	//CK_MECHANISM wrapSymmKeyMechanism = { CKM_SM2 , NULL, 0 };
	CK_ATTRIBUTE privateKeyCreatTemplate[] = {
			{ CKA_CLASS, &priKeyClass, sizeof(CK_OBJECT_CLASS) },
			{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_DECRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_SIGN, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_ID, (unsigned char *)"SM2_EXTERNAL_TEMP_SKF", strlen("SM2_EXTERNAL_TEMP_SKF") },
			{ CKA_UNWRAP, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_KEY_TYPE, &keyTypeSM2, sizeof(keyTypeSM2) },
			{ CKA_VALUE, localPriKey, ECC_MAX_MODULUS_BITS_LEN/16}
	};

	memcpy(localPriKey, pBlob->PrivateKey + ECC_MAX_MODULUS_BITS_LEN/16, ECC_MAX_MODULUS_BITS_LEN/16);

	ret_p11 = Adapter_C_OpenSession(pDev->id,  CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

	ret_p11 = Adapter_C_CreateObject(hSession, privateKeyCreatTemplate, sizeof(privateKeyCreatTemplate)/sizeof(CK_ATTRIBUTE), phKey);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s create obj failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
	}

	ret_p11 = Adapter_C_CloseSession(hSession);

	return ret_skf;
}


ULONG destroyObjByTemplate(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pAttr,
	CK_ULONG ulAttrCount
	)
{
	CK_RV ret_p11 =  CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_OBJECT_HANDLE hObj = 0;
	CK_ULONG findObj = 0;
    unsigned int logCount = 0;

	if((NULL == pAttr) || (0 == ulAttrCount)) {
		SKF_LOGE("destroyObjByTemplate input error %p %d", pAttr, ulAttrCount);
		return SAR_FAIL;
	}

	SKF_LOGW("obj to be destroied with template:");
	for(logCount = 0; logCount < ulAttrCount; logCount++) {
		logData((unsigned char *)(&(pAttr[logCount].type)), sizeof(CK_ATTRIBUTE_TYPE), plog_warning);
		logData((unsigned char *)pAttr[logCount].pValue, pAttr[logCount].ulValueLen, plog_warning);
		}

	ret_p11 = Adapter_C_FindObjectsInit(hSession, pAttr, ulAttrCount);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s find init failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
	}

do{
	// find object if exist
	findObj = 0;
	hObj = 0;
	ret_p11 = Adapter_C_FindObjects(hSession, &hObj, 1, &findObj);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s find failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}

	// delete object if exist
	if (findObj){
		SKF_LOGW("obj 0x%x to be destroied", hObj);
		ret_p11 = Adapter_C_DestroyObject(hSession, hObj);
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s destroy failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
			ret_skf = SAR_FAIL;
			break;
		}
	}
		
}while(findObj);

	ret_p11 = Adapter_C_FindObjectsFinal(hSession);

	return ret_skf;
	
}



ULONG findSingleObjByTemplate(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pAttr,
	CK_ULONG ulAttrCount,
	CK_OBJECT_HANDLE_PTR phObj
	)
{
	CK_RV ret_p11 =  CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_OBJECT_HANDLE hObj[2] = {0};
	CK_ULONG findObj = 0;

	if(0 == hSession || NULL == pAttr || 0 == ulAttrCount || NULL == phObj){
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

	*phObj = 0;

	ret_p11 = Adapter_C_FindObjectsInit(hSession, pAttr, ulAttrCount);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s find init failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

	// find object if exist
	ret_p11 = Adapter_C_FindObjects(hSession, hObj, sizeof(hObj)/sizeof(CK_OBJECT_HANDLE), &findObj);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s find failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}
		
	ret_p11 = Adapter_C_FindObjectsFinal(hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s find final failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

	if (1 == findObj){
		*phObj = hObj[0];
		return SAR_OK;
	}
	else {
		SKF_LOGE("%s find %d obj match as 0x%x 0x%x", __FUNCTION__, findObj, hObj[0], hObj[1]);
		return SAR_FAIL;
	}
	
}


CK_BYTE_PTR assembleKeyId(SKFHandleC_PTR hContainer, CK_BBOOL signatureFlag, CK_ULONG_PTR pKeyIdLen)
{
	CK_ULONG keyIdLen = 0;
	CK_BYTE_PTR keyIdBuf = NULL;

	// 1 space after appName, 1 space after containerName, 1 signature flag, 1 ending zero
	keyIdLen = ((SKFHandleC_PTR)hContainer)->pAppHandle->appName.length() + 1 + ((SKFHandleC_PTR)hContainer)->containerName.length() + 3;
	keyIdBuf = new CK_BYTE[keyIdLen];
	memset(keyIdBuf, 0, keyIdLen);
	memcpy(keyIdBuf, ((SKFHandleC_PTR)hContainer)->pAppHandle->appName.data(), ((SKFHandleC_PTR)hContainer)->pAppHandle->appName.length());
	memset(keyIdBuf + ((SKFHandleC_PTR)hContainer)->pAppHandle->appName.length(), ' ', 1); // set conjunction symbol 0 one byte
	memcpy(keyIdBuf + ((SKFHandleC_PTR)hContainer)->pAppHandle->appName.length() + 1, ((SKFHandleC_PTR)hContainer)->containerName.data(), ((SKFHandleC_PTR)hContainer)->containerName.length());
	memset(keyIdBuf + ((SKFHandleC_PTR)hContainer)->pAppHandle->appName.length() + 1 + ((SKFHandleC_PTR)hContainer)->containerName.length(), ' ', 1); // set conjunction symbol 0 one byte
	if(signatureFlag) {	
		memset(keyIdBuf + ((SKFHandleC_PTR)hContainer)->pAppHandle->appName.length() + 1 + ((SKFHandleC_PTR)hContainer)->containerName.length() + 1, '1', 1); // set bool flag for singature as 1 one byte
	}
	else {
		memset(keyIdBuf + ((SKFHandleC_PTR)hContainer)->pAppHandle->appName.length() + 1 + ((SKFHandleC_PTR)hContainer)->containerName.length() + 1, '0', 1); // set bool flag for singature as 1 one byte
	}
	
	*pKeyIdLen = keyIdLen;
	return keyIdBuf;
}



/*
*	生成ECC签名密钥对并输出签名公钥。
*	hContainer		[IN] 容器句柄
*	ulBitsLen		[IN] 密钥模长
*	pBlob			[OUT] 返回ECC公钥数据结构
*/
SKF_DEVAPI SKF_GenECCKeyPair(
IN HCONTAINER hContainer,
IN ULONG ulAlgId,
OUT ECCPUBLICKEYBLOB *pBlob
)
{
	CK_OBJECT_HANDLE hPubKey = 0;
	CK_OBJECT_HANDLE hPrivKey = 0;
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_MECHANISM mechanism = { CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE  keyType = CKK_SM2;
	CK_OBJECT_CLASS	pubkeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS prikeyClass = CKO_PRIVATE_KEY;
	CK_BYTE	m_ttrue = TRUE;
	CK_BYTE m_ffalse = FALSE;
	CK_BYTE_PTR keyID = NULL;
	CK_ULONG ulKeyIDLen = 0;
	CK_ULONG pubKeyLen = ECC_MAX_XCOORDINATE_BITS_LEN/8;
	CK_BYTE localPubKey[ECC_MAX_XCOORDINATE_BITS_LEN/8] = {0};
	CK_ATTRIBUTE pubkeyValAttr[] = {
			{ CKA_VALUE, localPubKey, pubKeyLen }
	};

	SKF_LOGD("%s entry with hContainer %p and ulAlgId 0x%lx", __FUNCTION__, hContainer, ulAlgId);
	
	if (NULL == hContainer || NULL == pBlob || SGD_SM2_1 != ulAlgId){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	HandleCheck handle;
	ret_skf = handle.Check((SKFHandleC_PTR)hContainer);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	// check if container open
	if (SKF_FLAG_EXIST == ((SKFHandleC_PTR)hContainer)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// check if app logged in
	if (SKF_FLAG_AUTH_USR != ((SKFHandleC_PTR)hContainer)->pAppHandle->flg){
		SKF_LOGE("%s exit 0x%x. user log in required to Gen keypair, current state %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, ((SKFHandleC_PTR)hContainer)->pAppHandle->flg);
		return SAR_USER_NOT_LOGGED_IN;
	}

	ret_p11 = Adapter_C_OpenSession(((SKFHandleC_PTR)hContainer)->pAppHandle->pDevHandle->id, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

	// assemble keyID, as "appName + 0 + containerName + 0 + BoolSignatureFlag"
	keyID = assembleKeyId((SKFHandleC_PTR)hContainer, TRUE, &ulKeyIDLen);
	if(NULL == keyID || 0 == ulKeyIDLen){
		SKF_LOGE("%s return 0x%x for assembleKeyId failure", __FUNCTION__, SAR_FAIL);
		if(keyID){
			delete[] keyID;
			keyID = NULL;
		}
		return SAR_FAIL;
	}
	
	CK_ATTRIBUTE publicKeyTemplate[] = {
			{ CKA_CLASS, &pubkeyClass, sizeof(CK_OBJECT_CLASS) },
			{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_ENCRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_VERIFY, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_ID, keyID, ulKeyIDLen },
			{ CKA_WRAP, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};

	CK_ATTRIBUTE privateKeyTemplate[] = {
			{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_CLASS, &prikeyClass, sizeof(CK_OBJECT_CLASS) },
			{ CKA_ID, keyID, ulKeyIDLen },
			{ CKA_DECRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_SIGN, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_UNWRAP, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};

	CK_ATTRIBUTE findTemplate[] = {
		{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
		{ CKA_ID, keyID, ulKeyIDLen },
		// shall NOT put CKA_SIGN in, this will cause public key cannot be destroied
		//{ CKA_SIGN, &m_ttrue, sizeof(m_ttrue) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	
do{
	
	ret_skf = destroyObjByTemplate(hSession, findTemplate, sizeof(findTemplate)/sizeof(CK_ATTRIBUTE));
	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s destroyObjByTemplate return 0x%x", __FUNCTION__, ret_skf);
		break;
	}
	
	ret_p11 = Adapter_C_GenerateKeyPair(hSession, &mechanism, publicKeyTemplate, sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
		privateKeyTemplate, sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE), &hPubKey, &hPrivKey);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_GenerateKeyPair return 0x%x", __FUNCTION__, ret_p11);
		ret_skf = p11Error2SkfError(ret_p11);
		break;
	}

	// check if the pubkey encrypt symmetric key match hPubKey in current container
	ret_p11 = Adapter_C_GetAttributeValue(hSession, hPubKey, pubkeyValAttr, sizeof(pubkeyValAttr)/sizeof(CK_ATTRIBUTE));
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_GetAttributeValue return 0x%x", __FUNCTION__, ret_p11);
		ret_skf = SAR_FAIL;
		break;
	}

	// current SM2 keypair, public key length always 64 bytes. exception if NOT 64
	if(ECC_MAX_XCOORDINATE_BITS_LEN/8 != pubkeyValAttr[0].ulValueLen){
		SKF_LOGE("%s get wrong pub key length return 0x%x", __FUNCTION__, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}

	// fill output buffer
	memset((unsigned char *)pBlob, 0, sizeof(ECCPUBLICKEYBLOB));
	pBlob->BitLen = ECC_MAX_XCOORDINATE_BITS_LEN/2;
	memcpy(pBlob->XCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, localPubKey, ECC_MAX_XCOORDINATE_BITS_LEN/16);
	memcpy(pBlob->YCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, localPubKey + ECC_MAX_XCOORDINATE_BITS_LEN/16, ECC_MAX_XCOORDINATE_BITS_LEN/16);
}while(0);

	// keypair shall be destroied before close session when failure
	if(SAR_OK != ret_skf) {
		// destroy key if already created
		if(hPubKey){
			ret_p11 = Adapter_C_DestroyObject(hSession, hPubKey);
		}

		if(hPrivKey){
			ret_p11 = Adapter_C_DestroyObject(hSession, hPrivKey);
		}

		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}
	else {
		SKF_LOGW("%s Adapter_C_GenerateKeyPair get pubkey 0x%x priv key 0x%x with keyID %s", __FUNCTION__, hPubKey, hPrivKey, keyID);
	}

	if(keyID){
		delete[] keyID;
		keyID = NULL;
	}

	// close session after all p11 object destroied.
	Adapter_C_CloseSession(hSession);

	SKF_LOGD("%s exit with return 0x%lx", __FUNCTION__, ret_skf);
	if(SAR_OK == ret_skf) {
		logData((unsigned char *)pBlob, sizeof(ECCPUBLICKEYBLOB), plog_verbose, "public key:");
	}

	return ret_skf;
}

/*
*	导入ECC公私钥对
*	hContainer		[IN] 容器句柄
*	pbWrapedData	[IN] 加密保护的ECC加密公私钥对密文
*	ulWrapedLen		[IN] 数据长度
*/
SKF_DEVAPI SKF_ImportECCKeyPair(
IN HCONTAINER hContainer,
IN PENVELOPEDKEYBLOB pEnvelopedKeyBlob
)
{
	// variables for general purpose
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	
	// for signature keypair in container
	CK_OBJECT_HANDLE hPubKeySign = 0;
	CK_OBJECT_HANDLE hPrivKeySign = 0;
	CK_BYTE signPubKey[64] = {0};
	CK_ATTRIBUTE pubkeyValAttr[] = {
			{ CKA_VALUE, signPubKey, 64 }
	};
	
	// for new imported crypto keypair
	CK_OBJECT_HANDLE hPubKey = 0;
	CK_OBJECT_HANDLE hPrivKey = 0;
	CK_KEY_TYPE  keyType = CKK_SM2;
	CK_OBJECT_CLASS	pubkeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS prikeyClass = CKO_PRIVATE_KEY;
	CK_BYTE	m_ttrue = TRUE;
	CK_BYTE m_ffalse = FALSE;
	CK_BYTE_PTR encryptKeyID = NULL;
	CK_ULONG ulEncryptKeyIDLen = 0;
	CK_BYTE_PTR signatureKeyID = NULL;
	CK_ULONG ulSignatureKeyIDLen = 0;
	CK_MECHANISM sm4mechanism_Dec = { CKM_SM4_ECB, NULL, 0 };
	ECCPRIVATEKEYBLOB cryptoPrivateKeyBlob;
	CK_BYTE cryptoPubKeyValue[ECC_MAX_XCOORDINATE_BITS_LEN/8] = {0};  // 64 bytes for x&y
	
	// for symmetric key unwrapped from input parameter
	CK_OBJECT_HANDLE hSymmKey = 0;
	CK_OBJECT_CLASS symmKeyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE  symmKeyType = CKK_SM4;
	CK_ATTRIBUTE symmKeyUnwrapTemplate[] = {
			{ CKA_CLASS, &symmKeyClass, sizeof(CK_OBJECT_CLASS) },
			{ CKA_TOKEN, &m_ffalse, sizeof(m_ffalse) },
			{ CKA_ENCRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_DECRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_WRAP, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_UNWRAP, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_KEY_TYPE, &symmKeyType, sizeof(symmKeyType) }
	};
	CK_MECHANISM unwrapSymmKeyMechanism = { CKM_SM2 , NULL, 0 };
	CK_BYTE symmKeyPlain[64] = {0};
	CK_ULONG symmKeyLen = 64;
	CK_MECHANISM sm3mechanism={ CKM_HASH_SM3,NULL_PTR,0 };
	CK_BYTE sm4KeyHashOut[HASH_OUTPUT_LEN] = {0};
	CK_BYTE_PTR p11Sm2DecInput = NULL;
	CK_ULONG sm2DecInputLen = 0;

	SKF_LOGD("%s entry with hContainer %p", __FUNCTION__, hContainer);
	//logData((unsigned char *)pEnvelopedKeyBlob, sizeof(ENVELOPEDKEYBLOB)+pEnvelopedKeyBlob->ECCCipherBlob.CipherLen-1, plog_verbose, "cipher key blob:");
	

	// windows endian is not same with TF card
	// version must be 1 for this lib, ulSymmAlgID must be SGD_SM4_ECB, pubKey bit Len must be 256
	if (NULL == hContainer || NULL == pEnvelopedKeyBlob || 1 != pEnvelopedKeyBlob->Version
		|| SGD_SMS4_ECB != pEnvelopedKeyBlob->ulSymmAlgID || 256 != pEnvelopedKeyBlob->PubKey.BitLen){
		//|| 0x80000000 != pEnvelopedKeyBlob->ulBits){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	if ((SM4_KEY_LEN != pEnvelopedKeyBlob->ECCCipherBlob.CipherLen)||(NULL == pEnvelopedKeyBlob->ECCCipherBlob.Cipher)){
		// key len shall be SM4 only
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	logData((unsigned char *)pEnvelopedKeyBlob, sizeof(ENVELOPEDKEYBLOB) + pEnvelopedKeyBlob->ECCCipherBlob.CipherLen, plog_verbose, "SKF_ImportECCKeyPair input raw ENVELOPEDKEYBLOB:");
	
	HandleCheck handle;
	ret_skf = handle.Check((SKFHandleC_PTR)hContainer);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	// check if container open
	if (SKF_FLAG_EXIST == ((SKFHandleC_PTR)hContainer)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// check if app logged in
	if (SKF_FLAG_AUTH_USR != ((SKFHandleC_PTR)hContainer)->pAppHandle->flg){
		SKF_LOGE("%s exit 0x%x. user log in required to import keypair, current state %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, ((SKFHandleC_PTR)hContainer)->pAppHandle->flg);
		return SAR_USER_NOT_LOGGED_IN;
	}

	ret_p11 = Adapter_C_OpenSession(((SKFHandleC_PTR)hContainer)->pAppHandle->pDevHandle->id, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

do{
	// assemble keyID, as "appName + 0 + containerName + 0 + BoolSignatureFlag"
	signatureKeyID = assembleKeyId((SKFHandleC_PTR)hContainer, TRUE, &ulSignatureKeyIDLen);
	if(NULL == signatureKeyID || 0 == ulSignatureKeyIDLen){
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s return 0x%x for assembleKeyId failure", __FUNCTION__, SAR_FAIL);
		break;
	}

	// get private key handle for signature operation in current container
	CK_ATTRIBUTE findSignPrivTemplate[] = {
		{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
		{ CKA_ID, signatureKeyID, ulSignatureKeyIDLen },
		{ CKA_CLASS, &prikeyClass, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	ret_skf = findSingleObjByTemplate(hSession, findSignPrivTemplate, sizeof(findSignPrivTemplate)/sizeof(CK_ATTRIBUTE), &hPrivKeySign);
	if(SAR_OK != ret_skf || 0 == hPrivKeySign)
	{
		SKF_LOGE("%s return 0x%x for findSingleObjByTemplate and handle 0x%x", __FUNCTION__, ret_skf, hPrivKeySign);
		unsigned char * keyIdPart1 = signatureKeyID;
        SKF_LOGE("key ID %s, keyType 0x%x class 0x%x", keyIdPart1, keyType, prikeyClass);
		ret_skf = SAR_KEYNOTFOUNDERR;
		break;
	}

	// unwrap symmetric key by signature private key
	// assemble sm2 decrypt input:
	// GM_T 0003.4-2012 SM2 document specified SM2 output sequence as C1||C3||C2 in section 6.2
	// but JW card implement C1||C2||C3 instead. need arrange input to C1||C2||C3 format
	sm2DecInputLen = ECC_MAX_XCOORDINATE_BITS_LEN/8 + HASH_OUTPUT_LEN + pEnvelopedKeyBlob->ECCCipherBlob.CipherLen;
	p11Sm2DecInput = new CK_BYTE[sm2DecInputLen];
	memset(p11Sm2DecInput, 0, sm2DecInputLen);
	memcpy(p11Sm2DecInput, pEnvelopedKeyBlob->ECCCipherBlob.XCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, ECC_MAX_XCOORDINATE_BITS_LEN/16);
	memcpy(p11Sm2DecInput + ECC_MAX_XCOORDINATE_BITS_LEN/16, pEnvelopedKeyBlob->ECCCipherBlob.YCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, ECC_MAX_XCOORDINATE_BITS_LEN/16);
	memcpy(p11Sm2DecInput + ECC_MAX_XCOORDINATE_BITS_LEN/8, pEnvelopedKeyBlob->ECCCipherBlob.Cipher, pEnvelopedKeyBlob->ECCCipherBlob.CipherLen);
	memcpy(p11Sm2DecInput + ECC_MAX_XCOORDINATE_BITS_LEN/8 + pEnvelopedKeyBlob->ECCCipherBlob.CipherLen, pEnvelopedKeyBlob->ECCCipherBlob.HASH, HASH_OUTPUT_LEN);
	
	
	ret_p11 = Adapter_C_UnwrapKey(hSession, &unwrapSymmKeyMechanism, hPrivKeySign, p11Sm2DecInput, sm2DecInputLen, symmKeyUnwrapTemplate, sizeof(symmKeyUnwrapTemplate)/sizeof(CK_ATTRIBUTE), &hSymmKey);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s return 0x%x for Adapter_C_UnwrapKey failure and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}

	// bcz private key is encrypted as 64 bytes, cannot be unwrapped directly, must decrypt to plain firstly...
	// decrypt private key plain value by symmetric key
	ret_p11 = Adapter_C_DecryptInit(hSession, &sm4mechanism_Dec, hSymmKey);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s return 0x%x for Adapter_C_DecryptInit failure and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}
	memset(&cryptoPrivateKeyBlob, 0, sizeof(cryptoPrivateKeyBlob));
	cryptoPrivateKeyBlob.BitLen = ECC_MAX_MODULUS_BITS_LEN/8;
	//ret_p11 = Adapter_C_Decrypt(hSession, pEnvelopedKeyBlob->cbEncryptedPriKey, pEnvelopedKeyBlob.ulBits, cryptoPrivateKeyBlob.PrivateKey, &cryptoPrivateKeyBlob.BitLen);
	ret_p11 = Adapter_C_Decrypt(hSession, pEnvelopedKeyBlob->cbEncryptedPriKey, ECC_MAX_MODULUS_BITS_LEN/8, cryptoPrivateKeyBlob.PrivateKey, &cryptoPrivateKeyBlob.BitLen);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s return 0x%x for Adapter_C_Decrypt failure and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}
	
	//SKF_LOGW("--------------------- log shall be removed ------------------------");
	//logData((unsigned char *)cryptoPrivateKeyBlob.PrivateKey, cryptoPrivateKeyBlob.BitLen, plog_warning, "private key plaintext ");
	//SKF_LOGW("--------------------- log shall be removed ------------------------");

	// assemble keyID, as "appName + 0 + containerName + 0 + BoolSignatureFlag"
	encryptKeyID = assembleKeyId((SKFHandleC_PTR)hContainer, FALSE, &ulEncryptKeyIDLen);
	if(NULL == encryptKeyID || 0 == ulEncryptKeyIDLen){
		SKF_LOGE("%s return 0x%x for assembleKeyId failure", __FUNCTION__, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}

	// find and destroy existing encrypt/decrypt keypair in token
	CK_ATTRIBUTE findDestroyTemplate[] = {
		{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
		{ CKA_ID, encryptKeyID, ulEncryptKeyIDLen },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	ret_skf = destroyObjByTemplate(hSession, findDestroyTemplate, sizeof(findDestroyTemplate)/sizeof(CK_ATTRIBUTE));
	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x for destroyObjByTemplate failure", __FUNCTION__, ret_skf);
		break;
	}

	// import private key
	CK_ATTRIBUTE privateKeyCreatTemplate[] = {
			{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_CLASS, &prikeyClass, sizeof(CK_OBJECT_CLASS) },
			{ CKA_ID, encryptKeyID, ulEncryptKeyIDLen },
			{ CKA_DECRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_SIGN, &m_ffalse, sizeof(m_ffalse) },
			{ CKA_UNWRAP, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_VALUE, cryptoPrivateKeyBlob.PrivateKey + ECC_MAX_MODULUS_BITS_LEN/16, ECC_MAX_MODULUS_BITS_LEN/16}
	};
	ret_p11 = Adapter_C_CreateObject(hSession, privateKeyCreatTemplate, sizeof(privateKeyCreatTemplate)/sizeof(CK_ATTRIBUTE), &hPrivKey);
	if(CKR_OK != ret_p11) {
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s return 0x%x for Adapter_C_CreateObject failure and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		break;
	}

	// import public key, XCoordinate and YCoordinate in bolb both size ECC_MAX_XCOORDINATE_BITS_LEN/8 = 64, while TF card support 32 bytes for X/Y
	memcpy(cryptoPubKeyValue, pEnvelopedKeyBlob->PubKey.XCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, ECC_MAX_XCOORDINATE_BITS_LEN/16);
	memcpy(cryptoPubKeyValue + ECC_MAX_XCOORDINATE_BITS_LEN/16, pEnvelopedKeyBlob->PubKey.YCoordinate + ECC_MAX_YCOORDINATE_BITS_LEN/16, ECC_MAX_YCOORDINATE_BITS_LEN/16);
	CK_ATTRIBUTE publicKeyCreatTemplate[] = {
			{ CKA_CLASS, &pubkeyClass, sizeof(CK_OBJECT_CLASS) },
			{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_ENCRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_VERIFY, &m_ffalse, sizeof(m_ffalse) },
			{ CKA_ID, encryptKeyID, ulEncryptKeyIDLen },
			{ CKA_WRAP, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_VALUE, cryptoPubKeyValue, ECC_MAX_XCOORDINATE_BITS_LEN/8}
	};
	ret_p11 = Adapter_C_CreateObject(hSession, publicKeyCreatTemplate, sizeof(publicKeyCreatTemplate)/sizeof(CK_ATTRIBUTE), &hPubKey);
	if(CKR_OK != ret_p11) {
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s return 0x%x for Adapter_C_CreateObject failure and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		break;
	}

	// below try check if the keypair is valid
	unsigned char checkInput[4] = {1, 2, 3, 4};
	unsigned char checkOutCipher[100] = {0};
	unsigned char checkoutPlain[4] = {0};
	ULONG cipherLen = sizeof(checkOutCipher);
	ULONG plainLen = sizeof(checkoutPlain);
	memset(checkOutCipher, 0, sizeof(checkOutCipher));
	memset(checkoutPlain, 0, sizeof(checkoutPlain));

	CK_MECHANISM  mechanismSm2 = {CKM_SM2, NULL_PTR, 0};
	
	ret_p11 = Adapter_C_EncryptInit(hSession, &mechanismSm2, hPubKey);
	if(CKR_OK != ret_p11) {
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s return 0x%x for Adapter_C_EncryptInit failure and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		break;
	}

	ret_p11 = Adapter_C_Encrypt(hSession, checkInput, sizeof(checkInput), checkOutCipher, &cipherLen);
	if(CKR_OK != ret_p11) {
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s return 0x%x for Adapter_C_Encrypt failure and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		break;
	}

	ret_p11 = Adapter_C_DecryptInit(hSession, &mechanismSm2, hPrivKey);
	if(CKR_OK != ret_p11) {
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s return 0x%x for Adapter_C_DecryptInit failure and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		break;
	}

	ret_p11 = Adapter_C_Decrypt(hSession, checkOutCipher, cipherLen, checkoutPlain, &plainLen);
	if(CKR_OK != ret_p11) {
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s return 0x%x for Adapter_C_Decrypt failure and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		break;
	}

	if(memcmp(checkInput, checkoutPlain, sizeof(checkInput))) {
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s return 0x%x for SM2 keypair valid checking failure and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		break;
	}
	// end of keypair validation
	
}while(0);

	// delete generated key objects when failed
	// object shall be destroied before close session
	if(SAR_OK != ret_skf){
		if(hPrivKey){
			ret_p11 = Adapter_C_DestroyObject(hSession, hPrivKey);
		}
		if(hPubKey){
			ret_p11 = Adapter_C_DestroyObject(hSession, hPubKey);
		}

		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}
	else {
		SKF_LOGW("%s SKF_ImportECCKeyPair get pubkey 0x%x priv key 0x%x with keyID %s", __FUNCTION__, hPubKey, hPrivKey, encryptKeyID);
	}

	// no need check return as suppose this will not impact the imported keypair
	// object shall be destroied before close session
	if(hSymmKey){
		ret_p11 = Adapter_C_DestroyObject(hSession, hSymmKey);
	}
	
	if(p11Sm2DecInput){
		delete p11Sm2DecInput;
		p11Sm2DecInput = NULL;
	}

	if(encryptKeyID){
		delete encryptKeyID;
		encryptKeyID = NULL;
	}

	if(signatureKeyID){
		delete[] signatureKeyID;
		signatureKeyID = NULL;
	}

	// close session after all p11 object destroied.
	Adapter_C_CloseSession(hSession);

	SKF_LOGD("%s exit with return 0x%lx", __FUNCTION__, ret_skf);

	return ret_skf;

}

/*
*	ECC数字签名。采用ECC算法和指定私钥hKey，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名值的长度
*	hContainer		[IN] 用来签名的私钥所在容器句柄
*	pbData			[IN] 被签名的数据
*	ulDataLen		[IN] 待签名数据长度，必须小于密钥模长
*	pbSignature		[OUT] 签名值，为NULL时用于获得签名值的长度
*	pulSigLen		[IN,OUT] 返回签名值长度的指针
*/
SKF_DEVAPI SKF_ECCSignData(
IN HANDLE hContainer,
IN BYTE *pbData,
IN ULONG ulDataLen,
OUT PECCSIGNATUREBLOB pSignature
)
{
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	
	CK_KEY_TYPE  keyType = CKK_SM2;
	CK_OBJECT_CLASS	pubkeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS prikeyClass = CKO_PRIVATE_KEY;
	CK_BYTE	m_ttrue = TRUE;
	CK_BYTE m_ffalse = FALSE;
	CK_BYTE_PTR keyID = NULL;
	CK_ULONG ulKeyIDLen = 0;
	
	CK_MECHANISM sm2CryptMechanism = { CKM_SM2, NULL_PTR, 0 };
	// input always 32 bytes output always 64 bytes 
	CK_BYTE signOutBuf[64] = {0};
	CK_ULONG signOutLen = 64;
	CK_OBJECT_HANDLE hPrivKeySign = 0;

	SKF_LOGD("%s entry with hContainer %p", __FUNCTION__, hContainer);

	// check input parameter
	if (NULL == hContainer || NULL == pbData || NULL == pSignature || HASH_OUTPUT_LEN != ulDataLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	logData(pbData, ulDataLen, plog_verbose, "data to sign:");

	HandleCheck handle;
	ret_skf = handle.Check((SKFHandleC_PTR)hContainer);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	// check if app logged in
	if (SKF_FLAG_AUTH_USR != ((SKFHandleC_PTR)hContainer)->pAppHandle->flg){
		SKF_LOGE("%s exit 0x%x. user log in required to sign data, current state %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, ((SKFHandleC_PTR)hContainer)->pAppHandle->flg);
		return SAR_USER_NOT_LOGGED_IN;
	}

	ret_p11 = Adapter_C_OpenSession(((SKFHandleC_PTR)hContainer)->pAppHandle->pDevHandle->id, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

do{
	// assemble keyID, as "appName + 0 + containerName + 0 + BoolSignatureFlag"
	keyID = assembleKeyId((SKFHandleC_PTR)hContainer, TRUE, &ulKeyIDLen);
	if(NULL == keyID || 0 == ulKeyIDLen){
		SKF_LOGE("%s return 0x%x for assembleKeyId failure", __FUNCTION__, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}
	
	CK_ATTRIBUTE findTemplate[] = {
		{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
		{ CKA_ID, keyID, ulKeyIDLen },
		{ CKA_SIGN, &m_ttrue, sizeof(m_ttrue) },
		{ CKA_CLASS, &prikeyClass, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	
	ret_skf = findSingleObjByTemplate(hSession, findTemplate, sizeof(findTemplate)/sizeof(CK_ATTRIBUTE), &hPrivKeySign);
	// check if there is valid signature private key within cryptoki
	if(SAR_OK != ret_skf || 0 == hPrivKeySign)
	{
		SKF_LOGE("%s return 0x%x for findSingleObjByTemplate and handle 0x%x", __FUNCTION__, ret_skf, hPrivKeySign);
        unsigned char * keyIdPart1 = keyID;
        SKF_LOGE("key ID %s, keyType 0x%x class 0x%x", keyIdPart1, keyType, prikeyClass);
		ret_skf = SAR_KEYNOTFOUNDERR;
		break;
	}

	// encrypt plain text
	ret_p11 = Adapter_C_SignInit(hSession, &sm2CryptMechanism, hPrivKeySign);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s return 0x%x for Adapter_C_SignInit failure", __FUNCTION__, ret_p11);
		ret_skf = SAR_FAIL;
		break;
	}

	ret_p11 = Adapter_C_Sign(hSession, pbData, ulDataLen, signOutBuf, &signOutLen);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s return 0x%x for Adapter_C_Sign failure", __FUNCTION__, ret_p11);
		ret_skf = SAR_FAIL;
		break;
	}

	// a sample signature output reference generated by LongMai SKF key
	/**
	0000000000000000000000000000000000000000000000000000000000000000
	9eeeb80df6cca8c572ddb55e46f326edf5ed89ee59f7a9e70f5fa5668fa1e53a
	0000000000000000000000000000000000000000000000000000000000000000
	51ed70fd9be3164c93d7e612448ba7fd34c17066e31f80a6f3fcb3af2dc5cead
	**/
	// fill output buffer
	memset(pSignature, 0, sizeof(ECCSIGNATUREBLOB));
	memcpy(pSignature->r + ECC_MAX_MODULUS_BITS_LEN/16, signOutBuf, ECC_MAX_MODULUS_BITS_LEN/16);
	memcpy(pSignature->s + ECC_MAX_MODULUS_BITS_LEN/16, signOutBuf + ECC_MAX_MODULUS_BITS_LEN/16, ECC_MAX_MODULUS_BITS_LEN/16);
}while(0);

	// close session after all p11 object destroied.
	ret_p11 = Adapter_C_CloseSession(hSession);

	if (keyID) {
		delete[] keyID;
		keyID = NULL;
	}

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}
	else {
		logData((unsigned char *)pSignature, sizeof(ECCSIGNATUREBLOB), plog_verbose, "sign output:");
	}

	SKF_LOGD("%s exit 0x%lx", __FUNCTION__, ret_skf);
	
	return ret_skf;
}

/*
*	用ECC公钥对数据进行验签
*	hDev			[IN] 设备句柄
*	pECCPubKeyBlob	[IN] ECC公钥数据结构
*	pbData			[IN] 待验证签名的数据
*	ulDataLen		[IN] 数据长度
*	pbSignature		[IN] 待验证的签名值
*	ulSigLen		[IN] 签名值长度
*/
SKF_DEVAPI SKF_ECCVerify(
IN DEVHANDLE			hDev,
IN ECCPUBLICKEYBLOB*	pECCPubKeyBlob,
IN BYTE*				pbData,
IN ULONG				ulDataLen,
IN PECCSIGNATUREBLOB pSignature
)
{
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_OBJECT_HANDLE hPubKey = 0;
	CK_MECHANISM sm2CryptMechanism = { CKM_SM2, NULL_PTR, 0 };
	CK_BYTE signatureLocal[64] = {0};

	SKF_LOGD("%s entry with hDev %p", __FUNCTION__, hDev);

	// check input parameter
	if (NULL == hDev || NULL == pECCPubKeyBlob || NULL == pbData || 0 == ulDataLen || NULL == pSignature){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	logData((unsigned char *)pECCPubKeyBlob, sizeof(ECCPUBLICKEYBLOB), plog_verbose, "input publice key:");
	logData((unsigned char *)pbData, ulDataLen, plog_verbose, "input raw data:");
	logData((unsigned char *)pSignature, sizeof(ECCSIGNATUREBLOB), plog_verbose, "input signature:");

	HandleCheck handle;
	ret_skf = handle.Check((SKFHandleD_PTR)hDev);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	ret_p11 = Adapter_C_OpenSession(((SKFHandleD_PTR)hDev)->id,  CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}
	
do{
	// import public key and get p11 handle
	ret_skf = Import_ECC_PublicKey(hDev, pECCPubKeyBlob, &hPubKey);
	if(SAR_OK != ret_skf){
		SKF_LOGE("%s Import_ECC_PublicKey return 0x%x", __FUNCTION__, ret_skf);
		break;
	}

	// verify
	ret_p11 = Adapter_C_VerifyInit(hSession, &sm2CryptMechanism, hPubKey);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_VerifyInit return 0x%x", __FUNCTION__, ret_p11);
		ret_skf = SAR_FAIL;
		break;
	}

	// a sample signature output reference generated by LongMai SKF key
	/**
	0000000000000000000000000000000000000000000000000000000000000000
	9eeeb80df6cca8c572ddb55e46f326edf5ed89ee59f7a9e70f5fa5668fa1e53a
	0000000000000000000000000000000000000000000000000000000000000000
	51ed70fd9be3164c93d7e612448ba7fd34c17066e31f80a6f3fcb3af2dc5cead
	**/
	// convert signature format to match P11 interface format
	memcpy(signatureLocal, pSignature->r + ECC_MAX_MODULUS_BITS_LEN/16, ECC_MAX_MODULUS_BITS_LEN/16);
	memcpy(signatureLocal + ECC_MAX_MODULUS_BITS_LEN/16, pSignature->s + ECC_MAX_MODULUS_BITS_LEN/16, ECC_MAX_MODULUS_BITS_LEN/16);
	ret_p11 = Adapter_C_Verify(hSession, pbData, ulDataLen, signatureLocal, sizeof(signatureLocal));
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_Verify return 0x%x", __FUNCTION__, ret_p11);
		ret_skf = SAR_FAIL;
		break;
	}
}while(0);

	// object shall be destroied before close session
	if(hPubKey){
		ret_p11 = Adapter_C_DestroyObject(hSession, hPubKey);
	}

	// close session after all p11 object destroied.
	ret_p11 = Adapter_C_CloseSession(hSession);

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}

	SKF_LOGD("%s exit with ret_skf 0x%lx", __FUNCTION__, ret_skf);

	return ret_skf;
}

/*
*	生成会话密钥并用外部公钥加密输出。
*	hContainer		[IN] 容器句柄
*	ulAlgID			[IN] 会话密钥的算法标识
*	pPubKey			[IN] 外部输入的公钥结构
*	pbData			[OUT] 导出的加密会话密钥密文
*	phSessionKey	[OUT] 会话密钥句柄
*/
SKF_DEVAPI SKF_ECCExportSessionKey(
IN HCONTAINER hContainer,
IN ULONG ulAlgID,
IN ECCPUBLICKEYBLOB* pPubKey,
OUT PECCCIPHERBLOB pData,
OUT HANDLE* phSessionKey
)
{
	// variables for general purpose
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_BYTE	m_ttrue = TRUE;
	CK_BYTE m_ffalse = FALSE;
	// public key attribute
	CK_OBJECT_HANDLE hSm2PubKey = 0;
	CK_MECHANISM wrapSymmKeyMechanism = { CKM_SM2 , NULL, 0 };
	// session key attribute
	CK_OBJECT_HANDLE hSymmKey = 0;
	CK_MECHANISM mechanismSM4Generate = { CKM_SM4_KEY_GEN, NULL, 0 };
	CK_OBJECT_CLASS symmKeyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE  symmKeyType = CKK_SM4;
	CK_BYTE symmKeyPlain[SM4_KEY_LEN] = {0};
	CK_MECHANISM sm3mechanism={ CKM_HASH_SM3,NULL_PTR,0 };
	CK_BYTE sm4KeyHashOut[HASH_OUTPUT_LEN] = {0};
	CK_ULONG sm4HashOutLen = HASH_OUTPUT_LEN;
	CK_ATTRIBUTE symmKeyTemplate[] = {
			{ CKA_CLASS, &symmKeyClass, sizeof(CK_OBJECT_CLASS) },
			{ CKA_TOKEN, &m_ffalse, sizeof(m_ffalse) },
			{ CKA_ENCRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_DECRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_WRAP, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_UNWRAP, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_EXTRACTABLE, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_KEY_TYPE, &symmKeyType, sizeof(symmKeyType) }
			//{ CKA_VALUE, symmKeyPlain, SM4_KEY_LEN}
	};
	CK_BYTE symmKeyCipher[ECC_MAX_XCOORDINATE_BITS_LEN/8 + HASH_OUTPUT_LEN + SM4_KEY_LEN] = {0};
	CK_ULONG wrappedKeyLen = ECC_MAX_XCOORDINATE_BITS_LEN/8 + HASH_OUTPUT_LEN + SM4_KEY_LEN;

	SKF_LOGD("%s entry with hContainer %p ulAlgID 0x%lx", __FUNCTION__, hContainer, ulAlgID);
	
	// check input parameter
	if (NULL == hContainer || NULL == pPubKey || NULL == pData || NULL == phSessionKey){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	logData((unsigned char *)pPubKey, sizeof(ECCPUBLICKEYBLOB), plog_verbose, "public key:");

	// check algID. only support SM4 ECB/CBC/OFB for now
	if ((SGD_SMS4_ECB != ulAlgID)&&(SGD_SMS4_CBC != ulAlgID)&&(SGD_SMS4_OFB != ulAlgID)){
		SKF_LOGE("%s input ulAlgID 0x%x return 0x%x", __FUNCTION__, ulAlgID, SAR_KEYUSAGEERR);
		return SAR_KEYUSAGEERR;
	}

	// directly return caller the buffer size needed to hold key cipher
	if(NULL == pData->Cipher) {
		SKF_LOGW("%s exit 0x%x", __FUNCTION__, SAR_OK);
		pData->CipherLen = SM4_KEY_LEN;
		return SAR_OK;
	}
	// check if output buffer enough to hold key cipher
	if (pData->CipherLen < SM4_KEY_LEN){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_BUFFER_TOO_SMALL);
		pData->CipherLen = SM4_KEY_LEN;
		return SAR_BUFFER_TOO_SMALL;
	}
		
	HandleCheck handle;
	ret_skf = handle.Check((SKFHandleC_PTR)hContainer);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	// check if container open
	if (SKF_FLAG_EXIST == ((SKFHandleC_PTR)hContainer)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// SKF interface document has no specification for user log in to access this interface
#if 0
	// check if app logged in
	if (SKF_FLAG_AUTH != ((SKFHandleC_PTR)hContainer)->pAppHandle->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
		return SAR_USER_NOT_LOGGED_IN;
	}
#endif

	ret_p11 = Adapter_C_OpenSession(((SKFHandleC_PTR)hContainer)->pAppHandle->pDevHandle->id, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

do{
	// generate SM4 session key
	ret_p11 = Adapter_C_GenerateKey(hSession, &mechanismSM4Generate, symmKeyTemplate, sizeof(symmKeyTemplate) / sizeof(CK_ATTRIBUTE), &hSymmKey);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_GenerateKey return 0x%x", __FUNCTION__, ret_p11);
		ret_skf = SAR_FAIL;
		break;
	}

	ret_skf = Import_ECC_PublicKey(((SKFHandleC_PTR)hContainer)->pAppHandle->pDevHandle, pPubKey, &hSm2PubKey);
	if (SAR_OK != ret_skf){
		SKF_LOGE("%s Import_ECC_PublicKey return 0x%x", __FUNCTION__, ret_skf);
		break;
	}

	// wrap generated symmetric key by imported ECC public key
	memset(symmKeyCipher, 0, sizeof(symmKeyCipher));
	wrappedKeyLen = ECC_MAX_XCOORDINATE_BITS_LEN/8 + HASH_OUTPUT_LEN + SM4_KEY_LEN;
	ret_p11 = Adapter_C_WrapKey(hSession, &wrapSymmKeyMechanism, hSm2PubKey, hSymmKey, symmKeyCipher, &wrappedKeyLen);
	if(CKR_OK != ret_p11) {
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s Adapter_C_GenerateKey return 0x%x", __FUNCTION__, ret_p11);
		break;
	}

	if (wrappedKeyLen != (ECC_MAX_XCOORDINATE_BITS_LEN/8 + HASH_OUTPUT_LEN + SM4_KEY_LEN)) {
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s wrappedKeyLen %d error return 0x%x", __FUNCTION__, wrappedKeyLen, SAR_FAIL);
		break;
	}

	// generate output PECCCIPHERBLOB pData...
	// GM_T 0003.4-2012 SM2 document specified SM2 output sequence as C1||C3||C2 in section 6.2
	// but JW card implement C1||C2||C3 instead. 
	memset(pData, 0, sizeof(ECCCIPHERBLOB) + SM4_KEY_LEN - 1); // SM4_KEY_LEN 16, one byte only in ECCCIPHERBLOB, need reserve 15 more bytes
	memcpy(pData->XCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, symmKeyCipher, ECC_MAX_XCOORDINATE_BITS_LEN/16);
	memcpy(pData->YCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, symmKeyCipher + ECC_MAX_XCOORDINATE_BITS_LEN/16, ECC_MAX_XCOORDINATE_BITS_LEN/16);
	pData->CipherLen = SM4_KEY_LEN;  // input CipherLen/Cipher shall allocate enough buffer to save output 
	memcpy(pData->Cipher, symmKeyCipher + ECC_MAX_XCOORDINATE_BITS_LEN/8, SM4_KEY_LEN);
	memcpy(pData->HASH, symmKeyCipher + ECC_MAX_XCOORDINATE_BITS_LEN/8 + SM4_KEY_LEN, HASH_OUTPUT_LEN);
	
	// generate output phSessionKey
	SKFHandleSYM_PTR tmp = new SKFHandleSYM();
	memset(tmp, 0, sizeof(SKFHandleSYM));
	tmp->pDevHandle = ((SKFHandleC_PTR)hContainer)->pAppHandle->pDevHandle;
	tmp->pContainerHandle = (SKFHandleC_PTR)hContainer;
	tmp->sessKeyHandle = hSymmKey;
	tmp->session = hSession;
	tmp->ulAlgId = ulAlgID;
	SKFGlobeData::setSessionKeyHandle.insert(tmp);
	*phSessionKey = (HANDLE)tmp;
	
}while(0);

	// SM2 public key shall be destroied no matter function return fail or not
	// hSm2PubKey shall be destroied before close session
	if(hSm2PubKey){
		ret_p11 = Adapter_C_DestroyObject(hSession, hSm2PubKey);
	}
	
	if(SAR_OK != ret_skf){
		// object shall be destroied before close session
		if(hSymmKey){
			ret_p11 = Adapter_C_DestroyObject(hSession, hSymmKey);
		}

		// close session after all p11 object destroied.
		ret_p11 = Adapter_C_CloseSession(hSession);
	}

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}
	else {
		logData((unsigned char *)pData, sizeof(ECCCIPHERBLOB) + pData->CipherLen - 1, plog_verbose, "envelopped session key:");
	}

	SKF_LOGD("%s exit 0x%lx and HANDLE as %p", __FUNCTION__, ret_skf, *phSessionKey);
	
	return ret_skf;
}

/*
*	使用外部传入的ECC公钥对输入数据做加密运算并输出结果
*	hDev			[IN] 设备句柄
*	pECCPubKeyBlob	[IN] ECC公钥数据结构
*	pbPlainText		[IN] 待加密的明文数据
*	ulPlainTextLen	[IN] 待加密明文数据的长度
*	pbCipherText	[OUT] 指向密文数据缓冲区，如果该参数为NULL，则由pulCipherTextLen返回密文数据的实际长度
*	pulCipherTextLen[OUT] 调用前表示pbCipherText缓冲区的长度，返回密文数据的实际长度
*/
SKF_DEVAPI SKF_ExtECCEncrypt(
IN DEVHANDLE hDev,
IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
IN BYTE* pbPlainText,
IN ULONG ulPlainTextLen,
OUT PECCCIPHERBLOB pbCipherText
)
{
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_OBJECT_HANDLE hPubKey = 0;
	CK_MECHANISM sm2CryptMechanism = { CKM_SM2, NULL_PTR, 0 };
	CK_ULONG outputBufLen = ulPlainTextLen + ECC_MAX_MODULUS_BITS_LEN/8 + HASH_OUTPUT_LEN;
	CK_BYTE_PTR outputBuf = NULL;

	SKF_LOGD("%s entry with hDev %p", __FUNCTION__, hDev);
	
	// check input parameter
	if (NULL == hDev || NULL == pECCPubKeyBlob || NULL == pbPlainText || 0 == ulPlainTextLen || NULL == pbCipherText){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	logData((unsigned char *)pECCPubKeyBlob, sizeof(ECCPUBLICKEYBLOB), plog_verbose, "public key:");
	logData((unsigned char *)pbPlainText, ulPlainTextLen, plog_verbose, "input plain:");

	// directly return caller the buffer size needed to hold cipher content
	if(NULL == pbCipherText->Cipher) {
		SKF_LOGW("%s exit 0x%x", __FUNCTION__, SAR_OK);
		pbCipherText->CipherLen = ulPlainTextLen;
		return SAR_OK;
	}
	// check if output buffer enough to hold cipher content
	if (pbCipherText->CipherLen < ulPlainTextLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_BUFFER_TOO_SMALL);
		pbCipherText->CipherLen = ulPlainTextLen;
		return SAR_BUFFER_TOO_SMALL;
	}

	ret_p11 = Adapter_C_OpenSession(((SKFHandleD_PTR)hDev)->id,  CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

	outputBuf = new CK_BYTE[outputBufLen];

do{
	// import public key and get p11 handle
	ret_skf = Import_ECC_PublicKey(hDev, pECCPubKeyBlob, &hPubKey);
	if(SAR_OK != ret_skf){
		SKF_LOGE("%s Import_ECC_PublicKey return 0x%x", __FUNCTION__, ret_skf);
		break;
	}

	// encrypt plain text
	ret_p11 = Adapter_C_EncryptInit(hSession, &sm2CryptMechanism, hPubKey);
	if(CKR_OK != ret_p11) {
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s Adapter_C_EncryptInit return 0x%x", __FUNCTION__, ret_p11);
		break;
	}
	// suppose pbCipherText->Cipher point to buffer enough
	// SM2 encrypt output always 96 bytes more than input
	ret_p11 = Adapter_C_Encrypt(hSession, pbPlainText, ulPlainTextLen, outputBuf, &outputBufLen);
	if(CKR_OK != ret_p11) {
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s Adapter_C_Encrypt return 0x%x", __FUNCTION__, ret_p11);
		break;
	}
	if(outputBufLen != (ulPlainTextLen + ECC_MAX_MODULUS_BITS_LEN/8 + HASH_OUTPUT_LEN)) {
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s outputBufLen %d, ulPlainTextLen %d", __FUNCTION__, outputBufLen, ulPlainTextLen);
		break;
	}

	// fill output public key part
	// GM_T 0003.4-2012 SM2 document specified SM2 output sequence as C1||C3||C2 in section 6.2
	// but JW card implement C1||C2||C3 instead. 
	memset(pbCipherText, 0, sizeof(ECCCIPHERBLOB) + ulPlainTextLen - 1);
	memcpy(pbCipherText->XCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, outputBuf, ECC_MAX_XCOORDINATE_BITS_LEN/16);
	memcpy(pbCipherText->YCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, outputBuf + ECC_MAX_XCOORDINATE_BITS_LEN/16, ECC_MAX_YCOORDINATE_BITS_LEN/16);
	pbCipherText->CipherLen = ulPlainTextLen;
	memcpy(pbCipherText->Cipher, outputBuf + ECC_MAX_XCOORDINATE_BITS_LEN/8, ulPlainTextLen);
	memcpy(pbCipherText->HASH, outputBuf + ECC_MAX_XCOORDINATE_BITS_LEN/8 + ulPlainTextLen, HASH_OUTPUT_LEN);
	
	
}while(0);

	// object shall be destroied before close session
	if(hPubKey){
		ret_p11 = Adapter_C_DestroyObject(hSession, hPubKey);
	}

	if (outputBuf) {
		delete [] outputBuf;
		outputBuf = NULL;
	}

	// close session after all p11 object destroied.
	ret_p11 = Adapter_C_CloseSession(hSession);

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}
	else {
		logData((unsigned char *)pbCipherText, (sizeof(ECCCIPHERBLOB) + pbCipherText->CipherLen - 1), plog_verbose);
	}

	SKF_LOGD("%s exit with return 0x%lx, Encrypt output length %ld", __FUNCTION__, ret_skf, pbCipherText->CipherLen);
	
	return ret_skf;
}

/*
*	使用外部传入的ECC私钥对输入数据做解密运算并输出结果
*	hDev			[IN] 设备句柄
*	pRSAPriKeyBlob	[IN] ECC私钥数据结构
*	pbInput			[IN] 待解密的密文数据
*	ulInputLen		[IN] 待解密密文数据的长度
*	pbOutput		[OUT] 返回明文数据，如果该参数为NULL，则由pulPlainTextLen返回明文数据的实际长度
*	pulOutputLen	[OUT] 调用前表示pbPlainText缓冲区的长度，返回明文数据的实际长度
*/
SKF_DEVAPI SKF_ExtECCDecrypt(
IN DEVHANDLE hDev,
IN ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
IN PECCCIPHERBLOB pbCipherText,
OUT BYTE* pbPlainText,
OUT ULONG* pulPlainTextLen
)
{
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_OBJECT_HANDLE hPrivKey = 0;
	CK_MECHANISM sm2CryptMechanism = { CKM_SM2, NULL_PTR, 0 };
	CK_MECHANISM sm3mechanism={ CKM_HASH_SM3,NULL_PTR,0 };
	CK_BYTE hashOutBuf[HASH_OUTPUT_LEN] = {0};
	CK_ULONG hashOutLen = HASH_OUTPUT_LEN;
	CK_ULONG plainDataLen = 0;

	CK_BYTE_PTR p11Sm2DecInput = NULL;

	SKF_LOGD("%s entry with hDev %p", __FUNCTION__, hDev);

	// check input parameter
	if (NULL == hDev || NULL == pECCPriKeyBlob || NULL == pbCipherText || NULL == pulPlainTextLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	SKF_LOGV("pbPlainText %p pulPlainTextLen %d", pbPlainText, *pulPlainTextLen);

	if (NULL == pbPlainText) {
		*pulPlainTextLen = pbCipherText->CipherLen;
		SKF_LOGD("%s exit with return 0x%lx", __FUNCTION__, SAR_OK);
		return SAR_OK;
	}

	// SM2 decrypt output always same as pbCipherText->CipherLen
	if( *pulPlainTextLen < pbCipherText->CipherLen){
		SKF_LOGE("%s exit 0x%x, input len %d, expected %d", __FUNCTION__, SAR_BUFFER_TOO_SMALL, *pulPlainTextLen, pbCipherText->CipherLen);
		*pulPlainTextLen = pbCipherText->CipherLen;
		return SAR_BUFFER_TOO_SMALL;
	}

	// output len should same as cipher len
	*pulPlainTextLen = pbCipherText->CipherLen;

	if(NULL == pbPlainText){
		return SAR_OK;
	}

	ret_p11 = Adapter_C_OpenSession(((SKFHandleD_PTR)hDev)->id,  CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

do{
	// import public key and get p11 handle
	ret_skf = Import_ECC_PrivateKey(hDev, pECCPriKeyBlob, &hPrivKey);
	if(SAR_OK != ret_skf){
		SKF_LOGE("%s Import_ECC_PrivateKey return 0x%x", __FUNCTION__, ret_skf);
		break;
	}

	// assemble sm2 decrypt input:
	// GM_T 0003.4-2012 SM2 document specified SM2 output sequence as C1||C3||C2 in section 6.2
	// but JW card implement C1||C2||C3 instead. 
	p11Sm2DecInput = new CK_BYTE[ECC_MAX_XCOORDINATE_BITS_LEN/8 + HASH_OUTPUT_LEN + pbCipherText->CipherLen];
	memset(p11Sm2DecInput, 0, ECC_MAX_XCOORDINATE_BITS_LEN/8 + HASH_OUTPUT_LEN + pbCipherText->CipherLen);
	memcpy(p11Sm2DecInput, pbCipherText->XCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, ECC_MAX_XCOORDINATE_BITS_LEN/16);
	memcpy(p11Sm2DecInput + ECC_MAX_XCOORDINATE_BITS_LEN/16, pbCipherText->YCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, ECC_MAX_XCOORDINATE_BITS_LEN/16);
	memcpy(p11Sm2DecInput + ECC_MAX_XCOORDINATE_BITS_LEN/8, pbCipherText->Cipher, pbCipherText->CipherLen);
	memcpy(p11Sm2DecInput + ECC_MAX_XCOORDINATE_BITS_LEN/8 + pbCipherText->CipherLen, pbCipherText->HASH, HASH_OUTPUT_LEN);
	

	// encrypt plain text
	ret_p11 = Adapter_C_DecryptInit(hSession, &sm2CryptMechanism, hPrivKey);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_DecryptInit return 0x%x", __FUNCTION__, ret_p11);
		ret_skf = SAR_FAIL;
		break;
	}

	plainDataLen = *pulPlainTextLen;
	ret_p11 = Adapter_C_Decrypt(hSession, p11Sm2DecInput, ECC_MAX_XCOORDINATE_BITS_LEN/8 + HASH_OUTPUT_LEN + pbCipherText->CipherLen, pbPlainText, &plainDataLen);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_Decrypt return 0x%x", __FUNCTION__, ret_p11);
		ret_skf = SAR_FAIL;
		break;
	}

	if((*pulPlainTextLen) != plainDataLen){
		SKF_LOGE("%s Adapter_C_Decrypt data len %d and expected len %d mismatch", __FUNCTION__, *pulPlainTextLen, plainDataLen);
		ret_skf = SAR_FAIL;
		break;
	}

}while(0);

	// object shall be destroied before close session
	if(hPrivKey){
		ret_p11 = Adapter_C_DestroyObject(hSession, hPrivKey);
	}

	// close session after all p11 object destroied.
	ret_p11 = Adapter_C_CloseSession(hSession);

	if (p11Sm2DecInput) {
		delete[] p11Sm2DecInput;
		p11Sm2DecInput = NULL;
	}

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}
	else {
		logData((unsigned char *)pbPlainText, (unsigned long)*pulPlainTextLen, plog_verbose, "plain text:");
	}
	
	SKF_LOGD("%s exit with return 0x%lx", __FUNCTION__, ret_skf);

	return ret_skf;
}

/*
*	使用外部传入的ECC私钥对输入数据做签名运算并输出结果。
*	hDev			[IN] 设备句柄
*	pRSAPriKeyBlob	[IN] ECC私钥数据结构
*	pbData			[IN] 待签名数据
*	ulDataLen		[IN] 待签名数据的长度
*	pbSignature		[OUT] 签名值，如果该参数为NULL，则由pulSignatureLen返回签名结果的实际长度
*	pulSignatureLen	[OUT] 调用前表示pbSignature缓冲区的长度，返回签名结果的实际长度
*/
SKF_DEVAPI SKF_ExtECCSign(
IN DEVHANDLE hDev,
IN ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
IN BYTE* pbData,
IN ULONG ulDataLen,
OUT PECCSIGNATUREBLOB pSignature
)
{
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_OBJECT_HANDLE hPrivKey = 0;
	CK_MECHANISM sm2CryptMechanism = { CKM_SM2, NULL_PTR, 0 };
	// input always 32 bytes output always 64 bytes 
	CK_BYTE signOutBuf[64] = {0};
	CK_ULONG signOutLen = 64;

	SKF_LOGD("%s entry with hDev %p", __FUNCTION__, hDev);

	// check input parameter
	if (NULL == hDev || NULL == pECCPriKeyBlob || NULL == pbData || NULL == pSignature || HASH_OUTPUT_LEN != ulDataLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}
	
	ret_p11 = Adapter_C_OpenSession(((SKFHandleD_PTR)hDev)->id,  CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

do{
	// import public key and get p11 handle
	ret_skf = Import_ECC_PrivateKey(hDev, pECCPriKeyBlob, &hPrivKey);
	if(SAR_OK != ret_skf){
		SKF_LOGE("%s Import_ECC_PrivateKey return 0x%x", __FUNCTION__, ret_skf);
		break;
	}

	// encrypt plain text
	ret_p11 = Adapter_C_SignInit(hSession, &sm2CryptMechanism, hPrivKey);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_SignInit return 0x%x", __FUNCTION__, ret_p11);
		ret_skf = SAR_FAIL;
		break;
	}

	ret_p11 = Adapter_C_Sign(hSession, pbData, ulDataLen, signOutBuf, &signOutLen);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_Sign return 0x%x", __FUNCTION__, ret_p11);
		ret_skf = SAR_FAIL;
		break;
	}

	// fill output buffer
	// a sample signature output reference generated by LongMai SKF key
	/**
	0000000000000000000000000000000000000000000000000000000000000000
	9eeeb80df6cca8c572ddb55e46f326edf5ed89ee59f7a9e70f5fa5668fa1e53a
	0000000000000000000000000000000000000000000000000000000000000000
	51ed70fd9be3164c93d7e612448ba7fd34c17066e31f80a6f3fcb3af2dc5cead
	**/
	memset(pSignature, 0, sizeof(ECCSIGNATUREBLOB));
	memcpy(pSignature->r + ECC_MAX_MODULUS_BITS_LEN/16, signOutBuf, ECC_MAX_MODULUS_BITS_LEN/16);
	memcpy(pSignature->s + ECC_MAX_MODULUS_BITS_LEN/16, signOutBuf + ECC_MAX_MODULUS_BITS_LEN/16, ECC_MAX_MODULUS_BITS_LEN/16);
}while(0);

	// object shall be destroied before close session
	if(hPrivKey){
		ret_p11 = Adapter_C_DestroyObject(hSession, hPrivKey);
	}

	// close session after all p11 object destroied.
	ret_p11 = Adapter_C_CloseSession(hSession);

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}

	SKF_LOGW("%s exit with return 0x%lx", __FUNCTION__, ret_skf);

	return ret_skf;
}

/*
*	外部使用传入的ECC公钥做签名验证
*	hDev			[IN] 设备句柄
*	pECCPubKeyBlob	[IN] ECC公钥数据结构
*	pbData			[IN] 待验证数据
*	ulDataLen		[IN] 待验证数据的长度
*	pbSignature		[OUT] 签名值
*	ulSignLen		[OUT] 签名值的长度
*/
SKF_DEVAPI SKF_ExtECCVerify(
IN DEVHANDLE hDev,
IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
IN BYTE* pbData,
IN ULONG ulDataLen,
IN PECCSIGNATUREBLOB pSignature
)
{
	return SKF_ECCVerify(hDev, pECCPubKeyBlob, pbData, ulDataLen, pSignature);
}

/*
*	使用ECC密钥协商算法，为计算会话密钥而产生协商参数，返回临时ECC密钥对的公钥及协商句柄
*	hContainer		[IN] 容器句柄
*	ulAlgId			[IN] 会话密钥算法标识
*	pTempECCPubKeyBlob	[OUT] 发起方临时ECC公钥
*	pbID			[IN] 发起方的ID
*	ulIDLen			[IN] 发起方ID的长度，不大于32
*	phAgreementHandle	[OUT] 返回的密钥协商句柄
*/
SKF_DEVAPI SKF_GenerateAgreementDataWithECC(
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
*	使用ECC密钥协商算法，产生协商参数并计算会话密钥，输出临时ECC密钥对公钥，并返回产生的密钥句柄
*	hContainer					[IN] 容器句柄
*	ulAlgId						[IN] 会话密钥算法标识
*	pSponsorECCPubKeyBlob		[IN] 发起方的ECC公钥
*	pSponsorTempECCPubKeyBlob	[IN] 发起方的临时ECC公钥
*	pTempECCPubKeyBlob			[OUT] 响应方的临时ECC公钥
*	pbID						[IN] 响应方的ID
*	ulIDLen						[IN] 响应方ID的长度，不大于32
*	pbSponsorID					[IN] 发起方的ID
*	ulSponsorIDLen				[IN] 发起方ID的长度，不大于32
*	phKeyHandle					[OUT] 返回的对称算法密钥句柄
*/
SKF_DEVAPI SKF_GenerateAgreementDataAndKeyWithECC(
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
*	使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥，同时返回会话密钥句柄
*	hAgreementHandle			[IN] 密钥协商句柄
*	pECCPubKeyBlob				[IN] 外部输入的响应方ECC公钥
*	pTempECCPubKeyBlob			[IN] 外部输入的响应方临时ECC公钥
*	pbID						[IN] 响应方的ID
*	ulIDLen						[IN] 响应方ID的长度，不大于32
*	phKeyHandle					[OUT] 返回的密钥句柄
*/
SKF_DEVAPI SKF_GenerateKeyWithECC(
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
*	导出容器中的签名公钥或者加密公钥
*	hContainer		[IN] 容器句柄
*	bSignFlag		[IN] TRUE表示导出签名公钥，FALSE表示导出加密公钥
*	pbBlob			[OUT] 指向RSA公钥结构（RSAPUBLICKEYBLOB）或者ECC公钥结构（ECCPUBLICKEYBLOB），如果此参数为NULL时，由pulBlobLen返回pbBlob的长度
*	pulBlobLen		[IN,OUT] 调用时表示pbBlob的长度，返回导出公钥结构的大小
*/
/**
LongMai reference output pulBlobLen format:
0001000000000000000000000000000000000000000000000000000000000000
0000000067756b2196f5d91be650fd2542b71dfaeff3e04474f91d79242cf615
c84b877500000000000000000000000000000000000000000000000000000000
00000000d8e012921c75fac1bbbf9f27081731fe24b73556525ff5fea3089ce4
5cb4f7db
**/
SKF_DEVAPI SKF_ExportPublicKey(
IN HCONTAINER hContainer,
IN BOOL bSignFlag,
OUT BYTE* pbBlob,
OUT ULONG* pulBlobLen
)
{
	// variables for general purpose
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_OBJECT_HANDLE hPubKey = 0;
	CK_BYTE localPubKey[64] = {0};
	CK_ATTRIBUTE pubkeyValAttr[] = {
			{ CKA_VALUE, localPubKey, 64 }
	};
	PECCPUBLICKEYBLOB pubKeyBlob = (PECCPUBLICKEYBLOB)pbBlob;

	CK_KEY_TYPE  keyType = CKK_SM2;
	CK_OBJECT_CLASS	pubkeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS prikeyClass = CKO_PRIVATE_KEY;
	CK_BYTE	m_ttrue = TRUE;
	CK_BYTE m_ffalse = FALSE;
	CK_BYTE_PTR keyID = NULL;
	CK_ULONG ulKeyIDLen = 0;

	SKF_LOGD("%s entry with hContainer %p bSignFlag %d", __FUNCTION__, hContainer, bSignFlag);

	// check input parameter
	if (NULL == hContainer || NULL == pulBlobLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	if((pbBlob)&&(*pulBlobLen < sizeof(ECCPUBLICKEYBLOB))){
		SKF_LOGE("%s input buffer size %d, return 0x%x", __FUNCTION__, *pulBlobLen, SAR_BUFFER_TOO_SMALL);
		*pulBlobLen = sizeof(ECCPUBLICKEYBLOB);
		return SAR_BUFFER_TOO_SMALL;
	}

	// inform caller the required buffer length when pbBlob is NULL
	if(NULL == pbBlob){
		*pulBlobLen = sizeof(ECCPUBLICKEYBLOB);
		return SAR_OK;
	}
		
	HandleCheck handle;
	ret_skf = handle.Check((SKFHandleC_PTR)hContainer);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	// check if container open
	if (SKF_FLAG_EXIST == ((SKFHandleC_PTR)hContainer)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// SKF interface document has no specification for user log in to access this interface
#if 0
	// check if app logged in
	if (SKF_FLAG_AUTH != ((SKFHandleC_PTR)hContainer)->pAppHandle->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
		return SAR_USER_NOT_LOGGED_IN;
	}
#endif

#if 0
	ret_skf = handle.GetSession((SKFHandleC_PTR)hContainer, &hSession);
	if (ret_skf != SAR_OK){
			return SAR_FAIL;
		}
#endif
	ret_p11 = Adapter_C_OpenSession(((SKFHandleC_PTR)hContainer)->pAppHandle->pDevHandle->id, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}
	
do{
	// assemble keyID, as "appName + 0 + containerName + 0 + BoolSignatureFlag"
	keyID = assembleKeyId((SKFHandleC_PTR)hContainer, bSignFlag, &ulKeyIDLen);
	if(NULL == keyID || 0 == ulKeyIDLen){
		SKF_LOGE("%s return 0x%x for assembleKeyId failure", __FUNCTION__, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}
	
	// get public key handle
	CK_ATTRIBUTE findPubTemplate[] = {
		{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
		{ CKA_ID, keyID, ulKeyIDLen },
		{ CKA_CLASS, &pubkeyClass, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	ret_skf = findSingleObjByTemplate(hSession, findPubTemplate, sizeof(findPubTemplate) / sizeof(CK_ATTRIBUTE), &hPubKey);
	// check if there is valid  key pair inside token
	if(SAR_OK != ret_skf || 0 == hPubKey)
	{
		SKF_LOGE("%s findSingleObjByTemplate return 0x%x and handle 0x%x", __FUNCTION__, ret_skf, hPubKey);
        unsigned char * keyIdPart1 = keyID;
        SKF_LOGE("key ID %s, keyType 0x%x class 0x%x", keyIdPart1, keyType, pubkeyClass);
		ret_skf = SAR_KEYNOTFOUNDERR;
		break;
	}

	// check if the pubkey encrypt symmetric key match hPubKey in current container
	ret_p11 = Adapter_C_GetAttributeValue(hSession, hPubKey, pubkeyValAttr, sizeof(pubkeyValAttr)/sizeof(CK_ATTRIBUTE));
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_GetAttributeValue return 0x%x", __FUNCTION__, ret_p11);
		ret_skf = SAR_FAIL;
		break;
	}

	// current SM2 keypair, public key length always 64 bytes. exception if NOT 64
	if(ECC_MAX_XCOORDINATE_BITS_LEN/8 != pubkeyValAttr[0].ulValueLen){
		ret_skf = SAR_FAIL;
		SKF_LOGE("%s Adapter_C_GetAttributeValue get length %d", __FUNCTION__, pubkeyValAttr[0].ulValueLen);
		break;
	}

	memset(pbBlob, 0, sizeof(ECCPUBLICKEYBLOB));
	((PECCPUBLICKEYBLOB)pbBlob)->BitLen = ECC_MAX_XCOORDINATE_BITS_LEN/2;
	memcpy(((PECCPUBLICKEYBLOB)pbBlob)->XCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN / 16, localPubKey, ECC_MAX_XCOORDINATE_BITS_LEN / 16);
	memcpy(((PECCPUBLICKEYBLOB)pbBlob)->YCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN / 16, localPubKey + ECC_MAX_XCOORDINATE_BITS_LEN / 16, ECC_MAX_XCOORDINATE_BITS_LEN / 16);
}while(0);

	// close temporary session
	ret_p11 = Adapter_C_CloseSession(hSession);

	if (keyID) {
		delete[] keyID;
		keyID = NULL;
	}

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}
	else {
		logData((unsigned char *)pbBlob, *pulBlobLen, plog_verbose, "public key:");
	}

	SKF_LOGD("%s exit 0x%lx with output len as %ld", __FUNCTION__, ret_skf, *pulBlobLen);
	
	return ret_skf;
}

/*
*	导入会话密钥
*	hContainer		[IN] 容器句柄
*	ulAlgID			[IN] 会话密钥的算法标识
*	pbWrapedData	[IN] 要导入的数据
*	ulWrapedLen		[IN] 数据长度
*	phKey			[OUT] 返回会话密钥句柄
*/
SKF_DEVAPI SKF_ImportSessionKey(
IN HCONTAINER hContainer,
IN ULONG ulAlgID,
IN BYTE *pbWrapedData,
IN ULONG ulWrapedLen,
OUT HANDLE* phKey
)
{
	// variables for general purpose
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_BYTE	m_ttrue = TRUE;
	CK_BYTE m_ffalse = FALSE;
	CK_OBJECT_HANDLE hPubKey = 0;
	CK_OBJECT_HANDLE hPrivKey = 0;
	PECCCIPHERBLOB pBlob = (PECCCIPHERBLOB)pbWrapedData;
	CK_BYTE localPubKey[64] = {0};
	CK_ATTRIBUTE pubkeyValAttr[] = {
			{ CKA_VALUE, localPubKey, 64 }
	};
	CK_MECHANISM unwrapSymmKeyMechanism = { CKM_SM2 , NULL, 0 };
	// for symmetric key unwrapped from input parameter
	CK_OBJECT_HANDLE hSymmKey = 0;
	CK_OBJECT_CLASS symmKeyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE  symmKeyType = CKK_SM4;
	CK_ATTRIBUTE symmKeyUnwrapTemplate[] = {
			{ CKA_CLASS, &symmKeyClass, sizeof(CK_OBJECT_CLASS) },
			{ CKA_TOKEN, &m_ffalse, sizeof(m_ffalse) },
			{ CKA_ENCRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_DECRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_WRAP, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_UNWRAP, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_KEY_TYPE, &symmKeyType, sizeof(symmKeyType) }
	};
	CK_BYTE symmKeyPlain[64] = {0};
	CK_ULONG symmKeyLen = 64;

	CK_KEY_TYPE  keyType = CKK_SM2;
	CK_OBJECT_CLASS	pubkeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS prikeyClass = CKO_PRIVATE_KEY;
	CK_BYTE_PTR keyID = NULL;
	CK_ULONG ulKeyIDLen = 0;
	CK_BYTE_PTR p11Sm2DecInput = NULL;
	CK_ULONG sm2DecInputLen = 0;
	
	SKF_LOGD("%s entry with hContainer %p, ulAlgID 0x%lx, wrap data len %ld pbWrapedData %p", __FUNCTION__, hContainer, ulAlgID, ulWrapedLen, pbWrapedData);
	
	// check input parameter
	if (NULL == hContainer || NULL == pbWrapedData || 0 == ulWrapedLen || NULL == phKey){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	// check algID. only support SM4 ECB/CBC/OFB for now
	if ((SGD_SMS4_ECB != ulAlgID)&&(SGD_SMS4_CBC != ulAlgID)&&(SGD_SMS4_OFB != ulAlgID)){
		SKF_LOGE("%s input ulAlgID 0x%x return 0x%x", __FUNCTION__, ulAlgID, SAR_KEYUSAGEERR);
		return SAR_KEYUSAGEERR;
	}

	// check cipher if valid
	if(NULL == pBlob->Cipher) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}
	// check cipher len if valid
	if (SM4_KEY_LEN != pBlob->CipherLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}
	
		
	HandleCheck handle;
	ret_skf = handle.Check((SKFHandleC_PTR)hContainer);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	// check if container open
	if (SKF_FLAG_EXIST == ((SKFHandleC_PTR)hContainer)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// check if app logged in
	if (SKF_FLAG_AUTH_USR != ((SKFHandleC_PTR)hContainer)->pAppHandle->flg){
		SKF_LOGE("%s exit 0x%x. user log in required to import session key, current state %d", __FUNCTION__, SAR_USER_NOT_LOGGED_IN, ((SKFHandleC_PTR)hContainer)->pAppHandle->flg);
		return SAR_USER_NOT_LOGGED_IN;
	}
	
	ret_p11 = Adapter_C_OpenSession(((SKFHandleC_PTR)hContainer)->pAppHandle->pDevHandle->id, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

	keyID = assembleKeyId((SKFHandleC_PTR)hContainer, FALSE, &ulKeyIDLen);
	if(NULL == keyID || 0 == ulKeyIDLen){
		SKF_LOGE("%s return 0x%x for assembleKeyId failure", __FUNCTION__, SAR_FAIL);
		if(keyID){
			delete[] keyID;
			keyID = NULL;
		}
		return SAR_FAIL;
	}
	
do{
	
	// get private key handle for encrypt operation in current container
	CK_ATTRIBUTE findSignPrivTemplate[] = {
		{ CKA_TOKEN, &m_ttrue, sizeof(m_ttrue) },
		{ CKA_ID, keyID, ulKeyIDLen },
		//{ CKA_SIGN, &m_ttrue, sizeof(m_ttrue) },
		{ CKA_CLASS, &prikeyClass, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	ret_skf = findSingleObjByTemplate(hSession, findSignPrivTemplate, sizeof(findSignPrivTemplate) / sizeof(CK_ATTRIBUTE), &hPrivKey);
	if(SAR_OK != ret_skf || 0 == hPrivKey )
	{
		SKF_LOGE("%s return 0x%x for findSingleObjByTemplate and handle 0x%x", __FUNCTION__, ret_skf, hPrivKey);
        unsigned char * keyIdPart1 = keyID;
        SKF_LOGE("key ID %s, keyType 0x%x class 0x%x", keyIdPart1, keyType, prikeyClass);
		ret_skf = SAR_KEYNOTFOUNDERR;
		break;
	}

	// unwrap symmetric key by SM2 private key
	// assemble sm2 decrypt input:
	// GM_T 0003.4-2012 SM2 document specified SM2 output sequence as C1||C3||C2 in section 6.2
	// but JW card implement C1||C2||C3 instead. 
	sm2DecInputLen = ECC_MAX_XCOORDINATE_BITS_LEN/8 + HASH_OUTPUT_LEN + pBlob->CipherLen;
	p11Sm2DecInput = new CK_BYTE[sm2DecInputLen];
	memset(p11Sm2DecInput, 0, sm2DecInputLen);
	memcpy(p11Sm2DecInput, pBlob->XCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, ECC_MAX_XCOORDINATE_BITS_LEN/16);
	memcpy(p11Sm2DecInput + ECC_MAX_XCOORDINATE_BITS_LEN/16, pBlob->YCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, ECC_MAX_XCOORDINATE_BITS_LEN/16);
	memcpy(p11Sm2DecInput + ECC_MAX_XCOORDINATE_BITS_LEN/8, pBlob->Cipher, pBlob->CipherLen);
	memcpy(p11Sm2DecInput + ECC_MAX_XCOORDINATE_BITS_LEN/8 + pBlob->CipherLen, pBlob->HASH, HASH_OUTPUT_LEN);
	
	ret_p11 = Adapter_C_UnwrapKey(hSession, &unwrapSymmKeyMechanism, hPrivKey, p11Sm2DecInput, sm2DecInputLen, symmKeyUnwrapTemplate, sizeof(symmKeyUnwrapTemplate)/sizeof(CK_ATTRIBUTE), &hSymmKey);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_UnwrapKey failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}

	// generate output...
	SKFHandleSYM_PTR tmp = new SKFHandleSYM();
	memset(tmp, 0, sizeof(SKFHandleSYM));
	tmp->pDevHandle = ((SKFHandleC_PTR)hContainer)->pAppHandle->pDevHandle;
	tmp->pContainerHandle = (SKFHandleC_PTR)hContainer;
	tmp->sessKeyHandle = hSymmKey;
	tmp->session = hSession;
	tmp->ulAlgId = ulAlgID;
	SKFGlobeData::setSessionKeyHandle.insert(tmp);

	*phKey = (HANDLE)tmp;
	
}while(0);

	// hSession shall NOT be closed becasue output key is session key
	// shall keep the hSession context for further operation with the session key if operation succeed
	if (SAR_OK != ret_skf) {

		// destroy key if already created
		// object shall be destroied before close session
		if(hSymmKey){
			ret_p11 = Adapter_C_DestroyObject(hSession, hSymmKey);
		}

		// close session after all p11 object destroied.
		ret_p11 = Adapter_C_CloseSession(hSession);
	}
	
	if (keyID) {
		delete[] keyID;
		keyID = NULL;
	}

	if (p11Sm2DecInput) {
		delete p11Sm2DecInput;
		p11Sm2DecInput = NULL;
	}

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}

	SKF_LOGD("%s exit 0x%lx with output phKey %p", __FUNCTION__, ret_skf, *phKey);
	
	return ret_skf;
}

/*
*	设置明文对称密钥，返回密钥句柄
*	hDev		    [IN] 设备句柄
*	pbKey			[IN] 指向会话密钥值的缓冲区
*	ulAlgID			[IN] 会话密钥的算法标识
*	phKey			[OUT] 返回会话密钥句柄
*/
SKF_DEVAPI SKF_SetSymmKey(
IN DEVHANDLE hDev,
IN BYTE* pbKey,
IN ULONG ulAlgID,
OUT HANDLE* phKey
)
{
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_BYTE	m_ttrue = TRUE;
	CK_BYTE m_ffalse = FALSE;
	// for symmetric key unwrapped from input parameter
	CK_OBJECT_HANDLE hSymmKey = 0;
	CK_OBJECT_CLASS symmKeyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE  symmKeyType = CKK_SM4;
	CK_ATTRIBUTE symmKeyTemplate[] = {
			{ CKA_CLASS, &symmKeyClass, sizeof(CK_OBJECT_CLASS) },
			{ CKA_TOKEN, &m_ffalse, sizeof(m_ffalse) },
			{ CKA_ENCRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_DECRYPT, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_WRAP, &m_ttrue, sizeof(m_ttrue) },
			{ CKA_UNWRAP, &m_ttrue, sizeof(m_ttrue) },
			// how to decide input keyLen?
			//{ CKA_VALUE, pbKey, strlen((const char *)pbKey)},
			{ CKA_VALUE, pbKey, SM4_KEY_LEN},
			{ CKA_KEY_TYPE, &symmKeyType, sizeof(symmKeyType) }
	};
	SKFHandleD_PTR myDev = (SKFHandleD_PTR)hDev;

	SKF_LOGD("%s entry with hDev %p, ulAlgID 0x%lx", __FUNCTION__, hDev, ulAlgID);

#ifdef WIN32
	if (SGD_SMS4_MASK & (ulAlgID >> 16)) {
		ulAlgID = ulAlgID>>16;
	}
#endif
	
	if (NULL == hDev || NULL == pbKey || NULL == phKey){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	// check algID. only support SM4 ECB/CBC/OFB for now
	if ((SGD_SMS4_ECB != ulAlgID)&&(SGD_SMS4_CBC != ulAlgID)&&(SGD_SMS4_OFB != ulAlgID)){
		SKF_LOGE("%s input ulAlgID 0x%x return 0x%x", __FUNCTION__, ulAlgID, SAR_KEYUSAGEERR);
		return SAR_KEYUSAGEERR;
	}

#if 0
	// shall NOT check strlen as there may be 0x0 in the key str. how to decide key len?
	if (SM4_KEY_LEN != strlen((const char *)pbKey)) {
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}
#endif
	
	HandleCheck handle;
	ret_skf = handle.Check((SKFHandleD_PTR)hDev);
	if (SAR_OK != ret_skf){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	logData((unsigned char *)pbKey, 16, plog_verbose, "input data:");

do{
	ret_p11 = Adapter_C_OpenSession(((SKFHandleD_PTR)myDev)->id,  CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}

	ret_p11 = Adapter_C_CreateObject(hSession, symmKeyTemplate, sizeof(symmKeyTemplate)/sizeof(CK_ATTRIBUTE), &hSymmKey);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_CreateObject failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		ret_skf = SAR_FAIL;
		break;
	}

	// generate output...
	SKFHandleSYM_PTR tmp = new SKFHandleSYM();
	memset(tmp, 0, sizeof(SKFHandleSYM));
	tmp->pDevHandle = (SKFHandleD_PTR)hDev;
	tmp->pContainerHandle = NULL;
	tmp->sessKeyHandle = hSymmKey;
	tmp->session = hSession;
	tmp->ulAlgId = ulAlgID;
	SKFGlobeData::setSessionKeyHandle.insert(tmp);

	*phKey = (HANDLE)tmp;
}while(0);

	// hSession shall NOT be closed becasue output key is session key
	// shall keep the hSession context for further operation with the session key
	if (SAR_OK != ret_skf) {
		
		// object shall be destroied before close session
		if(hSymmKey){
			ret_p11 = Adapter_C_DestroyObject(hSession, hSymmKey);
		}

		// close session after all p11 object destroied.
		ret_p11 = Adapter_C_CloseSession(hSession);
	}

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}

	SKF_LOGD("%s exit 0x%lx with output phKey %p", __FUNCTION__, ret_skf, *phKey);
	
	return ret_skf;
}

/*
*	数据加密初始化。设置数据加密的算法相关参数。
*	hKey			[IN] 加密密钥句柄
*	EncryptParam	[IN] 分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
*/
SKF_DEVAPI SKF_EncryptInit(
IN HANDLE hKey,
IN BLOCKCIPHERPARAM EncryptParam
)
{
	SKFHandleSYM_PTR handleKey = (SKFHandleSYM_PTR)hKey;
	CK_MECHANISM mechP11 = {0, NULL_PTR, 0};
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;

	SKF_LOGD("%s entry with hKey %p", __FUNCTION__, hKey);
	logData((unsigned char *)(&EncryptParam), sizeof(BLOCKCIPHERPARAM), plog_verbose, "parameters:");

	if (NULL == handleKey){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	// check input parameter
	HandleCheck handle;
	ret_skf = handle.Check(handleKey);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	// only support SGD_SMS4_ECB, SGD_SMS4_CBC, SGD_SMS4_OFB
	switch (handleKey->ulAlgId){
		case SGD_SMS4_ECB:
			mechP11.mechanism = CKM_SM4_ECB;
			break;
		case SGD_SMS4_CBC:
			// always need iv for this algorithm
			if((0 == EncryptParam.IVLen) || (NULL == EncryptParam.IV)) {
				break;
			}
			mechP11.mechanism = CKM_SM4_CBC;
			mechP11.pParameter = EncryptParam.IV;
			mechP11.ulParameterLen = EncryptParam.IVLen;
			break;
		case SGD_SMS4_CFB:
			break;
		case SGD_SMS4_OFB:
			// always need iv for this algorithm
			if((0 == EncryptParam.IVLen) || (NULL == EncryptParam.IV)) {
				break;
			}
			mechP11.mechanism = CKM_SM4_OFB;
			mechP11.pParameter = EncryptParam.IV;
			mechP11.ulParameterLen = EncryptParam.IVLen;
			break;
		default:
			break;
	}

	if(0 == mechP11.mechanism){
		SKF_LOGE("%s check mechanism 0x%x failed", __FUNCTION__, handleKey->ulAlgId);
		return SAR_KEYUSAGEERR;
	}

	ret_p11 = Adapter_C_EncryptInit(handleKey->session, &mechP11, handleKey->sessKeyHandle);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_EncryptInit failed 0x%x", __FUNCTION__, ret_p11);
		ret_skf = p11Error2SkfError(ret_p11);
	}

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}

	// save padding type and mechanism
	handleKey->paddingType = EncryptParam.PaddingType;
	handleKey->mechanism = mechP11.mechanism;

	SKF_LOGD("%s exit with return 0x%lx", __FUNCTION__, ret_skf);

	return ret_skf;
}

/*
*	单一分组数据的加密操作。
用指定加密密钥对指定数据进行加密，被加密的数据只包含一个分组，加密后的密文保存到指定的缓冲区中。
SKF_Encrypt只对单个分组数据进行加密，在调用SKF_Encrypt之前，必须调用SKF_EncryptInit初始化加密操作。
SKF_Encypt等价于先调用SKF_EncryptUpdate再调用SKF_EncryptFinal。
*	hKey			[IN] 加密密钥句柄
*	pbData			[IN] 待加密数据
*	ulDataLen		[IN] 待加密数据长度
*	pbEncryptedData [OUT] 加密后的数据缓冲区指针
*	pulEncryptedLen [IN,OUT] 输入，给出的缓冲区大小；输出，返回加密后的数据
长度
*	成功: SAR_OK
*	失败: SAR_FAIL SAR_MEMORYERR SAR_UNKNOWNERR  SAR_INVALIDPARAMERR SAR_BUFFER_TOO_SMALL
*/
SKF_DEVAPI SKF_Encrypt(
HANDLE	hKey,
BYTE*		pbData,
ULONG		ulDataLen,
BYTE*		pbEncryptedData,
ULONG*	pulEncryptedLen
)
{
	SKFHandleSYM_PTR handleKey = (SKFHandleSYM_PTR)hKey;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	BYTE* p11Input = NULL;
	ULONG p11InLen = 0;
	ULONG paddingLen = 0;

	SKF_LOGD("%s entry with hKey %p, input length %ld and content:", __FUNCTION__, hKey, ulDataLen);

	if (NULL == hKey || NULL == pbData || 0 == ulDataLen || NULL == pulEncryptedLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	logData((unsigned char *)pbData, ulDataLen, plog_verbose, "plain data:");

	// check input parameter
	HandleCheck handle;
	ret_skf = handle.Check(handleKey);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	// need padding before process
	if((CKM_SM4_ECB == handleKey->mechanism)&&(1 == handleKey->paddingType)) {
		p11InLen = SM4_KEY_LEN + SM4_KEY_LEN*(ulDataLen/SM4_KEY_LEN);
		if(NULL == pbEncryptedData) {
			*pulEncryptedLen = p11InLen;
			ret_skf = SAR_OK;
		}
		else if (*pulEncryptedLen < p11InLen)  { 
			SKF_LOGE("%s return 0x%x due input bufferLen %d and required %d", __FUNCTION__, SAR_BUFFER_TOO_SMALL, *pulEncryptedLen, p11InLen);
			*pulEncryptedLen = p11InLen;
			ret_skf = SAR_BUFFER_TOO_SMALL;
		}
		else {
			p11Input = new BYTE[p11InLen];
			paddingLen = SM4_KEY_LEN - ulDataLen%SM4_KEY_LEN;
			memcpy(p11Input, pbData, ulDataLen);
			memset(p11Input+ulDataLen, (unsigned char)paddingLen, paddingLen);
			ret_p11 = Adapter_C_Encrypt(handleKey->session, p11Input, p11InLen, pbEncryptedData, pulEncryptedLen);
			delete []p11Input;
			if(CKR_OK != ret_p11) {
				SKF_LOGE("%s Adapter_C_Encrypt failed 0x%x", __FUNCTION__, ret_p11);
				ret_skf = p11Error2SkfError(ret_p11);
			}
		}
	}
	else {
		// other mode, directly pass input to p11 interface
		ret_p11 = Adapter_C_Encrypt(handleKey->session, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen);
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_Encrypt failed 0x%x", __FUNCTION__, ret_p11);
			ret_skf = p11Error2SkfError(ret_p11);
		}
	}

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}
	else {
		logData((unsigned char *)pbEncryptedData, *pulEncryptedLen, plog_verbose, "cipher data:");
	}
	

	SKF_LOGD("%s exit with output length %ld", __FUNCTION__, *pulEncryptedLen);

	return ret_skf;

}

/*
*	多个分组数据的加密操作。
用指定加密密钥对指定数据进行加密，被加密的数据包含多个分组，加密后的密文保存到指定的缓冲区中。
SKF_EncryptUpdate对多个分组数据进行加密，在调用SKF_EncryptUpdate之前，必须调用SKF_EncryptInit初始化加密操作；
在调用SKF_EncryptUpdate之后，必须调用SKF_EncryptFinal结束加密操作。
*	hKey			[IN] 加密密钥句柄
*	pbData			[IN] 待加密数据
*	ulDataLen		[IN] 待加密数据长度
*	pbEncryptedData [OUT] 加密后的数据缓冲区指针
*	pulEncryptedLen [OUT] 返回加密后的数据长度
*/
SKF_DEVAPI SKF_EncryptUpdate(
IN HANDLE		hKey,
IN BYTE*		pbData,
IN ULONG		ulDataLen,
OUT BYTE*		pbEncryptedData,
OUT ULONG*	pulEncryptedLen
)
{
	SKFHandleSYM_PTR handleKey = (SKFHandleSYM_PTR)hKey;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	
	SKF_LOGW("%s entry with hKey %p, input length %ld", __FUNCTION__, hKey, ulDataLen);

	if (NULL == hKey || NULL == pbData || 0 == ulDataLen || NULL == pulEncryptedLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	logData((unsigned char *)pbData, ulDataLen, plog_verbose, "plain data:");

	// check input parameter
	HandleCheck handle;
	ret_skf = handle.Check(handleKey);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	if(1 == handleKey->paddingType) {
		SKF_LOGE("%s return 0x%x for padding not supported for update operation", __FUNCTION__, SAR_KEYUSAGEERR);
		return SAR_KEYUSAGEERR;
	}

	ret_p11 = Adapter_C_EncryptUpdate(handleKey->session, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_EncryptUpdate failed 0x%x", __FUNCTION__, ret_p11);
		ret_skf = p11Error2SkfError(ret_p11);
	}

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}
	else {
		logData((unsigned char *)pbEncryptedData, *pulEncryptedLen, plog_verbose, "cipher data:");
	}
	
	SKF_LOGD("%s exit with output length %ld", __FUNCTION__, *pulEncryptedLen);
	
	return ret_skf;
}

/*
*	结束多个分组数据的加密，返回剩余加密结果。
先调用SKF_EncryptInit初始化加密操作，
再调用SKF_EncryptUpdate对多个分组数据进行加密，
最后调用SKF_EncryptFinal结束多个分组数据的加密。
*	hKey			[IN] 加密密钥句柄
*	pbEncryptedData [OUT] 加密结果的缓冲区
*	pulEncryptedLen [OUT] 加密结果的长度
*/
SKF_DEVAPI SKF_EncryptFinal(
IN HANDLE hKey,
OUT BYTE *pbEncryptedData,
OUT ULONG *pulEncryptedDataLen
)
{
	SKFHandleSYM_PTR handleKey = (SKFHandleSYM_PTR)hKey;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;

	SKF_LOGD("%s entry with hKey %p", __FUNCTION__, hKey);

	if (NULL == hKey || NULL == pulEncryptedDataLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	// check input parameter
	HandleCheck handle;
	ret_skf = handle.Check(handleKey);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	if(1 == handleKey->paddingType) {
		SKF_LOGE("%s return 0x%x for padding not supported for update operation", __FUNCTION__, SAR_KEYUSAGEERR);
		return SAR_KEYUSAGEERR;
	}

	ret_p11 = Adapter_C_EncryptFinal(handleKey->session, pbEncryptedData, pulEncryptedDataLen);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_EncryptFinal failed 0x%x", __FUNCTION__, ret_p11);
		ret_skf = p11Error2SkfError(ret_p11);
	}

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}
	else {
		logData((unsigned char *)pbEncryptedData, *pulEncryptedDataLen, plog_verbose, "cipher data:");
	}
	
	SKF_LOGD("%s exit with output length %ld and content:", __FUNCTION__, *pulEncryptedDataLen);

	return ret_skf;
}

/*
*	数据解密初始化，设置解密密钥相关参数。
调用SKF_DecryptInit之后，可以调用SKF_Decrypt对单个分组数据进行解密，
也可以多次调用SKF_DecryptUpdate之后再调用SKF_DecryptFinal完成对多个分组数据的解密。
*	hKey [IN] 解密密钥句柄
*	DecryptParam [IN] 分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
*/
SKF_DEVAPI SKF_DecryptInit(
IN HANDLE hKey,
IN BLOCKCIPHERPARAM DecryptParam
)
{
	SKFHandleSYM_PTR handleKey = (SKFHandleSYM_PTR)hKey;
	CK_MECHANISM mechP11 = {0, NULL_PTR, 0};
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;

	SKF_LOGD("%s entry with hKey %p", __FUNCTION__, hKey);
	logData((unsigned char *)(&DecryptParam), sizeof(BLOCKCIPHERPARAM), plog_verbose, "parameters:");

	if (NULL == handleKey){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	// check input parameter
	HandleCheck handle;
	ret_skf = handle.Check(handleKey);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	// only support SGD_SMS4_ECB, SGD_SMS4_CBC, SGD_SMS4_OFB
	switch (handleKey->ulAlgId){
		case SGD_SMS4_ECB:
			mechP11.mechanism = CKM_SM4_ECB;
			break;
		case SGD_SMS4_CBC:
			mechP11.mechanism = CKM_SM4_CBC;
			mechP11.pParameter = DecryptParam.IV;
			mechP11.ulParameterLen = DecryptParam.IVLen;
			break;
		case SGD_SMS4_CFB:
			break;
		case SGD_SMS4_OFB:
			mechP11.mechanism = CKM_SM4_OFB;
			mechP11.pParameter = DecryptParam.IV;
			mechP11.ulParameterLen = DecryptParam.IVLen;
			break;
		default:
			break;
	}

	if(0 == mechP11.mechanism){
		SKF_LOGE("%s check mechanism 0x%x failed", __FUNCTION__, handleKey->ulAlgId);
		return SAR_KEYUSAGEERR;
	}

	ret_p11 = Adapter_C_DecryptInit(handleKey->session, &mechP11, handleKey->sessKeyHandle);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_DecryptInit failed 0x%x", __FUNCTION__, ret_p11);
		ret_skf = p11Error2SkfError(ret_p11);
	}

	// save padding type and mechanism
	handleKey->paddingType = DecryptParam.PaddingType;
	handleKey->mechanism = mechP11.mechanism;

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}

	SKF_LOGD("%s exit with return 0x%lx", __FUNCTION__, ret_skf);

	return ret_skf;

}

/*
*	单个分组数据的解密操作
用指定解密密钥对指定数据进行解密，被解密的数据只包含一个分组，解密后的明文保存到指定的缓冲区中
SKF_Decrypt只对单个分组数据进行解密，在调用SKF_Decrypt之前，必须调用SKF_DecryptInit初始化解密操作
SKF_Decypt等价于先调用SKF_DecryptUpdate再调用SKF_DecryptFinal
*	hKey			[IN] 解密密钥句柄
*	pbEncryptedData [IN] 待解密数据
*	ulEncryptedLen	[IN] 待解密数据长度
*	pbData			[OUT] 指向解密后的数据缓冲区指针，当为NULL时可获得解密后的数据长度
*	pulDataLen		[IN，OUT] 返回解密后的数据长度
*/
SKF_DEVAPI SKF_Decrypt(
IN HANDLE hKey,
IN BYTE*	pbEncryptedData,
IN ULONG	ulEncryptedLen,
OUT BYTE* pbData,
OUT ULONG* pulDataLen
)
{
	SKFHandleSYM_PTR handleKey = (SKFHandleSYM_PTR)hKey;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	BYTE* p11OutBuf = NULL;
	ULONG p11OutLen = 0;
	unsigned char paddingLen = 0;
	unsigned char countLoop = 0;
	
	SKF_LOGD("%s entry with hKey %p, input length %ld", __FUNCTION__, hKey, ulEncryptedLen);

	if (NULL == hKey || NULL == pbEncryptedData || 0 == ulEncryptedLen || NULL == pulDataLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	logData((unsigned char *)pbEncryptedData, ulEncryptedLen, plog_verbose, "cipher data:");

	// check input parameter
	HandleCheck handle;
	ret_skf = handle.Check(handleKey);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	if((CKM_SM4_ECB == handleKey->mechanism)&&(1 == handleKey->paddingType)) {
		if(NULL == pbData) {
			*pulDataLen = ulEncryptedLen;
			ret_skf = SAR_OK;
			SKF_LOGD("%s exit SAR_OK with expected output len %d", __FUNCTION__, ulEncryptedLen);
			return ret_skf;
		}
		
		if (*pulDataLen < ulEncryptedLen)  { 
			SKF_LOGE("%s return 0x%x due input bufferLen %d and required %d", __FUNCTION__, SAR_BUFFER_TOO_SMALL, *pulDataLen, ulEncryptedLen);
			*pulDataLen = ulEncryptedLen;
			ret_skf = SAR_BUFFER_TOO_SMALL;
			return ret_skf;
		}
		
		p11OutLen = ulEncryptedLen;
		p11OutBuf = new BYTE[p11OutLen];
		ret_p11 = Adapter_C_Decrypt(handleKey->session, pbEncryptedData, ulEncryptedLen, p11OutBuf, &p11OutLen);
		if(CKR_OK != ret_p11) {
			delete []p11OutBuf;
			SKF_LOGE("%s Adapter_C_Decrypt failed 0x%x", __FUNCTION__, ret_p11);
			ret_skf = p11Error2SkfError(ret_p11);
			return ret_skf;
		}
		
		ret_skf = SAR_OK;
		paddingLen = (unsigned char)p11OutBuf[p11OutLen - 1];
		// padding byte shall be within range 1~16
		if((paddingLen < 1)||(paddingLen > SM4_KEY_LEN)) {
			delete []p11OutBuf;
			SKF_LOGE("%s padding check failed return 0x%x, last byte %d", __FUNCTION__, SAR_FAIL, paddingLen);
			ret_skf = SAR_FAIL;
			return ret_skf;
		}

		// last paddingLen bytes in output shall be filled with value "paddingLen" in byte
		// if not, must be error
		for(countLoop=0; countLoop<paddingLen; countLoop++) {
			if(p11OutBuf[p11OutLen - 1 - countLoop] != paddingLen){
				SKF_LOGE("%s padding check failed return 0x%x", __FUNCTION__, SAR_FAIL);
				logData(p11OutBuf+p11OutLen-paddingLen, (unsigned long)paddingLen, plog_error, "decoded padding:");
				delete []p11OutBuf;
				ret_skf = SAR_FAIL;
				return ret_skf;
			}
		}

		// padding check pass, remove padding bytes, fill output buffer
		memcpy(pbData, p11OutBuf, p11OutLen-paddingLen);
		*pulDataLen = p11OutLen-paddingLen;
		ret_skf = SAR_OK;
	}
	else {
		ret_p11 = Adapter_C_Decrypt(handleKey->session, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen);
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_Decrypt failed 0x%x", __FUNCTION__, ret_p11);
			ret_skf = p11Error2SkfError(ret_p11);
		}
	}

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}
	else {
		logData((unsigned char *)pbData, *pulDataLen, plog_verbose, "plain data:");
	}
	
	SKF_LOGD("%s exit with output length %ld and content:", __FUNCTION__, *pulDataLen);

	return ret_skf;
}

/*
*	多个分组数据的解密操作。
用指定解密密钥对指定数据进行解密，被解密的数据包含多个分组，解密后的明文保存到指定的缓冲区中。
SKF_DecryptUpdate对多个分组数据进行解密，在调用SKF_DecryptUpdate之前，必须调用SKF_DecryptInit初始化解密操作；
在调用SKF_DecryptUpdate之后，必须调用SKF_DecryptFinal结束解密操作。
*	hKey			[IN] 解密密钥句柄
*	pbEncryptedData [IN] 待解密数据
*	ulEncryptedLen	[IN] 待解密数据长度
*	pbData			[OUT] 指向解密后的数据缓冲区指针
*	pulDataLen		[IN，OUT] 返回解密后的数据长度
*/
SKF_DEVAPI SKF_DecryptUpdate(
IN HANDLE hKey,
IN BYTE*	pbEncryptedData,
IN ULONG	ulEncryptedLen,
OUT BYTE* pbData,
OUT ULONG* pulDataLen
)
{
	SKFHandleSYM_PTR handleKey = (SKFHandleSYM_PTR)hKey;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;

	SKF_LOGD("%s entry with hKey %p, input length %ld", __FUNCTION__, hKey, ulEncryptedLen);

	if (NULL == hKey || NULL == pbEncryptedData || 0 == ulEncryptedLen || NULL == pulDataLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	logData((unsigned char *)pbEncryptedData, ulEncryptedLen, plog_verbose, "cipher data:");

	// check input parameter
	HandleCheck handle;
	ret_skf = handle.Check(handleKey);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	if(1 == handleKey->paddingType) {
		SKF_LOGE("%s return 0x%x for padding not supported for update operation", __FUNCTION__, SAR_KEYUSAGEERR);
		return SAR_KEYUSAGEERR;
	}

	ret_p11 = Adapter_C_DecryptUpdate(handleKey->session, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_DecryptUpdate failed 0x%x", __FUNCTION__, ret_p11);
		ret_skf = p11Error2SkfError(ret_p11);
	}

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}
	else {
		logData((unsigned char *)pbData, *pulDataLen, plog_verbose, "plain data:");
	}

	SKF_LOGD("%s exit with output length %ld", __FUNCTION__, *pulDataLen);

	return ret_skf;
}

/*
*	结束多个分组数据的解密。
*	hKey				[IN] 解密密钥句柄
*	pbPlainText			[OUT] 指向解密结果的缓冲区，如果此参数为NULL时，由pulPlainTextLen返回解密结果的长度
*	pulDecyptedDataLen	[IN，OUT] 调用时表示pbPlainText缓冲区的长度，返回解密结果的长度
*/
SKF_DEVAPI SKF_DecryptFinal(
IN HANDLE hKey,
OUT BYTE *pbPlainText,
OUT ULONG *pulPlainTextLen
)
{
	SKFHandleSYM_PTR handleKey = (SKFHandleSYM_PTR)hKey;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;

	SKF_LOGD("%s entry with hKey %p", __FUNCTION__, hKey);

	if (NULL == hKey || NULL == pulPlainTextLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	// check input parameter
	HandleCheck handle;
	ret_skf = handle.Check(handleKey);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	if(1 == handleKey->paddingType) {
		SKF_LOGE("%s return 0x%x for padding not supported for update operation", __FUNCTION__, SAR_KEYUSAGEERR);
		return SAR_KEYUSAGEERR;
	}

	ret_p11 = Adapter_C_DecryptFinal(handleKey->session, pbPlainText, pulPlainTextLen);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_DecryptFinal failed 0x%x", __FUNCTION__, ret_p11);
		ret_skf = p11Error2SkfError(ret_p11);
	}

	if(SAR_OK != ret_skf) {
		SKF_LOGE("%s return 0x%x", __FUNCTION__, ret_skf);
	}
	else {
		logData((unsigned char *)pbPlainText, *pulPlainTextLen, plog_verbose, "plain data:");
	}

	SKF_LOGD("%s exit with output length %ld", __FUNCTION__, *pulPlainTextLen);

	return ret_skf;
}

/*
*	初始化消息杂凑计算操作，指定计算消息杂凑的算法。
*	hDev			[IN] 连接设备时返回的设备句柄
*	ulAlgID			[IN] 杂凑算法标识
*	phHash			[OUT] 杂凑对象句柄
*/
//#define PADDING_TO_64_BYTES

SKF_DEVAPI SKF_DigestInit(
IN DEVHANDLE	hDev,
IN ULONG		ulAlgID,
IN ECCPUBLICKEYBLOB *pPubKey,
IN unsigned char *pucID,
IN ULONG ulIDLen,
OUT HANDLE*	phHash
)
{
	CK_SESSION_HANDLE hSession = 0;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;
	CK_MECHANISM sm3mechanism={ CKM_HASH_SM3,NULL_PTR,0 };
	CK_BYTE hashOutBuf[HASH_OUTPUT_LEN] = {0};
	CK_ULONG hashOutLen = HASH_OUTPUT_LEN;
	CK_ULONG cipherOutLen = 0;
	CK_BYTE ENTL[2] = {0};
	CK_ULONG entlBitLen = ulIDLen * 8;
	// swap the endian for pucID length
	ENTL[0] = (entlBitLen & 0xFF00) >> 8;
	ENTL[1] = (entlBitLen & 0x00FF);
	CK_BBOOL preProcess = TRUE;

#ifdef PADDING_TO_64_BYTES
	CK_BYTE padding_0_32bytes[32] = {0};
	memset(padding_0_32bytes, 0, sizeof(padding_0_32bytes));
#endif
	// SM2 standard parameters for pre-process
	// FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
	CK_BYTE sm2_a[] = {0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc};
	// 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
	CK_BYTE sm2_b[] = {0x28,0xe9,0xfa,0x9e,0x9d,0x9f,0x5e,0x34,0x4d,0x5a,0x9e,0x4b,0xcf,0x65,0x09,0xa7,0xf3,0x97,0x89,0xf5,0x15,0xab,0x8f,0x92,0xdd,0xbc,0xbd,0x41,0x4d,0x94,0x0e,0x93};
	// 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
	CK_BYTE sm2_X_G[] = {0x32,0xc4,0xae,0x2c,0x1f,0x19,0x81,0x19,0x5f,0x99,0x04,0x46,0x6a,0x39,0xc9,0x94,0x8f,0xe3,0x0b,0xbf,0xf2,0x66,0x0b,0xe1,0x71,0x5a,0x45,0x89,0x33,0x4c,0x74,0xc7};
	// BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
	CK_BYTE sm2_Y_G[] = {0xbc,0x37,0x36,0xa2,0xf4,0xf6,0x77,0x9c,0x59,0xbd,0xce,0xe3,0x6b,0x69,0x21,0x53,0xd0,0xa9,0x87,0x7c,0xc6,0x2a,0x47,0x40,0x02,0xdf,0x32,0xe5,0x21,0x39,0xf0,0xa0};

	SKF_LOGD("%s entry with hDev %p, ulAlgID 0x%lx", __FUNCTION__, hDev, ulAlgID);
	
	// check input parameter
	if (NULL == hDev || SGD_SM3 != ulAlgID || NULL == phHash
		|| entlBitLen > 65535){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	// if ulIDLen is 0, no need pre-processing
	if( 0 == ulIDLen ) {
		preProcess = FALSE;
	}
	else {
	// need pre-processing
		if (NULL == pPubKey || NULL == pucID ) {
			// no valid input pubkey and pucID, cannot do pre-processing, return error
			SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
			return SAR_INVALIDPARAMERR;
		}
	}

	logData(pucID, ulIDLen, plog_verbose, "pucID:");

	ret_p11 = Adapter_C_OpenSession(((SKFHandleD_PTR)hDev)->id, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret_p11, SAR_FAIL);
		return SAR_FAIL;
	}

	if (preProcess) {
		// pre-process for digest, follow GM_T 0009-2012 document section 8.1, 8.2
		// pre-process SM3(ENTL||pucID||SM2_a||SM2_b||SM2_X_G||SM2_Y_G||SM2_X_A||SM2_Y_A)
		// ENTL is 2 bytes value, indicate pucID length in bits
		// pucID is user defined specific identity
		// SM2_a, SM2_b, SM2_X_G, SM2_Y_G are SM2 ECC parameters defined in GM_T 0003.5 document
		// SM2_X_A, SM2_Y_A stand for the SM2 public key x/y part within input parameter
		ret_p11 = Adapter_C_DigestInit(hSession, &sm3mechanism);
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_DigestInit failed 0x%x", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}
		ret_p11 = Adapter_C_DigestUpdate(hSession, ENTL, sizeof(ENTL));
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_DigestUpdate failed 0x%x", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}
		ret_p11 = Adapter_C_DigestUpdate(hSession, pucID, ulIDLen);
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_DigestUpdate failed 0x%x", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}

		ret_p11 = Adapter_C_DigestUpdate(hSession, sm2_a, sizeof(sm2_a));
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_DigestUpdate failed 0x%x", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}

		ret_p11 = Adapter_C_DigestUpdate(hSession, sm2_b, sizeof(sm2_b));
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_DigestUpdate failed 0x%x", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}

		ret_p11 = Adapter_C_DigestUpdate(hSession, sm2_X_G, sizeof(sm2_X_G));
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_DigestUpdate failed 0x%x", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}

		ret_p11 = Adapter_C_DigestUpdate(hSession, sm2_Y_G, sizeof(sm2_Y_G));
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_DigestUpdate failed 0x%x", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}

		ret_p11 = Adapter_C_DigestUpdate(hSession, pPubKey->XCoordinate + ECC_MAX_XCOORDINATE_BITS_LEN/16, ECC_MAX_XCOORDINATE_BITS_LEN/16);
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_DigestUpdate failed 0x%x", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}

		ret_p11 = Adapter_C_DigestUpdate(hSession, pPubKey->YCoordinate + ECC_MAX_YCOORDINATE_BITS_LEN/16, ECC_MAX_YCOORDINATE_BITS_LEN/16);
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_DigestUpdate failed 0x%x", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}
		ret_p11 = Adapter_C_DigestFinal(hSession, hashOutBuf, &hashOutLen);
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_DigestFinal failed 0x%x", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}

		// follow GM_T 0009-2012 document section 8.2
		ret_p11 = Adapter_C_DigestInit(hSession, &sm3mechanism);
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_DigestInit failed 0x%x", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}
		ret_p11 = Adapter_C_DigestUpdate(hSession, hashOutBuf, hashOutLen);
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_DigestUpdate failed 0x%x", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}
	}
	else {
		// no pre-process
		ret_p11 = Adapter_C_DigestInit(hSession, &sm3mechanism);
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s Adapter_C_DigestInit failed 0x%x", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}
	}

	// generate output...
	// save context for coming digest operation
	SKFHandleSYM_PTR tmp = new SKFHandleSYM();
	memset(tmp, 0, sizeof(SKFHandleSYM));
	tmp->pDevHandle = (SKFHandleD_PTR)hDev;
	tmp->pContainerHandle = NULL;
	tmp->sessKeyHandle = NULL;
	tmp->session = hSession;
	tmp->ulAlgId = ulAlgID;
	SKFGlobeData::setSessionKeyHandle.insert(tmp);

	// fill context to output
	*phHash = (HANDLE)tmp;

	SKF_LOGD("%s exit success with phHash %p", __FUNCTION__, phHash);

	return SAR_OK;

}
/*
*	对单一分组的消息进行杂凑计算。
*	hHash			[IN] 杂凑对象句柄
*	pbData			[IN] 指向消息数据的缓冲区
*	ulDataLen		[IN] 消息数据的长度
*	pbHashData		[OUT] 杂凑数据缓冲区指针，当此参数为NULL时，由pulHashLen返回杂凑结果的长度
*	pulHashLen		[IN，OUT] 调用时表示pbHashData缓冲区的长度，返回杂凑结果的长度
*/
SKF_DEVAPI SKF_Digest(
IN HANDLE hHash,
IN BYTE *pbData,
IN ULONG ulDataLen,
OUT BYTE *pbHashData,
OUT ULONG *pulHashLen
)
{
	SKFHandleSYM_PTR handleKey = (SKFHandleSYM_PTR)hHash;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;

	SKF_LOGD("%s entry hHash %p", __FUNCTION__, hHash);;
	
	if (NULL == handleKey || NULL == pbData || 0 == ulDataLen || NULL == pulHashLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	logData((unsigned char *)pbData, ulDataLen, plog_verbose, "input data:");

	// check input parameter
	HandleCheck handle;
	ret_skf = handle.Check(handleKey);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	// set output length, always as HASH_OUTPUT_LEN
	if (NULL == pbHashData){
		*pulHashLen = HASH_OUTPUT_LEN;
		SKF_LOGD("%s exit success", __FUNCTION__);
		return SAR_OK;
	}
	else if (*pulHashLen < HASH_OUTPUT_LEN) {
		SKF_LOGE("%s exit error due input buffer len %d", __FUNCTION__, *pulHashLen);
		*pulHashLen = HASH_OUTPUT_LEN;
		return SAR_BUFFER_TOO_SMALL;
	}
	else {
		*pulHashLen = HASH_OUTPUT_LEN;
	}

	// shall NOT directly call C_Digest due to C_DigestUpdate may be called already in SKF_DigestInit func for pre-process
	ret_p11 = Adapter_C_DigestUpdate(handleKey->session, pbData, ulDataLen);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_DigestUpdate failed 0x%x", __FUNCTION__, ret_p11);
		return SAR_FAIL;
	}
	ret_p11 = Adapter_C_DigestFinal(handleKey->session, pbHashData, pulHashLen);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_DigestFinal failed 0x%x", __FUNCTION__, ret_p11);
		return SAR_FAIL;
	}

	SKF_LOGD("%s exit success", __FUNCTION__);
	logData((unsigned char *)pbHashData, *pulHashLen, plog_verbose, "hash:");

	return SAR_OK;
}

/*
*	对多个分组的消息进行杂凑计算。
*	hHash			[IN] 杂凑对象句柄
*	pbPart			[IN] 指向消息数据的缓冲区
*	ulPartLen		[IN] 消息数据的长度
*/
SKF_DEVAPI SKF_DigestUpdate(
IN HANDLE hHash,
IN BYTE *pbData,
IN ULONG ulDataLen
)
{
	SKFHandleSYM_PTR handleKey = (SKFHandleSYM_PTR)hHash;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;

	SKF_LOGD("%s entry with hHash %p", __FUNCTION__, hHash);

	if (NULL == handleKey || NULL == pbData || 0 == ulDataLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	logData((unsigned char *)pbData, ulDataLen, plog_verbose, "input data:");

	// check input parameter
	HandleCheck handle;
	ret_skf = handle.Check(handleKey);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	ret_p11 = Adapter_C_DigestUpdate(handleKey->session, pbData, ulDataLen);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_DigestUpdate failed 0x%x", __FUNCTION__, ret_p11);
		return p11Error2SkfError(ret_p11);
	}

	SKF_LOGD("%s exit success", __FUNCTION__);

	return SAR_OK;
}

/*
*	结束多个分组消息的杂凑计算操作，将杂凑保存到指定的缓冲区。
*	hHash			[IN] 哈希对象句柄
*	pHashData		[OUT] 返回的杂凑数据缓冲区指针，如果此参数NULL时，由pulHashLen返回杂凑结果的长度
*	pulHashLen		[IN，OUT] 调用时表示杂凑结果的长度，返回杂凑数据的长度
*/
SKF_DEVAPI SKF_DigestFinal(
IN HANDLE hHash,
OUT BYTE *pHashData,
OUT ULONG *pulHashLen
)
{
	SKFHandleSYM_PTR handleKey = (SKFHandleSYM_PTR)hHash;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;

	SKF_LOGD("%s entry with hHash %p", __FUNCTION__, hHash);

	if (NULL == handleKey || NULL == pulHashLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	// check input parameter
	HandleCheck handle;
	ret_skf = handle.Check(handleKey);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	// set output length, always as HASH_OUTPUT_LEN
	if (NULL == pHashData){
		*pulHashLen = HASH_OUTPUT_LEN;
		SKF_LOGD("%s exit success", __FUNCTION__);
		return SAR_OK;
	}
	else if (*pulHashLen < HASH_OUTPUT_LEN) {
		SKF_LOGE("%s exit error due input buffer len %d", __FUNCTION__, *pulHashLen);
		*pulHashLen = HASH_OUTPUT_LEN;
		return SAR_BUFFER_TOO_SMALL;
	}
	else {
		*pulHashLen = HASH_OUTPUT_LEN;
	}

	ret_p11 = Adapter_C_DigestFinal(handleKey->session, pHashData, pulHashLen);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s Adapter_C_DigestFinal failed 0x%x", __FUNCTION__, ret_p11);
		return p11Error2SkfError(ret_p11);
	}

	SKF_LOGD("%s exit success", __FUNCTION__);
	logData((unsigned char *)pHashData, *pulHashLen, plog_verbose, "hash:");

	return SAR_OK;
}

/*
*	初始化消息认证码计算操作，设置计算消息认证码的密钥参数，并返回消息认证码句柄。
*	hKey			[IN] 计算消息认证码的密钥句柄
*	MacParam		[IN] 消息认证计算相关参数，包括初始向量、初始向量长度、填充方法等
*	phMac			[OUT] 消息认证码对象句柄
*/
SKF_DEVAPI SKF_MacInit(
IN HANDLE hKey,
IN BLOCKCIPHERPARAM* MacParam,
OUT HANDLE *phMac
)
{
return SAR_NOTSUPPORTYETERR;
}

/*
*	SKF_Mac计算单一分组数据的消息认证码。
*	hMac			[IN] 消息认证码句柄
*	pbData			[IN] 指向待计算数据的缓冲区
*	ulDataLen		[IN] 待计算数据的长度
*	pbMacData		[OUT] 指向计算后的Mac结果，如果此参数为NULL时，由pulMacLen返回计算后Mac结果的长度
*	pulMacLen		[IN，OUT] 调用时表示pbMacData缓冲区的长度，返回计算Mac结果的长度
*/
SKF_DEVAPI SKF_Mac(
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
*	计算多个分组数据的消息认证码。
*	hMac			[IN] 消息认证码句柄
*	pbData			[IN] 指向待计算数据的缓冲区
*	plDataLen		[IN] 待计算数据的长度
*/
SKF_DEVAPI SKF_MacUpdate(
IN HANDLE hMac,
IN BYTE*	pbData,
IN ULONG	ulDataLen
)
{
return SAR_NOTSUPPORTYETERR;
}

/*
*	结束多个分组数据的消息认证码计算操作
*	hMac			[IN] 消息认证码句柄
*	pbMacData		[OUT] 指向消息认证码的缓冲区，当此参数为NULL时，由pulMacDataLen返回消息认证码返回的长度
*	pulMacDataLen	[OUT] 调用时表示消息认证码缓冲区的最大长度，返回消息认证码的长度
*/
SKF_DEVAPI SKF_MacFinal(
IN HANDLE hMac,
OUT BYTE*	pbMacData,
OUT ULONG* pulMacDataLen
)
{
return SAR_NOTSUPPORTYETERR;
}

/*
*	关闭会话密钥、杂凑、消息认证码句柄。
*	hHandle			[IN] 要关闭的对象句柄
*/
SKF_DEVAPI SKF_CloseHandle(
IN HANDLE hHandle
)
{
	SKFHandleSYM_PTR handleKey = (SKFHandleSYM_PTR)hHandle;
	CK_RV ret_p11 = CKR_OK;
	ULONG ret_skf = SAR_OK;

	SKF_LOGW("%s entry with hHandle %p:", __FUNCTION__, hHandle);

	if (NULL == hHandle){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	// check input parameter
	// currently only support session key and hash handle (both regarded as session key inside SKF)
	// mac key object, ECC agreement key not support in current version
	HandleCheck handle;
	ret_skf = handle.Check(handleKey);
	if (ret_skf != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret_skf);
		return SAR_INVALIDHANDLEERR;
	}

	// release cryptoki material before close session
	// for hash operation, no object to destroy
	if (SGD_SM3 != handleKey->ulAlgId) {
		ret_p11 = Adapter_C_DestroyObject(handleKey->session, handleKey->sessKeyHandle);
		if(CKR_OK != ret_p11) {
			SKF_LOGE("%s return 0x%x for Adapter_C_DestroyObject failure", __FUNCTION__, ret_p11);
			return SAR_FAIL;
		}
	}

	// close session after all p11 object destroied.
	ret_p11 = Adapter_C_CloseSession(handleKey->session);
	if(CKR_OK != ret_p11) {
		SKF_LOGE("%s return 0x%x for Adapter_C_CloseSession failure", __FUNCTION__, ret_p11);
		return SAR_FAIL;
	}

	// remove handle from symmetric key set
	SKFGlobeData::setSessionKeyHandle.erase(handleKey);

	delete handleKey;

	SKF_LOGW("%s exit with SAR_OK", __FUNCTION__); 

	return SAR_OK;
}

/*
*	将命令直接发送给设备，并返回结果
*	hDev			[IN] 设备句柄
*	pbCommand		[IN] 设备命令
*	ulCommandLen	[IN] 命令长度
*	pbData			[OUT] 返回结果数据
*	pulDataLen		[OUT] 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度
*/
SKF_DEVAPI SKF_Transmit(
IN DEVHANDLE hDev,
IN BYTE* pbCommand,
IN ULONG ulCommandLen,
OUT BYTE* pbData,
OUT ULONG* pulDataLen
)
{
return SAR_NOTSUPPORTYETERR;
}

/*
*	往容器中导入签名证书或者加密证书
*	hContainer		[IN] 容器句柄
*	bSignFlag		[IN] TRUE表示导入签名证书，FALSE表示导入加密证书
*	pbCert			[IN] 指向证书数据的缓冲区
*	ulCertLen		[IN] 证书数据的长度
*/
SKF_DEVAPI SKF_ImportCertificate(
IN HCONTAINER hContainer,
IN BOOL bSignFlag,
IN BYTE* pbCert,
IN ULONG ulCertLen
)
{
	SKF_LOGW("%s entry with %p, flag %d, length %d for %p", __FUNCTION__, hContainer, bSignFlag, ulCertLen, pbCert);
	
	if (NULL == hContainer || NULL == pbCert || 0 == ulCertLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	HandleCheck handle;
	CK_RV ret = handle.Check((SKFHandleC_PTR)hContainer);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	// check if container open
	if (SKF_FLAG_EXIST == ((SKFHandleC_PTR)hContainer)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// there is no request for user log in to access this interface
#if 0
	// check if app logged in
	if (SKF_FLAG_AUTH != ((SKFHandleC_PTR)hContainer)->pAppHandle->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
		return SAR_USER_NOT_LOGGED_IN;
	}
#endif

	CK_ATTRIBUTE attributes[] = {
		{ CKA_VALUE, pbCert, ulCertLen }
	};

	CK_SESSION_HANDLE session = 0;
	ret = handle.GetSession((SKFHandleC_PTR)hContainer,&session);
	if (ret != SAR_OK){
		SKF_LOGE("%s get session failed 0x%x and return 0x%x", __FUNCTION__, ret, SAR_FAIL);
		return SAR_FAIL;
	}


	SKFHandleCT_PTR pCert = NULL;
	set<SKFHandleCT_PTR>::iterator it = SKFGlobeData::setCertHandle.begin();
	for (; it != SKFGlobeData::setCertHandle.end(); it++){
		pCert = (SKFHandleCT_PTR)(*it);
		if (pCert->pContainerHandle == (SKFHandleC_PTR)hContainer && 
			pCert->SignFlg == bSignFlag){
			ret = Adapter_C_SetAttributeValue(session, pCert->certHandle, attributes, sizeof(attributes)/sizeof(CK_ATTRIBUTE));
			if (ret != SAR_OK){
				SKF_LOGE("%s get 0x%x for Adapter_C_SetAttributeValue failure", __FUNCTION__, ret);
				handle.CloseSession(session);
				return SAR_OBJERR;
			}

			pCert->cert.clear();
			pCert->cert.append((char*)pbCert, ulCertLen);
			
			handle.CloseSession(session);

			SKF_LOGD("%s exit with %p", __FUNCTION__, pCert);
			
			return SAR_OK;
		}
	}

	pCert = new SKFHandleCT();
	pCert->cert.append((char*)pbCert, ulCertLen);
	pCert->SignFlg = bSignFlag;
	pCert->pContainerHandle = (SKFHandleC_PTR)hContainer;

	CK_OBJECT_CLASS dataClass = CKO_DATA;
	CK_BBOOL ttrue = CK_TRUE;

	string certApp;
	SKF_CERT_APPLICATION_DESC(pCert->pContainerHandle->pAppHandle->appName,
		pCert->pContainerHandle->containerName, certApp);
	
	ULONG eccFlg = 1;

	string certLabel;
	certLabel.append((char*)&eccFlg,sizeof(eccFlg));
	certLabel.append((char*)&bSignFlag, sizeof(bSignFlag));

	CK_ATTRIBUTE createAttributes[] = {
		{ CKA_APPLICATION, (char*)certApp.data(), certApp.size() },
		{ CKA_LABEL, (char*)certLabel.data(), certLabel.size() },
		{ CKA_CLASS,&dataClass,sizeof(dataClass)},
		{ CKA_TOKEN, &ttrue, sizeof(ttrue) },
		{ CKA_PRIVATE, &ttrue, sizeof(ttrue) },
		{ CKA_VALUE, pbCert, ulCertLen },

	};

	ret = Adapter_C_CreateObject(session, createAttributes, sizeof(createAttributes) / sizeof(CK_ATTRIBUTE), &pCert->certHandle);
	if (ret != SAR_OK){
		SKF_LOGE("%s get 0x%x for Adapter_C_CreateObject failure", __FUNCTION__, ret);
		handle.CloseSession(session);
		return SAR_OBJERR;
	}

	handle.CloseSession(session);

	SKFGlobeData::setCertHandle.insert(pCert);

	SKF_LOGD("%s exit with %p", __FUNCTION__, pCert);

	return SAR_OK;
}

/*
*	导出容器中的签名证书或者加密证书
*	hContainer		[IN] 容器句柄
*	bSignFlag		[IN] TRUE表示导出签名证书，FALSE表示导出加密证书
*	pbCert			[OUT] 指向证书数据的缓冲区
*	pulCertLen		[IN,OUT] 调用时表示pbCert的长度，返回导出证书的大小
*/
SKF_DEVAPI SKF_ExportCertificate(
IN HCONTAINER hContainer,
IN BOOL bSignFlag,
OUT BYTE* pbCert,
IN OUT ULONG* pulCertLen
)
{
	if (NULL == hContainer || NULL == pulCertLen){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}
	SKF_LOGW("%s entry with %p, flag %d, length %d", __FUNCTION__, hContainer, bSignFlag, *pulCertLen);

	HandleCheck handle;
	CK_RV ret = handle.Check((SKFHandleC_PTR)hContainer);
	if (ret != SAR_OK){
		SKF_LOGE("%s return 0x%x for handle check failer", __FUNCTION__, ret);
		return SAR_INVALIDHANDLEERR;
	}

	// check if container open
	if (SKF_FLAG_EXIST == ((SKFHandleC_PTR)hContainer)->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDHANDLEERR);
		return SAR_INVALIDHANDLEERR;
	}

	// there is no request for user log in to access this interface
#if 0
	// check if app logged in
	if (SKF_FLAG_AUTH != ((SKFHandleC_PTR)hContainer)->pAppHandle->flg){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_USER_NOT_LOGGED_IN);
		return SAR_USER_NOT_LOGGED_IN;
	}
#endif

	SKFHandleCT_PTR tmp = NULL;
	set<SKFHandleCT_PTR>::iterator it = SKFGlobeData::setCertHandle.begin();
	for (;it != SKFGlobeData::setCertHandle.end();it++){
		tmp = *it;
		if (tmp->pContainerHandle == (SKFHandleC_PTR)hContainer &&
			tmp->SignFlg == bSignFlag){
			if(NULL == pbCert) {
				SKF_LOGD("%s exit 0x%x", __FUNCTION__, SAR_OK);
				*pulCertLen = tmp->cert.size();
				return SAR_OK;
			}
			
			if(*pulCertLen < tmp->cert.size()) {
				SKF_LOGE("%s exit 0x%x, required %d", __FUNCTION__, SAR_BUFFER_TOO_SMALL, tmp->cert.size());
				*pulCertLen = tmp->cert.size();
				return SAR_BUFFER_TOO_SMALL;
			}
			
			*pulCertLen = tmp->cert.size();
			memcpy(pbCert,tmp->cert.data(), tmp->cert.size());
			SKF_LOGD("%s exit", __FUNCTION__);
			return SAR_OK;
		}
	}

	SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_CERTNOTFOUNDERR);

	return SAR_CERTNOTFOUNDERR;
}

/*
*	获取容器的属性
*	hContainer		[IN] 容器句柄
*	pulConProperty	[OUT] 获得的容器属性。指针指向的值为0表示未知、尚未分配属性或者为空容器，为1表示为RSA容器，为2表示为ECC容器。
*/
SKF_DEVAPI SKF_GetContainerProperty(
IN HCONTAINER hContainer,
OUT ULONG *pulConProperty
)
{
	if (NULL == hContainer || NULL == pulConProperty){
		SKF_LOGE("%s exit 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}
	return SKF_GetContainerType(hContainer, pulConProperty);
}

