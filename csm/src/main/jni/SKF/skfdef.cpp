#include "skfdef.h"
#ifdef WIN32
#else
#include "P11Adapter.h"
#endif
using namespace std;

set<SKFHandleD_PTR> SKFGlobeData::setDevHandle;

set<SKFHandleA_PTR> SKFGlobeData::setAppHandle;

set<SKFHandleC_PTR> SKFGlobeData::setContainerHandle;

set<SKFHandleSYM_PTR> SKFGlobeData::setSessionKeyHandle;

set<SKFHandleF_PTR> SKFGlobeData::setFileHandle;
set<SKFHandleCT_PTR> SKFGlobeData::setCertHandle;
set<SKFHandleASYM_PTR> SKFGlobeData::setAysmHandle;

bool SKFGlobeData::loggerInitialized = false;


void SKFGlobeData::clearAll(){
	
	set<SKFHandleD_PTR>::iterator itD;
	set<SKFHandleA_PTR>::iterator itA;
	set<SKFHandleC_PTR>::iterator itC;
	set<SKFHandleF_PTR>::iterator itF;
	set<SKFHandleSYM_PTR>::iterator itSK;
	set<SKFHandleCT_PTR>::iterator itCT;
	set<SKFHandleASYM_PTR>::iterator itAK;

	SKFHandleD_PTR tempDeviceHandle = NULL;
	SKFHandleA_PTR tempApplicationHandle = NULL;
	SKFHandleC_PTR tempContainerHandle = NULL;
	SKFHandleF_PTR tempFileHandle = NULL;
	SKFHandleSYM_PTR tempSessionKeyHandle = NULL;
	SKFHandleCT_PTR tempCertificationHandle = NULL;
	SKFHandleASYM_PTR tempAsmKeyHandle = NULL;

	itD = SKFGlobeData::setDevHandle.begin();
	for (;itD != SKFGlobeData::setDevHandle.end(); ) {
		tempDeviceHandle = *itD;
		SKFGlobeData::setDevHandle.erase(itD++);
		delete tempDeviceHandle;
		tempDeviceHandle = NULL;
	}

	itA = SKFGlobeData::setAppHandle.begin();
	for (;itA != SKFGlobeData::setAppHandle.end(); ) {
		tempApplicationHandle = *itA;
		
		if(tempApplicationHandle->appValue.soPin) {
			delete[] tempApplicationHandle->appValue.soPin;
			tempApplicationHandle->appValue.soPin = NULL;
		}

		if(tempApplicationHandle->appValue.soDefaultPin) {
			delete[] tempApplicationHandle->appValue.soDefaultPin;
			tempApplicationHandle->appValue.soDefaultPin = NULL;
		}

		if(tempApplicationHandle->appValue.usrDefaultPin) {
			delete[] tempApplicationHandle->appValue.usrDefaultPin;
			tempApplicationHandle->appValue.usrDefaultPin = NULL;
		}

		if(tempApplicationHandle->appValue.usrPin) {
			delete[] tempApplicationHandle->appValue.usrPin;
			tempApplicationHandle->appValue.usrPin = NULL;
		}

		SKFGlobeData::setAppHandle.erase(itA++);
		delete tempApplicationHandle;
		tempApplicationHandle = NULL;
	}

	itC = SKFGlobeData::setContainerHandle.begin();
	for (;itC != SKFGlobeData::setContainerHandle.end(); ) {
		tempContainerHandle = *itC;
		SKFGlobeData::setContainerHandle.erase(itC++);
		delete tempContainerHandle;
		tempContainerHandle = NULL;
	}

	itSK = SKFGlobeData::setSessionKeyHandle.begin();
	for (;itSK != SKFGlobeData::setSessionKeyHandle.end(); ) {
		tempSessionKeyHandle = *itSK;
		SKFGlobeData::setSessionKeyHandle.erase(itSK++);
		delete tempSessionKeyHandle;
		tempSessionKeyHandle = NULL;
	}

	itF = SKFGlobeData::setFileHandle.begin();
	for (;itF != SKFGlobeData::setFileHandle.end(); ) {
		tempFileHandle = *itF;
		SKFGlobeData::setFileHandle.erase(itF++);
		delete tempFileHandle;
		tempFileHandle = NULL;
	}

	itCT = SKFGlobeData::setCertHandle.begin();
	for (;itCT != SKFGlobeData::setCertHandle.end(); ) {
		tempCertificationHandle = *itCT;
		SKFGlobeData::setCertHandle.erase(itCT++);
		delete tempCertificationHandle;
		tempCertificationHandle = NULL;
	}

	itAK = SKFGlobeData::setAysmHandle.begin();
	for (;itAK != SKFGlobeData::setAysmHandle.end(); ) {
		tempAsmKeyHandle = *itAK;
		SKFGlobeData::setAysmHandle.erase(itAK++);
		delete tempAsmKeyHandle;
		tempAsmKeyHandle = NULL;
	}
	
	return;
}


HandleCheck::HandleCheck(){

}

HandleCheck::~HandleCheck(){

}

ULONG HandleCheck::Check(LPSTR devName){

	if (NULL == devName){
		return SAR_INVALIDPARAMERR;
	}

	CK_SLOT_ID id = 0;
#ifdef WIN32
	sscanf_s(devName,"%08x",&id);
#else
	sscanf(devName,"%08x",&id);
#endif

	set<SKFHandleD_PTR>::iterator it = SKFGlobeData::setDevHandle.begin();
	while (it != SKFGlobeData::setDevHandle.end()){
		if ((*it)->id == id){
			return SAR_OK;
		}
		it++;
	}

	return SAR_DEVICE_REMOVED;
	
}

ULONG HandleCheck::Check(SKFHandleD_PTR dev){
	if (NULL == dev){
		return SAR_INVALIDPARAMERR;
	}

	set<SKFHandleD_PTR>::iterator it = SKFGlobeData::setDevHandle.begin();
	while (it != SKFGlobeData::setDevHandle.end()){
		if ((*it) == dev){
			return SAR_OK;
		}

		it++;
	}

	return SAR_INVALIDHANDLEERR;
}

ULONG HandleCheck::Check(SKFHandleA_PTR app){
	if (NULL == app){
		return SAR_INVALIDPARAMERR;
	}

	set<SKFHandleA_PTR>::iterator it = SKFGlobeData::setAppHandle.begin();
	while (it != SKFGlobeData::setAppHandle.end()){
		if ((*it) == app){
			return SAR_OK;
		}

		it++;
	}

	return SAR_INVALIDHANDLEERR;
}

ULONG HandleCheck::Check(SKFHandleC_PTR container){
	if (NULL == container){
		return SAR_INVALIDPARAMERR;
	}

	set<SKFHandleC_PTR>::iterator it = SKFGlobeData::setContainerHandle.begin();
	while (it != SKFGlobeData::setContainerHandle.end()){
		if ((*it) == container){
			return SAR_OK;
		}

		it++;
	}

	return SAR_INVALIDHANDLEERR;
}

ULONG HandleCheck::CheckExist(LPSTR devName,SKFHandleD_PTR *ppDev){
	if (NULL == devName){
		return SAR_INVALIDPARAMERR;
	}

	CK_SLOT_ID id = 0;
#ifdef WIN32
	sscanf_s(devName,"%08x",&id);
#else
	sscanf(devName,"%08x",&id);
#endif

	set<SKFHandleD_PTR>::iterator it = SKFGlobeData::setDevHandle.begin();
	while (it != SKFGlobeData::setDevHandle.end()){
		if ((*it)->id == id){
			if (NULL != ppDev){
				*ppDev = (*it);
			}
			return SAR_OK;
		}
		it++;
	}

	return SAR_DEVICE_REMOVED;
}

ULONG HandleCheck::CheckExist(SKFHandleD_PTR dev){
	if (NULL == dev){
		return SAR_INVALIDPARAMERR;
	}

	set<SKFHandleD_PTR>::iterator it = SKFGlobeData::setDevHandle.begin();
	while (it != SKFGlobeData::setDevHandle.end()){
		if ((*it) == dev){
			return SAR_OK;
		}

		it++;
	}

	return SAR_INVALIDHANDLEERR;
}

ULONG HandleCheck::CheckExist(SKFHandleA_PTR app){
	if (NULL == app){
		return SAR_INVALIDPARAMERR;
	}

	set<SKFHandleA_PTR>::iterator it = SKFGlobeData::setAppHandle.begin();
	while (it != SKFGlobeData::setAppHandle.end()){
		if ((*it) == app){
			return SAR_OK;
		}

		it++;
	}

	return SAR_INVALIDHANDLEERR;
}

ULONG HandleCheck::CheckExist(SKFHandleC_PTR container){
	if (NULL == container){
		return SAR_INVALIDPARAMERR;
	}

	set<SKFHandleC_PTR>::iterator it = SKFGlobeData::setContainerHandle.begin();
	while (it != SKFGlobeData::setContainerHandle.end()){
		if ((*it) == container){
			return SAR_OK;
		}

		it++;
	}

	return SAR_INVALIDHANDLEERR;
}

ULONG HandleCheck::Check(SKFHandleSYM_PTR symmKey){
	if (NULL == symmKey){
		return SAR_INVALIDPARAMERR;
	}

	set<SKFHandleSYM_PTR>::iterator it = SKFGlobeData::setSessionKeyHandle.begin();
	while (it != SKFGlobeData::setSessionKeyHandle.end()){
		if ((*it) == symmKey){
			return SAR_OK;
		}

		it++;
	}

	return SAR_INVALIDHANDLEERR;
}



ULONG HandleCheck::CloseSession(CK_SESSION_HANDLE session){
	CK_RV ret = Adapter_C_CloseSession(session);
	if (ret != CKR_OK){
		return ret;
	}

	return SAR_OK;
}

ULONG HandleCheck::GetSession(LPSTR devName, CK_SESSION_HANDLE_PTR pSession){
	
	SKFHandleD_PTR tmp = NULL;
	ULONG ret = CheckExist(devName, &tmp);
	if (ret != SAR_OK){
		return ret;
	}

	if (NULL != pSession){
		ret = Adapter_C_OpenSession(tmp->id,CKF_SERIAL_SESSION | CKF_RW_SESSION,NULL,NULL,pSession);
		if (ret != SAR_OK){
			return ret;
		}
	}

	return SAR_OK;
}

ULONG HandleCheck::GetSession(SKFHandleD_PTR dev, CK_SESSION_HANDLE_PTR pSession){
	ULONG ret = CheckExist(dev);
	if (ret != SAR_OK){
		return ret;
	}

	if (NULL != pSession){
		ret = Adapter_C_OpenSession(dev->id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, pSession);
		if (ret != SAR_OK){
			return ret;
		}
	}

	return SAR_OK;
}

ULONG HandleCheck::GetSession(SKFHandleA_PTR app, CK_SESSION_HANDLE_PTR pSession){
	ULONG ret = CheckExist(app);
	if (ret != SAR_OK){
		return ret;
	}

	if (NULL != pSession){
		ret = Adapter_C_OpenSession(app->pDevHandle->id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, pSession);
		if (ret != SAR_OK){
			return ret;
		}
	}
	return SAR_OK;
}

ULONG HandleCheck::GetSession(SKFHandleC_PTR container, CK_SESSION_HANDLE_PTR pSession){
	ULONG ret = CheckExist(container);
	if (ret != SAR_OK){
		return ret;
	}

	if (NULL != pSession){
		ret = Adapter_C_OpenSession(container->pAppHandle->pDevHandle->id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, pSession);
		if (ret != SAR_OK){
			return ret;
		}
	}

	return SAR_OK;
}


ULONG HandleCheck::AppEnum(SKFHandleD_PTR tmp){

	if (NULL == tmp){
		return SAR_INVALIDPARAMERR;
	}

	CK_RV ret = Check(tmp);
	if (ret != SAR_OK){
		return SAR_INVALIDHANDLEERR;
	}

	CK_SESSION_HANDLE session = 0;
	ret = GetSession(tmp,&session);
	if (ret != SAR_OK){
		return SAR_INVALIDHANDLEERR;
	}


	CK_BBOOL ttrue = CK_TRUE;

	CK_ATTRIBUTE attributes[] = {
		{ CKA_APPLICATION, (unsigned char *)SKF_APP_APPLICATION_DESC, strlen(SKF_APP_APPLICATION_DESC) },
		{CKA_TOKEN,&ttrue,sizeof(ttrue)}
	};

	ret = Adapter_C_FindObjectsInit(session,attributes,sizeof(attributes) / sizeof(CK_ATTRIBUTE));
	if (ret != CKR_OK){
		Adapter_C_CloseSession(session);
		SKF_LOGE("%s Adapter_C_FindObjectsInit eixt 0x%x", __FUNCTION__, ret);
		return ret;
	}

	CK_OBJECT_HANDLE obj[4096] = { 0 };
	CK_ULONG count = 0;
	ret = Adapter_C_FindObjects(session,obj,sizeof(obj)/sizeof(CK_OBJECT_HANDLE),&count);
	if (ret != CKR_OK){
		Adapter_C_CloseSession(session);
		SKF_LOGE("%s Adapter_C_FindObjects eixt 0x%x", __FUNCTION__, ret);
		return ret;
	}

	ret = Adapter_C_FindObjectsFinal(session);
	if (ret != CKR_OK){
		Adapter_C_CloseSession(session);
		SKF_LOGE("%s Adapter_C_FindObjectsFinal eixt 0x%x", __FUNCTION__, ret);
		return ret;
	}

	if (count > 4096){
		Adapter_C_CloseSession(session);
		SKF_LOGE("%s too many objects error. count %d", __FUNCTION__, count);
		return SAR_BUFFER_TOO_SMALL;
	}

	CK_ATTRIBUTE valueAttr[] = {
		{CKA_LABEL,NULL,0},
		{CKA_VALUE,NULL,0}
	};

	
	for (unsigned int loop = 0; loop < count; loop++){
	
		ret = Adapter_C_GetAttributeValue(session, obj[loop], valueAttr, sizeof(valueAttr) / sizeof(CK_ATTRIBUTE));
		if (ret != CKR_OK){
			Adapter_C_CloseSession(session);
			SKF_LOGE("%s Adapter_C_GetAttributeValue eixt 0x%x", __FUNCTION__, ret);
			return ret;
		}

		valueAttr[0].pValue = new CK_BYTE[valueAttr[0].ulValueLen];
		valueAttr[1].pValue = new CK_BYTE[valueAttr[1].ulValueLen];
		ret = Adapter_C_GetAttributeValue(session, obj[loop], valueAttr, sizeof(valueAttr) / sizeof(CK_ATTRIBUTE));
		if (ret != CKR_OK){
			delete[] valueAttr[0].pValue;
			valueAttr[0].pValue = NULL;
			delete[] valueAttr[1].pValue;
			valueAttr[1].pValue = NULL;

			Adapter_C_CloseSession(session);
			SKF_LOGE("%s Adapter_C_GetAttributeValue eixt 0x%x", __FUNCTION__, ret);
			return ret;
		}


		SKFHandleA_PTR tmpA = new SKFHandleA();
//		memset(tmpA, 0, sizeof(SKFHandleA));
		tmpA->flg = 0;
		tmpA->appName = "";
		memset(&tmpA->appValue,0,sizeof(SKFValueApplication));

		tmpA->appHandle = obj[loop];
		tmpA->appName.append((char*)valueAttr[0].pValue, valueAttr[0].ulValueLen);
		tmpA->pDevHandle = tmp;
		
		ret = DerializationSKFValueApplication((CK_BYTE_PTR)valueAttr[1].pValue, valueAttr[1].ulValueLen, &tmpA->appValue);
		if (ret != CKR_OK){
			delete[] valueAttr[0].pValue;
			valueAttr[0].pValue = NULL;
			delete[] valueAttr[1].pValue;
			valueAttr[1].pValue = NULL;
			delete tmpA;
			tmpA = NULL;
			Adapter_C_CloseSession(session);
			SKF_LOGE("%s DerializationSKFValueApplication eixt 0x%x", __FUNCTION__, ret);
			return ret;
		}

		tmpA->appValue.soDefaultPin = (LPSTR)new BYTE[tmpA->appValue.soDefaultPinlen];
		tmpA->appValue.soPin = (LPSTR)new BYTE[tmpA->appValue.soPinlen];
		tmpA->appValue.usrDefaultPin = (LPSTR)new BYTE[tmpA->appValue.usrDefaultPinlen];
		tmpA->appValue.usrPin = (LPSTR)new BYTE[tmpA->appValue.usrPinlen];

		ret = DerializationSKFValueApplication((CK_BYTE_PTR)valueAttr[1].pValue, valueAttr[1].ulValueLen, &tmpA->appValue);
		if (ret != CKR_OK){
			delete[] valueAttr[0].pValue;
			valueAttr[0].pValue = NULL;
			delete[] valueAttr[1].pValue;
			valueAttr[1].pValue = NULL;


			delete[] tmpA->appValue.soDefaultPin;
			tmpA->appValue.soDefaultPin = NULL;
			
			delete[] tmpA->appValue.soPin;
			tmpA->appValue.soPin = NULL;

				
			delete[] tmpA->appValue.usrDefaultPin;
			tmpA->appValue.usrDefaultPin = NULL;

			delete[] tmpA->appValue.usrPin;
			tmpA->appValue.usrPin = NULL;

			delete tmpA;
			tmpA = NULL;

			Adapter_C_CloseSession(session);
			SKF_LOGE("%s DerializationSKFValueApplication eixt 0x%x", __FUNCTION__, ret);
			return ret;
		}


		delete[] valueAttr[0].pValue;
		valueAttr[0].pValue = NULL;
		delete[] valueAttr[1].pValue;
		valueAttr[1].pValue = NULL;

		tmpA->flg = SKF_FLAG_EXIST;
		SKFGlobeData::setAppHandle.insert(tmpA);
	}

	return SAR_OK;
	
}

ULONG HandleCheck::ContainerEnum(SKFHandleA_PTR tmp){
	if (NULL == tmp){
		return SAR_INVALIDPARAMERR;
	}

	CK_RV ret = CheckExist(tmp);
	if (ret != SAR_OK){
		return SAR_INVALIDHANDLEERR;
	}

	CK_SESSION_HANDLE session = 0;
	ret = GetSession(tmp, &session);
	if (ret != SAR_OK){
		return SAR_INVALIDHANDLEERR;
	}

	CK_BBOOL ttrue = CK_TRUE;
	string containerDesc;
	SKF_CONTAINER_APPLICATION_DESC(tmp->appName, containerDesc);

	CK_ATTRIBUTE attributes[] = {
		{ CKA_APPLICATION, (CK_VOID_PTR)containerDesc.data(), containerDesc.size() },
		{ CKA_TOKEN, &ttrue, sizeof(ttrue) }
	};

	ret = Adapter_C_FindObjectsInit(session, attributes, sizeof(attributes) / sizeof(CK_ATTRIBUTE));
	if (ret != CKR_OK){
		Adapter_C_CloseSession(session);
		SKF_LOGE("%s Adapter_C_FindObjectsInit eixt 0x%x", __FUNCTION__, ret);
		return ret;
	}

	CK_OBJECT_HANDLE obj[4096] = { 0 };
	CK_ULONG count = 0;
	ret = Adapter_C_FindObjects(session, obj, sizeof(obj) / sizeof(CK_OBJECT_HANDLE), &count);
	if (ret != CKR_OK){
		Adapter_C_CloseSession(session);
		SKF_LOGE("%s Adapter_C_FindObjects eixt 0x%x", __FUNCTION__, ret);
		return ret;
	}

	ret = Adapter_C_FindObjectsFinal(session);
	if (ret != CKR_OK){
		Adapter_C_CloseSession(session);
		SKF_LOGE("%s Adapter_C_FindObjectsFinal eixt 0x%x", __FUNCTION__, ret);
		return ret;
	}

	if (count > sizeof(obj) / sizeof(CK_OBJECT_HANDLE)){
		Adapter_C_CloseSession(session);
		SKF_LOGE("%s error, count %d expected %d eixt 0x%x", __FUNCTION__, count, sizeof(obj) / sizeof(CK_OBJECT_HANDLE), ret);
		return SAR_NO_ROOM;
	}

	CK_ATTRIBUTE valueAttr[] = {
		{ CKA_LABEL, NULL, 0 }
	};


	for (unsigned int loop = 0; loop < count; loop++){

		ret = Adapter_C_GetAttributeValue(session, obj[loop], valueAttr, sizeof(valueAttr) / sizeof(CK_ATTRIBUTE));
		if (ret != CKR_OK){
			Adapter_C_CloseSession(session);
			SKF_LOGE("%s Adapter_C_GetAttributeValue eixt 0x%x", __FUNCTION__, ret);
			return ret;
		}

		valueAttr[0].pValue = new CK_BYTE[valueAttr[0].ulValueLen];
		ret = Adapter_C_GetAttributeValue(session, obj[loop], valueAttr, sizeof(valueAttr) / sizeof(CK_ATTRIBUTE));
		if (ret != CKR_OK){
			delete[] valueAttr[0].pValue;
			valueAttr[0].pValue = NULL;
			
			Adapter_C_CloseSession(session);
			SKF_LOGE("%s Adapter_C_GetAttributeValue eixt 0x%x", __FUNCTION__, ret);
			return ret;
		}


		SKFHandleC_PTR tmpC = new SKFHandleC();
		
		tmpC->containerHandle = obj[loop];
		tmpC->containerName.append((char*)valueAttr[0].pValue, valueAttr[0].ulValueLen);
		tmpC->pAppHandle = tmp;
		delete[] valueAttr[0].pValue;
		valueAttr[0].pValue = NULL;
		tmpC->flg = SKF_FLAG_EXIST;
		SKFGlobeData::setContainerHandle.insert(tmpC);
	}

	return SAR_OK;
}

ULONG HandleCheck::FileEnum(SKFHandleA_PTR tmp){
	if (NULL == tmp){
		return SAR_INVALIDPARAMERR;
	}
	
	CK_RV ret = CheckExist(tmp);
	if (ret != SAR_OK){
		return SAR_INVALIDHANDLEERR;
	}

	CK_SESSION_HANDLE session = 0;
	ret = GetSession(tmp, &session);
	if (ret != SAR_OK){
		return SAR_INVALIDHANDLEERR;
	}

	string fileDesc;
	SKF_FILE_APPLICATION_DESC(tmp->appName,fileDesc);

	CK_ATTRIBUTE attributes[] = {
		{ CKA_APPLICATION, (CK_VOID_PTR)fileDesc.data(), fileDesc.size() }
	};

	ret = Adapter_C_FindObjectsInit(session,attributes,sizeof(attributes)/sizeof(CK_ATTRIBUTE));
	if (ret != SAR_OK){
		CloseSession(session);
		SKF_LOGE("%s Adapter_C_FindObjectsInit eixt 0x%x", __FUNCTION__, ret);
		return ret;
	}

	CK_OBJECT_HANDLE obj[4096] = { 0 };
	CK_ULONG count = 0;
	ret = Adapter_C_FindObjects(session,obj,sizeof(obj)/sizeof(CK_OBJECT_HANDLE),&count);
	if (ret != SAR_OK){
		CloseSession(session);
		SKF_LOGE("%s Adapter_C_FindObjects eixt 0x%x", __FUNCTION__, ret);
		return ret;
	}

	ret = Adapter_C_FindObjectsFinal(session);
	if (ret != SAR_OK){
		CloseSession(session);
		SKF_LOGE("%s Adapter_C_FindObjectsFinal eixt 0x%x", __FUNCTION__, ret);
		return ret;
	}

	if (count > sizeof(obj) / sizeof(CK_OBJECT_HANDLE)){
		CloseSession(session);
		SKF_LOGE("%s error, count %d expected %d eixt 0x%x", __FUNCTION__, count, sizeof(obj) / sizeof(CK_OBJECT_HANDLE), ret);
		return SAR_NO_ROOM;
	}

	CK_ATTRIBUTE valueAttr[] = {
		{ CKA_LABEL, NULL, 0 },
		{ CKA_VALUE, NULL, 0 }
	};


	for (unsigned int loop = 0; loop < count; loop++){

		ret = Adapter_C_GetAttributeValue(session, obj[loop], valueAttr, sizeof(valueAttr) / sizeof(CK_ATTRIBUTE));
		if (ret != CKR_OK ){
			Adapter_C_CloseSession(session);
			SKF_LOGE("%s Adapter_C_GetAttributeValue eixt 0x%x", __FUNCTION__, ret);
			return ret;
		}

		if (valueAttr[1].ulValueLen < sizeof(ULONG)* 2){
			return SAR_OBJERR;
		}

		valueAttr[0].pValue = new CK_BYTE[valueAttr[0].ulValueLen];
		valueAttr[1].pValue = new CK_BYTE[valueAttr[1].ulValueLen];
		ret = Adapter_C_GetAttributeValue(session, obj[loop], valueAttr, sizeof(valueAttr) / sizeof(CK_ATTRIBUTE));
		if (ret != CKR_OK){
			delete[] valueAttr[0].pValue;
			valueAttr[0].pValue = NULL;
			delete[] valueAttr[1].pValue;
			valueAttr[1].pValue = NULL;

			Adapter_C_CloseSession(session);
			SKF_LOGE("%s Adapter_C_GetAttributeValue eixt 0x%x", __FUNCTION__, ret);
			return ret;
		}


		SKFHandleF_PTR tmpF = new SKFHandleF();
		tmpF->fileName.append((char*)valueAttr[0].pValue, valueAttr[0].ulValueLen);
		tmpF->fileHandle = obj[loop];
		tmpF->pAppHandle = tmp;
		memcpy(&tmpF->readRights,valueAttr[1].pValue, sizeof(tmpF->readRights));
		memcpy(&tmpF->writeRights,(CK_BYTE_PTR)valueAttr[1].pValue + sizeof(tmpF->readRights), sizeof(tmpF->writeRights));
		tmpF->value.append((char*)valueAttr[1].pValue + sizeof(tmpF->readRights) + sizeof(tmpF->writeRights),
			valueAttr[1].ulValueLen - sizeof(tmpF->readRights) - sizeof(tmpF->writeRights));

		delete[] valueAttr[0].pValue;
		valueAttr[0].pValue = NULL;
		delete[] valueAttr[1].pValue;
		valueAttr[1].pValue = NULL;

		SKFGlobeData::setFileHandle.insert(tmpF);
	}

	return SAR_OK;


}

ULONG HandleCheck::CertEnum(SKFHandleC_PTR tmp){

	if (NULL == tmp){
		return SAR_INVALIDPARAMERR;
	}

	CK_RV ret = CheckExist(tmp);
	if (ret != SAR_OK){
		return SAR_INVALIDHANDLEERR;
	}

	CK_SESSION_HANDLE session = 0;
	ret = GetSession(tmp, &session);
	if (ret != SAR_OK){
		return SAR_INVALIDHANDLEERR;
	}

	string certDesc;
	SKF_CERT_APPLICATION_DESC(tmp->pAppHandle->appName,tmp->containerName ,certDesc);

	CK_ATTRIBUTE attributes[] = {
		{ CKA_APPLICATION, (CK_VOID_PTR)certDesc.data(), certDesc.size() }
	};

	ret = Adapter_C_FindObjectsInit(session, attributes, sizeof(attributes) / sizeof(CK_ATTRIBUTE));
	if (ret != SAR_OK){
		CloseSession(session);
		SKF_LOGE("%s Adapter_C_FindObjectsInit eixt 0x%x", __FUNCTION__, ret);
		return ret;
	}

	CK_OBJECT_HANDLE obj[4096] = { 0 };
	CK_ULONG count = 0;
	ret = Adapter_C_FindObjects(session, obj, sizeof(obj) / sizeof(CK_OBJECT_HANDLE), &count);
	if (ret != SAR_OK){
		CloseSession(session);
		SKF_LOGE("%s Adapter_C_FindObjects eixt 0x%x", __FUNCTION__, ret);
		return ret;
	}

	ret = Adapter_C_FindObjectsFinal(session);
	if (ret != SAR_OK){
		CloseSession(session);
		SKF_LOGE("%s Adapter_C_FindObjectsFinal eixt 0x%x", __FUNCTION__, ret);
		return ret;
	}

	if (count > sizeof(obj) / sizeof(CK_OBJECT_HANDLE)){
		CloseSession(session);
		SKF_LOGE("%s error, count %d expected %d eixt 0x%x", __FUNCTION__, count, sizeof(obj) / sizeof(CK_OBJECT_HANDLE), ret);
		return SAR_NO_ROOM;
	}

	CK_ATTRIBUTE valueAttr[] = {
		{ CKA_LABEL, NULL, 0 },
		{ CKA_VALUE, NULL, 0 }
	};


	for (unsigned int loop = 0; loop < count; loop++){

		ret = Adapter_C_GetAttributeValue(session, obj[loop], valueAttr, sizeof(valueAttr) / sizeof(CK_ATTRIBUTE));
		if (ret != CKR_OK){
			Adapter_C_CloseSession(session);
			SKF_LOGE("%s Adapter_C_GetAttributeValue eixt 0x%x", __FUNCTION__, ret);
			return ret;
		}

		if (valueAttr[0].ulValueLen < sizeof(bool)* 2){
			Adapter_C_CloseSession(session);
			SKF_LOGE("%s Adapter_C_GetAttributeValue get obj error (%d) eixt 0x%x", __FUNCTION__, valueAttr[0].ulValueLen, ret);
			return SAR_OBJERR;
		}

		valueAttr[0].pValue = new CK_BYTE[valueAttr[0].ulValueLen];
		valueAttr[1].pValue = new CK_BYTE[valueAttr[1].ulValueLen];
		ret = Adapter_C_GetAttributeValue(session, obj[loop], valueAttr, sizeof(valueAttr) / sizeof(CK_ATTRIBUTE));
		if (ret != CKR_OK){
			delete[] valueAttr[0].pValue;
			valueAttr[0].pValue = NULL;
			delete[] valueAttr[1].pValue;
			valueAttr[1].pValue = NULL;

			Adapter_C_CloseSession(session);
			SKF_LOGE("%s Adapter_C_GetAttributeValue eixt 0x%x", __FUNCTION__, ret);
			return ret;
		}


		SKFHandleCT_PTR tmpCT = new SKFHandleCT();
		tmpCT->certHandle = obj[loop];
		tmpCT->cert.append((char*)valueAttr[1].pValue, valueAttr[1].ulValueLen);
		memcpy(&tmpCT->EccType,valueAttr[0].pValue, sizeof(tmpCT->EccType));
		memcpy(&tmpCT->SignFlg,(CK_BYTE_PTR)valueAttr[0].pValue + sizeof(tmpCT->EccType), sizeof(tmpCT->SignFlg));
		tmpCT->pContainerHandle = tmp;

		SKFGlobeData::setCertHandle.insert(tmpCT);

		delete[] valueAttr[0].pValue;
		valueAttr[0].pValue = NULL;
		delete[] valueAttr[1].pValue;
		valueAttr[1].pValue = NULL;

	}

	return SAR_OK;

}

ULONG HandleCheck::KeyEnum(SKFHandleC_PTR tmp){

	return SAR_OK;
}


ULONG HandleCheck::AppRemove(SKFHandleD_PTR tmp){
	if (NULL == tmp){
		return SAR_INVALIDHANDLEERR;
	}

	CK_RV ret = Check(tmp);
	if (SAR_OK != ret){
		return ret;
	}

	set<SKFHandleA_PTR>::iterator it;
	SKFHandleA_PTR tmpA = NULL;

	for (it = SKFGlobeData::setAppHandle.begin(); it != SKFGlobeData::setAppHandle.end();){
		if ((*it)->pDevHandle == tmp){
			tmpA = *it;
			ContainerRemove(tmpA);
			FileRemove(tmpA);			
		}
		else
		{
			it++;
		}
	}
	return SAR_OK;
}

ULONG HandleCheck::ContainerRemove(SKFHandleA_PTR tmp){

	if (NULL == tmp){
		return SAR_INVALIDHANDLEERR;
	}

	CK_RV ret = Check(tmp);
	if (SAR_OK != ret){
		return ret;
	}

	set<SKFHandleC_PTR>::iterator itExist, it;
	SKFHandleC_PTR tmpC = NULL;

	for (itExist = SKFGlobeData::setContainerHandle.begin(); itExist != SKFGlobeData::setContainerHandle.end();){
		if ((*itExist)->pAppHandle == tmp){
			tmpC = *itExist;

			CertRemove(tmpC);
			KeyRemove(tmpC);

			delete tmpC;
			tmpC = NULL;
			SKFGlobeData::setContainerHandle.erase(itExist);
		}
		else
		{
			itExist++;
		}
	}
	return SAR_OK;
}

ULONG HandleCheck::FileRemove(SKFHandleA_PTR tmp){
	if (NULL == tmp){
		return SAR_INVALIDHANDLEERR;
	}

	CK_RV ret = Check(tmp);
	if (SAR_OK != ret){
		return ret;
	}

	set<SKFHandleF_PTR>::iterator it;
	SKFHandleF_PTR tmpF = NULL;

	for (it = SKFGlobeData::setFileHandle.begin(); it != SKFGlobeData::setFileHandle.end();){
		if ((*it)->pAppHandle == tmp){
			tmpF = *it;	
			delete tmpF;
			tmpF = NULL;
			SKFGlobeData::setFileHandle.erase(it);
		}
		else
		{
			it++;
		}
	}

	return SAR_OK;
}

ULONG HandleCheck::CertRemove(SKFHandleC_PTR tmp){
	if (NULL == tmp){
		return SAR_INVALIDHANDLEERR;
	}

	CK_RV ret = Check(tmp);
	if (SAR_OK != ret){
		return ret;
	}

	set<SKFHandleCT_PTR>::iterator it;
	SKFHandleCT_PTR tmpCT = NULL;

	for (it = SKFGlobeData::setCertHandle.begin(); it != SKFGlobeData::setCertHandle.end();){
		if ((*it)->pContainerHandle == tmp){
			tmpCT = *it;
			delete tmpCT;
			tmpCT = NULL;
			SKFGlobeData::setCertHandle.erase(it);
		}
		else
		{
			it++;
		}
	}

	return SAR_OK;
}

ULONG HandleCheck::KeyRemove(SKFHandleC_PTR tmp){
	return SAR_OK;
}

ULONG HandleCheck::AppDestroy(SKFHandleA_PTR tmp){
	
	HandleCheck handle;

	CK_RV ret = handle.Check(tmp);
	if (ret != CKR_OK) {
		return SAR_FAIL;
	}

	CK_SESSION_HANDLE session = 0;
	ret = handle.GetSession((SKFHandleA_PTR)tmp, &session);
	if (ret != CKR_OK) {
		return SAR_FAIL;
	}
	
	ret = Adapter_C_DestroyObject(session, tmp->appHandle);
	if (ret != CKR_OK) {
		handle.CloseSession(session);
		return SAR_FAIL;
	}

	delete[]tmp->appValue.soPin;
	delete[]tmp->appValue.soDefaultPin;
	delete[]tmp->appValue.usrPin;
	delete[]tmp->appValue.usrDefaultPin;

	delete tmp;
	return SAR_OK;
}

ULONG HandleCheck::ContainerDestroy(SKFHandleC_PTR tmp){
	return SAR_OK;
}

ULONG HandleCheck::FileDestroy(SKFHandleF_PTR tmp){
	return SAR_OK;
}

ULONG HandleCheck::CertDestroy(SKFHandleCT_PTR tmp){
	return SAR_OK;
}

ULONG HandleCheck::KeyDestroy(SKFHandleASYM_PTR tmp){
	return SAR_OK;
}

ULONG SerializationSKFValueApplication(SKFValueApplication_PTR ptr, string &dst){
	if (NULL == ptr){
		return SAR_INVALIDPARAMERR;
	}

	dst.append((char*)&ptr->soDefaultPinlen, sizeof(ptr->soDefaultPinlen));
	dst.append(ptr->soDefaultPin, ptr->soDefaultPinlen);

	dst.append((char*)&ptr->soPinlen, sizeof(ptr->soPinlen));
	dst.append(ptr->soPin, ptr->soPinlen);

	dst.append((char*)&ptr->soPinMaxCount, sizeof(ptr->soPinMaxCount));
	dst.append((char*)&ptr->soPinAlreadyCount, sizeof(ptr->soPinAlreadyCount));

	dst.append((char*)&ptr->usrDefaultPinlen, sizeof(ptr->usrDefaultPinlen));
	dst.append(ptr->usrDefaultPin, ptr->usrDefaultPinlen);

	dst.append((char*)&ptr->usrPinlen, sizeof(ptr->usrPinlen));
	dst.append(ptr->usrPin, ptr->usrPinlen);

	dst.append((char*)&ptr->usrPinMaxCount, sizeof(ptr->usrPinMaxCount));
	dst.append((char*)&ptr->usrPinAlreadyCount, sizeof(ptr->usrPinAlreadyCount));

	dst.append((char*)&ptr->rights, sizeof(ptr->rights));

	return SAR_OK;
}

ULONG DerializationSKFValueApplication(unsigned char *buf,unsigned int len, SKFValueApplication_PTR ptr){

	if (buf == NULL || len == 0 || ptr == NULL){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INVALIDPARAMERR);
		return SAR_INVALIDPARAMERR;
	}

	unsigned int offset = 0;

	if (len < offset + sizeof(ptr->soDefaultPinlen)){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}
	
	memcpy(&ptr->soDefaultPinlen,buf, sizeof(ptr->soDefaultPinlen));
	offset += sizeof(ptr->soDefaultPinlen);

	if (len < offset + ptr->soDefaultPinlen){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}

	if (NULL != ptr->soDefaultPin){
		memcpy(ptr->soDefaultPin,buf + offset, ptr->soDefaultPinlen);
	}
	offset += ptr->soDefaultPinlen;

	if (len < offset + sizeof(ptr->soPinlen)){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}

	memcpy(&ptr->soPinlen,buf + offset, sizeof(ptr->soPinlen));
	offset += sizeof(ptr->soPinlen);

	if (len < offset + ptr->soPinlen){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}

	if (NULL != ptr->soPin){
		memcpy(ptr->soPin,buf + offset, ptr->soPinlen);
	}
	offset += ptr->soPinlen;


	if (len < offset + sizeof(ptr->soPinMaxCount)){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}

	memcpy(&ptr->soPinMaxCount,buf + offset, sizeof(ptr->soPinMaxCount));
	offset += sizeof(ptr->soPinMaxCount);

	if (len < offset + sizeof(ptr->soPinAlreadyCount)){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}

	memcpy(&ptr->soPinAlreadyCount,buf + offset, sizeof(ptr->soPinAlreadyCount));
	offset += sizeof(ptr->soPinAlreadyCount);


	if (len < offset + sizeof(ptr->usrDefaultPinlen)){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}

	memcpy(&ptr->usrDefaultPinlen,buf + offset, sizeof(ptr->usrDefaultPinlen));
	offset += sizeof(ptr->usrDefaultPinlen);

	if (len < offset + ptr->usrDefaultPinlen){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}

	if (NULL != ptr->usrDefaultPin){
		memcpy(ptr->usrDefaultPin,buf + offset, ptr->usrDefaultPinlen);
	}
	offset += ptr->usrDefaultPinlen;

	if (len < offset + sizeof(ptr->usrPinlen)){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}

	memcpy(&ptr->usrPinlen,buf + offset, sizeof(ptr->usrPinlen));
	offset += sizeof(ptr->usrPinlen);

	if (len < offset + ptr->usrPinlen){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}

	if (NULL != ptr->usrPin){
		memcpy(ptr->usrPin,buf + offset, ptr->usrPinlen);
	}
	offset += ptr->usrPinlen;


	if (len < offset + sizeof(ptr->usrPinMaxCount)){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}

	memcpy(&ptr->usrPinMaxCount,buf + offset, sizeof(ptr->usrPinMaxCount));
	offset += sizeof(ptr->usrPinMaxCount);

	if (len < offset + sizeof(ptr->usrPinAlreadyCount)){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}

	memcpy(&ptr->usrPinAlreadyCount,buf + offset, sizeof(ptr->usrPinAlreadyCount));
	offset += sizeof(ptr->usrPinAlreadyCount);

	if (len < offset + sizeof(ptr->rights)){
		SKF_LOGE("%s eixt 0x%x", __FUNCTION__, SAR_INDATALENERR);
		return SAR_INDATALENERR;
	}

	memcpy(&ptr->rights,buf + offset, sizeof(ptr->rights));
	offset += sizeof(ptr->rights);

	return SAR_OK;
}

