#ifndef __SKF_DEF_H
#define __SKF_DEF_H
#include <iostream>
#include "cryptoki.h"
#include "skf_t.h"
#include <map>
#include <set>
using namespace std;

#define SKF_FLAG_EXIST		0 // applicable to device, app and container
#define SKF_FLAG_OPEN		1 // applicable to device, app and container
#define SKF_FLAG_AUTH_DEV	2 // applicable to device
#define SKF_FLAG_AUTH_ADM	3 // applicable to app and container
#define SKF_FLAG_AUTH_USR	4 // applicable to app and container


#define DEV_AUTH_RANDOM_LEN 8

#include "RecordLog.h"

#ifdef WIN32
#else
#include <android/log.h>
#endif

#ifdef _DEBUG
#define DEFAULT_LOG_LEVEL plog_verbose
#else
//#define DEFAULT_LOG_LEVEL plog_warning
#define DEFAULT_LOG_LEVEL plog_verbose
#endif


#ifdef WIN32
// windows dll directly call JW p11 interface, not adapter
#define Adapter_C_Initialize			C_Initialize
#define Adapter_C_Finalize				C_Finalize
#define Adapter_C_GetInfo				C_GetInfo
#define Adapter_C_GetFunctionList		C_GetFunctionList
#define Adapter_C_GetSlotList			C_GetSlotList
#define Adapter_C_GetSlotInfo			C_GetSlotInfo
#define Adapter_C_GetTokenInfo			C_GetTokenInfo
#define Adapter_C_GetMechanismList		C_GetMechanismList
#define Adapter_C_GetMechanismInfo		C_GetMechanismInfo
#define Adapter_C_InitToken				C_InitToken
#define Adapter_C_InitPIN				C_InitPIN
#define Adapter_C_SetPIN				C_SetPIN
#define Adapter_C_OpenSession			C_OpenSession
#define Adapter_C_CloseSession			C_CloseSession
#define Adapter_C_CloseAllSessions		C_CloseAllSessions
#define Adapter_C_GetSessionInfo		C_GetSessionInfo
#define Adapter_C_GetOperationState		C_GetOperationState
#define Adapter_C_SetOperationState		C_SetOperationState
#define Adapter_C_Login					C_Login
#define Adapter_C_Logout				C_Logout
#define Adapter_C_CreateObject			C_CreateObject
#define Adapter_C_CopyObject			C_CopyObject
#define Adapter_C_DestroyObject			C_DestroyObject
#define Adapter_C_GetObjectSize			C_GetObjectSize
#define Adapter_C_GetAttributeValue		C_GetAttributeValue
#define Adapter_C_SetAttributeValue		C_SetAttributeValue
#define Adapter_C_FindObjectsInit		C_FindObjectsInit
#define Adapter_C_FindObjects			C_FindObjects
#define Adapter_C_FindObjectsFinal		C_FindObjectsFinal
#define Adapter_C_EncryptInit			C_EncryptInit
#define Adapter_C_Encrypt				C_Encrypt
#define Adapter_C_EncryptUpdate			C_EncryptUpdate
#define Adapter_C_EncryptFinal			C_EncryptFinal
#define Adapter_C_DecryptInit			C_DecryptInit
#define Adapter_C_Decrypt				C_Decrypt
#define Adapter_C_DecryptUpdate			C_DecryptUpdate
#define Adapter_C_DecryptFinal			C_DecryptFinal
#define Adapter_C_DigestInit			C_DigestInit
#define Adapter_C_Digest				C_Digest
#define Adapter_C_DigestUpdate			C_DigestUpdate
#define Adapter_C_DigestKey				C_DigestKey
#define Adapter_C_DigestFinal			C_DigestFinal
#define Adapter_C_SignInit				C_SignInit
#define Adapter_C_Sign					C_Sign
#define Adapter_C_SignUpdate			C_SignUpdate
#define Adapter_C_SignFinal				C_SignFinal
#define Adapter_C_SignRecoverInit		C_SignRecoverInit
#define Adapter_C_SignRecover			C_SignRecover
#define Adapter_C_VerifyInit			C_VerifyInit
#define Adapter_C_Verify				C_Verify
#define Adapter_C_VerifyUpdate			C_VerifyUpdate
#define Adapter_C_VerifyFinal			C_VerifyFinal
#define Adapter_C_VerifyRecoverInit		C_VerifyRecoverInit
#define Adapter_C_VerifyRecover			C_VerifyRecover
#define Adapter_C_DigestEncryptUpdate	C_DigestEncryptUpdate
#define Adapter_C_DecryptDigestUpdate	C_DecryptDigestUpdate
#define Adapter_C_SignEncryptUpdate		C_SignEncryptUpdate
#define Adapter_C_DecryptVerifyUpdate	C_DecryptVerifyUpdate
#define Adapter_C_GenerateKey			C_GenerateKey
#define Adapter_C_GenerateKeyPair		C_GenerateKeyPair
#define Adapter_C_WrapKey				C_WrapKey
#define Adapter_C_UnwrapKey				C_UnwrapKey
#define Adapter_C_DeriveKey				C_DeriveKey
#define Adapter_C_SeedRandom			C_SeedRandom
#define Adapter_C_GenerateRandom		C_GenerateRandom
#define Adapter_C_GetFunctionStatus		C_GetFunctionStatus
#define Adapter_C_CancelFunction		C_CancelFunction
#define Adapter_C_WaitForSlotEvent		C_WaitForSlotEvent
#define Adapter_C_Extend_GetPinRemainCount		C_Extend_GetPinRemainCount
#define Adapter_C_Extend_GetStatus				C_Extend_GetStatus
#define Adapter_C_Extend_Register_Callback		C_Extend_Register_Callback
#define Adapter_C_Extend_Unregister_Callback	C_Extend_Unregister_Callback
#define Adapter_C_Extend_GetExchangeSessionKey	C_Extend_GetExchangeSessionKey
#define Adapter_C_Extend_Destroy				C_Extend_Destroy
#define Adapter_C_Extend_Reset_Pin_With_OTP		C_Extend_Reset_Pin_With_OTP
#define Adapter_C_Extend_Reset_OTP				C_Extend_Reset_OTP
#define Adapter_C_Extend_Get_OTP_Unlock_Count	C_Extend_Get_OTP_Unlock_Count
#define Adapter_C_Extend_Get_OTP_Remain_Count	C_Extend_Get_OTP_Remain_Count
#define Adapter_C_Extend_DeriveSessionKey		C_Extend_DeriveSessionKey
#define Adapter_C_Extend_EncryptInit			C_Extend_EncryptInit
#define Adapter_C_Extend_DecryptInit			C_Extend_DecryptInit
#define Adapter_C_Extend_EncryptUpdate			C_Extend_EncryptUpdate
#define Adapter_C_Extend_DecryptUpdate			C_Extend_DecryptUpdate
#define Adapter_C_Extend_EncryptFinalize		C_Extend_EncryptFinalize
#define Adapter_C_Extend_DecryptFinalize		C_Extend_DecryptFinalize
#define Adapter_C_Extend_PointMultiply			C_Extend_PointMultiply
#define Adapter_C_Extend_Reset_TT				C_Extend_Reset_TT
#define Adapter_C_Extend_Reset_BK				C_Extend_Reset_BK
#endif


#ifdef WIN32
#define SKF_LOGV(...)		if (SKFGlobeData::loggerInitialized){do{log_skf(plog_verbose, __FUNCTION__, __LINE__, __FILE__, __VA_ARGS__);}while(0);};
#define SKF_LOGD(...)		if (SKFGlobeData::loggerInitialized){do{log_skf(plog_debug, __FUNCTION__, __LINE__, __FILE__, __VA_ARGS__);}while(0);};
#define SKF_LOGI(...)		if (SKFGlobeData::loggerInitialized){do{log_skf(plog_info, __FUNCTION__, __LINE__, __FILE__, __VA_ARGS__);}while(0);};
#define SKF_LOGW(...)		if (SKFGlobeData::loggerInitialized){do{log_skf(plog_warning, __FUNCTION__, __LINE__, __FILE__, __VA_ARGS__);}while(0);};
#define SKF_LOGE(...)		if (SKFGlobeData::loggerInitialized){do{log_skf(plog_error, __FUNCTION__, __LINE__, __FILE__, __VA_ARGS__);}while(0);};
#define SKF_LOGF(...)		if (SKFGlobeData::loggerInitialized){do{log_skf(plog_fatal, __FUNCTION__, __LINE__, __FILE__, __VA_ARGS__);}while(0);};
#else
#define SKF_LOGV(...)  __android_log_print(ANDROID_LOG_VERBOSE,"skf_p11",__VA_ARGS__)
#define SKF_LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,"skf_p11",__VA_ARGS__)
#define SKF_LOGI(...)  __android_log_print(ANDROID_LOG_INFO,"skf_p11",__VA_ARGS__)
#define SKF_LOGW(...)  __android_log_print(ANDROID_LOG_WARN,"skf_p11",__VA_ARGS__)
#define SKF_LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,"skf_p11",__VA_ARGS__)
#define SKF_LOGF(...)  __android_log_print(ANDROID_LOG_FATAL,"skf_p11",__VA_ARGS__)
#endif
/*
*Application:
	CKA_APPLICATION : SKFApplicationV1.0
	CKA_LABEL: appName
	CKA_VALUE: 创建的权限值 + PIN
*/

/*
*Container:
	CKA_APPLICATION : appName + 0 + container
	CKA_LABEL: containerName
	CKA_VALUE: NULL
*/


/*
*File:
	CKA_APPLICATION : appName + 0 + file
	CKA_LABEL: fileName
	CKA_VALUE: r + w + fileData

*/

/*
  Key
  CKA_ID:appName + 0 + containerName + 0 + "key"
  CKA_LABEL:EccFlg+signFlg
  
*/

/*
Cert
CKA_ID:appName + 0 + containerName + 0 + "cert"
CKA_LABEL:EccFlg+signFlg
*/

/*
设备名称：SlotID的十六进制字符串
*/

/*
设备句柄：
	包含slotID
*/

/*
 应用句柄：
	设备句柄 + Application句柄 + appName
*/

/*
    容器句柄：
	    应用句柄 + Container句柄 + containerName
*/



#define SKF_P11_USER_PIN "123456"
#define  SKF_APP_APPLICATION_DESC "SKFApplicationV1.0"

#define  SKF_PIN_APPLICATION_DESC(appName,stringPin) {\
	char pad[1] = { 0 }; \
	stringFile.append(appName); \
	stringFile.append(pad, 1); \
	stringFile.append("pin"); \
}

#define  SKF_FILE_APPLICATION_DESC(appName,stringFile) {\
	char pad[1] = { 0 }; \
	stringFile.append(appName); \
	stringFile.append(pad, 1); \
	stringFile.append("file"); \
}

#define  SKF_CONTAINER_APPLICATION_DESC(appName,stringContainer) {\
	char pad[1] = { 0 }; \
	stringContainer.append(appName); \
	stringContainer.append(pad, 1); \
	stringContainer.append("container"); \
}

#define  SKF_CERT_APPLICATION_DESC(appName,containerName,stringCert) {\
	char pad[1] = { 0 }; \
	stringCert.append(appName); \
	stringCert.append(pad, 1); \
	stringCert.append(containerName); \
	stringCert.append(pad, 1); \
	stringCert.append("cert"); \
}

#define  SKF_KEY_APPLICATION_DESC(appName,containerName,stringKey) {\
	char pad[1] = { 0 }; \
	stringKey.append(appName); \
	stringKey.append(pad, 1); \
	stringKey.append(containerName); \
	stringKey.append(pad, 1); \
	stringKey.append("key"); \
}

typedef struct SKFValueApplication_t{
	
	unsigned int soDefaultPinlen;
	LPSTR soDefaultPin;

	unsigned int soPinlen;
	LPSTR soPin;
	DWORD soPinMaxCount;
	DWORD soPinAlreadyCount;
	
	unsigned int usrDefaultPinlen;
	LPSTR usrDefaultPin;

	unsigned int usrPinlen;
	LPSTR usrPin;
	DWORD usrPinMaxCount;
	DWORD usrPinAlreadyCount;
	
	DWORD rights;

}SKFValueApplication, *SKFValueApplication_PTR;

ULONG SerializationSKFValueApplication(SKFValueApplication_PTR ptr,string &dst);
ULONG DerializationSKFValueApplication(unsigned char *buf, unsigned int len, SKFValueApplication_PTR ptr);

/*设备句柄*/
typedef struct SKFHandle_d{
	CK_SLOT_ID id;
	ULONG flg;
	CHAR devAuthPlain[16];
}SKFHandleD,*SKFHandleD_PTR;

/*应用句柄*/
typedef struct SKFHandle_a{
	SKFHandleD_PTR pDevHandle;
	ULONG flg;
	string appName;
	CK_OBJECT_HANDLE appHandle;
	SKFValueApplication appValue;
}SKFHandleA,*SKFHandleA_PTR;

/*容器句柄*/
typedef struct SKFHandle_c{
	SKFHandleA_PTR pAppHandle;
	ULONG flg;
	string containerName;
	CK_OBJECT_HANDLE containerHandle;
}SKFHandleC,*SKFHandleC_PTR;

/*文件句柄*/
typedef struct SKFHandle_f{
	SKFHandleA_PTR pAppHandle;
	string fileName;
	CK_OBJECT_HANDLE fileHandle;
	DWORD readRights;
	DWORD writeRights;
	string value;
}SKFHandleF, *SKFHandleF_PTR;

/*证书*/
typedef struct SKFHandle_ct{
	SKFHandleC_PTR pContainerHandle;
	ULONG EccType;
	ULONG SignFlg;
	CK_OBJECT_HANDLE certHandle;
	string cert;
}SKFHandleCT, *SKFHandleCT_PTR;

/*非对称密钥*/
typedef struct SKFHandle_asym{
	SKFHandleC_PTR containerHandle;
	bool EccType;
	bool SignFlg;
	CK_OBJECT_HANDLE pubHandle;
	CK_OBJECT_HANDLE priHandle;
}SKFHandleASYM, *SKFHandleASYM_PTR;

/*对称密钥*/
typedef struct SKFHandle_sym{
	SKFHandleD_PTR pDevHandle;
	SKFHandleC_PTR pContainerHandle;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE sessKeyHandle;
	ULONG ulAlgId;
	ULONG mechanism;
	ULONG paddingType;
}SKFHandleSYM, *SKFHandleSYM_PTR;

/*HASH MAC对象*/
typedef struct SKFHandle_h{
	SKFHandleD_PTR pDevHandle;
	ULONG ulAlgID;
	CK_SESSION_HANDLE session;
}SKFHandleH, *SKFHandleH_PTR;


/*全局缓存对象*/
class SKFGlobeData
{
public:
	static set<SKFHandleD_PTR> setDevHandle;//设备句柄						   
	static set<SKFHandleA_PTR> setAppHandle;//应用句柄						   
	static set<SKFHandleC_PTR> setContainerHandle;//容器句柄
	
	static set<SKFHandleSYM_PTR> setSessionKeyHandle;  // session key handle
	static set<SKFHandleF_PTR> setFileHandle;//文件句柄
	static set<SKFHandleCT_PTR> setCertHandle;//文件句柄
	static set<SKFHandleASYM_PTR> setAysmHandle;//密钥句柄
	static void clearAll();
	static bool loggerInitialized;
private:

};


class HandleCheck
{
public:
	HandleCheck();
	virtual ~HandleCheck();

	ULONG AppEnum(SKFHandleD_PTR tmp);
	ULONG ContainerEnum(SKFHandleA_PTR tmp);
	ULONG FileEnum(SKFHandleA_PTR tmp);
	ULONG CertEnum(SKFHandleC_PTR tmp);
	ULONG KeyEnum(SKFHandleC_PTR tmp);

	ULONG AppRemove(SKFHandleD_PTR tmp);
	ULONG ContainerRemove(SKFHandleA_PTR tmp);
	ULONG FileRemove(SKFHandleA_PTR tmp);
	ULONG CertRemove(SKFHandleC_PTR tmp);
	ULONG KeyRemove(SKFHandleC_PTR tmp);

	ULONG AppDestroy(SKFHandleA_PTR tmp);
	ULONG ContainerDestroy(SKFHandleC_PTR tmp);
	ULONG FileDestroy(SKFHandleF_PTR tmp);
	ULONG CertDestroy(SKFHandleCT_PTR tmp);
	ULONG KeyDestroy(SKFHandleASYM_PTR tmp);
	
	ULONG CheckExist(LPSTR devName, SKFHandleD_PTR *ppDev);
	ULONG CheckExist(SKFHandleD_PTR dev);
	ULONG CheckExist(SKFHandleA_PTR app);
	ULONG CheckExist(SKFHandleC_PTR container);

	ULONG Check(SKFHandleSYM_PTR symmKey);
	ULONG Check(LPSTR devName);
	ULONG Check(SKFHandleD_PTR dev);
	ULONG Check(SKFHandleA_PTR app);
	ULONG Check(SKFHandleC_PTR container);

	ULONG GetSession(LPSTR devName, CK_SESSION_HANDLE_PTR pSession);
	ULONG GetSession(SKFHandleD_PTR dev,CK_SESSION_HANDLE_PTR pSession);
	ULONG GetSession(SKFHandleA_PTR app, CK_SESSION_HANDLE_PTR pSession);
	ULONG GetSession(SKFHandleC_PTR container, CK_SESSION_HANDLE_PTR pSession);

	ULONG CloseSession(CK_SESSION_HANDLE session);

private:

};

#endif //__SKF_DEF_H

