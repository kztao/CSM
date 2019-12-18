#include <cstring>
#include "P11Adapter.h"
#include "AttributesConvert.h"
#include "p11func_hd.h"
#include "p11func_jw.h"
#include "p11func_sc.h"

#include "P11Mapping.h"
#include "logserver.h"
#include "ReturnCode.h"
#include "FunctionParse.h"

#include <vector>

#include <set>
using std::string;
using std::map;
using std::vector;
using std::make_pair;
using std::set;
using std::pair;
using std::multimap;

static const char* tag = "csm_p11adapter";

static P11AdapterFunction *pJW = NULL;
static P11AdapterFunction *pHD = NULL;
static P11AdapterFunction *pSC = NULL;

static P11Mapping p11Table;

static set<register_status_callback_func> SetCallBackFunc;
static map<CK_SLOT_ID ,string> mapMonopolize;
static vector<long> enc_time;
static string clientname;
static bool mountCardFlg = false;


/*
 *	掉电恢复,若不启用
 * */
#define BATTERY_RECOVERY
static string pwRecovery;

#ifdef BATTERY_RECOVERY
#undef BATTERY_RECOVERY  //若不启用掉电恢复,恢复该行代码
#endif


#define HEMIHUAPACKAGE "com.cmcc.hemihua"
#define TESTPACKAGE "com.westone.csmmanager"
#define CHENGXUNPACKAGE "com.raycom.securesms"
#define SMSPACKAGE "com.westone.securitySMS"

#define MAX_APPSESSION  8

multimap<string, CK_SESSION_HANDLE> map_session;
extern map<CommunicationServer::Communication*,string> mapClientName;

vector<string> split(string strtem,char a)    
{        
	vector<string> strvec;         
	string::size_type pos1, pos2;       
	pos2 = strtem.find(a);       
	pos1 = 0;     
	while (string::npos != pos2)     
		{              
		strvec.push_back(strtem.substr(pos1, pos2 - pos1));               
		pos1 = pos2 + 1;               
		pos2 = strtem.find(a, pos1);      
		}      
	strvec.push_back(strtem.substr(pos1));     
	return strvec;   
}


void setMountCardFlg(bool flg){
    if(mountCardFlg == true && flg == false){
        p11Table.DelSlot("hd");
        p11Table.DelSlot("jw");
    }

	mountCardFlg = flg;
}

int add_clientsession(string appname, CK_SESSION_HANDLE hsession)
{
	map_session.insert(pair<string, CK_SESSION_HANDLE>(appname, hsession));
	LOGSERVERI(tag,"%s, appname %s, hsession is %lx",__FUNCTION__,appname.c_str(),hsession);
	return 0;	
}

int del_clientsession(string appname, CK_SESSION_HANDLE hsession)
{
	LOGSERVERI(tag,"%s IN, hsession is 0x%lx",__FUNCTION__,hsession);
	multimap<string, CK_SESSION_HANDLE>::size_type  cnt = map_session.count(appname);
    multimap<string, CK_SESSION_HANDLE>::iterator  iter = map_session.find(appname);
    for(int i=0; i<cnt;i++)
    {
    	if(iter!=map_session.end() && iter->second == hsession)
    	{
    		map_session.erase(iter);
    		break;
    	}
		++iter;
    }
	
	LOGSERVERI(tag,"%s, appname %s, hsession is 0x%lx",__FUNCTION__,appname.c_str(),hsession);
	return 0;
}

void close_clientsession(CommunicationServer::Communication *client)
{
	map<CommunicationServer::Communication *,string>::iterator itmap_clientname = mapClientName.find(client);

	multimap<string, CK_SESSION_HANDLE>::size_type  cnt = 0;
	multimap<string, CK_SESSION_HANDLE>::iterator  iter;
	if(itmap_clientname!=mapClientName.end())
	{
		cnt = map_session.count(itmap_clientname->second);

	}
	
	LOGSERVERI(tag,"%s IN,find session count: %d",__FUNCTION__,cnt);
	
	for(int i=0; i<cnt;i++)
    {
    	iter = map_session.find(itmap_clientname->second);
		if(iter!=map_session.end())
		{
			Adapter_C_CloseSession(iter->second);
		}
    }

	if(itmap_clientname!=mapClientName.end())
	{
		mapClientName.erase(itmap_clientname);	
	}	

	LOGSERVERI(tag,"%s OUT, mapsize is %d",__FUNCTION__, map_session.size());
}

void close_appsession(string appname)
{
	multimap<string, CK_SESSION_HANDLE>::size_type  cnt = 0;
	multimap<string, CK_SESSION_HANDLE>::iterator  iter;
	
	cnt = map_session.count(appname);
	
	LOGSERVERI(tag,"%s IN,find session count: %d",__FUNCTION__,cnt);
	
	for(int i=0; i<cnt;i++)
    {
    	iter = map_session.find(appname);
		if(iter!=map_session.end())
		{
			Adapter_C_CloseSession(iter->second);
		}
    }

	LOGSERVERI(tag,"%s OUT, mapsize is %d",__FUNCTION__, map_session.size());
}
	
void del_session(set<CK_SESSION_HANDLE> handleindexes){
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
    multimap<string, CK_SESSION_HANDLE>::iterator  it;
	set<CK_SESSION_HANDLE>::iterator iter;
	
    for(it = map_session.begin();it != map_session.end();)
    {
    	LOGSERVERI(tag,"search session: 0x%lx",it->second);
    	if((iter = handleindexes.find(it->second))!=handleindexes.end())
    	{
    		it = map_session.erase(it);
    	}else{   	
			++it;
    	}
    }
	
	LOGSERVERI(tag,"%s OUT",__FUNCTION__);
}

bool checkClientSessionNum(string appname){
	multimap<string, CK_SESSION_HANDLE>::size_type  cnt = map_session.count(appname);
	if(cnt<MAX_APPSESSION){	
		return true;
	}
	else{		
		return false;
	}
}

void getclientname(string name)
{
	clientname = name;
	LOGSERVERD(tag, "client name is %s",clientname.c_str());
}


void statusCallBackBySession(CK_SESSION_HANDLE hSession, CK_STATUS_ENUM statusEnum)
{
	set<register_status_callback_func> ::iterator it;
	CK_SLOT_ID slotId = 0;
	if(CKR_OK != p11Table.GetSlotFromSession(hSession,&slotId))
	{
        LOGSERVERE(tag,"statusCallBackBySession  GetSlot Not Ok");
		return;
	}

    LOGSERVERD(tag,"SetCallBackFunc count = %d",SetCallBackFunc.size());

	for(it = SetCallBackFunc.begin();it != SetCallBackFunc.end();++it)
	{
        LOGSERVERI(tag,"begin callback, statusnum is %d",statusEnum);
		(*it)(slotId, statusEnum);
	}

	p11Table.SetSlotStatus(slotId, statusEnum);
}


void statusCallBackBySlotId(CK_SLOT_ID slotId, CK_STATUS_ENUM statusEnum)
{
	set<register_status_callback_func> ::iterator it;
	for(it = SetCallBackFunc.begin();it != SetCallBackFunc.end();++it)
	{
        LOGSERVERI(tag,"begin callback, statusnum is %d",statusEnum);
		(*it)(slotId, statusEnum);
	}
	p11Table.SetSlotStatus(slotId, statusEnum);	
}

void closeTFCard(){
	CK_RV ret = 0;
//	slotIDServer server;

	if(pHD){
		ret = pHD->Adapter_C_Finalize(NULL);
		LOGSERVERI(tag,"Finalize HD,ret = %lu",ret);
	}
	if(pJW){		
		ret = pJW->Adapter_C_Finalize(NULL);
		LOGSERVERI(tag,"Finalize JW,ret = %lu",ret);
	}

	CK_SLOT_ID slotid = 0;
	ret = p11Table.GetIndexByName("hd",&slotid);
	if(ret == 0){
		p11Table.DelSlot(slotid);
		set<CK_SESSION_HANDLE> hdsession = p11Table.ClearSessionbySlot(slotid);
		del_session(hdsession);
		statusCallBackBySlotId(slotid,CK_STATUS_ENUM_DEVICE_OFF);
	}

	ret = p11Table.GetIndexByName("jw",&slotid);
	if(ret == 0){
		p11Table.DelSlot(slotid);
		set<CK_SESSION_HANDLE> jwsession = p11Table.ClearSessionbySlot(slotid);		
		del_session(jwsession);
		statusCallBackBySlotId(slotid,CK_STATUS_ENUM_DEVICE_OFF);
	}
	
}

void GetTFcardStatus(){
	CK_RV ret = 0;
	CK_ULONG num = 0;
	CK_ULONG_PTR slotList = NULL;
	CK_STATUS_ENUM status = CK_STATUS_ENUM_DEVICE_ERROR;
	slotIDServer slotserver;
	
	Adapter_C_Initialize(NULL_PTR);
	ret = Adapter_C_GetSlotList(CK_TRUE,NULL,&num);

	if(ret!=CKR_OK || 0==num){
		LOGSERVERI(tag,"%s, No Card Found",__FUNCTION__);
		return;
	}

	slotList = new CK_ULONG[num];
	Adapter_C_GetSlotList(CK_TRUE,slotList,&num);

	for(int i=0; i<num;i++){
		p11Table.GetSlot(slotList[i],&slotserver);
		if(slotserver.des != "sc"){
			ret = Adapter_C_Extend_GetStatus(slotList[i], &status);
			if(CKR_OK == ret){
				statusCallBackBySlotId(slotList[i],status);
			}
			else{
				LOGSERVERE(tag,"%s, getstatus fail",__FUNCTION__);
			}
		}		
	}

	delete[] slotList;
	slotList = NULL;
	return;
}


CK_RV Adapter_P11_CheckAttribute(
        string packageName,
        CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
        CK_ULONG          ulCount)
{
	if((packageName != HEMIHUAPACKAGE)&&(packageName != TESTPACKAGE) && (packageName != CHENGXUNPACKAGE)&& (packageName != SMSPACKAGE))
	{
		return CKR_OK;
	}

	LOGSERVERI(tag,"%s IN00",__FUNCTION__);

	CK_OBJECT_CLASS getclass = 0;
	
	get_KeytypeAndClass(pTemplate, ulCount,  &getclass);
	for(int i=0;i<ulCount;i++)
	{
		if(pTemplate[i].type == CKA_SESSKEY_ID)
		{
			if((*(CK_BYTE_PTR)pTemplate[i].pValue) >= CK_SESSKEY_PRESET_ID0 && (*(CK_BYTE_PTR)pTemplate[i].pValue) <= CK_SESSKEY_PRESET_ID6)
			{	
				
				LOGSERVERI(tag,"%s change attr type",__FUNCTION__);
				pTemplate[i].type = CKA_LABEL;
			} else{
				LOGSERVERI(tag,"%s BK",__FUNCTION__);
			}
		}
		
		if(pTemplate[i].type == CKA_ID && getclass == CKO_SECRET_KEY)
		{
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}
	
	LOGSERVERI(tag,"%s OUT",__FUNCTION__);
    return CKR_OK;
}

int tfStatusCallback(unsigned char event, unsigned int param)
{
	return 0;
}

static CK_RV Adapter_Init(string des,P11AdapterFunction* p11AdapterFunction,CK_VOID_PTR   pInitArgs){
	CK_RV ret;
	CK_ULONG ulCount = 0;
	CK_SLOT_ID_PTR slotIdPtr = NULL;
	slotIDServer server;
//	CK_SLOT_ID getslotid = 0;

	if(des != "sc")
	{
		if(!mountCardFlg)
		{
			LOGSERVERI(tag,"no SDcard inserted");
			return CKR_OK;
		}
	}

	ret = p11AdapterFunction->Adapter_C_Initialize(pInitArgs);
	if(ret != CKR_OK && ret != CKR_CRYPTOKI_ALREADY_INITIALIZED){
		LOGSERVERE(tag, "%s init fail! ret is 0x%lx",des.c_str(),ret);
		return ret;
	}

	ret = p11AdapterFunction->Adapter_C_GetSlotList(CK_TRUE,slotIdPtr,&ulCount);	
	LOGSERVERI(tag,"des = %s,slot count = %lu,ret = 0x%lx",des.c_str(),ulCount,ret);
	if(ret != CKR_OK || 0 == ulCount){	
		p11Table.DelSlot(des);
		if(des != "sc"){
            p11AdapterFunction->Adapter_C_Finalize(NULL);
		}

		return ret;
	}

	slotIdPtr = new CK_SLOT_ID[ulCount];
	ret = p11AdapterFunction->Adapter_C_GetSlotList(CK_TRUE,slotIdPtr,&ulCount);
	if(ret != CKR_OK || 0 == ulCount){
		LOGSERVERE(tag,"%s get slot again fail, ret = 0x%lx",des.c_str(),ret);
		p11Table.DelSlot(des);
		
		delete[] slotIdPtr;
		slotIdPtr = NULL;
		return ret;
	}

	server.des = des;
	if(ret == CKR_OK && ulCount > 0){
		for(int i = 0;i < ulCount;i++){
			server.slotID = slotIdPtr[i];
			p11Table.AddSlot(server);
		}
	}

	delete[] slotIdPtr;
	slotIdPtr = NULL;
	return ret;

}




CK_RV Adapter_C_Initialize(CK_VOID_PTR   pInitArgs){
	CK_RV scRet =0,jwRet = 0,hdRet = 0;
		
	if(NULL != pHD && NULL != pJW && NULL != pSC){
        LOGSERVERD(tag,"hd = %p,jw = %p,sc = %p",pHD,pJW,pSC);
	}
	else{
		pHD = new P11func_HD();
		pJW = new P11func_JW();
		pSC = new P11func_SC();
	}

	
	scRet = Adapter_Init("sc",pSC,pInitArgs);
    jwRet = CKR_OK;
    hdRet = CKR_OK;

	if(mountCardFlg){
        jwRet = Adapter_Init("jw",pJW,pInitArgs);
        hdRet = Adapter_Init("hd",pHD,pInitArgs);
	}

	LOGSERVERI(tag,"sc ret = 0x%lx",scRet);
	LOGSERVERI(tag,"jw ret = 0x%lx",jwRet);
	LOGSERVERI(tag,"hd ret = 0x%lx",hdRet);

	if((scRet != CKR_OK && scRet != CKR_CRYPTOKI_ALREADY_INITIALIZED)
	   &&((jwRet != CKR_OK && jwRet != CKR_CRYPTOKI_ALREADY_INITIALIZED)) &&
			(hdRet != CKR_OK && hdRet != CKR_CRYPTOKI_ALREADY_INITIALIZED)){
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	
	return CKR_OK;
}



/* C_Finalize indicates that an application is done with the
 * Cryptoki library.
 */
CK_RV Adapter_C_Finalize(CK_VOID_PTR   pReserved){
	close_appsession(clientname);
	return CKR_OK;
}



/* C_GetInfo returns general information about Cryptoki. */
CK_RV Adapter_C_GetInfo(CK_INFO_PTR   pInfo){
	if(NULL == pInfo)
	{
		LOGSERVERE(tag,"pInfo is null");
		return CKR_ARGUMENTS_BAD;
	}
	
	pInfo->libraryVersion.major = VERSION_MAJOR;
	pInfo->libraryVersion.minor = VERSION_MINOR;
	memset(pInfo->manufacturerID,0,sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID,"westone",sizeof("westone"));
	pInfo->cryptokiVersion.major = 2;
	pInfo->cryptokiVersion.minor = 40;
	
	return CKR_OK;	
}



/* C_GetFunctionList returns the function list. */
CK_RV Adapter_C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList){
	if(NULL != ppFunctionList){
		(*ppFunctionList)->C_Initialize = Adapter_C_Initialize;

		(*ppFunctionList)->C_Finalize = Adapter_C_Finalize;

		(*ppFunctionList)->C_GetInfo = Adapter_C_GetInfo;

		(*ppFunctionList)->C_GetFunctionList = Adapter_C_GetFunctionList;

		(*ppFunctionList)->C_GetSlotList = Adapter_C_GetSlotList;

		(*ppFunctionList)->C_GetSlotInfo = Adapter_C_GetSlotInfo;

		(*ppFunctionList)->C_GetTokenInfo = Adapter_C_GetTokenInfo;

		(*ppFunctionList)->C_GetMechanismList = Adapter_C_GetMechanismList;

		(*ppFunctionList)->C_GetMechanismInfo = Adapter_C_GetMechanismInfo;

		(*ppFunctionList)->C_InitToken = Adapter_C_InitToken;

		(*ppFunctionList)->C_InitPIN = Adapter_C_InitPIN;

		(*ppFunctionList)->C_SetPIN = Adapter_C_SetPIN;

		(*ppFunctionList)->C_OpenSession = Adapter_C_OpenSession;

		(*ppFunctionList)->C_CloseSession = Adapter_C_CloseSession;

		(*ppFunctionList)->C_CloseAllSessions = Adapter_C_CloseAllSessions;

		(*ppFunctionList)->C_GetSessionInfo = Adapter_C_GetSessionInfo;

		(*ppFunctionList)->C_GetOperationState = Adapter_C_GetOperationState;

		(*ppFunctionList)->C_SetOperationState = Adapter_C_SetOperationState;

		(*ppFunctionList)->C_Login = Adapter_C_Login;

		(*ppFunctionList)->C_Logout = Adapter_C_Logout;

		(*ppFunctionList)->C_CreateObject = Adapter_C_CreateObject;

		(*ppFunctionList)->C_CopyObject = Adapter_C_CopyObject;

		(*ppFunctionList)->C_DestroyObject = Adapter_C_DestroyObject;

		(*ppFunctionList)->C_GetObjectSize = Adapter_C_GetObjectSize;

		(*ppFunctionList)->C_GetAttributeValue = Adapter_C_GetAttributeValue;

		(*ppFunctionList)->C_SetAttributeValue = Adapter_C_SetAttributeValue;

		(*ppFunctionList)->C_FindObjectsInit = Adapter_C_FindObjectsInit;

		(*ppFunctionList)->C_FindObjects = Adapter_C_FindObjects;

		(*ppFunctionList)->C_FindObjectsFinal = Adapter_C_FindObjectsFinal;

		(*ppFunctionList)->C_EncryptInit = Adapter_C_EncryptInit;

		(*ppFunctionList)->C_Encrypt = Adapter_C_Encrypt;

		(*ppFunctionList)->C_EncryptUpdate = Adapter_C_EncryptUpdate;

		(*ppFunctionList)->C_EncryptFinal = Adapter_C_EncryptFinal;

		(*ppFunctionList)->C_DecryptInit = Adapter_C_DecryptInit;

		(*ppFunctionList)->C_Decrypt = Adapter_C_Decrypt;

		(*ppFunctionList)->C_DecryptUpdate = Adapter_C_DecryptUpdate;

		(*ppFunctionList)->C_DecryptFinal = Adapter_C_DecryptFinal;

		(*ppFunctionList)->C_DigestInit = Adapter_C_DigestInit;

		(*ppFunctionList)->C_Digest = Adapter_C_Digest;

		(*ppFunctionList)->C_DigestUpdate = Adapter_C_DigestUpdate;

		(*ppFunctionList)->C_DigestKey = Adapter_C_DigestKey;

		(*ppFunctionList)->C_DigestFinal = Adapter_C_DigestFinal;

		(*ppFunctionList)->C_SignInit = Adapter_C_SignInit;

		(*ppFunctionList)->C_Sign = Adapter_C_Sign;

		(*ppFunctionList)->C_SignUpdate = Adapter_C_SignUpdate;

		(*ppFunctionList)->C_SignFinal = Adapter_C_SignFinal;

		(*ppFunctionList)->C_SignRecoverInit = Adapter_C_SignRecoverInit;

		(*ppFunctionList)->C_SignRecover = Adapter_C_SignRecover;

		(*ppFunctionList)->C_VerifyInit = Adapter_C_VerifyInit;

		(*ppFunctionList)->C_Verify = Adapter_C_Verify;

		(*ppFunctionList)->C_VerifyUpdate = Adapter_C_VerifyUpdate;

		(*ppFunctionList)->C_VerifyFinal = Adapter_C_VerifyFinal;

		(*ppFunctionList)->C_VerifyRecoverInit = Adapter_C_VerifyRecoverInit;

		(*ppFunctionList)->C_VerifyRecover = Adapter_C_VerifyRecover;

		(*ppFunctionList)->C_DigestEncryptUpdate = Adapter_C_DigestEncryptUpdate;

		(*ppFunctionList)->C_DecryptDigestUpdate = Adapter_C_DecryptDigestUpdate;

		(*ppFunctionList)->C_SignEncryptUpdate = Adapter_C_SignEncryptUpdate;

		(*ppFunctionList)->C_DecryptVerifyUpdate = Adapter_C_DecryptVerifyUpdate;

		(*ppFunctionList)->C_GenerateKey = Adapter_C_GenerateKey;

		(*ppFunctionList)->C_GenerateKeyPair = Adapter_C_GenerateKeyPair;

		(*ppFunctionList)->C_WrapKey = Adapter_C_WrapKey;

		(*ppFunctionList)->C_UnwrapKey = Adapter_C_UnwrapKey;

		(*ppFunctionList)->C_DeriveKey = Adapter_C_DeriveKey;

		(*ppFunctionList)->C_SeedRandom = Adapter_C_SeedRandom;

		(*ppFunctionList)->C_GenerateRandom = Adapter_C_GenerateRandom;

		(*ppFunctionList)->C_GetFunctionStatus = Adapter_C_GetFunctionStatus;

		(*ppFunctionList)->C_CancelFunction = Adapter_C_CancelFunction;

		(*ppFunctionList)->C_WaitForSlotEvent = Adapter_C_WaitForSlotEvent; 



		(*ppFunctionList)->C_Extend_GetPinRemainCount = Adapter_C_Extend_GetPinRemainCount;

		(*ppFunctionList)->C_Extend_GetStatus = Adapter_C_Extend_GetStatus;

		(*ppFunctionList)->C_Extend_Register_Callback = Adapter_C_Extend_Register_Callback;

		(*ppFunctionList)->C_Extend_Unregister_Callback = Adapter_C_Extend_Unregister_Callback;

		(*ppFunctionList)->C_Extend_GetExchangeSessionKey = Adapter_C_Extend_GetExchangeSessionKey;

		(*ppFunctionList)->C_Extend_Destroy = Adapter_C_Extend_Destroy;

		(*ppFunctionList)->C_Extend_Reset_Pin_With_OTP = Adapter_C_Extend_Reset_Pin_With_OTP;

		(*ppFunctionList)->C_Extend_Reset_OTP = Adapter_C_Extend_Reset_OTP;

		(*ppFunctionList)->C_Extend_Get_OTP_Unlock_Count = Adapter_C_Extend_Get_OTP_Unlock_Count;

		(*ppFunctionList)->C_Extend_Get_OTP_Remain_Count = Adapter_C_Extend_Get_OTP_Remain_Count;

		(*ppFunctionList)->C_Extend_DeriveSessionKey = Adapter_C_Extend_DeriveSessionKey;

		(*ppFunctionList)->C_Extend_EncryptInit = Adapter_C_Extend_EncryptInit;

		(*ppFunctionList)->C_Extend_DecryptInit = Adapter_C_Extend_DecryptInit;

		(*ppFunctionList)->C_Extend_EncryptUpdate = Adapter_C_Extend_EncryptUpdate;

		(*ppFunctionList)->C_Extend_DecryptUpdate = Adapter_C_Extend_DecryptUpdate;

		(*ppFunctionList)->C_Extend_EncryptFinalize = Adapter_C_Extend_EncryptFinalize;

		(*ppFunctionList)->C_Extend_DecryptFinalize = Adapter_C_Extend_DecryptFinalize;

		(*ppFunctionList)->C_Extend_PointMultiply = Adapter_C_Extend_PointMultiply;

		(*ppFunctionList)->C_Extend_MonopolizeEnable = Adapter_C_Extend_MonopolizeEnable;

		(*ppFunctionList)->C_Extend_MonopolizeDisable = Adapter_C_Extend_MonopolizeDisable;
		
		(*ppFunctionList)->C_Extend_GetDevInfo = Adapter_C_Extend_GetDevInfo;
		(*ppFunctionList)->C_Extend_DevSign = Adapter_C_Extend_DevSign;
		
	}

	return CKR_OK;	
}




/* Slot and token management */

/* C_GetSlotList obtains a list of slots in the system. */
CK_RV Adapter_C_GetSlotList(CK_BBOOL       tokenPresent,  /* only slots with tokens */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
){
	CK_ULONG slotCount = 0;
	slotCount = p11Table.GetSlotCount();

    LOGSERVERI(tag,"slotCount = %ld",slotCount);

	if(NULL==pulCount)
	{
		LOGSERVERE(tag,"ulcount empty!");
		return CKR_ARGUMENTS_BAD;
	}

	if(NULL == pSlotList)
	{
		*pulCount = slotCount;
	}
	else
	{
		if(*pulCount<slotCount)
		{
			*pulCount = slotCount;
			return CKR_BUFFER_TOO_SMALL;
		}

		*pulCount = slotCount;
		for(int i = 0;i < slotCount;i++){
			pSlotList[i] = p11Table.GetSlot(i);
		}
	}

	return CKR_OK;
}



/* C_GetSlotInfo obtains information about a particular slot in
 * the system.
 */
CK_RV Adapter_C_GetSlotInfo(
  CK_SLOT_ID       slotID,  /* the ID of the slot */
  CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
){
	slotIDServer server;

	p11Table.GetSlot(slotID,&server);
	CK_RV ret = CKR_SLOT_ID_INVALID;

	if(server.des == "hd"){
		ret = pHD->Adapter_C_GetSlotInfo(server.slotID,pInfo);

	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_GetSlotInfo(server.slotID,pInfo);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_GetSlotInfo(server.slotID,pInfo);
	}

	return ret;
}


/* C_GetTokenInfo obtains information about a particular token
 * in the system.
 */
CK_RV Adapter_C_GetTokenInfo(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
){
	slotIDServer server;

	p11Table.GetSlot(slotID,&server);

	CK_RV ret = CKR_SLOT_ID_INVALID;

	if(server.des == "hd"){
		ret = pHD->Adapter_C_GetTokenInfo(server.slotID,pInfo);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_GetTokenInfo(server.slotID,pInfo);
	}
	else if(server.des == "sc"){
		ret = pSC->Adapter_C_GetTokenInfo(server.slotID,pInfo);
	}
	return ret;
}



/* C_GetMechanismList obtains a list of mechanism types
 * supported by a token.
 */
CK_RV Adapter_C_GetMechanismList(
  CK_SLOT_ID            slotID,          /* ID of token's slot */
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
){
	slotIDServer server;

	p11Table.GetSlot(slotID,&server);
	CK_RV ret = CKR_SLOT_ID_INVALID;

	if(server.des == "hd"){
		ret = pHD->Adapter_C_GetMechanismList(server.slotID,pMechanismList,pulCount);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_GetMechanismList(server.slotID,pMechanismList,pulCount);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_GetMechanismList(server.slotID,pMechanismList,pulCount);
	}
	return ret;
}



/* C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token.
 */
CK_RV Adapter_C_GetMechanismInfo(
  CK_SLOT_ID            slotID,  /* ID of the token's slot */
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
){
	slotIDServer server;
	p11Table.GetSlot(slotID,&server);
	CK_RV ret = CKR_SLOT_ID_INVALID;
	if(server.des == "hd"){
		ret = pHD->Adapter_C_GetMechanismInfo(server.slotID,type,pInfo);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_GetMechanismInfo(server.slotID,type,pInfo);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_GetMechanismInfo(server.slotID,type,pInfo);
	}

	return ret;
}



/* C_InitToken initializes a token. */
CK_RV Adapter_C_InitToken(
  CK_SLOT_ID      slotID,    /* ID of the token's slot */
  CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
  CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
  CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
){
	slotIDServer server;

	p11Table.GetSlot(slotID,&server);
	CK_RV ret = CKR_SLOT_ID_INVALID;
	if(server.des == "hd"){
		ret = pHD->Adapter_C_InitToken(server.slotID,pPin,ulPinLen,pLabel);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_InitToken(server.slotID,pPin,ulPinLen,pLabel);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_InitToken(server.slotID,pPin,ulPinLen,pLabel);
	}

	return ret;
}



/* C_InitPIN initializes the normal user's PIN. */
CK_RV Adapter_C_InitPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
){
	sessionServer server;
	p11Table.GetSession(hSession,&server);
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;

	if(server.des == "hd"){
		ret = pHD->Adapter_C_InitPIN(server.handle,pPin,ulPinLen);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_InitPIN(server.handle,pPin,ulPinLen);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_InitPIN(server.handle,pPin,ulPinLen);
	}
	return ret;
}



/* C_SetPIN modifies the PIN of the user who is logged in. */
CK_RV Adapter_C_SetPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
){
	sessionServer server;
	p11Table.GetSession(hSession,&server);
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;

	if(server.des == "hd"){
		ret = pHD->Adapter_C_SetPIN(server.handle,pOldPin,ulOldLen,pNewPin,ulNewLen);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_SetPIN(server.handle,pOldPin,ulOldLen,pNewPin,ulNewLen);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_SetPIN(server.handle,pOldPin,ulOldLen,pNewPin,ulNewLen);
	}

	if(ret == CKR_PIN_LOCKED)
	{
		statusCallBackBySession(hSession, CK_STATUS_ENUM_DEVICE_LOCKED);
	}
	
	return ret;
}




/* Session management */

/* C_OpenSession opens a session between an application and a
 * token.
 */
CK_RV Adapter_C_OpenSession(
  CK_SLOT_ID            slotID,        /* the slot's ID */
  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
  CK_VOID_PTR           pApplication,  /* passed to callback */
  CK_NOTIFY             Notify,        /* callback function */
  CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
){
	slotIDServer slot;
	sessionServer session;
	CK_RV ret = CKR_SLOT_ID_INVALID;

	if(NULL == phSession){
		LOGSERVERE(tag,"%s, session null!",__FUNCTION__);
		return CKR_ARGUMENTS_BAD;
	}

	if(!checkClientSessionNum(clientname)){
		LOGSERVERE(tag,"client is limited to open new session!");
		return CKR_SESSION_COUNT;
	}
	
	LOGSERVERI(tag,"%s,slotID = 0x%lx",__FUNCTION__,slotID);
	
	p11Table.GetSlot(slotID,&slot);
	
	if(slot.des == "hd"){
		ret = pHD->Adapter_C_OpenSession(slot.slotID,flags,pApplication,Notify,phSession);
	}else if(slot.des == "jw"){
		ret = pJW->Adapter_C_OpenSession(slot.slotID,flags,pApplication,Notify,phSession);
	} else if(slot.des == "sc"){
		ret = pSC->Adapter_C_OpenSession(slot.slotID,flags,pApplication,Notify,phSession);
	} 

	session.des = slot.des;
	session.handle = 0;
	
	session.handle = *phSession;
	
	CK_SESSION_HANDLE temp = p11Table.AddSession(slotID,session);

	memcpy(phSession,&temp, sizeof(CK_SESSION_HANDLE));

	if(ret == CKR_OK)
	{		
		add_clientsession(clientname,*phSession);
	}

	return ret;
}



/* C_CloseSession closes a session between an application and a
 * token.
 */
CK_RV Adapter_C_CloseSession(
  CK_SESSION_HANDLE hSession  /* the session's handle */
){
	sessionServer server;
	p11Table.GetSession(hSession,&server);
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	if(server.des == "hd"){
		ret = pHD->Adapter_C_CloseSession(server.handle);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_CloseSession(server.handle);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_CloseSession(server.handle);
	}

	if(ret == CKR_OK)
	{		
		del_clientsession(clientname,hSession);
	}

	return ret;
}



/* C_CloseAllSessions closes all sessions with a token. */
CK_RV Adapter_C_CloseAllSessions(
  CK_SLOT_ID     slotID  /* the token's slot */
){
	slotIDServer server;

	p11Table.GetSlot(slotID,&server);
	CK_RV ret = CKR_SLOT_ID_INVALID;

	if(server.des == "hd"){
		ret = pHD->Adapter_C_CloseAllSessions(server.slotID);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_CloseAllSessions(server.slotID);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_CloseAllSessions(server.slotID);
	}

	if(ret == CKR_OK)
	{
		map_session.clear();
	}
	return ret;
}



/* C_GetSessionInfo obtains information about the session. */
CK_RV Adapter_C_GetSessionInfo(
  CK_SESSION_HANDLE   hSession,  /* the session's handle */
  CK_SESSION_INFO_PTR pInfo      /* receives session info */
){
	sessionServer server;
	p11Table.GetSession(hSession,&server);
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	if(server.des == "hd"){
		ret = pHD->Adapter_C_GetSessionInfo(server.handle,pInfo);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_GetSessionInfo(server.handle,pInfo);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_GetSessionInfo(server.handle,pInfo);
	}

	return ret;
}



/* C_GetOperationState obtains the state of the cryptographic operation
 * in a session.
 */
CK_RV Adapter_C_GetOperationState(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
){
	sessionServer server;
	p11Table.GetSession(hSession,&server);
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	if(server.des == "hd"){
		ret = pHD->Adapter_C_GetOperationState(server.handle,pOperationState,pulOperationStateLen);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_GetOperationState(server.handle,pOperationState,pulOperationStateLen);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_GetOperationState(server.handle,pOperationState,pulOperationStateLen);
	}
	return ret;
}



/* C_SetOperationState restores the state of the cryptographic
 * operation in a session.
 */
CK_RV Adapter_C_SetOperationState(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
){
	sessionServer server;
	p11Table.GetSession(hSession,&server);
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;

	if(server.des == "hd"){
		ret = pHD->Adapter_C_SetOperationState(server.handle,pOperationState,ulOperationStateLen,hEncryptionKey,hAuthenticationKey);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_SetOperationState(server.handle,pOperationState,ulOperationStateLen,hEncryptionKey,hAuthenticationKey);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_SetOperationState(server.handle,pOperationState,ulOperationStateLen,hEncryptionKey,hAuthenticationKey);
	}

	return ret;
}



/* C_Login logs a user into a token. */
CK_RV Adapter_C_Login(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
){
	sessionServer server;
	p11Table.GetSession(hSession,&server);
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	
	if(server.des == "hd"){
		ret = pHD->Adapter_C_Login(server.handle,userType,pPin,ulPinLen);
#ifdef BATTERY_RECOVERY
		if(ret == CKR_OK && userType == CKU_USER){
            pwRecovery.clear();
            pwRecovery.append((char*)pPin,ulPinLen);
		}
#endif

	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_Login(server.handle,userType,pPin,ulPinLen);
#ifdef BATTERY_RECOVERY
        if(ret == CKR_OK && userType == CKU_USER){
            pwRecovery.clear();
            pwRecovery.append((char*)pPin,ulPinLen);
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Login(server.handle,userType,pPin,ulPinLen);
	}
  
	if(ret == CKR_OK || ret == CKR_USER_ALREADY_LOGGED_IN)
	{
		statusCallBackBySession(hSession, CK_STATUS_ENUM_LOGIN);
	}
	if(ret == CKR_PIN_LOCKED)
	{
		statusCallBackBySession(hSession, CK_STATUS_ENUM_DEVICE_LOCKED);
	}
	
	
	return ret;
}



/* C_Logout logs a user out from a token. */
CK_RV Adapter_C_Logout(
  CK_SESSION_HANDLE hSession  /* the session's handle */
){
	sessionServer server;
	p11Table.GetSession(hSession,&server);
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	if(server.des == "hd"){
		ret = pHD->Adapter_C_Logout(server.handle);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_Logout(server.handle);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Logout(server.handle);
	}
	
	if(ret == CKR_OK){
		statusCallBackBySession(hSession, CK_STATUS_ENUM_UNLOGIN);
	}
	
	return ret;
}




/* Object management */

/* C_CreateObject creates a new object. */
CK_RV Adapter_C_CreateObject(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
){
	CK_RV ret= CKR_SESSION_HANDLE_INVALID;;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
	    START_HD:
		ret = pHD->Adapter_C_CreateObject(server.handle,pTemplate,ulCount,phObject);
#ifdef BATTERY_RECOVERY
		if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
		    ret = pHD->Adapter_C_Logout(server.handle);
		    ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
		    goto START_HD;
		}
#endif
	}else if(server.des == "jw"){
	    
		ret = Adapter_P11_CheckAttribute(clientname,pTemplate,ulCount);

		if(ret != CKR_OK)
		{
			LOGSERVERI(tag, "%s, check attribute for JW error",__FUNCTION__);
			return ret;
		}

		START_JW:
		ret = pJW->Adapter_C_CreateObject(server.handle,pTemplate,ulCount,phObject);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_CreateObject(server.handle,pTemplate,ulCount,phObject);
	}

	return ret;
}



/* C_CopyObject copies an object, creating a new object for the
 * copy.
 */
CK_RV Adapter_C_CopyObject(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_OBJECT_HANDLE     hObject,     /* the object's handle */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
  CK_ULONG             ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
        START_HD:
		ret = pHD->Adapter_C_CopyObject(server.handle,hObject,pTemplate,ulCount,phNewObject);
#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif

	}else if(server.des == "jw"){
	    START_JW:
		ret = pJW->Adapter_C_CopyObject(server.handle,hObject,pTemplate,ulCount,phNewObject);
#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_CopyObject(server.handle,hObject,pTemplate,ulCount,phNewObject);
	}

	return ret;
}



/* C_DestroyObject destroys an object. */
CK_RV Adapter_C_DestroyObject(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
	    START_HD:
		ret = pHD->Adapter_C_DestroyObject(server.handle,hObject);
#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
	    START_JW:
		ret = pJW->Adapter_C_DestroyObject(server.handle,hObject);
#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_DestroyObject(server.handle,hObject);
	}

	return ret;
}



/* C_GetObjectSize gets the size of an object in bytes. */
CK_RV Adapter_C_GetObjectSize(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
        START_HD:
		ret = pHD->Adapter_C_GetObjectSize(server.handle,hObject,pulSize);
#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_GetObjectSize(server.handle,hObject,pulSize);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif

	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_GetObjectSize(server.handle,hObject,pulSize);
	}

	return ret;
}



/* C_GetAttributeValue obtains the value of one or more object
 * attributes.
 */
CK_RV Adapter_C_GetAttributeValue(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount     /* attributes in template */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_GetAttributeValue(server.handle,hObject,pTemplate,ulCount);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif

	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_GetAttributeValue(server.handle,hObject,pTemplate,ulCount);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif

	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_GetAttributeValue(server.handle,hObject,pTemplate,ulCount);
	}

	return ret;
}



/* C_SetAttributeValue modifies the value of one or more object
 * attributes.
 */
CK_RV Adapter_C_SetAttributeValue(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_SetAttributeValue(server.handle,hObject,pTemplate,ulCount);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_SetAttributeValue(server.handle,hObject,pTemplate,ulCount);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif

	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_SetAttributeValue(server.handle,hObject,pTemplate,ulCount);
	}
	return ret;
}



/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template.
 */
CK_RV Adapter_C_FindObjectsInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;

	if(NULL == pTemplate && 0!=ulCount){
		return CKR_ARGUMENTS_BAD;
	}
	
	sessionServer server;
	p11Table.GetSession(hSession,&server);


	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_FindObjectsInit(server.handle,pTemplate,ulCount);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif

	}else if(server.des == "jw"){		
		ret = Adapter_P11_CheckAttribute(clientname,pTemplate,ulCount);
		if(ret != CKR_OK)
		{
			LOGSERVERI(tag, "%s, check attribute for JW error",__FUNCTION__);
			return ret;
		}
		START_JW:
		ret = pJW->Adapter_C_FindObjectsInit(server.handle,pTemplate,ulCount);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_FindObjectsInit(server.handle,pTemplate,ulCount);
	}

	return ret;
}



/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles.
 */
CK_RV Adapter_C_FindObjects(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_FindObjects(server.handle,phObject,ulMaxObjectCount,pulObjectCount);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
		#endif

	}else if(server.des == "jw"){
	    bool tryFlg = false;
		START_JW:
		ret = pJW->Adapter_C_FindObjects(server.handle,phObject,ulMaxObjectCount,pulObjectCount);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED || (tryFlg == false && NULL != pulObjectCount && *pulObjectCount == 0)){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            tryFlg = true;
            goto START_JW;
        }
		#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_FindObjects(server.handle,phObject,ulMaxObjectCount,pulObjectCount);
	}

	return ret;
}



/* C_FindObjectsFinal finishes a search for token and session
 * objects.
 */
CK_RV Adapter_C_FindObjectsFinal(
  CK_SESSION_HANDLE hSession  /* the session's handle */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_FindObjectsFinal(server.handle);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_FindObjectsFinal(server.handle);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_FindObjectsFinal(server.handle);
	}

	return ret;
}




/* Encryption and decryption */

/* C_EncryptInit initializes an encryption operation. */
CK_RV Adapter_C_EncryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_EncryptInit(server.handle,pMechanism,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_EncryptInit(server.handle,pMechanism,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_EncryptInit(server.handle,pMechanism,hKey);
	}

	return ret;
}



/* C_Encrypt encrypts single-part data. */
CK_RV Adapter_C_Encrypt(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Encrypt(server.handle,pData,ulDataLen,pEncryptedData,pulEncryptedDataLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif

	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Encrypt(server.handle,pData,ulDataLen,pEncryptedData,pulEncryptedDataLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif

	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Encrypt(server.handle,pData,ulDataLen,pEncryptedData,pulEncryptedDataLen);
	}

	return ret;
}



/* C_EncryptUpdate continues a multiple-part encryption
 * operation.
 */
CK_RV Adapter_C_EncryptUpdate(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_EncryptUpdate(server.handle,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_EncryptUpdate(server.handle,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_EncryptUpdate(server.handle,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
	}

	return ret;
}



/* C_EncryptFinal finishes a multiple-part encryption
 * operation.
 */
CK_RV Adapter_C_EncryptFinal(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_EncryptFinal(server.handle,pLastEncryptedPart,pulLastEncryptedPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_EncryptFinal(server.handle,pLastEncryptedPart,pulLastEncryptedPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_EncryptFinal(server.handle,pLastEncryptedPart,pulLastEncryptedPartLen);
	}

	return ret;
}



/* C_DecryptInit initializes a decryption operation. */
CK_RV Adapter_C_DecryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_DecryptInit(server.handle,pMechanism,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_DecryptInit(server.handle,pMechanism,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_DecryptInit(server.handle,pMechanism,hKey);
	}

	return ret;
}



/* C_Decrypt decrypts encrypted data in a single part. */
CK_RV Adapter_C_Decrypt(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Decrypt(server.handle,pEncryptedData,ulEncryptedDataLen,pData,pulDataLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Decrypt(server.handle,pEncryptedData,ulEncryptedDataLen,pData,pulDataLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif

	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Decrypt(server.handle,pEncryptedData,ulEncryptedDataLen,pData,pulDataLen);
	}

	return ret;
}



/* C_DecryptUpdate continues a multiple-part decryption
 * operation.
 */
CK_RV Adapter_C_DecryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_DecryptUpdate(server.handle,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_DecryptUpdate(server.handle,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif

	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_DecryptUpdate(server.handle,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
	}

	return ret;
}



/* C_DecryptFinal finishes a multiple-part decryption
 * operation.
 */
CK_RV Adapter_C_DecryptFinal(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_DecryptFinal(server.handle,pLastPart,pulLastPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_DecryptFinal(server.handle,pLastPart,pulLastPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_DecryptFinal(server.handle,pLastPart,pulLastPartLen);
	}

	return ret;
}




/* Message digesting */

/* C_DigestInit initializes a message-digesting operation. */
CK_RV Adapter_C_DigestInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_DigestInit(server.handle,pMechanism);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_DigestInit(server.handle,pMechanism);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_DigestInit(server.handle,pMechanism);
	}

	return ret;
}



/* C_Digest digests data in a single part. */
CK_RV Adapter_C_Digest(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Digest(server.handle,pData,ulDataLen,pDigest,pulDigestLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Digest(server.handle,pData,ulDataLen,pDigest,pulDigestLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Digest(server.handle,pData,ulDataLen,pDigest,pulDigestLen);
	}

	return ret;
}



/* C_DigestUpdate continues a multiple-part message-digesting
 * operation.
 */
CK_RV Adapter_C_DigestUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_DigestUpdate(server.handle,pPart,ulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_DigestUpdate(server.handle,pPart,ulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_DigestUpdate(server.handle,pPart,ulPartLen);
	}

	return ret;
}



/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested.
 */
CK_RV Adapter_C_DigestKey(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_DigestKey(server.handle,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_DigestKey(server.handle,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_DigestKey(server.handle,hKey);
	}

	return ret;
}



/* C_DigestFinal finishes a multiple-part message-digesting
 * operation.
 */
CK_RV Adapter_C_DigestFinal(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_DigestFinal(server.handle,pDigest,pulDigestLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_DigestFinal(server.handle,pDigest,pulDigestLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_DigestFinal(server.handle,pDigest,pulDigestLen);
	}

	return ret;
}




/* Signing and MACing */

/* C_SignInit initializes a signature (private key encryption)
 * operation, where the signature is (will be) an appendix to
 * the data, and plaintext cannot be recovered from the
 * signature.
 */
CK_RV Adapter_C_SignInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signature key */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_SignInit(server.handle,pMechanism,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_SignInit(server.handle,pMechanism,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_SignInit(server.handle,pMechanism,hKey);
	}

	return ret;
}



/* C_Sign signs (encrypts with private key) data in a single
 * part, where the signature is (will be) an appendix to the
 * data, and plaintext cannot be recovered from the signature.
 */
CK_RV Adapter_C_Sign(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Sign(server.handle,pData,ulDataLen,pSignature,pulSignatureLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Sign(server.handle,pData,ulDataLen,pSignature,pulSignatureLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Sign(server.handle,pData,ulDataLen,pSignature,pulSignatureLen);
	}

	return ret;
}



/* C_SignUpdate continues a multiple-part signature operation,
 * where the signature is (will be) an appendix to the data,
 * and plaintext cannot be recovered from the signature.
 */
CK_RV Adapter_C_SignUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_SignUpdate(server.handle,pPart,ulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_SignUpdate(server.handle,pPart,ulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_SignUpdate(server.handle,pPart,ulPartLen);
	}

	return ret;
}



/* C_SignFinal finishes a multiple-part signature operation,
 * returning the signature.
 */
CK_RV Adapter_C_SignFinal(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_SignFinal(server.handle,pSignature,pulSignatureLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_SignFinal(server.handle,pSignature,pulSignatureLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_SignFinal(server.handle,pSignature,pulSignatureLen);
	}

	return ret;
}



/* C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature.
 */
CK_RV Adapter_C_SignRecoverInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_SignRecoverInit(server.handle,pMechanism,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_SignRecoverInit(server.handle,pMechanism,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_SignRecoverInit(server.handle,pMechanism,hKey);
	}

	return ret;
}



/* C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature.
 */
CK_RV Adapter_C_SignRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_SignRecover(server.handle,pData,ulDataLen,pSignature,pulSignatureLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_SignRecover(server.handle,pData,ulDataLen,pSignature,pulSignatureLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_SignRecover(server.handle,pData,ulDataLen,pSignature,pulSignatureLen);
	}

	return ret;
}




/* Verifying signatures and MACs */

/* C_VerifyInit initializes a verification operation, where the
 * signature is an appendix to the data, and plaintext cannot
 * cannot be recovered from the signature (e.g. DSA).
 */
CK_RV Adapter_C_VerifyInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_VerifyInit(server.handle,pMechanism,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_VerifyInit(server.handle,pMechanism,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_VerifyInit(server.handle,pMechanism,hKey);
	}

	return ret;
}



/* C_Verify verifies a signature in a single-part operation,
 * where the signature is an appendix to the data, and plaintext
 * cannot be recovered from the signature.
 */
CK_RV Adapter_C_Verify(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Verify(server.handle,pData,ulDataLen,pSignature,ulSignatureLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Verify(server.handle,pData,ulDataLen,pSignature,ulSignatureLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Verify(server.handle,pData,ulDataLen,pSignature,ulSignatureLen);
	}

	return ret;
}



/* C_VerifyUpdate continues a multiple-part verification
 * operation, where the signature is an appendix to the data,
 * and plaintext cannot be recovered from the signature.
 */
CK_RV Adapter_C_VerifyUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_VerifyUpdate(server.handle,pPart,ulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_VerifyUpdate(server.handle,pPart,ulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_VerifyUpdate(server.handle,pPart,ulPartLen);
	}

	return ret;
}



/* C_VerifyFinal finishes a multiple-part verification
 * operation, checking the signature.
 */
CK_RV Adapter_C_VerifyFinal(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_VerifyFinal(server.handle,pSignature,ulSignatureLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_VerifyFinal(server.handle,pSignature,ulSignatureLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_VerifyFinal(server.handle,pSignature,ulSignatureLen);
	}

	return ret;
}



/* C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature.
 */
CK_RV Adapter_C_VerifyRecoverInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_VerifyRecoverInit(server.handle,pMechanism,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_VerifyRecoverInit(server.handle,pMechanism,hKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_VerifyRecoverInit(server.handle,pMechanism,hKey);
	}

	return ret;
}



/* C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature.
 */
CK_RV Adapter_C_VerifyRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_VerifyRecover(server.handle,pSignature,ulSignatureLen,pData,pulDataLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_VerifyRecover(server.handle,pSignature,ulSignatureLen,pData,pulDataLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_VerifyRecover(server.handle,pSignature,ulSignatureLen,pData,pulDataLen);
	}

	return ret;
}




/* Dual-function cryptographic operations */

/* C_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation.
 */
CK_RV Adapter_C_DigestEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_DigestEncryptUpdate(server.handle,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_DigestEncryptUpdate(server.handle,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_DigestEncryptUpdate(server.handle,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
	}

	return ret;
}



/* C_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation.
 */
CK_RV Adapter_C_DecryptDigestUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_DecryptDigestUpdate(server.handle,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_DecryptDigestUpdate(server.handle,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_DecryptDigestUpdate(server.handle,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
	}

	return ret;
}



/* C_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation.
 */
CK_RV Adapter_C_SignEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_SignEncryptUpdate(server.handle,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_SignEncryptUpdate(server.handle,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_SignEncryptUpdate(server.handle,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
	}

	return ret;
}



/* C_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation.
 */
CK_RV Adapter_C_DecryptVerifyUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_DecryptVerifyUpdate(server.handle,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_DecryptVerifyUpdate(server.handle,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_DecryptVerifyUpdate(server.handle,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
	}

	return ret;
}




/* Key management */

/* C_GenerateKey generates a secret key, creating a new key
 * object.
 */
CK_RV Adapter_C_GenerateKey(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(NULL == pTemplate)
	{
		LOGSERVERE(tag,"%s, template empty!",__FUNCTION__);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_GenerateKey(server.handle,pMechanism,pTemplate,ulCount,phKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		ret = Adapter_P11_CheckAttribute(clientname,pTemplate,ulCount);
		if(ret != CKR_OK)
		{
			LOGSERVERI(tag, "%s, check attribute for JW error",__FUNCTION__);
			return ret;
		}
		START_JW:
		ret = pJW->Adapter_C_GenerateKey(server.handle,pMechanism,pTemplate,ulCount,phKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_GenerateKey(server.handle,pMechanism,pTemplate,ulCount,phKey);
	}

	return ret;
}



/* C_GenerateKeyPair generates a public-key/private-key pair,
 * creating new key objects.
 */
CK_RV Adapter_C_GenerateKeyPair(
  CK_SESSION_HANDLE    hSession,                    /* session handle */
  CK_MECHANISM_PTR     pMechanism,                  /* key-gen mech. */
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template for pub. key */
  CK_ULONG             ulPublicKeyAttributeCount,   /* # pub. attrs. */
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template for priv. key */
  CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.  attrs. */
  CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
  CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets priv. key handle */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_GenerateKeyPair(server.handle,pMechanism,pPublicKeyTemplate,ulPublicKeyAttributeCount,
			pPrivateKeyTemplate,ulPrivateKeyAttributeCount,phPublicKey,phPrivateKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_GenerateKeyPair(server.handle,pMechanism,pPublicKeyTemplate,ulPublicKeyAttributeCount,
			pPrivateKeyTemplate,ulPrivateKeyAttributeCount,phPublicKey,phPrivateKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_GenerateKeyPair(server.handle,pMechanism,pPublicKeyTemplate,ulPublicKeyAttributeCount,
			pPrivateKeyTemplate,ulPrivateKeyAttributeCount,phPublicKey,phPrivateKey);
	}

	return ret;
}



/* C_WrapKey wraps (i.e., encrypts) a key. */
CK_RV Adapter_C_WrapKey(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_WrapKey(server.handle,pMechanism,hWrappingKey,hKey,pWrappedKey,pulWrappedKeyLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_WrapKey(server.handle,pMechanism,hWrappingKey,hKey,pWrappedKey,pulWrappedKeyLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_WrapKey(server.handle,pMechanism,hWrappingKey,hKey,pWrappedKey,pulWrappedKeyLen);
	}

	return ret;
}



/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object.
 */
CK_RV Adapter_C_UnwrapKey(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(NULL == pTemplate)
	{
		LOGSERVERE(tag,"%s, template empty!",__FUNCTION__);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_UnwrapKey(server.handle,pMechanism,hUnwrappingKey,
			pWrappedKey,ulWrappedKeyLen,pTemplate,ulAttributeCount,phKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		ret = Adapter_P11_CheckAttribute(clientname,pTemplate,ulAttributeCount);
		if(ret != CKR_OK)
		{
			LOGSERVERI(tag, "%s, check attribute for JW error",__FUNCTION__);
			return ret;
		}
		START_JW:
		ret = pJW->Adapter_C_UnwrapKey(server.handle,pMechanism,hUnwrappingKey,
			pWrappedKey,ulWrappedKeyLen,pTemplate,ulAttributeCount,phKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_UnwrapKey(server.handle,pMechanism,hUnwrappingKey,
			pWrappedKey,ulWrappedKeyLen,pTemplate,ulAttributeCount,phKey);
	}

	return ret;
}



/* C_DeriveKey derives a key from a base key, creating a new key
 * object.
 */
CK_RV Adapter_C_DeriveKey(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_DeriveKey(server.handle,pMechanism,hBaseKey,pTemplate,ulAttributeCount,phKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_DeriveKey(server.handle,pMechanism,hBaseKey,pTemplate,ulAttributeCount,phKey);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_DeriveKey(server.handle,pMechanism,hBaseKey,pTemplate,ulAttributeCount,phKey);
	}

	return ret;
}




/* Random number generation */

/* C_SeedRandom mixes additional seed material into the token's
 * random number generator.
 */
CK_RV Adapter_C_SeedRandom(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_SeedRandom(server.handle,pSeed,ulSeedLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_SeedRandom(server.handle,pSeed,ulSeedLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_SeedRandom(server.handle,pSeed,ulSeedLen);
	}

	return ret;
}



/* C_GenerateRandom generates random data. */
CK_RV Adapter_C_GenerateRandom(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_BYTE_PTR       RandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_GenerateRandom(server.handle,RandomData,ulRandomLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_GenerateRandom(server.handle,RandomData,ulRandomLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_GenerateRandom(server.handle,RandomData,ulRandomLen);
	}

	return ret;
}




/* Parallel function management */

/* C_GetFunctionStatus is a legacy function; it obtains an
 * updated status of a function running in parallel with an
 * application.
 */
CK_RV Adapter_C_GetFunctionStatus(
  CK_SESSION_HANDLE hSession  /* the session's handle */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		ret = pHD->Adapter_C_GetFunctionStatus(server.handle);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_GetFunctionStatus(server.handle);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_GetFunctionStatus(server.handle);
	}

	return ret;
}



/* C_CancelFunction is a legacy function; it cancels a function
 * running in parallel.
 */
CK_RV Adapter_C_CancelFunction(
  CK_SESSION_HANDLE hSession  /* the session's handle */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		ret = pHD->Adapter_C_CancelFunction(server.handle);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_CancelFunction(server.handle);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_CancelFunction(server.handle);
	}

	return ret;
}



/* C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur.
 */
CK_RV Adapter_C_WaitForSlotEvent(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
){

	return CKR_OK;
}


/********************************
 *剩余口令剩余尝试次数
*/
CK_RV Adapter_C_Extend_GetPinRemainCount(
  CK_SESSION_HANDLE hSession,
  CK_ULONG_PTR pUiRemainCount
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_GetPinRemainCount(server.handle,pUiRemainCount);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_Extend_GetPinRemainCount(server.handle,pUiRemainCount);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_GetPinRemainCount(server.handle,pUiRemainCount);
	}

	if(ret == CKR_PIN_LOCKED)
	{
		statusCallBackBySession(hSession, CK_STATUS_ENUM_DEVICE_LOCKED);
	}

	return ret;
}

/********************************
 *获取密码卡状态
*/
CK_RV Adapter_C_Extend_GetStatus(
  CK_SLOT_ID slotID,
  CK_STATUS_ENUM_PTR pStatus
){
	slotIDServer server;
    CK_RV ret = CKR_SLOT_ID_INVALID;
	p11Table.GetSlot(slotID,&server);

	if(NULL == pStatus)
	{
		LOGSERVERE(tag,"%s, Status empty!",__FUNCTION__);
		return CKR_ARGUMENTS_BAD;
	}

	if(p11Table.GetSlotStatus(slotID,pStatus) == 0)
	{
		if(*pStatus == CK_STATUS_ENUM_DEVICE_DESTROY)
		{
			return CKR_OK;
		}
	}

	if(server.des == "hd"){
		ret = pHD->Adapter_C_Extend_GetStatus(server.slotID,pStatus);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_Extend_GetStatus(server.slotID,pStatus);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_GetStatus(server.slotID,pStatus);
	}
    return ret;
}

/********************************
 *注册密码卡状态回调函数
*/


CK_RV Adapter_C_Extend_Register_Callback(

  register_status_callback_func func
)
{

	SetCallBackFunc.insert(func);
    return CKR_OK;
}

/********************************
 *注销密码卡状态回调函数
*/
CK_RV Adapter_C_Extend_Unregister_Callback(

  register_status_callback_func func
)
{

	 SetCallBackFunc.erase(func);
    return CKR_OK;
}

/********************************
 *使用监听公钥导出协商密钥
*/
CK_RV Adapter_C_Extend_GetExchangeSessionKey(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hSessionKey,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG_PTR pulEncryptedDataLen
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_GetExchangeSessionKey(server.handle,hSessionKey,pEncryptedData,pulEncryptedDataLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_Extend_GetExchangeSessionKey(server.handle,hSessionKey,pEncryptedData,pulEncryptedDataLen);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_GetExchangeSessionKey(server.handle,hSessionKey,pEncryptedData,pulEncryptedDataLen);
	}

	return ret;
}



/********************************
 *参数注销
*/
CK_RV Adapter_C_Extend_Destroy(
  CK_SLOT_ID slotID,
  CK_BYTE_PTR containerName
){
	slotIDServer server;

	p11Table.GetSlot(slotID,&server);
    CK_RV ret = CKR_SLOT_ID_INVALID;
	if(server.des == "hd"){
		ret = pHD->Adapter_C_Extend_Destroy(server.slotID,containerName);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_Extend_Destroy(server.slotID,containerName);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_Destroy(server.slotID,containerName);
	}

    return ret;
}

/********************************
 *重设用户口令
*/
CK_RV Adapter_C_Extend_Reset_Pin_With_OTP(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbOTPPIN,
  CK_ULONG ulOTPPINLen,
  CK_BYTE_PTR pbNewUserPIN,
  CK_ULONG ulNewUserPINLen
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	CK_RV ret1 = CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slotid = 0;
	CK_STATUS_ENUM newstatus = CK_STATUS_ENUM_DEVICE_OFF;	
	CK_STATUS_ENUM oldstatus = CK_STATUS_ENUM_DEVICE_OFF;
	
	sessionServer serversession;
	slotIDServer serverslot;
	
	p11Table.GetSession(hSession,&serversession);

	ret = p11Table.GetSlotFromSession(hSession,&slotid);
	if(ret != CKR_OK)
	{
		LOGSERVERE(tag, "GetSlotFromSession ERROR!");
		return CKR_SESSION_HANDLE_INVALID;
	}

	p11Table.GetSlot(slotid,&serverslot);
	
	if(ret != CKR_OK)
	{
		LOGSERVERE(tag, "%s, getslot fail!", __FUNCTION__);		
		return CKR_SESSION_HANDLE_INVALID;
	}	

	if(serversession.des == "hd"){
		pHD->Adapter_C_Extend_GetStatus(serverslot.slotID,&oldstatus);
		ret = pHD->Adapter_C_Extend_Reset_Pin_With_OTP(serversession.handle,pbOTPPIN,ulOTPPINLen,pbNewUserPIN,ulNewUserPINLen);
		ret1 = pHD->Adapter_C_Extend_GetStatus(serverslot.slotID,&newstatus);
	}else if(serversession.des == "jw"){
		pJW->Adapter_C_Extend_GetStatus(serverslot.slotID,&oldstatus);
		ret = pJW->Adapter_C_Extend_Reset_Pin_With_OTP(serversession.handle,pbOTPPIN,ulOTPPINLen,pbNewUserPIN,ulNewUserPINLen);
		ret1 = pJW->Adapter_C_Extend_GetStatus(serverslot.slotID,&newstatus);
	}else if(serversession.des == "sc"){
		pSC->Adapter_C_Extend_GetStatus(serverslot.slotID,&oldstatus);
		ret = pSC->Adapter_C_Extend_Reset_Pin_With_OTP(serversession.handle,pbOTPPIN,ulOTPPINLen,pbNewUserPIN,ulNewUserPINLen);
		ret1 = pSC->Adapter_C_Extend_GetStatus(serverslot.slotID,&newstatus);
	}

	if(ret == CKR_PIN_LOCKED)
	{
		statusCallBackBySession(hSession, CK_STATUS_ENUM_DEVICE_LOCKED);
	}

	if(ret == CKR_OK)
	{		
		LOGSERVERI(tag,"oldstatus is %d, new status is %d",oldstatus,newstatus);
		if(ret1 == CKR_OK && oldstatus != newstatus)
		{
			LOGSERVERI(tag, "%s,status changed",__FUNCTION__);
			statusCallBackBySession(hSession,newstatus);
		}	
		else
		{
			LOGSERVERE(tag,"%s, error get status, ret is 0x%lx",__FUNCTION__,ret1);
		}	
	}	

	return ret;
}


CK_RV Adapter_C_Extend_Reset_OTP(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbOTPMpk,
  CK_ULONG ulMpkLen,
  CK_BYTE_PTR pbMpkIV,
  CK_ULONG ulMpkIVLen
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		ret = pHD->Adapter_C_Extend_Reset_OTP(server.handle,pbOTPMpk,ulMpkLen,pbMpkIV,ulMpkIVLen);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_Extend_Reset_OTP(server.handle,pbOTPMpk,ulMpkLen,pbMpkIV,ulMpkIVLen);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_Reset_OTP(server.handle,pbOTPMpk,ulMpkLen,pbMpkIV,ulMpkIVLen);
	}

	
	if(ret == CKR_PIN_LOCKED)
	{
		statusCallBackBySession(hSession, CK_STATUS_ENUM_DEVICE_LOCKED);
	}
	return ret;
}


CK_RV Adapter_C_Extend_Get_OTP_Unlock_Count(
  CK_SESSION_HANDLE hSession,
  CK_ULONG_PTR pulCount
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		ret = pHD->Adapter_C_Extend_Get_OTP_Unlock_Count(server.handle,pulCount);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_Extend_Get_OTP_Unlock_Count(server.handle,pulCount);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_Get_OTP_Unlock_Count(server.handle,pulCount);
	}

	return ret;
}


/********************************
 *获取剩余OTP尝试次数
*/
CK_RV Adapter_C_Extend_Get_OTP_Remain_Count(
  CK_SESSION_HANDLE hSession,
  CK_ULONG_PTR pulCount
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		ret = pHD->Adapter_C_Extend_Get_OTP_Remain_Count(server.handle,pulCount);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_Extend_Get_OTP_Remain_Count(server.handle,pulCount);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_Get_OTP_Remain_Count(server.handle,pulCount);
	}

	return ret;
}


CK_RV Adapter_C_Extend_DeriveSessionKey(
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
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_DeriveSessionKey(server.handle,
			pMechanism,hLocalKey,hRemoteKey,pTemplate,ulAttributeCount,phKey,
			pExchangeIV,pExchangeIVLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Extend_DeriveSessionKey(server.handle,
			pMechanism,hLocalKey,hRemoteKey,pTemplate,ulAttributeCount,phKey,
			pExchangeIV,pExchangeIVLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_DeriveSessionKey(server.handle,
			pMechanism,hLocalKey,hRemoteKey,pTemplate,ulAttributeCount,phKey,
			pExchangeIV,pExchangeIVLen);
	}

	return ret;
}


CK_RV Adapter_C_Extend_EncryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG ulAttributeCount
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;	
	enc_time.clear();
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
	    START_HD:
		ret = pHD->Adapter_C_Extend_EncryptInit(server.handle,pMechanism,pTemplate,ulAttributeCount);
#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
	    START_JW:
		ret = pJW->Adapter_C_Extend_EncryptInit(server.handle,pMechanism,pTemplate,ulAttributeCount);
#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}
	else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_EncryptInit(server.handle,pMechanism,pTemplate,ulAttributeCount);
	}

	return ret;
}


CK_RV Adapter_C_Extend_DecryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_ATTRIBUTE_PTR  pTemplate,	 /* template of decryption key */
  CK_ULONG ulAttributeCount		 /* template of decryption key count*/	
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);
	
	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_DecryptInit(server.handle,pMechanism,pTemplate,ulAttributeCount);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Extend_DecryptInit(server.handle,pMechanism,pTemplate,ulAttributeCount);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_DecryptInit(server.handle,pMechanism,pTemplate,ulAttributeCount);
	}

	return ret;
}



CK_RV Adapter_C_Extend_EncryptUpdate(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pIv,                /* encrypted iv */
  CK_ULONG          ulIvLen,            /* encrypted iv len */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	//UtilscTime ttc1={0, 0},ttc2={0,0};
	struct timeval t1,t2;
	
	p11Table.GetSession(hSession,&server);
	
	gettimeofday(&t1,NULL);
	
	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_EncryptUpdate(server.handle,pIv,ulIvLen,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Extend_EncryptUpdate(server.handle,pIv,ulIvLen,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_EncryptUpdate(server.handle,pIv,ulIvLen,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
	}

	gettimeofday(&t2,NULL);

	enc_time.push_back((t2.tv_sec - t1.tv_sec) * 1000 + (t2.tv_usec - t1.tv_usec) / 1000);
		
	return ret;
}


CK_RV Adapter_C_Extend_DecryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pIv,                /* decrypted iv */
  CK_ULONG          ulIvLen,            /* decrypted iv len */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_DecryptUpdate(server.handle,pIv,ulIvLen,pEncryptedPart,
			ulEncryptedPartLen,pPart,pulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Extend_DecryptUpdate(server.handle,pIv,ulIvLen,pEncryptedPart,
			ulEncryptedPartLen,pPart,pulPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_DecryptUpdate(server.handle,pIv,ulIvLen,pEncryptedPart,
			ulEncryptedPartLen,pPart,pulPartLen);
	}

	return ret;
}

//#define TEST_PERFORMANCE

/********************************
 *协商会话密钥分步加密结束
*/
CK_RV Adapter_C_Extend_EncryptFinalize(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_EncryptFinalize(server.handle,pLastEncryptedPart,pulLastEncryptedPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
        #endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Extend_EncryptFinalize(server.handle,pLastEncryptedPart,pulLastEncryptedPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
        #endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_EncryptFinalize(server.handle,pLastEncryptedPart,pulLastEncryptedPartLen);
	}

#ifdef TEST_PERFORMANCE    
    const char* testFile ={ "/sdcard/Test/ZUCenc_card.xls"};
	char strtemp[256];
	FILE *_fp;
	_fp=fopen(testFile,"w");
	if (!_fp)
	{
		LOGSERVERI(tag,"Adapter_C_Extend_EncryptFinalize,fopen fail.");
	} 
	else
	{
		for(int i=0;i<enc_time.size();i++)
		{
			sprintf(strtemp, "%d", enc_time[i]);
			fputs(strtemp, _fp);
			fputs("\n", _fp);
		}	
		
		fclose(_fp);
	}
#endif

    enc_time.clear();
	return ret;
}


/********************************
 *协商会话密钥分步解密结束
*/
CK_RV Adapter_C_Extend_DecryptFinalize(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_DecryptFinalize(server.handle,pLastPart,pulLastPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Extend_DecryptFinalize(server.handle,pLastPart,pulLastPartLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_DecryptFinalize(server.handle,pLastPart,pulLastPartLen);
	}

	return ret;
}


/********************************
 *SM2点乘
*/
CK_RV Adapter_C_Extend_PointMultiply(

  CK_SESSION_HANDLE hSession,

  CK_MECHANISM_PTR pMechanism,

  CK_OBJECT_HANDLE hKey,

  CK_BYTE_PTR pOutData,

  CK_ULONG_PTR pOutLen
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_PointMultiply(server.handle,pMechanism,hKey,pOutData,pOutLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Extend_PointMultiply(server.handle,pMechanism,hKey,pOutData,pOutLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_PointMultiply(server.handle,pMechanism,hKey,pOutData,pOutLen);
	}

	return ret;
}

/********************************
 *重设TT口令
*/
CK_RV Adapter_C_Extend_Reset_TT(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbTTMpk,
  CK_ULONG ulMpkLen,
  CK_BYTE_PTR pbMpkIV,
  CK_ULONG ulMpkIVLen
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_Reset_TT(server.handle,pbTTMpk,ulMpkLen,pbMpkIV,ulMpkIVLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Extend_Reset_TT(server.handle,pbTTMpk,ulMpkLen,pbMpkIV,ulMpkIVLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_Reset_TT(server.handle,pbTTMpk,ulMpkLen,pbMpkIV,ulMpkIVLen);
	}
	
	if(ret == CKR_PIN_LOCKED)
	{
		statusCallBackBySession(hSession, CK_STATUS_ENUM_DEVICE_LOCKED);
	}

	return ret;
}

/********************************
 *重设BK口令
*/
CK_RV Adapter_C_Extend_Reset_BK(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbBKMpk,
  CK_ULONG ulMpkLen,
  CK_BYTE_PTR pbMpkIV,
  CK_ULONG ulMpkIVLen
){
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_Reset_BK(server.handle,pbBKMpk,ulMpkLen,pbMpkIV,ulMpkIVLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Extend_Reset_BK(server.handle,pbBKMpk,ulMpkLen,pbMpkIV,ulMpkIVLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_Reset_BK(server.handle,pbBKMpk,ulMpkLen,pbMpkIV,ulMpkIVLen);
	}

	
	if(ret == CKR_PIN_LOCKED)
	{
		statusCallBackBySession(hSession, CK_STATUS_ENUM_DEVICE_LOCKED);
	}

	return ret;
}


CK_RV Adapter_C_Extend_Get_Special_Object_Version
(
	CK_SESSION_HANDLE            hSession,
	CK_OBJECT_CLASS 	  objectClass,
	CK_BYTE_PTR pVersion,
	CK_ULONG_PTR pUlLen

)
{
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_Get_Special_Object_Version(server.handle,objectClass,pVersion,pUlLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Extend_Get_Special_Object_Version(server.handle,objectClass,pVersion,pUlLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_Get_Special_Object_Version(server.handle,objectClass,pVersion,pUlLen);
	}

	return ret;
}

CK_RV Adapter_C_Extend_DestroyCard
(
	CK_SLOT_ID slotID,
	CK_BYTE_PTR prandomIn,
	CK_ULONG randomInLen,
	CK_BYTE_PTR prandomOut,
	CK_ULONG_PTR prandomOutLen
)
{	
	slotIDServer server;

	p11Table.GetSlot(slotID,&server);

	CK_RV ret = CKR_SLOT_ID_INVALID;

	if(server.des == "hd"){
		ret = pHD->Adapter_C_Extend_DestroyCard(server.slotID,prandomIn,randomInLen,prandomOut,prandomOutLen);
	}else if(server.des == "jw"){
		ret = pJW->Adapter_C_Extend_DestroyCard(server.slotID,prandomIn,randomInLen,prandomOut,prandomOutLen);
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_DestroyCard(server.slotID,prandomIn,randomInLen,prandomOut,prandomOutLen);
	}

	if(ret == CKR_OK)
	{
		statusCallBackBySlotId(slotID,CK_STATUS_ENUM_DEVICE_DESTROY);
		p11Table.DelSlot(slotID);
		set<CK_SESSION_HANDLE> handles = p11Table.ClearSessionbySlot(slotID);
		del_session(handles);
	}
	
	return ret;
}

CK_RV Adapter_C_Extend_Get_ExchangePubKey
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR 	  pExchangePubKeyValue,	  
	CK_ULONG_PTR	  pulKeyLen  
)
{	
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_Get_ExchangePubKey(server.handle,pExchangePubKeyValue,pulKeyLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Extend_Get_ExchangePubKey(server.handle,pExchangePubKeyValue,pulKeyLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_Get_ExchangePubKey(server.handle,pExchangePubKeyValue,pulKeyLen);
	}

	return ret;
}


/******************************
 *独占
*/

CK_RV Adapter_C_Extend_MonopolizeEnable(
  CK_SLOT_ID            slotID        /* the slot's ID */
){
	return 0;
}


/******************************
 *取消独占
*/
CK_RV Adapter_C_Extend_MonopolizeDisable(
  CK_SLOT_ID            slotID        /* the slot's ID */
){
	return 0;
}

CK_RV Adapter_C_Extend_GetDevInfo
(
 CK_SLOT_ID slotID,
 const char *userName,         
 CK_IP_PARAMS_PTR cspp,
 CK_BYTE_PTR pDevInfo,
 CK_ULONG_PTR pUlDevInfoLen
)
{
	slotIDServer server;
		
	p11Table.GetSlot(slotID,&server);
	CK_RV ret = CKR_FUNCTION_NOT_SUPPORTED;

	if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_GetDevInfo(server.slotID,userName,cspp,pDevInfo,pUlDevInfoLen);
	}	
	
	return ret;
}
CK_RV Adapter_C_Extend_DevSign
(
	CK_SLOT_ID slotID,
	CK_BYTE_PTR       pData,           /* the data to sign */
	CK_ULONG          ulDataLen,       /* count of bytes to sign */
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{	
	slotIDServer server;
	
	p11Table.GetSlot(slotID,&server);

	CK_RV ret = CKR_FUNCTION_NOT_SUPPORTED;
	if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_DevSign(server.slotID,pData,ulDataLen,pSignature,pulSignatureLen);
	}
	return ret;
}

CK_RV Adapter_C_Extend_Set_DestroyKey
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pDestroyKeyMpk,
	CK_ULONG ulMpkLen,
	CK_BYTE_PTR pbMpkIV,
	CK_ULONG ulMpkIVLen
)
{	
	CK_RV ret = CKR_SESSION_HANDLE_INVALID;
	sessionServer server;
	p11Table.GetSession(hSession,&server);

	if(server.des == "hd"){
		START_HD:
		ret = pHD->Adapter_C_Extend_Set_DestroyKey(server.handle,pDestroyKeyMpk,ulMpkLen,pbMpkIV,ulMpkIVLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pHD->Adapter_C_Logout(server.handle);
            ret = pHD->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_HD;
        }
#endif
	}else if(server.des == "jw"){
		START_JW:
		ret = pJW->Adapter_C_Extend_Set_DestroyKey(server.handle,pDestroyKeyMpk,ulMpkLen,pbMpkIV,ulMpkIVLen);
		#ifdef BATTERY_RECOVERY
        if(ret == CKR_VENDOR_MAYBE_POWEROFFED){
            ret = pJW->Adapter_C_Logout(server.handle);
            ret = pJW->Adapter_C_Login(server.handle,CKU_USER,(CK_UTF8CHAR_PTR)pwRecovery.data(),pwRecovery.size());
            goto START_JW;
        }
#endif
	}else if(server.des == "sc"){
		ret = pSC->Adapter_C_Extend_Set_DestroyKey(server.handle,pDestroyKeyMpk,ulMpkLen,pbMpkIV,ulMpkIVLen);
	}

	
	if(ret == CKR_PIN_LOCKED)
	{
		statusCallBackBySession(hSession, CK_STATUS_ENUM_DEVICE_LOCKED);
	}
	return ret;

}

CK_RV Adapter_SC_C_Destroy_Extend(){
	CK_SLOT_ID scslot = -1;
	CK_RV ret  = CKR_SLOT_ID_INVALID;

	if(NULL_PTR == pSC){
		Adapter_C_Initialize(NULL);
	}	
	
	ret = p11Table.GetIndexByName("sc",&scslot);
	
	if(ret == 0){
		ret = Adapter_C_Extend_DestroyCard(scslot,NULL,0,NULL,0);
	}

	return ret;
}

CK_RV Adapter_SC_CREATESC(string token, string userName, string licSesrverAddr, string csppAddr){
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	
    CK_CHAR ttoken[CK_MAX_TOKEN_SIZE] = {0};
    CK_CHAR tuserName[CK_MAX_NAME_SIZE] = {0};
    memcpy(ttoken,token.data(),token.size());
    memcpy(tuserName,userName.data(),userName.size());
	CK_ULONG slotID = 0;
	CK_CHAR_PTR licRootCaCert[CK_MAX_CERTLIST_CNT] = {NULL};
    CK_UINT licRootCaCertLen[CK_MAX_CERTLIST_CNT] = {0};
	
	
	char splittag = ' ';
    vector<string> licArray = split(licSesrverAddr, splittag);
    string licserverip = licArray[0];
	int licport1 = atoi(licArray[1].c_str());
	int licport2 = atoi(licArray[2].c_str());	
	
    vector<string> csppArray = split(csppAddr,splittag);
    string csppip = csppArray[0];
	int csppport1 = atoi(csppArray[1].c_str());
	int csppport2 = atoi(csppArray[2].c_str());
	
	CK_IP_PARAMS licServer;
	memset(&licServer,0,sizeof(CK_IP_PARAMS));
	strncpy((char*)licServer.ip,licserverip.data(),licserverip.size());
	licServer.oWayPort = licport1;
	licServer.tWayPort = licport2;

	CK_IP_PARAMS cspp_scm;
	memset(&cspp_scm,0,sizeof(CK_IP_PARAMS));
    strncpy((char*)cspp_scm.ip,csppip.data(),csppip.size());
    cspp_scm.oWayPort = csppport1;
    cspp_scm.tWayPort = csppport2;

	CK_RV ret = SC_C_DevProduct_Extend((CK_CHAR*)ttoken,(CK_CHAR*)tuserName,licRootCaCert, licRootCaCertLen,&licServer, &cspp_scm,&slotID);

	return ret;
}




