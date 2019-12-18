#include "cryptoki.h"
#include "logserver.h"
#include "p11func_hd.h"

#include <stdlib.h>
#include <string.h>
#include "LibLoadManager.h"

#include <unistd.h>
#include "Utils_c.h"
#include "hd_transmitdelay.h"
#include <errno.h>
#include "AttributesConvert.h"
#include "sm3.h"

static const char *tag = "csm_hdp11";
static CK_FUNCTION_LIST_PTR function_list_ptr;

#define NORMAL_FIND 0
#define BK_FIND 1
#define EXKEYPAIR_FIND 2
#define SYMKEY_FIND  3


mm_handle sm3Handle = NULL;

static int getAppRecordPath(char* pAppRecordPath,const char* fileName)
{
	char proc_pid_path[256] = {0};
	char buf[256] = {0};
	char task_name[256] = {0};
	char AppName[256] = {0};
	const char* path = "/sdcard/Android/data/";
	char strProcessPath[1024] = {0};
	bool Flag_Proc = false;
	int t = 0;

	if(readlink("/proc/self/exe", strProcessPath,1024) <=0)
	{
		return 1;
	}

	sprintf(proc_pid_path, "/proc/%d/cmdline",(int)getpid());
	FILE* fp = fopen(proc_pid_path, "r");
	if(NULL != fp)
	{
		if( fgets(buf, 255, fp)== NULL )
		{
			fclose(fp);
			LOGSERVERE(tag,"no buf in file");
			return 1;
		}
		fclose(fp);
		sscanf(buf, "%255s", task_name);
	}
	else
	{
		LOGSERVERE(tag,"open fail errno = %d", errno);
		return 1;
	}

	LOGSERVERD(tag,"path name to record: %s\n",buf);

	for(t =0; t< sizeof(task_name); t++)
	{
		if(buf[t] == '/')
		{
			return 1;
		}
		else if(buf[t] == ':')
		{
			memcpy(AppName, task_name, t);
			Flag_Proc = true;
			break;
		}
	}
	if(!Flag_Proc)
	{
		sprintf(AppName, "%s", task_name);

	}

	sprintf(pAppRecordPath, "%s%s/%s", path, AppName, fileName);
	LOGSERVERD(tag,"path name to record1: %s",pAppRecordPath);

	return 0;

}


CK_RV switchSM2template(CK_OBJECT_CLASS keyclass,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount,CK_ATTRIBUTE_PTR pTemplate_new,CK_ULONG_PTR pulCount_new)
{	
	bool findCKA_VALUE = FALSE; 	
	
	if(keyclass == CKO_PUBLIC_KEY)
	{	
		LOGSERVERI(tag,"switch pub key");

		CK_ULONG index_new = 0;
		for(int index = 0; index < ulCount; index++)
		{
			if(pTemplate[index].type!=CKA_VALUE && pTemplate[index].type!= CKA_EXTRACTABLE)
			{	
				pTemplate_new[index_new].type = pTemplate[index].type;
								
				pTemplate_new[index_new].pValue = NULL;
				if(pTemplate[index].pValue)
				{		
					pTemplate_new[index_new].pValue = (CK_BYTE_PTR)malloc(pTemplate[index].ulValueLen);
					
					memcpy(pTemplate_new[index_new].pValue,pTemplate[index].pValue,pTemplate[index].ulValueLen);
				}
				pTemplate_new[index_new].ulValueLen = pTemplate[index].ulValueLen;
				index_new++;
			}
			else if(CKA_VALUE == pTemplate[index].type)
			{				
				findCKA_VALUE = TRUE;
				pTemplate_new[index_new].type = CKA_ECC_BITS_LEN;					
				CK_UINT 	modulusBits = 256;
				pTemplate_new[index_new].pValue = malloc(sizeof(CK_UINT));
				memcpy(pTemplate_new[index_new].pValue,&modulusBits,sizeof(CK_UINT));
				pTemplate_new[index_new].ulValueLen = sizeof(CK_UINT);
				index_new++;
				
				pTemplate_new[index_new].type = CKA_ECC_X_COORDINATE;
				pTemplate_new[index_new].ulValueLen = 32; 				
				pTemplate_new[index_new].pValue = NULL;				
				pTemplate_new[index_new].pValue = (CK_BYTE_PTR)malloc(pTemplate_new[index_new].ulValueLen);					
				memcpy(pTemplate_new[index_new].pValue,(CK_BYTE_PTR)pTemplate[index].pValue,32);
				index_new++;
				
				pTemplate_new[index_new].type = CKA_ECC_Y_COORDINATE;					
				pTemplate_new[index_new].ulValueLen = 32;					
				pTemplate_new[index_new].pValue = NULL; 			
				pTemplate_new[index_new].pValue = (CK_BYTE_PTR)malloc(pTemplate_new[index_new].ulValueLen);
				memcpy(pTemplate_new[index_new].pValue,(CK_BYTE_PTR)pTemplate[index].pValue+32,32);		
				index_new++;
			}
		}
		
		if(!findCKA_VALUE)
		{			
			pTemplate_new[index_new].type = CKA_ECC_BITS_LEN;					
			CK_UINT 	modulusBits = 256;

			pTemplate_new[index_new].pValue = malloc(sizeof(CK_UINT));
			memcpy(pTemplate_new[index_new].pValue,&modulusBits,sizeof(CK_UINT));
			pTemplate_new[index_new].ulValueLen = sizeof(CK_UINT);
			index_new++;					
		}

		memcpy(pulCount_new,&index_new,sizeof(CK_ULONG));

	}
	else if(keyclass == CKO_PRIVATE_KEY)
	{		
		*pulCount_new = ulCount+1;
		
		LOGSERVERI(tag,"switch pri key");
		
		for(int index = 0; index < ulCount; index++)
		{
			if(pTemplate[index].type!=CKA_VALUE)
			{				
				pTemplate_new[index].type = pTemplate[index].type;
				pTemplate_new[index].pValue = NULL;
				if(pTemplate[index].pValue)
				{				
					pTemplate_new[index].pValue = (CK_BYTE_PTR)malloc(pTemplate[index].ulValueLen);
					memcpy(pTemplate_new[index].pValue,pTemplate[index].pValue,pTemplate[index].ulValueLen);
				}
				pTemplate_new[index].ulValueLen = pTemplate[index].ulValueLen;				
			}
			else
			{				
				findCKA_VALUE = TRUE;
				pTemplate_new[index].type = CKA_ECC_BITS_LEN;					
				CK_UINT 	modulusBits = 256;
				pTemplate_new[index].pValue = (CK_BYTE_PTR)malloc(sizeof(CK_UINT));
				memcpy(pTemplate_new[index].pValue,&modulusBits,sizeof(CK_UINT));
				pTemplate_new[index].ulValueLen = sizeof(CK_UINT);

	
				pTemplate_new[ulCount].type = CKA_ECC_PRIVATE;
				pTemplate_new[ulCount].ulValueLen = 32; 				
				pTemplate_new[ulCount].pValue = NULL;				
				pTemplate_new[ulCount].pValue = (CK_BYTE_PTR)malloc(pTemplate_new[ulCount].ulValueLen);
				memcpy(pTemplate_new[ulCount].pValue,pTemplate[index].pValue,32);
			}				
			
		}
		if(!findCKA_VALUE)
		{
			pTemplate_new[ulCount].type = CKA_ECC_BITS_LEN;					
			CK_UINT 	modulusBits = 256;
			pTemplate_new[ulCount].pValue = malloc(sizeof(CK_UINT));
			memcpy(pTemplate_new[ulCount].pValue,&modulusBits,sizeof(CK_UINT));
			pTemplate_new[ulCount].ulValueLen = sizeof(CK_UINT);
		}
	}
	else
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}	

	return CKR_OK;
}

//to adapt the limitation of unwrap template on HD card
void checkAndModifyUnwrapTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulAttributeCount)
{
	int i=0;
	int index_encrypt = INVALID_VALUE;
	int index_decrypt = INVALID_VALUE;
	bool temp_unwrap = CK_FALSE;
	bool temp_wrap = CK_FALSE;
	bool ffalse = CK_FALSE;
	CK_OBJECT_CLASS keyclass = 0;
	
	CK_KEY_TYPE getkeytype = get_KeytypeAndClass(pTemplate,ulAttributeCount, &keyclass);
	if(getkeytype!=CKK_SM4)
	{
		return;
	}

	for(i=0;i<ulAttributeCount;i++)
	{
		switch(pTemplate[i].type)
		{
			case(CKA_ENCRYPT):
				index_encrypt = i;
				break;
			case(CKA_DECRYPT):
				index_decrypt = i;
				break;
			case(CKA_UNWRAP):
				temp_unwrap =*(bool *) pTemplate[i].pValue;
				break;
			case(CKA_WRAP):
				temp_wrap =*(bool *) pTemplate[i].pValue;
				break;
			default:
				break;
		}		
	}

	if(temp_unwrap && index_encrypt!= INVALID_VALUE)
	{
        LOGSERVERI(tag,"%s, set encrypt",__FUNCTION__);
		memcpy(pTemplate[index_encrypt].pValue,&ffalse,sizeof(CK_BBOOL));
	}

	if(temp_wrap && index_decrypt!= INVALID_VALUE)
	{
        LOGSERVERI(tag,"%s, set decrypt",__FUNCTION__);
		memcpy(pTemplate[index_decrypt].pValue,&ffalse,sizeof(CK_BBOOL));
	}
}


static CK_RV (*Pointer_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
static CK_RV (*Pointer_C_CryptoExtend)(CK_SESSION_HANDLE hSession,
                                       CK_EXTEND_IN_PTR pExtendIn,
                                       CK_EXTEND_OUT_PTR pExtendOut,
                                       CK_VOID_PTR pReserved );

static CK_RV (*Pointer_C_ExtendSetLogger)(CK_LOGGER logInst);
static int (*Pointer_CC_SetTransmitDelay)(unsigned int nDelay1, unsigned int nDelay2);

 P11func_HD::P11func_HD(){
    libLoadManager = new LibLoadManager(libPath);
	Pointer_C_GetFunctionList = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))libLoadManager->GetFuncPointer("C_GetFunctionList");	
	Pointer_C_GetFunctionList(&function_list_ptr);			
    Pointer_C_CryptoExtend = (CK_RV (*)(CK_SESSION_HANDLE,CK_EXTEND_IN_PTR,CK_EXTEND_OUT_PTR,CK_VOID_PTR))libLoadManager->GetFuncPointer("C_CryptoExtend");
	Pointer_C_ExtendSetLogger = (CK_RV (*)(CK_LOGGER))libLoadManager->GetFuncPointer("C_ExtendSetLogger");
	Pointer_CC_SetTransmitDelay = (int (*)(unsigned int,unsigned int))libLoadManager->GetFuncPointer("cc_SetTransmitDelay");
}

 P11func_HD::~P11func_HD() {
 	LOGSERVERI(tag, "%s IN",__FUNCTION__);
 	if(libLoadManager!= NULL)
	{		
		delete libLoadManager;
		libLoadManager = NULL;
	}
    mutex.Unlock();
}

string P11func_HD::GetDes() {
	return Describe;
}

 
bool plog_init_HD1 = false;

bool initPlogHD(const char * filename, const char * defaultRecordPath)
 {
	 char recordPath[256] = {0};
 
	 if (!plog_init_HD1)
	 {
		 LOGSERVERI(tag,"HD initialize plog interface...");
	 
		 if(getApplogPath(recordPath,filename))
		 {
			 sprintf(recordPath, "%s", defaultRecordPath);
		 }
 
		 plog::init<1>(plog::debug, recordPath, 10*1024*1024, 10);
		 plog_init_HD1 = true;
 
		 LOGSERVERI(tag,"HD initialize plog interface done...");
		 
	 }
	 else
	 {
		 LOGSERVERI(tag,"HD plog interface already initialized...");
		 return true;
	 }
 
	 return true;
 }
 

 void log_p11(CK_LOG_SEVERITY severity, const char* func, unsigned int line, const char* file, const char* format,	...)
 {
	 char buf[2048] = { 0 };
	 va_list arg;
 
	 if(!(plog::get<1>()
		 && plog::get<1>()->checkSeverity(static_cast<plog::Severity>(severity))))
			 return;
 
	 va_start(arg, format);

	 vsnprintf(buf, 2048,format, arg);

	 va_end(arg);
 
	 (*plog::get<1>()) += plog::Record(static_cast<plog::Severity>(severity), func, line, file, PLOG_GET_THIS()) << buf;
 
	 return;
 }


 CK_RV P11func_HD::Adapter_C_Initialize(CK_VOID_PTR   pInitArgs)
{	
	CK_RV ret = 0;
	
	char recordPath[256] = {0};
	const char* defaultRecordPath = "/sdcard/hdlog.txt";

	initPlogHD("hdlog.txt", defaultRecordPath);
	
	ret = Pointer_C_ExtendSetLogger(log_p11);

	if(ret != CKR_OK)
	{		
		LOGSERVERE(tag,"C_ExtendSetLogger rv = %lu",ret);
	}

    mutex.Lock();
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
    ret = function_list_ptr->C_Initialize(pInitArgs);
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
    mutex.Unlock();
    return ret;
}

 CK_RV P11func_HD::Adapter_C_Finalize(CK_VOID_PTR   pReserved)
{
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_Finalize(pReserved);
  mutex.Unlock();
  return ret;
}



/* Adapter_C_GetInfo returns general information about Cryptoki. */
 CK_RV P11func_HD::Adapter_C_GetInfo(CK_INFO_PTR   pInfo)
{
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_GetInfo(pInfo);
  mutex.Unlock();
  return ret;
}



/* Adapter_C_GetFunctionList returns the function list. */
 CK_RV P11func_HD::Adapter_C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR pfunction_list_ptr)
{
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_GetFunctionList(pfunction_list_ptr);
  mutex.Unlock();
  return ret;
}




/* Slot and token management */

/* Adapter_C_GetSlotList obtains a list of slots in the system. */
 CK_RV P11func_HD::Adapter_C_GetSlotList(CK_BBOOL       tokenPresent,  /* only slots with tokens */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
)
{  
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_GetSlotList(tokenPresent, pSlotList, pulCount);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx, ulcount = %ld",__FUNCTION__,ret,*pulCount);
  return ret;
}



/* Adapter_C_GetSlotInfo obtains information about a particular slot in
 * the system.
 */
 CK_RV P11func_HD::Adapter_C_GetSlotInfo(
  CK_SLOT_ID       slotID,  /* the ID of the slot */
  CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
)
{
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_GetSlotInfo(slotID,  pInfo);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_GetTokenInfo obtains information about a particular token
 * in the system.
 */
 CK_RV P11func_HD::Adapter_C_GetTokenInfo(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
)
{ 
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_GetTokenInfo(slotID,pInfo);
  mutex.Unlock();
  return ret;
}



/* Adapter_C_GetMechanismList obtains a list of mechanism types
 * supported by a token.
 */
 CK_RV P11func_HD::Adapter_C_GetMechanismList(
  CK_SLOT_ID            slotID,          /* ID of token's slot */
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
)
{
  
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_GetMechanismList(slotID, pMechanismList, pulCount);
  mutex.Unlock();
  return ret;
}



/* Adapter_C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token.
 */
 CK_RV P11func_HD::Adapter_C_GetMechanismInfo(
  CK_SLOT_ID            slotID,  /* ID of the token's slot */
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
  
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_GetMechanismInfo(slotID, type, pInfo);
  mutex.Unlock();
  return ret;
}



/* Adapter_C_InitToken initializes a token. */
 CK_RV P11func_HD::Adapter_C_InitToken(
  CK_SLOT_ID      slotID,    /* ID of the token's slot */
  CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
  CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
  CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
)
{  
	LOGSERVERI(tag,"%s IN",__FUNCTION__);

	mutex.Lock();
	CK_RV ret = function_list_ptr->C_InitToken(slotID,pPin,ulPinLen,pLabel);
	mutex.Unlock();

	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}



/* Adapter_C_InitPIN initializes the normal user's PIN. */
 CK_RV P11func_HD::Adapter_C_InitPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{ 
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	mutex.Lock();
	CK_RV ret = function_list_ptr->C_InitPIN(hSession,pPin,ulPinLen);
	mutex.Unlock();

	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}



/* Adapter_C_SetPIN modifies the PIN of the user who is logged in. */
 CK_RV P11func_HD::Adapter_C_SetPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
	CK_EXTEND_IN ExtIn_VerifyPin = {CK_EXTEND_VERIFYPIN, pOldPin,ulOldLen};
	CK_EXTEND_OUT ExtOut_VerifyPin = {CK_EXTEND_VERIFYPIN, NULL, 0};

	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_VerifyPin, &ExtOut_VerifyPin, NULL);
	mutex.Unlock();

	if(ret != CKR_OK){
		LOGSERVERI(tag,"%s OUT1,ret = 0x%lx",__FUNCTION__,ret);
		return ret;
	}	
	
	mutex.Lock();
	ret = function_list_ptr->C_SetPIN(hSession,pOldPin,ulOldLen,pNewPin,ulNewLen);
	mutex.Unlock();

	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}




/* Session management */

/* Adapter_C_OpenSession opens a session between an application and a
 * token.
 */
 CK_RV P11func_HD::Adapter_C_OpenSession(
  CK_SLOT_ID            slotID,        /* the slot's ID */
  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
  CK_VOID_PTR           pApplication,  /* passed to callback */
  CK_NOTIFY             Notify,        /* callback function */
  CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{ 
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	mutex.Lock();
	CK_RV ret = function_list_ptr->C_OpenSession(slotID,flags,pApplication,Notify,phSession);
	mutex.Unlock();

	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}



/* Adapter_C_CloseSession closes a session between an application and a
 * token.
 */
 CK_RV P11func_HD::Adapter_C_CloseSession(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{  
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_CloseSession(hSession);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_CloseAllSessions closes all sessions with a token. */
 CK_RV P11func_HD::Adapter_C_CloseAllSessions(
  CK_SLOT_ID     slotID  /* the token's slot */
)
{  
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_CloseAllSessions(slotID);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_GetSessionInfo obtains information about the session. */
 CK_RV P11func_HD::Adapter_C_GetSessionInfo(
  CK_SESSION_HANDLE   hSession,  /* the session's handle */
  CK_SESSION_INFO_PTR pInfo      /* receives session info */
)
{
  
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_GetSessionInfo(hSession, pInfo);
  mutex.Unlock();
  return ret;
}



/* Adapter_C_GetOperationState obtains the state of the cryptographic operation
 * in a session.
 */
 CK_RV P11func_HD::Adapter_C_GetOperationState(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
  
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_GetOperationState(hSession,pOperationState,pulOperationStateLen);
  mutex.Unlock();
  return ret;
}


/* Adapter_C_SetOperationState restores the state of the cryptographic
 * operation in a session.
 */
 CK_RV P11func_HD::Adapter_C_SetOperationState(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
)
{
  
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_SetOperationState(hSession,pOperationState,ulOperationStateLen,hEncryptionKey,hAuthenticationKey);
  mutex.Unlock();
  return ret;
}



/* Adapter_C_Login logs a user into a token. */
 CK_RV P11func_HD::Adapter_C_Login(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
)
{ 
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	mutex.Lock();
	CK_RV ret = function_list_ptr->C_Login(hSession,userType,pPin,ulPinLen);
	mutex.Unlock();
	int delay = 0;
	bool result = FALSE;
	char recordPath_para[256] = {0};
	char buf[256] = {0};
	

	//set transmit delay for HD card at first time login
	if(ret == CKR_OK)
	{
		//check if the para file exists. If not, ran training to get para		
		CK_RV rv = getAppRecordPath(recordPath_para,"para.txt");
		if(rv == CKR_OK)
		{
			FILE* file_para = fopen(recordPath_para,"r");
			if(file_para!= NULL)
			{
				if(fgets(buf, 255, file_para)!=NULL)
				{
					int getdelay1 = atoi(buf);
					LOGSERVERI(tag, "set transmit: %d",getdelay1);
					mutex.Lock();
					Pointer_CC_SetTransmitDelay(getdelay1,500);
					mutex.Unlock();

					fclose(file_para);
					file_para = NULL;
					LOGSERVERI(tag,"%s OUT1 with ret = 0x%lx",__FUNCTION__,ret);
					return ret;
				}

				fclose(file_para);
				file_para = NULL;
			}
						
			mutex.Lock();
			result = HD_TransmitDelay_Traning(Pointer_CC_SetTransmitDelay,function_list_ptr,hSession,1000,3400,400,600,200,100, 7, &delay);
			mutex.Unlock();
			
			if(result)
			{
				LOGSERVERI(tag,"set transmit %d", delay);
				mutex.Lock();
				Pointer_CC_SetTransmitDelay(delay,500);
				mutex.Unlock();

				//record the para into file
				file_para = fopen(recordPath_para,"w+");
				if(file_para)
				{
					sprintf(buf, "%d", delay);
					fputs(buf, file_para);
					fclose(file_para);
					file_para = NULL;
				}
				else
				{
					LOGSERVERE(tag, "write training record fail, errno is %d", errno);
				}				
			}
			else
			{
				LOGSERVERE(tag,"delay training failed");
			}								
		}
		
	}

	LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}




/* Adapter_C_Logout logs a user out from a token. */
 CK_RV P11func_HD::Adapter_C_Logout(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_Logout(hSession);
  mutex.Unlock();
  return ret;
}


/* Object management */

/* Adapter_C_CreateObject creates a new object. */
 CK_RV P11func_HD::Adapter_C_CreateObject(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
)
{
	CK_RV ret = 0;
	CK_OBJECT_CLASS key_class;
	CK_ATTRIBUTE_PTR pTemplate_new = NULL;
	CK_ULONG ulCountnew = 0;
	LOGSERVERI(tag, "%s IN",__FUNCTION__);
	if(get_KeytypeAndClass(pTemplate,ulCount,&key_class) == CKK_SM2)
	{		
		pTemplate_new = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * (ulCount+2));	
		ret = switchSM2template(key_class,pTemplate,ulCount,pTemplate_new,&ulCountnew);
		
		if(ret == CKR_OK)
		{
			mutex.Lock();
			ret = function_list_ptr->C_CreateObject(hSession,pTemplate_new,ulCountnew,phObject);
			mutex.Unlock();
		}	

		freeTemplate(&pTemplate_new,ulCountnew);
	}
	else{
	  mutex.Lock();
	  ret = function_list_ptr->C_CreateObject(hSession,pTemplate,ulCount,phObject);
	  mutex.Unlock();
	}
	
	LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}




/* Adapter_C_CopyObject copies an object, creating a new object for the
 * copy.
 */
 CK_RV P11func_HD::Adapter_C_CopyObject(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_OBJECT_HANDLE     hObject,     /* the object's handle */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
  CK_ULONG             ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
)
{
  
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_CopyObject(hSession,hObject,pTemplate,ulCount,phNewObject);
  mutex.Unlock();
  LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}




/* Adapter_C_DestroyObject destroys an object. */
 CK_RV P11func_HD::Adapter_C_DestroyObject(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
)
{ 
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = CKR_OK;
	if(hObject == 0xFFFFFFFF)
	{
		LOGSERVERI(tag, "destroy exkeypair");
		return ret;
	}

	mutex.Lock();
	ret = function_list_ptr->C_DestroyObject(hSession,hObject);
	mutex.Unlock();
	LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
	return ret;

}



/* Adapter_C_GetObjectSize gets the size of an object in bytes. */
 CK_RV P11func_HD::Adapter_C_GetObjectSize(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
) 
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	mutex.Lock();
	CK_RV ret = function_list_ptr->C_GetObjectSize(hSession,hObject,pulSize);
	mutex.Unlock();
	LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}




/* Adapter_C_GetAttributeValue obtains the value of one or more object
 * attributes.
 */
/*
	when client wants to get an object's attribute:
	1. check if CKA_VAUE is among the required attributes' type. if not, nothing needs to be 
	modified. Call TF card with original parameters directly
	2. if the answer is 'yes' in step 1, check if the CKA_CLASS of the require object is CKO_PUBLIC_KEY by hObject.
	3. if the answer is 'yes' in step 2, which means client wants to get the value of a publickey, 
	check CKA_ISEXCHANGEKEY attr.
	4. if the answer is 'yes' in step 3, which means client is trying to get the value of the publickey used in 
	keyexchange process, call the extend interface(C_CryptoExtend) to get the public key value. 
	5. Otherwise, modify the SM2 template attr to HD definition and then call C_GetAttributeValue with the modified template
	to get required attribute value.
*/
 CK_RV P11func_HD::Adapter_C_GetAttributeValue(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount     /* attributes in template */
)
{
	int i=0;
	CK_RV ret = 0;
	
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	for(i=0;i<ulCount;i++)
	{
		if(pTemplate[i].type==CKA_VALUE)
		{		
			CK_OBJECT_CLASS getclass = -1;
			CK_ATTRIBUTE getclassTemplate[1] = {
				{CKA_CLASS, &getclass, sizeof(CK_OBJECT_CLASS)}
			};

			//get the object's class
			mutex.Lock();
			ret = function_list_ptr->C_GetAttributeValue(hSession,hObject,&getclassTemplate[0],1);
			mutex.Unlock();
			LOGSERVERI(tag,"getclass is 0x%lx",getclass);

			if(ret!=CKR_OK)
			{				
				LOGSERVERE(tag,"C_GetAttributeValue1 rv is 0x%lx",ret);
				return ret;
			}

			if(getclass != CKO_PUBLIC_KEY)
			{
				break;
			}
			
			else
			{
				CK_ULONG ulCountnew = ulCount+2;
				CK_ATTRIBUTE_PTR pTemplate_new = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * ulCountnew);
				if(NULL==pTemplate_new)
				{
					LOGSERVERE(tag,"%s, malloc fail",__FUNCTION__);
					return CKR_FUNCTION_FAILED;
				}
				
				switchSM2template(getclass, pTemplate, ulCount, pTemplate_new, &ulCountnew);

				mutex.Lock();
				ret = function_list_ptr->C_GetAttributeValue(hSession,hObject,pTemplate_new,ulCountnew);
				mutex.Unlock();

				if(ret!=CKR_OK)
				{
					return ret;
				}

				//copy got template value to origin parameter
				for(i=0;i<ulCount;i++)
				{					
					if(pTemplate[i].type!=CKA_VALUE)
					{				
						pTemplate[i].ulValueLen = pTemplate_new[i].ulValueLen;
						if(pTemplate[i].pValue)
						{
							memcpy(pTemplate[i].pValue,pTemplate_new[i].pValue,pTemplate_new[i].ulValueLen);
						}
					}
					else
					{
						pTemplate[i].ulValueLen = 64;
						if(pTemplate[i].pValue)
						{
							memcpy(pTemplate[i].pValue,pTemplate_new[ulCount].pValue,32);						
							memcpy((CK_BYTE_PTR)pTemplate[i].pValue+32,(CK_BYTE_PTR)pTemplate_new[ulCount+1].pValue,32);
						}
					}
				}

				freeTemplate(&pTemplate_new,ulCountnew);

				
				LOGSERVERI(tag,"%s OUT2 with ret = 0x%lx", __FUNCTION__,ret);

				return ret;
				
			}
		}
	}	

	
    LOGSERVERI(tag,"%s IN2",__FUNCTION__);

	mutex.Lock();
	ret = function_list_ptr->C_GetAttributeValue(hSession,hObject,pTemplate,ulCount);
	
	mutex.Unlock();
	
	LOGSERVERI(tag,"%s OUT with ret = 0x%lx", __FUNCTION__, ret);
	return ret;
}




/* Adapter_C_SetAttributeValue modifies the value of one or more object
 * attributes.
 */
 //vector public key value?
 CK_RV P11func_HD::Adapter_C_SetAttributeValue(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
)
{ 
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_SetAttributeValue(hSession,hObject,pTemplate,ulCount);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}




/* Adapter_C_FindObjectsInit initializes a search for token and session
 * objects that match a template.
 */
//find public key by key value? 
 CK_RV P11func_HD::Adapter_C_FindObjectsInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
)
{
	LOGSERVERI(tag,"%s IN NEW",__FUNCTION__);
	int i=0;

	if(pTemplate == NULL_PTR || ulCount == 0){
		return CKR_ARGUMENTS_BAD;
	}

	if(findtypemap.find(hSession)!=findtypemap.end()){
		LOGSERVERE(tag,"already find init, hsession = %lu",hSession);
		return CKR_OPERATION_ACTIVE;
	}

	findtypemap[hSession] = NORMAL_FIND;
    CK_RV ret = 0;
    for(i=0;i<ulCount;i++)
	{
		if(pTemplate[i].type == CKA_SESSKEY_ID)
		{		
			if(!memcmp(pTemplate[i].pValue,&nSessKeyBK,sizeof(CK_BYTE)))
			{
				LOGSERVERI(tag, "find BK");
				findtypemap[hSession] = BK_FIND;

			}
			else
			{		
				LOGSERVERI(tag,"find symmetric key");
				findtypemap[hSession] = SYMKEY_FIND;
				
				CK_BYTE id = 0;
				CK_BBOOL tokenvalue = CK_FALSE;
				CK_BBOOL encryptvalue = CK_FALSE;
				CK_BBOOL decryptvalue = CK_FALSE;
				CK_BBOOL extractvalue = CK_FALSE;
				CK_BBOOL skwrapvalue = CK_FALSE;
				CK_BBOOL skunwrapvalue = CK_FALSE;
				CK_BBOOL wraptrustvalue = CK_FALSE;
				CK_KEY_TYPE tempKeyType = CKK_SM4;
				CK_ATTRIBUTE psesstemp[10] = {
					{CKA_CLASS, &keyClass, sizeof(keyClass)},
					{CKA_TOKEN, &tokenvalue, sizeof(CK_BBOOL)},
					{CKA_KEY_TYPE, &tempKeyType, sizeof(CK_KEY_TYPE)},
					{CKA_ENCRYPT, &encryptvalue, sizeof(CK_BBOOL)},
					{CKA_DECRYPT, &decryptvalue, sizeof(CK_BBOOL)},
					{CKA_EXTRACTABLE,&extractvalue,sizeof(CK_BBOOL)},
					{CKA_WRAP_WITH_TRUSTED,&wraptrustvalue,sizeof(CK_BBOOL)},
					{CKA_SESSKEY_ID, &id,sizeof(CK_BYTE)},
					{CKA_WRAP,&skwrapvalue,sizeof(CK_BBOOL)},
					{CKA_UNWRAP,&skunwrapvalue,sizeof(CK_BBOOL)}
				};

				memcpy(psesstemp[7].pValue,pTemplate[i].pValue,sizeof(CK_BYTE));
				
				int j=0;
				for(j=0;j<ulCount;j++){
					if(pTemplate[j].type == CKA_TOKEN)
					{
						memcpy(psesstemp[1].pValue,pTemplate[j].pValue,sizeof(CK_BBOOL));
					}

					if(pTemplate[j].type == CKA_KEY_TYPE)
					{ 	
						memcpy(psesstemp[2].pValue,pTemplate[j].pValue,sizeof(CK_KEY_TYPE));
					}

					if(pTemplate[j].type == CKA_ENCRYPT)
					{
						memcpy(psesstemp[3].pValue, pTemplate[j].pValue,sizeof(CK_BBOOL));
					}
					if(pTemplate[j].type == CKA_DECRYPT)
					{
						memcpy(psesstemp[4].pValue,pTemplate[j].pValue,sizeof(CK_BBOOL));
					}
					if(pTemplate[j].type == CKA_EXTRACTABLE)
					{
						memcpy(psesstemp[5].pValue,pTemplate[j].pValue,sizeof(CK_BBOOL));
					}
					if(pTemplate[j].type == CKA_WRAP_WITH_TRUSTED)
					{		
						memcpy(psesstemp[6].pValue,pTemplate[j].pValue,sizeof(CK_BBOOL));
					}

					if(pTemplate[j].type == CKA_WRAP)
					{
						memcpy(psesstemp[8].pValue,pTemplate[j].pValue,sizeof(CK_BBOOL));
					}

					if(pTemplate[j].type == CKA_UNWRAP)
					{
						memcpy(psesstemp[9].pValue,pTemplate[j].pValue,sizeof(CK_BBOOL));
					}								
				}

				CK_OBJECT_HANDLE hKey_Enc = 0;
				mutex.Lock();	
				ret = function_list_ptr->C_CreateObject(hSession, psesstemp, sizeof(psesstemp)/sizeof(CK_ATTRIBUTE), &hKey_Enc);		
				mutex.Unlock();
				
				if(ret == CKR_OK){
					mapsymkeyhandle[hSession] = hKey_Enc;
				}else{
					LOGSERVERE(tag,"%s,createobject,ret = 0x%lx",__FUNCTION__,ret);
				}
			}
		}

		if(pTemplate[i].type == CKA_ISEXCHANGEKEY)
		{
			LOGSERVERI(tag,"find exchangekey");
			findtypemap[hSession] = EXKEYPAIR_FIND;
		}
	}

	if(findtypemap[hSession])
	{  	
		LOGSERVERI(tag,"%s OUT2",__FUNCTION__);
		return 0;
	}
		

	mutex.Lock();
	ret = function_list_ptr->C_FindObjectsInit(hSession,pTemplate,ulCount);
	mutex.Unlock();

	if(ret != CKR_OK){
		findtypemap.erase(hSession);
	}

	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}



/* Adapter_C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles.
 */
 CK_RV P11func_HD::Adapter_C_FindObjects(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{	
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;

	if(findtypemap[hSession] == EXKEYPAIR_FIND)
	{
		*pulObjectCount = 1;
		*phObject = 0xFFFFFFFF;
		LOGSERVERI(tag,"%s OUT(exkeypair)",__FUNCTION__);
		return ret;
	}

	if(findtypemap[hSession] == BK_FIND)
	{	
		mutex.Lock();
		ret = function_list_ptr->C_CreateObject(hSession, BKTemplate, sizeof(BKTemplate)/sizeof(CK_ATTRIBUTE), phObject);
		mutex.Unlock();
		*pulObjectCount = 1;
		LOGSERVERI(tag,"%s OUT(BK),hobject = 0x%lx",__FUNCTION__,*phObject);
		return ret;
	}
	
	if(findtypemap[hSession] == SYMKEY_FIND)
	{
		CK_OBJECT_HANDLE hKey_Enc=0;
		if(mapsymkeyhandle.find(hSession) != mapsymkeyhandle.end()){
			hKey_Enc = mapsymkeyhandle[hSession];
			*pulObjectCount = 1;
			memcpy(phObject,&hKey_Enc,sizeof(CK_OBJECT_HANDLE));
			LOGSERVERI(tag,"hKey_Enc is 0x%lx", hKey_Enc);
		}
		else{
			LOGSERVERE(tag,"no sym key found!");
		}
	}
	else
	{
		mutex.Lock();		
		ret = function_list_ptr->C_FindObjects(hSession,phObject,ulMaxObjectCount,pulObjectCount);
		mutex.Unlock();
	}

	
	LOGSERVERI(tag,"%s OUT with ret = 0x%lx,count = %lu, hobject0 = 0x%lx",__FUNCTION__,ret,*pulObjectCount,*phObject);
	return ret;

}



/* Adapter_C_FindObjectsFinal finishes a search for token and session
 * objects.
 */
 CK_RV P11func_HD::Adapter_C_FindObjectsFinal(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{	
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  
  if(findtypemap[hSession])
  {  	
	LOGSERVERI(tag,"%s OUT2",__FUNCTION__);
	
	if(findtypemap[hSession] == SYMKEY_FIND){
		mapsymkeyhandle.erase(hSession);
	}	
	findtypemap.erase(hSession);
  	return 0;
  }

  mutex.Lock();
  CK_RV ret = function_list_ptr->C_FindObjectsFinal(hSession);
  mutex.Unlock();

  if(ret == CKR_OK){
  	findtypemap.erase(hSession);
  }
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}




/* Encryption and decryption */

/* Adapter_C_EncryptInit initializes an encryption operation. */
 CK_RV P11func_HD::Adapter_C_EncryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{	
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	mutex.Lock();
	CK_RV ret = function_list_ptr->C_EncryptInit(hSession,pMechanism,hKey);
	mutex.Unlock();
	
	//HD TF card doesn't support normal ZUC EEA, store IV for later use
	if(ret == CKR_OK)
	{
		memcpy(&mechmap_enc[hSession],&pMechanism->mechanism,sizeof(CK_MECHANISM_TYPE));
		if(pMechanism->mechanism == CKM_ZUC_EEA){
			IV_struct tmp_iv;
			int temp_len = sizeof(pMechanism->ulParameterLen)<sizeof(tmp_iv.iv)?sizeof(pMechanism->ulParameterLen):sizeof(tmp_iv.iv);
			memcpy(tmp_iv.iv,pMechanism->pParameter,temp_len);
			zucivmap_enc.insert(std::pair <CK_SESSION_HANDLE,IV_struct>(hSession, tmp_iv));
		}	
	}
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}



/* Adapter_C_Encrypt encrypts single-part data. */
 CK_RV P11func_HD::Adapter_C_Encrypt(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
)
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_BYTE *pzucdata = NULL;
    CK_RV ret = 0;
	//if inited to ZUC, copy iv ahead of data
	if(mechmap_enc[hSession] == CKM_ZUC_EEA)
	{
		pzucdata = (CK_BYTE *)malloc((ulDataLen+5)*sizeof(CK_BYTE));

		if(NULL==pzucdata)
		{
			LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
			return CKR_FUNCTION_FAILED;
		}

		CK_BYTE ZUCDB = zucivmap_enc[hSession].iv[11]<5+zucivmap_enc[hSession].iv[7];
		memcpy(pzucdata,zucivmap_enc[hSession].iv,4);
		memcpy(pzucdata+4,&ZUCDB,1);	
		memcpy(pzucdata+5,pData,ulDataLen);
		
		mutex.Lock();
        ret = function_list_ptr->C_Encrypt(hSession,pzucdata,ulDataLen+5,pEncryptedData,pulEncryptedDataLen);
		mutex.Unlock();
	
		
		free(pzucdata);
		pzucdata = NULL;
	}
	else{
		mutex.Lock();
        ret = function_list_ptr->C_Encrypt(hSession,pData,ulDataLen,pEncryptedData,pulEncryptedDataLen);
		mutex.Unlock();
	}
	
	LOGSERVERI(tag, "%s OUT, ulEncryptedDataLen is %ld", __FUNCTION__, (*pulEncryptedDataLen));
	return ret;
}




/* Adapter_C_EncryptUpdate continues a multiple-part encryption
 * operation.
 */
 CK_RV P11func_HD::Adapter_C_EncryptUpdate(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
)
{ 
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_BYTE *pzucdata = NULL;
	CK_RV ret = 0;
	//if inited to ZUC, copy iv ahead of data
	if(mechmap_enc[hSession] == CKM_ZUC_EEA)
	{
		pzucdata = (CK_BYTE *)malloc((ulPartLen+5)*sizeof(CK_BYTE));

		if(NULL==pzucdata)
		{
		  LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		  return CKR_FUNCTION_FAILED;
		}

		CK_BYTE ZUCDB = zucivmap_enc[hSession].iv[11]<5+zucivmap_enc[hSession].iv[7];
		memcpy(pzucdata,zucivmap_enc[hSession].iv,4);
		memcpy(pzucdata+4,&ZUCDB,1); 
		memcpy(pzucdata+5,pPart,ulPartLen);

		mutex.Lock();
		ret = function_list_ptr->C_EncryptUpdate(hSession,pzucdata,ulPartLen+5,pEncryptedPart,pulEncryptedPartLen);
		mutex.Unlock();

		free(pzucdata);
		pzucdata = NULL;
	  
	}
	else
	{
		mutex.Lock();
		ret = function_list_ptr->C_EncryptUpdate(hSession,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
		mutex.Unlock();
	} 

	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}



/* Adapter_C_EncryptFinal finishes a multiple-part encryption
 * operation.
 */
 CK_RV P11func_HD::Adapter_C_EncryptFinal(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
)
{ 
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_EncryptFinal(hSession,pLastEncryptedPart,pulLastEncryptedPartLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_DecryptInit initializes a decryption operation. */
 CK_RV P11func_HD::Adapter_C_DecryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
)
{ 
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_DecryptInit(hSession,pMechanism,hKey);
  mutex.Unlock();
  
  //HD TF card doesn't support normal ZUC EEA, store IV for later use
  if(ret == CKR_OK)
  {  
	  memcpy(&mechmap_dec[hSession],&pMechanism->mechanism,sizeof(CK_MECHANISM_TYPE));
	  if(pMechanism->mechanism == CKM_ZUC_EEA){
		  IV_struct tmp_iv;		  
		  int temp_len = sizeof(pMechanism->ulParameterLen)<sizeof(tmp_iv.iv)?sizeof(pMechanism->ulParameterLen):sizeof(tmp_iv.iv);
		  memcpy(tmp_iv.iv,pMechanism->pParameter,temp_len);
		  zucivmap_dec.insert(std::pair <CK_SESSION_HANDLE,IV_struct>(hSession, tmp_iv));
	  }   
  }
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_Decrypt decrypts encrypted data in a single part. */
 CK_RV P11func_HD::Adapter_C_Decrypt(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_BYTE *pzucdata = NULL;
	CK_RV ret = 0;
	//if inited to ZUC, copy iv ahead of data
	if(mechmap_dec[hSession] == CKM_ZUC_EEA)
	{
		pzucdata = (CK_BYTE *)malloc((ulEncryptedDataLen+5)*sizeof(CK_BYTE));
		if(NULL==pzucdata)
		{
		  LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		  return CKR_FUNCTION_FAILED;
		}
		  
		CK_BYTE ZUCDB = zucivmap_dec[hSession].iv[11]<5+zucivmap_dec[hSession].iv[7];
		memcpy(pzucdata,zucivmap_dec[hSession].iv,4);
		memcpy(pzucdata+4,&ZUCDB,1);
		memcpy(pzucdata+5,pEncryptedData,ulEncryptedDataLen);

		mutex.Lock();
		ret = function_list_ptr->C_Decrypt(hSession,pzucdata,ulEncryptedDataLen+5,pData,pulDataLen);
		mutex.Unlock();

		free(pzucdata);
		pzucdata = NULL;
	}
	else{
		mutex.Lock();
		ret = function_list_ptr->C_Decrypt(hSession,pEncryptedData,ulEncryptedDataLen,pData,pulDataLen);
		mutex.Unlock();
	}
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_DecryptUpdate continues a multiple-part decryption
 * operation.
 */
 CK_RV P11func_HD::Adapter_C_DecryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
)
{
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  CK_BYTE *pzucdata = NULL;
    CK_RV ret = 0;
  //if inited to ZUC, copy iv ahead of data
  if(mechmap_dec[hSession] == CKM_ZUC_EEA)
  {
		pzucdata = (CK_BYTE *)malloc((ulEncryptedPartLen+5)*sizeof(CK_BYTE));
		if(NULL==pzucdata)
		{
		  LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		  return CKR_FUNCTION_FAILED;
		}

		CK_BYTE ZUCDB = zucivmap_dec[hSession].iv[11]<5+zucivmap_dec[hSession].iv[7];
		memcpy(pzucdata,zucivmap_dec[hSession].iv,4);
		memcpy(pzucdata+4,&ZUCDB,1);
		memcpy(pzucdata+5,pEncryptedPart,ulEncryptedPartLen);

		mutex.Lock();
		ret = function_list_ptr->C_DecryptUpdate(hSession,pzucdata,ulEncryptedPartLen+5,pPart,pulPartLen);
		mutex.Unlock();


		free(pzucdata);
		pzucdata = NULL;
  }
  else{	
		mutex.Lock();
		ret = function_list_ptr->C_DecryptUpdate(hSession,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
		mutex.Unlock();
  }

  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_DecryptFinal finishes a multiple-part decryption
 * operation.
 */
 CK_RV P11func_HD::Adapter_C_DecryptFinal(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{ 
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_DecryptFinal(hSession,pLastPart,pulLastPartLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}




/* Message digesting */

/* Adapter_C_DigestInit initializes a message-digesting operation. */
 CK_RV P11func_HD::Adapter_C_DigestInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
	LOGSERVERI(tag, "%s IN, Mech is 0x%lx", __FUNCTION__, pMechanism->mechanism);
	CK_RV ret = 0;
	mutex.Lock();

	sm3Handle = sm3_init();
	mutex.Unlock();

	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}



/* Adapter_C_Digest digests data in a single part. */
 CK_RV P11func_HD::Adapter_C_Digest(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
)
{ 
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	mutex.Lock();

    if(pulDigestLen){
        *pulDigestLen = 32;
        if(pDigest){
            sm3_hash(pData,ulDataLen,pDigest);
        }
    }

    CK_RV ret = CKR_OK;
	mutex.Unlock();
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);

	return ret;
}



/* Adapter_C_DigestUpdate continues a multiple-part message-digesting
 * operation.
 */
 CK_RV P11func_HD::Adapter_C_DigestUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{ 
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	mutex.Lock();
	CK_RV ret = CKR_OK;//= function_list_ptr->C_DigestUpdate(hSession,pPart,ulPartLen);
	sm3_process(sm3Handle,pPart,ulPartLen);
	mutex.Unlock();

	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}



/* Adapter_C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested.
 */
 CK_RV P11func_HD::Adapter_C_DigestKey(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{ 
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_DigestKey(hSession,hKey);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_DigestFinal finishes a multiple-part message-digesting
 * operation.
 */
 CK_RV P11func_HD::Adapter_C_DigestFinal(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{  
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_DigestFinal(hSession,pDigest,pulDigestLen);
    if(pulDigestLen){
        *pulDigestLen = 32;
        if(pDigest){
            sm3_unit(sm3Handle,pDigest);
        }
    }

  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}




/* Signing and MACing */

/* Adapter_C_SignInit initializes a signature (private key encryption)
 * operation, where the signature is (will be) an appendix to
 * the data, and plaintext cannot be recovered from the
 * signature.
 */
 CK_RV P11func_HD::Adapter_C_SignInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signature key */
)
{ 
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_SignInit(hSession,pMechanism,hKey);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_Sign signs (encrypts with private key) data in a single
 * part, where the signature is (will be) an appendix to the
 * data, and plaintext cannot be recovered from the signature.
 */
 CK_RV P11func_HD::Adapter_C_Sign(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
  LOGSERVERI(tag,"%s IN",__FUNCTION__);  
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_Sign(hSession,pData,ulDataLen,pSignature,pulSignatureLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_SignUpdate continues a multiple-part signature operation,
 * where the signature is (will be) an appendix to the data,
 * and plaintext cannot be recovered from the signature.
 */
 CK_RV P11func_HD::Adapter_C_SignUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
)
{  
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_SignUpdate(hSession,pPart,ulPartLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_SignFinal finishes a multiple-part signature operation,
 * returning the signature.
 */
 CK_RV P11func_HD::Adapter_C_SignFinal(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{  
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_SignFinal(hSession,pSignature,pulSignatureLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature.
 */
 CK_RV P11func_HD::Adapter_C_SignRecoverInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
)
{
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_SignRecoverInit(hSession,pMechanism,hKey);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}




/* Adapter_C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature.
 */
 CK_RV P11func_HD::Adapter_C_SignRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{ 
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_SignRecover(hSession,pData,ulDataLen,pSignature,pulSignatureLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}




/* Verifying signatures and MACs */

/* Adapter_C_VerifyInit initializes a verification operation, where the
 * signature is an appendix to the data, and plaintext cannot
 * cannot be recovered from the signature (e.g. DSA).
 */
 CK_RV P11func_HD::Adapter_C_VerifyInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{ 
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_VerifyInit(hSession,pMechanism,hKey);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_Verify verifies a signature in a single-part operation,
 * where the signature is an appendix to the data, and plaintext
 * cannot be recovered from the signature.
 */
 CK_RV P11func_HD::Adapter_C_Verify(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
)
{  
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_Verify(hSession,pData,ulDataLen,pSignature,ulSignatureLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_VerifyUpdate continues a multiple-part verification
 * operation, where the signature is an appendix to the data,
 * and plaintext cannot be recovered from the signature.
 */
 CK_RV P11func_HD::Adapter_C_VerifyUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
)
{ 
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_VerifyUpdate(hSession,pPart,ulPartLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_VerifyFinal finishes a multiple-part verification
 * operation, checking the signature.
 */
 CK_RV P11func_HD::Adapter_C_VerifyFinal(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
)
{  
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_VerifyFinal(hSession,pSignature,ulSignatureLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature.
 */
 CK_RV P11func_HD::Adapter_C_VerifyRecoverInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
  LOGSERVERI(tag,"%s IN",__FUNCTION__);  
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_VerifyRecoverInit(hSession,pMechanism,hKey);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature.
 */
 CK_RV P11func_HD::Adapter_C_VerifyRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
)
{
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_VerifyRecover(hSession,pSignature,ulSignatureLen,pData,pulDataLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}




/* Dual-function cryptographic operations */

/* Adapter_C_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation.
 */
 CK_RV P11func_HD::Adapter_C_DigestEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_DigestEncryptUpdate(hSession,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation.
 */
 CK_RV P11func_HD::Adapter_C_DecryptDigestUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
)
{
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_DecryptDigestUpdate(hSession,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation.
 */
 CK_RV P11func_HD::Adapter_C_SignEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{ 
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_SignEncryptUpdate(hSession,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation.
 */
 CK_RV P11func_HD::Adapter_C_DecryptVerifyUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
)
{  
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_DecryptVerifyUpdate(hSession,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}




/* Key management */

/* Adapter_C_GenerateKey generates a secret key, creating a new key
 * object.
 */
 CK_RV P11func_HD::Adapter_C_GenerateKey(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
)
{ 
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_GenerateKey(hSession,pMechanism,pTemplate,ulCount,phKey);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_GenerateKeyPair generates a public-key/private-key pair,
 * creating new key objects.
 */
 CK_RV P11func_HD::Adapter_C_GenerateKeyPair(
  CK_SESSION_HANDLE    hSession,                    /* session handle */
  CK_MECHANISM_PTR     pMechanism,                  /* key-gen mech. */
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template for pub. key */
  CK_ULONG             ulPublicKeyAttributeCount,   /* # pub. attrs. */
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template for priv. key */
  CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.  attrs. */
  CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
  CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets priv. key handle */
)
{  
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_ATTRIBUTE_PTR pTemplate_pubnew = NULL;
	CK_ULONG ulCount_pubnew = 0;
	
	CK_ATTRIBUTE_PTR pTemplate_prinew = NULL;
	CK_ULONG ulCount_prinew = 0;

	pTemplate_pubnew = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * (ulPublicKeyAttributeCount+2));	
	pTemplate_prinew = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * (ulPrivateKeyAttributeCount+1));

	switchSM2template(CKO_PUBLIC_KEY, pPublicKeyTemplate,ulPublicKeyAttributeCount, pTemplate_pubnew, &ulCount_pubnew);
	switchSM2template(CKO_PRIVATE_KEY, pPrivateKeyTemplate,ulPrivateKeyAttributeCount, pTemplate_prinew, &ulCount_prinew);
	
	mutex.Lock();
	CK_RV ret = function_list_ptr->C_GenerateKeyPair(hSession,pMechanism,pTemplate_pubnew,ulCount_pubnew,
	  pTemplate_prinew,ulCount_prinew,phPublicKey,phPrivateKey);
	mutex.Unlock();
	
	freeTemplate(&pTemplate_pubnew,ulCount_pubnew);
	freeTemplate(&pTemplate_prinew,ulCount_prinew);

	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}



/* Adapter_C_WrapKey wraps (i.e., encrypts) a key. */
 CK_RV P11func_HD::Adapter_C_WrapKey(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
)
{ 
  LOGSERVERI(tag,"%s IN,hWrappingKey = 0x%lx, hKey = 0x%lx",__FUNCTION__,hWrappingKey,hKey);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_WrapKey(hSession,pMechanism,hWrappingKey,hKey,pWrappedKey,pulWrappedKeyLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object.
 */
 CK_RV P11func_HD::Adapter_C_UnwrapKey(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
	CK_OBJECT_CLASS key_class;
	CK_ATTRIBUTE_PTR	 pTemplate_new = NULL; 
	CK_ULONG ulCount_new = 0;
	if(get_KeytypeAndClass(pTemplate,ulAttributeCount,&key_class) == CKK_SM2)
	{	
		pTemplate_new = (CK_ATTRIBUTE_PTR)malloc((ulAttributeCount+2)*sizeof(CK_ATTRIBUTE));	
		ret = switchSM2template(key_class,pTemplate,ulAttributeCount,pTemplate_new,&ulCount_new);
		if(ret == CKR_OK)
		{
			mutex.Lock();
			ret = function_list_ptr->C_UnwrapKey(hSession,pMechanism,hUnwrappingKey,pWrappedKey,ulWrappedKeyLen,pTemplate_new,ulCount_new,phKey);
			mutex.Unlock();
		}	

		freeTemplate(&pTemplate_new,ulCount_new);
		return ret;
	}

	checkAndModifyUnwrapTemplate(pTemplate,ulAttributeCount);
		
	mutex.Lock();
	ret = function_list_ptr->C_UnwrapKey(hSession,pMechanism,hUnwrappingKey,pWrappedKey,ulWrappedKeyLen,pTemplate,ulAttributeCount,phKey);
	mutex.Unlock();
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}



/* Adapter_C_DeriveKey derives a key from a base key, creating a new key
 * object.
 */
 CK_RV P11func_HD::Adapter_C_DeriveKey(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_DeriveKey(hSession,pMechanism,hBaseKey,pTemplate,ulAttributeCount,phKey);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}


/* Random number generation */

/* Adapter_C_SeedRandom mixes additional seed material into the token's
 * random number generator.
 */
 CK_RV P11func_HD::Adapter_C_SeedRandom(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
)
{ 
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_SeedRandom(hSession,pSeed,ulSeedLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}



/* Adapter_C_GenerateRandom generates random data. */
 CK_RV P11func_HD::Adapter_C_GenerateRandom(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_BYTE_PTR       RandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{ 
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_GenerateRandom(hSession,RandomData,ulRandomLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}




/* Parallel function management */

/* Adapter_C_GetFunctionStatus is a legacy function; it obtains an
 * updated status of a function running in parallel with an
 * application.
 */
 CK_RV P11func_HD::Adapter_C_GetFunctionStatus(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_GetFunctionStatus(hSession);
  mutex.Unlock();
  return ret;
}



/* Adapter_C_CancelFunction is a legacy function; it cancels a function
 * running in parallel.
 */
 CK_RV P11func_HD::Adapter_C_CancelFunction(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_CancelFunction(hSession);
  mutex.Unlock();
  return ret;
}



/* Adapter_C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur.
 */
 CK_RV P11func_HD::Adapter_C_WaitForSlotEvent(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
)
{
  
  mutex.Lock();
  CK_RV ret = function_list_ptr->C_WaitForSlotEvent(flags,pSlot,pRserved);
  mutex.Unlock();
  return ret;
}




/********************************
 *剩余口令剩余尝试次数
*/
 CK_RV P11func_HD::Adapter_C_Extend_GetPinRemainCount
(
  CK_SESSION_HANDLE hSession,
  CK_ULONG_PTR pUiRemainCount
)
{
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  CK_RV ret = 0;  
  CK_EXTEND_IN ExtIn_GetPinTime = {CK_EXTEND_GETPINTIME, NULL, 0};
  CK_EXTEND_OUT ExtOut_GetPinTime = {CK_EXTEND_GETPINTIME, pUiRemainCount, sizeof(int)};


  mutex.Lock();
  ret = Pointer_C_CryptoExtend(hSession, &ExtIn_GetPinTime, &ExtOut_GetPinTime, NULL);
  mutex.Unlock();
  
  LOGSERVERI(tag, "%s OUT, rv = 0x%lx, count = %ld",__FUNCTION__,ret, *pUiRemainCount);
  return ret;
}



/********************************
 *获取密码卡状态
*/
 CK_RV P11func_HD::Adapter_C_Extend_GetStatus
(
  CK_SLOT_ID slotID,
  CK_STATUS_ENUM_PTR pStatus
)
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
  	CK_RV ret = 0;
	CK_SESSION_HANDLE hSession;
	CK_EXTEND_IN ExtIn_SDStatus = {CK_EXTEND_GETSDSTATUS, NULL, 0};
	CK_EXTEND_OUT ExtOut_SDStatus = {CK_EXTEND_GETSDSTATUS, NULL, 0};
	
	int iLoginState = 0;
	CK_EXTEND_IN ExtIn_GetLoginState = {CK_EXTEND_GETLOGINSTATE, NULL, 0};
	CK_EXTEND_OUT ExtOut_GetLoginState = {CK_EXTEND_GETLOGINSTATE, &iLoginState, sizeof(iLoginState)};

	mutex.Lock();
	ret = function_list_ptr->C_OpenSession(slotID,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL_PTR,NULL_PTR,&hSession);
	if(ret != CKR_OK)
	{
		mutex.Unlock();
		return ret;
	}	


	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_SDStatus, &ExtOut_SDStatus, NULL);

	if(ret == CKR_DEVICE_REMOVED){
		*pStatus = CK_STATUS_ENUM_DEVICE_OFF;
	}
	else if(ret == CKR_PIN_LOCKED){
		*pStatus = CK_STATUS_ENUM_DEVICE_LOCKED;
	}

	else if(ret == CKR_OK){		
		ret= Pointer_C_CryptoExtend(hSession, &ExtIn_GetLoginState, &ExtOut_GetLoginState, NULL);

		if(iLoginState == 1)
		{
			*pStatus = CK_STATUS_ENUM_LOGIN;
		}
		else
		{
			*pStatus = CK_STATUS_ENUM_UNLOGIN;
		}
	}	
	else{	
		*pStatus = CK_STATUS_ENUM_DEVICE_ABNORMAL;
	}

	ret = function_list_ptr->C_CloseSession(hSession);
	mutex.Unlock();

	if(ret != CKR_OK)
	{	
		return ret;
	}
	
    LOGSERVERI(tag,"%s OUT",__FUNCTION__);
	return CKR_OK;
}

/********************************
 *注册密码卡状态回调函数
*/
 CK_RV P11func_HD::Adapter_C_Extend_Register_Callback
(

  register_status_callback_func func
)
{
  return CKR_OK;
}

/********************************
 *注销密码卡状态回调函数
*/
 CK_RV P11func_HD::Adapter_C_Extend_Unregister_Callback
(

  register_status_callback_func func
)
{
  return CKR_OK;
}

/********************************
 *使用监听公钥导出协商密钥
*/
 CK_RV P11func_HD::Adapter_C_Extend_GetExchangeSessionKey
(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hSessionKey,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG_PTR pulEncryptedDataLen
)
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
	CK_BYTE nSessKeyID = 0;
	CK_EXTEND_IN	ExtIn_GetExchangeSessKey = {CK_EXTEND_GETEXCHANGESESSKEY, &nSessKeyID, sizeof(CK_BYTE)};
	CK_EXTEND_OUT   ExtOut_GetExchangeSessKey = {CK_EXTEND_GETEXCHANGESESSKEY, pEncryptedData, *pulEncryptedDataLen};
	
	//get attribute value	

	CK_ATTRIBUTE template_get[] = {
		{CKA_SESSKEY_ID, &nSessKeyID, sizeof(CK_BYTE)}
	};

	LOGSERVERI(tag,"hSessionKey is 0x%lx", hSessionKey);
		
	mutex.Lock();
	ret = function_list_ptr->C_GetAttributeValue(hSession,hSessionKey,template_get,sizeof(template_get)/sizeof(template_get[0]));
	mutex.Unlock();

	if(ret != CKR_OK)
	{
		LOGSERVERI(tag,"get sesskeyID fail");
		return ret;
	}

	LOGSERVERI(tag, "%s, keyid is %d",__FUNCTION__,nSessKeyID);	
	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_GetExchangeSessKey, &ExtOut_GetExchangeSessKey, NULL);
	mutex.Unlock();

//	Print_Data((char *)tag,(unsigned char *) pEncryptedData,*pulEncryptedDataLen);
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

/********************************
 *参数注销
*/
 CK_RV P11func_HD::Adapter_C_Extend_Destroy
(
  CK_SLOT_ID slotID,
  CK_BYTE_PTR containerName
)
{
	return CKR_OK;
}

/********************************
 *重设用户口令
*/
 CK_RV P11func_HD::Adapter_C_Extend_Reset_Pin_With_OTP
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbOTPPIN,
  CK_ULONG ulOTPPINLen,
  CK_BYTE_PTR pbNewUserPIN,
  CK_ULONG ulNewUserPINLen
)
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
  	CK_RV ret = 0;
	unsigned char *pbBuffer = NULL;
	
  	CK_EXTEND_IN ExtIn_ReSetUserPin = {CK_EXTEND_RESET_USERPIN, NULL, 0};
	CK_EXTEND_OUT ExtOut_ReSetUserPin = {CK_EXTEND_RESET_USERPIN, NULL, 0};

	pbBuffer = (unsigned char *)malloc(ulOTPPINLen+ ulNewUserPINLen + 2);

	if(NULL==pbBuffer)
	{
		LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
		  
	ExtIn_ReSetUserPin.pParameter = pbBuffer;
	*pbBuffer = ulOTPPINLen;
	memcpy(pbBuffer + 1, pbOTPPIN, ulOTPPINLen);
	*(pbBuffer + 1 + ulOTPPINLen) = ulNewUserPINLen;
	memcpy(pbBuffer + 2 + ulOTPPINLen, pbNewUserPIN, ulNewUserPINLen);
	ExtIn_ReSetUserPin.ulParameterLen = 2 + ulOTPPINLen + ulNewUserPINLen;
	
	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_ReSetUserPin, &ExtOut_ReSetUserPin, NULL);
	mutex.Unlock();
	
	free(pbBuffer);
	pbBuffer = NULL;
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

/********************************
 *重设OTP口令
*/
 CK_RV P11func_HD::Adapter_C_Extend_Reset_OTP
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbOTPMpk,
  CK_ULONG ulMpkLen,
  CK_BYTE_PTR pbMpkIV,
  CK_ULONG ulMpkIVLen
)

{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;

	unsigned int remotevectorType = CKO_REMOTE_OTP;
	CK_EXTEND_IN ExtIn_vectorData_Remote = {CK_EXTEND_REMOTE_SET_DATA, NULL, 0};
	CK_EXTEND_OUT ExtOut_vectorData_Remote = {CK_EXTEND_REMOTE_SET_DATA, NULL, 0};
	
	unsigned char* pbBuffer_T = NULL_PTR;
	ExtIn_vectorData_Remote.ulParameterLen = sizeof(remotevectorType) + ulMpkIVLen + ulMpkLen;
	pbBuffer_T=(unsigned char*)malloc(sizeof(unsigned char)*(ExtIn_vectorData_Remote.ulParameterLen));
	if(NULL==pbBuffer_T)
	{
		LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
		
	ExtIn_vectorData_Remote.pParameter = pbBuffer_T;

	memcpy(pbBuffer_T, &remotevectorType, sizeof(remotevectorType));
	memcpy(pbBuffer_T + sizeof(remotevectorType), pbMpkIV, ulMpkIVLen);
	memcpy(pbBuffer_T + sizeof(remotevectorType) + ulMpkIVLen, pbOTPMpk, ulMpkLen);
	
	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_vectorData_Remote, &ExtOut_vectorData_Remote, NULL);
	mutex.Unlock();

	free(pbBuffer_T);
	pbBuffer_T = NULL;
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

/********************************
 *获取剩余OTP解锁次数
*/
 CK_RV P11func_HD::Adapter_C_Extend_Get_OTP_Unlock_Count
(
  CK_SESSION_HANDLE hSession,
  CK_ULONG_PTR pulCount
)
{
	CK_RV ret = 0;
	unsigned char nOTPPinTryTime = 0;

	CK_EXTEND_IN ExtIn_GetOTPPinTime_Try = {CK_EXTEND_GETOTPTIME_TRY, NULL, 0};
	CK_EXTEND_OUT ExtOut_GetOTPPinTime_Try = {CK_EXTEND_GETOTPTIME_TRY, (void*)&nOTPPinTryTime, 1};

	LOGSERVERI(tag,"%s IN", __FUNCTION__);

	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession,&ExtIn_GetOTPPinTime_Try, &ExtOut_GetOTPPinTime_Try, NULL);
	mutex.Unlock();

	*pulCount = nOTPPinTryTime;

	LOGSERVERI(tag, "%s OUT, ret = 0x%lx, count = %d,%lu",__FUNCTION__,ret, nOTPPinTryTime,*pulCount);
	  
	return ret;
}

/********************************
 *获取剩余OTP尝试次数
*/
 CK_RV P11func_HD::Adapter_C_Extend_Get_OTP_Remain_Count
(
  CK_SESSION_HANDLE hSession,
  CK_ULONG_PTR pulCount
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
	unsigned char nOTPPinRemainTime = 0;

	CK_EXTEND_IN ExtIn_GetOTPPinTime_Usable = {CK_EXTEND_GETOTPTIME_USABLE, NULL, 0};
	CK_EXTEND_OUT ExtOut_GetOTPPinTime_Usable = {CK_EXTEND_GETOTPTIME_USABLE, (void*)&nOTPPinRemainTime, 1};

	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession,&ExtIn_GetOTPPinTime_Usable, &ExtOut_GetOTPPinTime_Usable, NULL);
	mutex.Unlock();

	*pulCount = nOTPPinRemainTime;

	LOGSERVERI(tag, "%s OUT, ret = 0x%lx, count = %d,%lu",__FUNCTION__,ret, nOTPPinRemainTime,*pulCount);
	return ret;
}

/********************************
 *协商会话密钥加密初始化
*/
 CK_RV P11func_HD::Adapter_C_Extend_DeriveSessionKey
(
   CK_SESSION_HANDLE hSession,

   CK_MECHANISM_PTR pMechanism,

   CK_OBJECT_HANDLE hLocalKey,

   CK_OBJECT_HANDLE hRemoteKey,

   CK_ATTRIBUTE_PTR pTemplate,

   CK_ULONG ulAttributeCount,

   CK_OBJECT_HANDLE_PTR phKey,

   CK_BYTE_PTR pExchangeIV,

   CK_ULONG_PTR pExchangeIVLen
)
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
	
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;	
	CK_KEY_TYPE SessKeyExchangeKeyType = CKK_SESSKEY_EXCHANGE;
	
	unsigned char* pMechanismParameter = NULL ;
	CK_MECHANISM	DeriveKeyMechanism = {CKM_SESSKEY_DERIVE, NULL, 0};

	DeriveKeyMechanism.ulParameterLen = sizeof(CK_OBJECT_HANDLE)*2 + 16;
	pMechanismParameter = (unsigned char*)malloc(DeriveKeyMechanism.ulParameterLen);
	if(NULL==pMechanismParameter)
	{
		LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
		
	memset(pMechanismParameter, 0, DeriveKeyMechanism.ulParameterLen);
	memcpy(pMechanismParameter, &hLocalKey, sizeof(CK_OBJECT_HANDLE));
	memcpy(pMechanismParameter+sizeof(CK_OBJECT_HANDLE),&hRemoteKey, sizeof(CK_OBJECT_HANDLE));
	DeriveKeyMechanism.pParameter = pMechanismParameter;

	mutex.Lock();
	ret = function_list_ptr->C_DeriveKey(hSession, &DeriveKeyMechanism, NULL_PTR, pTemplate, ulAttributeCount, phKey);
	mutex.Unlock();

	*pExchangeIVLen = 16;
	memcpy(pExchangeIV,pMechanismParameter+sizeof(CK_OBJECT_HANDLE)+sizeof(CK_OBJECT_HANDLE),16);
	free(pMechanismParameter);
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

/********************************
 *协商会话密钥加密初始化
*/
 CK_RV P11func_HD::Adapter_C_Extend_EncryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG ulAttributeCount
)
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
	CK_OBJECT_HANDLE hKey = 0;
	CK_KEY_TYPE zuctype = CKK_ZUC;
	CK_KEY_TYPE exchangetype = CKK_SESSKEY_EXCHANGE;

	int i=0;
	for(i=0;i<ulAttributeCount;i++)
	{
		if(pTemplate[i].type == CKA_KEY_TYPE)
		{
			if(!memcmp(pTemplate[i].pValue,&exchangetype,sizeof(CK_KEY_TYPE)))
			{
				memcpy(pTemplate[i].pValue,&zuctype,sizeof(CK_KEY_TYPE));
			}
		}
	}

	mutex.Lock();  
	ret = function_list_ptr->C_CreateObject(hSession,pTemplate,ulAttributeCount,&hKey);
	mutex.Unlock();

	if(ret != CKR_OK)
	{ 	
		LOGSERVERI(tag,"%s, createobject fail",__FUNCTION__);
	    return ret;
	}

	mutex.Lock();  
	ret = function_list_ptr->C_EncryptInit(hSession,pMechanism,hKey);
	mutex.Unlock();

	if(ret == CKR_OK)
	{
	  mechmap_enc[hSession] = pMechanism->mechanism;
	}
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

/******************************
 *协商会话密钥解密初始化
*/
 CK_RV P11func_HD::Adapter_C_Extend_DecryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_ATTRIBUTE_PTR  pTemplate,        /* handle of decryption key */
  CK_ULONG ulAttributeCount
)
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0; 
	CK_OBJECT_HANDLE hKey = 0;
	CK_KEY_TYPE zuctype = CKK_ZUC;
	CK_KEY_TYPE exchangetype = CKK_SESSKEY_EXCHANGE;

	int i=0;
	for(i=0;i<ulAttributeCount;i++)
	{
		if(pTemplate[i].type == CKA_KEY_TYPE)
		{
			if(!memcmp(pTemplate[i].pValue,&exchangetype,sizeof(CK_KEY_TYPE)))
			{
				memcpy(pTemplate[i].pValue,&zuctype,sizeof(CK_KEY_TYPE));
			}
		}
	}

	mutex.Lock();
	ret = function_list_ptr->C_CreateObject(hSession,pTemplate,ulAttributeCount,&hKey);
	mutex.Unlock();

	if(ret != CKR_OK)
	{ 	
        LOGSERVERI(tag,"%s, createobject fail",__FUNCTION__);
        return ret;
	}

	LOGSERVERI(tag, "%s, hKey is 0x%lx", __FUNCTION__,hKey);
		
	mutex.Lock();
	ret = function_list_ptr->C_DecryptInit(hSession,pMechanism,hKey);
	mutex.Unlock();

	if(ret == CKR_OK)
	{
	  mechmap_dec[hSession] = pMechanism->mechanism;
	}
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

/********************************
 *协商会话密钥分步加密
*/
 CK_RV P11func_HD::Adapter_C_Extend_EncryptUpdate
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pIv,                /* encrypted iv */
  CK_ULONG          ulIvLen,            /* encrypted iv len */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
)
{
    LOGSERVERD(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
	
	CK_BYTE_PTR indata = NULL_PTR;
	CK_ULONG indatalen = 5 + ulPartLen;

	if((ulIvLen!=16) || (mechmap_enc[hSession]!=CKM_ZUC_EEA))
		return CKR_ARGUMENTS_BAD;

	indata = (CK_BYTE_PTR)malloc(indatalen * sizeof(CK_BYTE));
	if(NULL==indata)
	{
		LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	
	CK_BYTE ZUCDB = (pIv[11]<<5)+pIv[7];
	
	memcpy(indata, pIv, 4);	
	memcpy(indata+4, &ZUCDB, 1);
	memcpy(indata+5, pPart, ulPartLen);
	
	mutex.Lock();
	ret = function_list_ptr->C_EncryptUpdate(hSession, indata, indatalen, pEncryptedPart, pulEncryptedPartLen);
	mutex.Unlock();
	free(indata);
	indata = NULL;
	
	LOGSERVERD(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

/********************************
 *协商会话密钥分步解密
*/
 CK_RV P11func_HD::Adapter_C_Extend_DecryptUpdate
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pIv,                /* decrypted iv */
  CK_ULONG          ulIvLen,            /* decrypted iv len */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
)
{
	LOGSERVERD(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;

	CK_BYTE_PTR indata = NULL_PTR;
	CK_ULONG indatalen = 5 + ulEncryptedPartLen;

	if((ulIvLen!=16) || (mechmap_dec[hSession]!=CKM_ZUC_EEA))
	  return CKR_ARGUMENTS_BAD;

	indata = (CK_BYTE_PTR)malloc(indatalen * sizeof(CK_BYTE));  
	if(NULL==indata)
	{
		LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	CK_BYTE ZUCDB = (pIv[11]<<5)+pIv[7];

	memcpy(indata, pIv, 4); 
	memcpy(indata+4, &ZUCDB, 1);
	memcpy(indata+5, pEncryptedPart, ulEncryptedPartLen);

	LOGSERVERD(tag,"%s IN 2",__FUNCTION__);
	mutex.Lock();
	ret = function_list_ptr->C_DecryptUpdate(hSession, indata, indatalen, pPart, pulPartLen);
	mutex.Unlock();

	free(indata);
	indata = NULL;

	LOGSERVERD(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

/********************************
 *协商会话密钥分步加密结束
*/
 CK_RV P11func_HD::Adapter_C_Extend_EncryptFinalize
(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
)
{
  LOGSERVERI(tag,"%s IN",__FUNCTION__);
  CK_RV ret = 0;

  mutex.Lock();
  ret = function_list_ptr->C_EncryptFinal(hSession,pLastEncryptedPart,pulLastEncryptedPartLen);
  mutex.Unlock();
  
  LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
  return ret;
}

/********************************
 *协商会话密钥分步解密结束
*/
 CK_RV P11func_HD::Adapter_C_Extend_DecryptFinalize
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
  	CK_RV ret = 0;

	mutex.Lock();
	ret = function_list_ptr->C_DecryptFinal(hSession,pLastPart,pulLastPartLen);
	mutex.Unlock();
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

/********************************
 *SM2点乘
*/
 CK_RV P11func_HD::Adapter_C_Extend_PointMultiply
(

  CK_SESSION_HANDLE hSession,

  CK_MECHANISM_PTR pMechanism,

  CK_OBJECT_HANDLE hKey,

  CK_BYTE_PTR pOutData,

  CK_ULONG_PTR pOutLen
)
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
	unsigned char *pMechanismParameter2 = NULL;
	CK_MECHANISM PointMultMechanism2 = {CKM_DERIVE_SM2_POINTMUL_2, NULL, 0};

	if((pOutData != NULL) && (*pOutLen<64))
	{
		return CKR_BUFFER_TOO_SMALL;
	}

	pMechanismParameter2 = (unsigned char*)malloc(sizeof(CK_OBJECT_HANDLE)+64+64);
	if(NULL==pMechanismParameter2)
	{
		LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	memset(pMechanismParameter2, 0, sizeof(CK_OBJECT_HANDLE)+64+64);
	PointMultMechanism2.pParameter = pMechanismParameter2;
	PointMultMechanism2.ulParameterLen = sizeof(CK_OBJECT_HANDLE)+64+64;

	(*(CK_OBJECT_HANDLE *)pMechanismParameter2) = hKey;
	memcpy(pMechanismParameter2 + sizeof(CK_OBJECT_HANDLE), pMechanism->pParameter, 64);

	mutex.Lock();
	ret = function_list_ptr->C_DeriveKey(hSession, &PointMultMechanism2, NULL_PTR, NULL, 0, NULL);
	mutex.Unlock();

	if(pOutData)
	{
		memcpy(pOutData,pMechanismParameter2+sizeof(CK_OBJECT_HANDLE)+64,64);
	}	
	*pOutLen = 64;
	
	free(pMechanismParameter2);
	pMechanismParameter2 = NULL;
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

/********************************
 *重设TT口令
*/
 CK_RV P11func_HD::Adapter_C_Extend_Reset_TT
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbTTMpk,
  CK_ULONG ulMpkLen,
  CK_BYTE_PTR pbMpkIV,
  CK_ULONG ulMpkIVLen
)
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;

	unsigned int remotevectorType = CKO_REMOTE_TT;
	CK_EXTEND_IN ExtIn_vectorData_Remote = {CK_EXTEND_REMOTE_SET_DATA, NULL, 0};
	CK_EXTEND_OUT ExtOut_vectorData_Remote = {CK_EXTEND_REMOTE_SET_DATA, NULL, 0};
	
	unsigned char* pbBuffer_T = NULL_PTR;
	ExtIn_vectorData_Remote.ulParameterLen = sizeof(remotevectorType) + ulMpkIVLen + ulMpkLen;
	pbBuffer_T=(unsigned char*)malloc(sizeof(unsigned char)*(ExtIn_vectorData_Remote.ulParameterLen));
	if(NULL==pbBuffer_T)
	{
		LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	ExtIn_vectorData_Remote.pParameter = pbBuffer_T;

	memcpy(pbBuffer_T, &remotevectorType, sizeof(remotevectorType));
	memcpy(pbBuffer_T + sizeof(remotevectorType), pbMpkIV, ulMpkIVLen);
	memcpy(pbBuffer_T + sizeof(remotevectorType) + ulMpkIVLen, pbTTMpk, ulMpkLen);
	
	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_vectorData_Remote, &ExtOut_vectorData_Remote, NULL);
	mutex.Unlock();

	free(pbBuffer_T);
	pbBuffer_T = NULL;
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

/********************************
 *重设BK口令
*/
 CK_RV P11func_HD::Adapter_C_Extend_Reset_BK
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbBKMpk,
  CK_ULONG ulMpkLen,
  CK_BYTE_PTR pbMpkIV,
  CK_ULONG ulMpkIVLen
)
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;

	unsigned int remotevectorType = CKO_REMOTE_SECRET_KEY;
	CK_EXTEND_IN ExtIn_vectorData_Remote = {CK_EXTEND_REMOTE_SET_DATA, NULL, 0};
	CK_EXTEND_OUT ExtOut_vectorData_Remote = {CK_EXTEND_REMOTE_SET_DATA, NULL, 0};
	
	unsigned char* pbBuffer_T = NULL_PTR;
	ExtIn_vectorData_Remote.ulParameterLen = sizeof(remotevectorType) + ulMpkIVLen + ulMpkLen;
	pbBuffer_T=(unsigned char*)malloc(sizeof(unsigned char)*(ExtIn_vectorData_Remote.ulParameterLen));
	if(NULL==pbBuffer_T)
	{
		LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	ExtIn_vectorData_Remote.pParameter = pbBuffer_T;

	memcpy(pbBuffer_T, &remotevectorType, sizeof(remotevectorType));
	memcpy(pbBuffer_T + sizeof(remotevectorType), pbMpkIV, ulMpkIVLen);
	memcpy(pbBuffer_T + sizeof(remotevectorType) + ulMpkIVLen, pbBKMpk, ulMpkLen);
	
	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_vectorData_Remote, &ExtOut_vectorData_Remote, NULL);
	mutex.Unlock();

	free(pbBuffer_T);
	pbBuffer_T = NULL;
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}



CK_RV P11func_HD::Adapter_C_Extend_Get_Special_Object_Version
(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_CLASS objectClass,
	CK_BYTE_PTR pVersion,
	CK_ULONG_PTR pUlLen
) 
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
	
	CK_EXTEND_IN ExtIn_GetUpdateData_Version = {CK_EXTEND_REMOTE_GET_DATAVER, &objectClass, sizeof(objectClass)};
	CK_EXTEND_OUT ExtOut_GetUpdateData_Version = {CK_EXTEND_REMOTE_GET_DATAVER, pVersion, *pUlLen};

	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_GetUpdateData_Version, &ExtOut_GetUpdateData_Version, NULL);
	mutex.Unlock();

	*pUlLen = 4;
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	
	return ret;
}

CK_RV P11func_HD::Adapter_C_Extend_DestroyCard
(
	CK_SLOT_ID slotID,
	CK_BYTE_PTR prandomIn,
	CK_ULONG randomInLen,
	CK_BYTE_PTR prandomOut,
	CK_ULONG_PTR prandomOutLen
)
{
    LOGSERVERI(tag,"%s IN",__FUNCTION__);

	CK_RV ret = 0;	
	CK_SESSION_HANDLE hSession;
	CK_EXTEND_IN ExtIn_DoDestroy = {CK_EXTEND_DODESTROY, (void*)prandomIn, randomInLen};		
	CK_EXTEND_OUT ExtOut_DoDestroy = {CK_EXTEND_DODESTROY, (void*)prandomOut, (*prandomOutLen)};	

	
	mutex.Lock();
	ret = function_list_ptr->C_OpenSession(slotID,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL_PTR,NULL_PTR,&hSession);	
	mutex.Unlock();
	if(ret != CKR_OK)
	{
		return ret;
	}
	
	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_DoDestroy, &ExtOut_DoDestroy, NULL);
	mutex.Unlock();
	
	*prandomOutLen = 32;
	
	mutex.Lock();
	function_list_ptr->C_CloseSession(hSession);
	mutex.Unlock();
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}


CK_RV P11func_HD::Adapter_C_Extend_Get_ExchangePubKey
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR 	  pExchangePubKeyValue,   
	CK_ULONG_PTR	  pulKeyLen  
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;	
	

	CK_EXTEND_IN	ExtIn_GetExchangePubKey = {CK_EXTEND_GETEXCHANGEPUBKEY, NULL, 0};
	CK_EXTEND_OUT	ExtOut_GetExchangePubKey = {CK_EXTEND_GETEXCHANGEPUBKEY, pExchangePubKeyValue, *pulKeyLen};
		
	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_GetExchangePubKey, &ExtOut_GetExchangePubKey, NULL);
	mutex.Unlock();
	
	LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}


CK_RV P11func_HD::Adapter_C_Extend_GetDevInfo
(
 CK_SLOT_ID slotID,
 const char *userName, 
 CK_IP_PARAMS_PTR cspp,
 CK_BYTE_PTR pDevInfo,
 CK_ULONG_PTR pUlDevInfoLen
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV P11func_HD::Adapter_C_Extend_DevSign
(
	CK_SLOT_ID slotID,
	CK_BYTE_PTR       pData,           /* the data to sign */
	CK_ULONG          ulDataLen,       /* count of bytes to sign */
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV P11func_HD::Adapter_C_Extend_Set_DestroyKey
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pDestroyKeyMpk,
	CK_ULONG ulMpkLen,
	CK_BYTE_PTR pbMpkIV,
	CK_ULONG ulMpkIVLen
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


