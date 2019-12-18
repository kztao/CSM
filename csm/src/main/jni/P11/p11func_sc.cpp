//#pragma GCC visibility push(hidden)
#include "cryptoki.h"
//#pragma GCC visibility pop
#include "ucm.h"
#include "p11func_sc.h"
#include "logserver.h"
#include <stdio.h>
#include <stdlib.h>
#include "AttributesConvert.h"
#include <string.h>
#include "ucm.h"
#include "GetPackageName.h"
#include "P11Mapping.h"

using std::vector;


static const char *libPath = "libCMApi.so";
static LibLoadManager *libLoadManager = new LibLoadManager(libPath);;
static CK_FUNCTION_LIST_PTR function_list_ptr = NULL;
static const char *tag = "csm_scp11";
static UCM_HANDLE UcmHandle = NULL;

static CK_SESSION_HANDLE ucm_session = 0;

#define OTPPIN_LEN_SIZE  1
#define DESTORYRND_LEN  32

#define HASSIDFLAG_LOC  0
#define SID_LOC  1
#define NO_SID   0
#define HAS_SID  1
#define FLAG_LEN 1
#define SID_LEN  1


int tfStatusCallback1(unsigned char event, unsigned int param){
	LOGSERVERI(tag,"sc status callback: %d, %d",event,param);
	return 0;
}

static CK_RV (*Pointer_C_GetFunctionList_SC)
(
    CK_FUNCTION_LIST_PTR_PTR
);


/*
 * C_DevProduct_Extend
 *//*
static CK_RV (*Point_C_DevProduct_Extend)
(
	CK_CHAR token[CK_MAX_TOKEN_SIZE],
	CK_CHAR userName[CK_MAX_NAME_SIZE],
	CK_CHAR_PTR licRootCaCert[CK_MAX_CERTLIST_CNT],
	CK_UINT licRootCaCertLen[CK_MAX_CERTLIST_CNT],
	CK_IP_PARAMS_PTR licServer,
	CK_IP_PARAMS_PTR cspp,
	CK_SLOT_ID_PTR pSlotID
);*/

static CK_RV (*Pointer_C_CryptoExtend)
(
    CK_SESSION_HANDLE hSession,
    CK_EXTEND_IN_PTR pExtendIn,
    CK_EXTEND_OUT_PTR pExtendOut,
    CK_VOID_PTR pReserved
);

static CK_RV (*Pointer_C_GenerateExchangeKeypair_sc)
(
	CK_SESSION_HANDLE hSession,             /* the session's handle */
	CK_MECHANISM_PTR pMechanism, 			/* key deriv. mech. */
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,	/* template for pub. key */
	CK_ULONG ulPublicKeyAttributeCount,		/* # pub. attrs. */
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,	/* template for pri. key */
	CK_ULONG ulPrivateKeyAttributeCount,	/* # pri. attrs. */
	CK_OBJECT_HANDLE_PTR phPublicKey,		/* gets pub. key handle */
	CK_OBJECT_HANDLE_PTR phPrivateKey		/* gets pri. key handle */
	
);

static CK_RV (*Pointer_C_GenerateLocalSessKey)
(
	CK_SESSION_HANDLE hSession,		/* the session's handle */
	CK_MECHANISM_PTR pMechanism, 	/* key deriv. mech. */
	CK_ATTRIBUTE_PTR pTemplate,		/* template for new key */
	CK_ULONG ulCount,				/* # of attrs in template */
	CK_OBJECT_HANDLE_PTR phKey		/* gets new key handle */
);

static CK_RV (*Pointer_C_WrapLocalSessKey)
(
	CK_SESSION_HANDLE hSession,		/* the session's handle */
	CK_MECHANISM_PTR pMechanism, 	/* wrap mech. */
	CK_OBJECT_HANDLE hKey,			/* key to be wrapped */
	CK_BYTE_PTR pWrappedKey,		/* gets wrapped key */
	CK_ULONG_PTR pulWrappedKeyLen	/* gets wrapped key size*/
);

static CK_RV (*Pointer_C_UnwrapRemoteSessKey)
(
	CK_SESSION_HANDLE hSession,		/* the session's handle */
	CK_MECHANISM_PTR pMechanism,	/* unwrap mech. */
	CK_OBJECT_HANDLE hUnwrappingKey, /*private key handle*/
	CK_BYTE_PTR pWrappedKey,		/* the wrapped key */
	CK_ULONG ulWrappedKeyLen,		/* the wrapped key size*/
	CK_ATTRIBUTE_PTR pTemplate,		/* template for new key */
	CK_ULONG ulAttributeCount,		/* # of attrs in template */
	CK_OBJECT_HANDLE_PTR phKey		/* gets new key handle */

);

static CK_RV (*Pointer_C_DeriveSessKey)
(
	CK_SESSION_HANDLE hSession,		/* the session's handle */
	CK_MECHANISM_PTR pMechanism,	/* key deriv. mech. */
	CK_OBJECT_HANDLE hLocalKey,		/* local key handle */
	CK_OBJECT_HANDLE hRemoteKey,	/* remote key handle */
	CK_ATTRIBUTE_PTR pTemplate,		/* template for new key */
	CK_ULONG ulAttributeCount,		/* # of attrs in template */
	CK_OBJECT_HANDLE_PTR phKey,		/* gets new key handle */
	CK_BYTE_PTR pExchangeIV,		/* gets iv */
	CK_ULONG_PTR pExchangeIVLen		/* gets iv size */
);

static CK_RV (*Pointer_C_PointMultiply)
(
	CK_SESSION_HANDLE hSession,		/* the session's handle */
	CK_MECHANISM_PTR pMechanism, 	/* the point multiply mechanism with public key value*/
	CK_OBJECT_HANDLE hKey, 			/* private key handle */
	CK_BYTE_PTR pOutData, 			/* gets result */
	CK_ULONG_PTR pOutLen 			/* gets result size*/
);

static CK_RV (*Pointer_C_EncryptUpdate_Extend)
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pPart,
	CK_ULONG ulPartLen,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG_PTR pulEncryptedPartLen
);

static CK_RV (*Pointer_C_DecryptUpdate_Extend)
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedPart,
	CK_ULONG ulEncryptedPartLen,
	CK_BYTE_PTR pPart,
	CK_ULONG_PTR pulPartLen
);

static CK_RV (*Pointer_C_CreateSlot_Extend)
(
	CK_CHAR token[CK_MAX_TOKEN_SIZE],
	CK_CHAR userName[CK_MAX_NAME_SIZE],
	CK_CHAR_PTR licRootCaCert[CK_MAX_CERTLIST_CNT],
	CK_UINT licRootCaCertLen[CK_MAX_CERTLIST_CNT],
	CK_IP_PARAMS_PTR licServer,
	CK_IP_PARAMS_PTR cspp,
	CK_SLOT_ID_PTR pSlotID
);


P11func_SC::P11func_SC(){
    Pointer_C_GetFunctionList_SC = (CK_RV(*)(CK_FUNCTION_LIST_PTR_PTR))libLoadManager->GetFuncPointer("C_GetFunctionList");
    Pointer_C_GetFunctionList_SC(&function_list_ptr);
	Pointer_C_GenerateExchangeKeypair_sc = (CK_RV (*)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_ATTRIBUTE_PTR,CK_ULONG,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR,CK_OBJECT_HANDLE_PTR))libLoadManager->GetFuncPointer("C_GenerateExchangeKeyPair");
	Pointer_C_GenerateLocalSessKey = (CK_RV (*)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR))libLoadManager->GetFuncPointer("C_GenerateLocalSessKey");	
	Pointer_C_WrapLocalSessKey = (CK_RV (*)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR))libLoadManager->GetFuncPointer("C_WrapLocalSessKey");	
	Pointer_C_UnwrapRemoteSessKey = (CK_RV (*)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR))libLoadManager->GetFuncPointer("C_UnwrapRemoteSessKey");
	Pointer_C_DeriveSessKey = (CK_RV (*)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR,CK_BYTE_PTR,CK_ULONG_PTR))libLoadManager->GetFuncPointer("C_DeriveSessKey");
	Pointer_C_PointMultiply = (CK_RV (*)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR))libLoadManager->GetFuncPointer("C_PointMultiply");
	Pointer_C_EncryptUpdate_Extend = (CK_RV (*)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))libLoadManager->GetFuncPointer("C_EncryptUpdate_Extend");
	Pointer_C_DecryptUpdate_Extend = (CK_RV (*)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))libLoadManager->GetFuncPointer("C_DecryptUpdate_Extend");
	Pointer_C_CryptoExtend = (CK_RV (*)(CK_SESSION_HANDLE,CK_EXTEND_IN_PTR,CK_EXTEND_OUT_PTR,CK_VOID_PTR))libLoadManager->GetFuncPointer("C_CryptoExtend");

//	tmp_id_len = 0;
//	tmp_sid = INVALID_VALUE;
	map_tmpsid.clear();
}

P11func_SC::~P11func_SC() {
	LOGSERVERI(tag, "%s IN",__FUNCTION__);
    mutex.Unlock();
}

string P11func_SC::GetDes() {
	return Describe;
}

vector<string> splitpack(string strtem,char a)
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


CK_RV P11func_SC::Adapter_C_Initialize(CK_VOID_PTR   pInitArgs)
{
  	CK_RV ret = 0;
	CK_C_INITIALIZE_ARGS p11_init_args;
    CK_INITPARAMS scm_init_args;

    memset(&p11_init_args, 0, sizeof(CK_C_INITIALIZE_ARGS));
    memset(&scm_init_args, 0, sizeof(CK_INITPARAMS));

    scm_init_args.callback = tfStatusCallback1;
	
    GetPackageName *getPackageName = new GetPackageName();
	string packageNameall = getPackageName->GetName();

	char splittag = ':';
    vector<string> packArray = splitpack(packageNameall, splittag);
    string packageName = packArray[0];
	
	strncpy((char *)scm_init_args.packageName, packageName.c_str(), packageName.size());

	LOGSERVERI(tag, "package name: %s",scm_init_args.packageName);
    p11_init_args.pReserved = &scm_init_args;
	
    mutex.Lock();
	ret = function_list_ptr->C_Initialize(&p11_init_args);
 	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, rv = 0x%lx",__FUNCTION__,ret);

	delete getPackageName;
	getPackageName = NULL;
	
 	return ret;
}

CK_RV P11func_SC::Adapter_C_Finalize(CK_VOID_PTR   pReserved)
{
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_Finalize(pReserved);
  	mutex.Unlock();
 	return ret;
}



/* HD_C_GetInfo returns general information about Cryptoki. */
CK_RV P11func_SC::Adapter_C_GetInfo(CK_INFO_PTR   pInfo)
{
	CK_RV ret = 0;
	mutex.Lock();
	ret = function_list_ptr->C_GetInfo(pInfo);
	mutex.Unlock();
 	return ret;

}



/* HD_C_GetFunctionList returns the function list. */
CK_RV P11func_SC::Adapter_C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	CK_RV ret = 0;
	mutex.Lock();
	ret = function_list_ptr->C_GetFunctionList(ppFunctionList);
	mutex.Unlock();
 	return ret;

}

/* Slot and token management */

/* HD_C_GetSlotList obtains a list of slots in the system. */
CK_RV P11func_SC::Adapter_C_GetSlotList(CK_BBOOL       tokenPresent,  /* only slots with tokens */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
)
{
	CK_RV ret = 0;
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	mutex.Lock();
	ret = function_list_ptr->C_GetSlotList(tokenPresent, pSlotList, pulCount);
	mutex.Unlock();
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx, ulcount = %ld",__FUNCTION__,ret,*pulCount);
 	return ret;

}



/* HD_C_GetSlotInfo obtains information about a particular slot in
 * the system.
 */
CK_RV P11func_SC::Adapter_C_GetSlotInfo(
  CK_SLOT_ID       slotID,  /* the ID of the slot */
  CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
)
{	
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_GetSlotInfo(slotID,  pInfo);
  	mutex.Unlock();
	
	LOGSERVERI(tag,"%s OUT with ret = 0x%lx",__FUNCTION__,ret);
 	return ret;

}



/* HD_C_GetTokenInfo obtains information about a particular token
 * in the system.
 */
CK_RV P11func_SC::Adapter_C_GetTokenInfo(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
)
{	
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_GetTokenInfo(slotID,pInfo);
  	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT, rv = 0x%lx",__FUNCTION__,ret);
 	return ret;

}



/* HD_C_GetMechanismList obtains a list of mechanism types
 * supported by a token.
 */
CK_RV P11func_SC::Adapter_C_GetMechanismList(
  CK_SLOT_ID            slotID,          /* ID of token's slot */
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
)
{
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_GetMechanismList(slotID, pMechanismList, pulCount);
  	mutex.Unlock();
 	return ret;

}



/* HD_C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token.
 */
CK_RV P11func_SC::Adapter_C_GetMechanismInfo(
  CK_SLOT_ID            slotID,  /* ID of the token's slot */
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
	CK_RV ret = 0;
 	mutex.Lock();
	ret = function_list_ptr->C_GetMechanismInfo(slotID, type, pInfo);
  	mutex.Unlock();
 	return ret;

}



/* HD_C_InitToken initializes a token. */
CK_RV P11func_SC::Adapter_C_InitToken(
  CK_SLOT_ID      slotID,    /* ID of the token's slot */
  CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
  CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
  CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);

	CK_RV ret = 0;
 	mutex.Lock();
	ret = function_list_ptr->C_InitToken(slotID,pPin,ulPinLen,pLabel);
  	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT, rv = 0x%lx",__FUNCTION__,ret);
 	return ret;

}



/* HD_C_InitPIN initializes the normal user's PIN. */
CK_RV P11func_SC::Adapter_C_InitPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_InitPIN(hSession,pPin,ulPinLen);
  	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT, rv = 0x%lx",__FUNCTION__,ret);
 	return ret;
}



/* HD_C_SetPIN modifies the PIN of the user who is logged in. */
CK_RV P11func_SC::Adapter_C_SetPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_SetPIN(hSession,pOldPin,ulOldLen,pNewPin,ulNewLen);
  	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT, rv = 0x%lx",__FUNCTION__,ret);
 	return ret;

}




/* Session management */

/* HD_C_OpenSession opens a session between an application and a
 * token.
 */
CK_RV P11func_SC::Adapter_C_OpenSession(
  CK_SLOT_ID            slotID,        /* the slot's ID */
  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
  CK_VOID_PTR           pApplication,  /* passed to callback */
  CK_NOTIFY             Notify,        /* callback function */
  CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_OpenSession(slotID,flags,pApplication,Notify,phSession);
  	mutex.Unlock();

	LOGSERVERI(tag, "%s OUT, ret = 0x%lx,new sesssion is 0x%lx",__FUNCTION__,ret,*phSession);
 	return ret;

}



/* HD_C_CloseSession closes a session between an application and a
 * token.
 */
CK_RV P11func_SC::Adapter_C_CloseSession(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	LOGSERVERI(tag,"%s IN, hSession = 0x%lx",__FUNCTION__,hSession);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_CloseSession(hSession);
  	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT, rv = 0x%lx",__FUNCTION__,ret);
 	return ret;

}



/* HD_C_CloseAllSessions closes all sessions with a token. */
CK_RV P11func_SC::Adapter_C_CloseAllSessions(
  CK_SLOT_ID     slotID  /* the token's slot */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_CloseAllSessions(slotID);
  	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT, rv = 0x%lx",__FUNCTION__,ret);
 	return ret;

}



/* HD_C_GetSessionInfo obtains information about the session. */
CK_RV P11func_SC::Adapter_C_GetSessionInfo(
  CK_SESSION_HANDLE   hSession,  /* the session's handle */
  CK_SESSION_INFO_PTR pInfo      /* receives session info */
)
{
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_GetSessionInfo(hSession, pInfo);
  	mutex.Unlock();
 	return ret;

}



/* HD_C_GetOperationState obtains the state of the cryptographic operation
 * in a session.
 */
CK_RV P11func_SC::Adapter_C_GetOperationState(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_GetOperationState(hSession,pOperationState,pulOperationStateLen);
  	mutex.Unlock();
 	return ret;

}


/* HD_C_SetOperationState restores the state of the cryptographic
 * operation in a session.
 */
CK_RV P11func_SC::Adapter_C_SetOperationState(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
)
{
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_SetOperationState(hSession,pOperationState,ulOperationStateLen,hEncryptionKey,hAuthenticationKey);
  	mutex.Unlock();
 	return ret;

}



/* HD_C_Login logs a user into a token. */
CK_RV P11func_SC::Adapter_C_Login(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
	CK_RV ret = 0;
	
	LOGSERVERI(tag, "%s IN",__FUNCTION__);
  	mutex.Lock();
	ret = function_list_ptr->C_Login(hSession,userType,pPin,ulPinLen);
  	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT with ret = 0x%lx",__FUNCTION__,ret);
 	return ret;

}




/* HD_C_Logout logs a user out from a token. */
CK_RV P11func_SC::Adapter_C_Logout(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_Logout(hSession);
	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT, rv = 0x%lx",__FUNCTION__,ret);
	return ret;

}




/* Object management */

/* HD_C_CreateObject creates a new object. */
CK_RV P11func_SC::Adapter_C_CreateObject(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
)
{
	CK_RV ret = 0;
	//if the object is a symmetric key, switch the template
	CK_OBJECT_CLASS key_class;
	CK_ATTRIBUTE_PTR pTemplate_new = NULL;
	CK_ULONG ulCountnew = 0;
	LOGSERVERI(tag, "%s IN",__FUNCTION__);

	CK_KEY_TYPE keytype = get_KeytypeAndClass(pTemplate,ulCount,&key_class); 

	if(key_class == CKO_SECRET_KEY)
	{		
		ret = switchSecretKeyTemplate(pTemplate,ulCount,&pTemplate_new,&ulCountnew);
		
		if(ret == CKR_OK)
		{
			mutex.Lock();
			ret = function_list_ptr->C_CreateObject(hSession,pTemplate_new,ulCountnew,phObject);
			mutex.Unlock();
		}	
		freeTemplate(&pTemplate_new,ulCountnew);
	}
	else
	{	
		mutex.Lock();
		ret = function_list_ptr->C_CreateObject(hSession,pTemplate,ulCount,phObject);
		mutex.Unlock();
	}
	
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}




/* HD_C_CopyObject copies an object, creating a new object for the
 * copy.
 */
CK_RV P11func_SC::Adapter_C_CopyObject(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_OBJECT_HANDLE     hObject,     /* the object's handle */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
  CK_ULONG             ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
)
{
	CK_RV ret = 0;
	mutex.Lock();
	ret = function_list_ptr->C_CopyObject(hSession,hObject,pTemplate,ulCount,phNewObject);
	mutex.Unlock();
	return ret;
}


/* HD_C_DestroyObject destroys an object. */
CK_RV P11func_SC::Adapter_C_DestroyObject(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
)
{
	LOGSERVERI(tag, "%s IN, hObject is 0x%lx", __FUNCTION__,hObject);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_DestroyObject(hSession,hObject);
	mutex.Unlock();

	LOGSERVERI(tag, "%s OUT, ret is 0x%lx", __FUNCTION__,ret);
	return ret;

}



/* HD_C_GetObjectSize gets the size of an object in bytes. */
CK_RV P11func_SC::Adapter_C_GetObjectSize(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
) 
{

	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_GetObjectSize(hSession,hObject,pulSize);
	mutex.Unlock();
	return ret;

}




/* HD_C_GetAttributeValue obtains the value of one or more object
 * attributes.
 */
CK_RV P11func_SC::Adapter_C_GetAttributeValue(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount     /* attributes in template */
)
{
	CK_RV ret = 0;
	int i,j;
	LOGSERVERI(tag,"%s IN", __FUNCTION__);

	ret = checkIdAndSID(pTemplate,ulCount,NULL,NULL);
	if(ret>0)
	{
		CK_OBJECT_CLASS getclass = -1;
		CK_ATTRIBUTE pTemplate_getclass[] ={
			{CKA_CLASS, &getclass, sizeof(CK_OBJECT_CLASS)}
		};
		mutex.Lock();		
		ret = function_list_ptr->C_GetAttributeValue(hSession,hObject,pTemplate_getclass,ulCount);
		mutex.Unlock();
		
		if(getclass == CKO_SECRET_KEY)
		{			
			CK_ATTRIBUTE_PTR pTemplate_new = NULL;
			if(NULL==pTemplate_new)
			{
				LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
				return CKR_FUNCTION_FAILED;
			}
			CK_ULONG ulCountnew = 0;
			ret = switchSecretKeyTemplate(pTemplate,ulCount,&pTemplate_new,&ulCountnew);
		
			mutex.Lock();
			ret = function_list_ptr->C_GetAttributeValue(hSession,hObject,pTemplate_new,ulCountnew);
			mutex.Unlock();
			
			if(ret == CKR_OK)
			{
				for(i=0;i<ulCount;i++)
				{
					for(j=0;j<ulCountnew;j++)
					{
						if(pTemplate[i].type==pTemplate_new[i].type)
						{
							pTemplate[i].ulValueLen = pTemplate_new[i].ulValueLen;
							if(pTemplate[i].pValue)
							{
								memcpy(pTemplate[i].pValue,pTemplate_new[i].pValue,pTemplate[i].ulValueLen);
							}
							break;
						}
					}
				}
			}
			freeTemplate(&pTemplate_new, ulCount);
			LOGSERVERI(tag,"%s OUT2,ret = 0x%lx", __FUNCTION__,ret);
			return ret;
		}
	}

	LOGSERVERI(tag,"%s IN2", __FUNCTION__);			
	mutex.Lock();
	ret = function_list_ptr->C_GetAttributeValue(hSession,hObject,pTemplate,ulCount);
	mutex.Unlock();
	
	LOGSERVERI(tag,"%s OUT,ret = 0x%lx", __FUNCTION__,ret);
	return ret;

}




/* HD_C_SetAttributeValue modifies the value of one or more object
 * attributes.
 */
CK_RV P11func_SC::Adapter_C_SetAttributeValue(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
)
{
	CK_RV ret = 0;
	
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	if(checkIdAndSID(pTemplate,ulCount,NULL,NULL))
	{		
		CK_OBJECT_CLASS getclass = -1;
		CK_ATTRIBUTE pTemplate_getclass[] ={
			{CKA_CLASS, &getclass, sizeof(CK_OBJECT_CLASS)}
		};
		mutex.Lock();		
		ret = function_list_ptr->C_GetAttributeValue(hSession,hObject,pTemplate_getclass,ulCount);
		mutex.Unlock();

		if(getclass == CKO_SECRET_KEY)
		{			
//			CK_ATTRIBUTE_PTR pTemplate_new = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * ulCount);
			CK_ATTRIBUTE_PTR pTemplate_new = NULL;

			CK_ULONG ulCountnew = 0;
			ret = switchSecretKeyTemplate(pTemplate,ulCount,&pTemplate_new,&ulCountnew);
			
			mutex.Lock();
			ret = function_list_ptr->C_SetAttributeValue(hSession,hObject,pTemplate_new,ulCountnew);
			mutex.Unlock();
						
			freeTemplate(&pTemplate_new,ulCountnew);
			
			LOGSERVERI(tag, "%s OUT2, ret = 0x%lx",__FUNCTION__,ret);	
			return ret;
		}
	}
	
	LOGSERVERI(tag,"%s IN2",__FUNCTION__);
  	mutex.Lock();
	ret = function_list_ptr->C_SetAttributeValue(hSession,hObject,pTemplate,ulCount);
	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}




/* HD_C_FindObjectsInit initializes a search for token and session
 * objects that match a template.
 */
CK_RV P11func_SC::Adapter_C_FindObjectsInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
)
{
	CK_RV ret = 0;
	CK_BYTE idindex = 0;
	CK_BYTE sidindex = 0;

	tmpSIDstruct tmp_struct = {0};
	
	memset(&tmp_struct,0,sizeof(tmp_struct));
	tmp_struct.tmp_sid = INVALID_VALUE;
	CK_ULONG ulCountNew;
	
	LOGSERVERI(tag,"%s IN", __FUNCTION__);
	CK_OBJECT_CLASS getclass = INVALID_VALUE;
	
	if(pTemplate != NULL_PTR && ulCount != 0)
	{
		ret = get_KeytypeAndClass(pTemplate,ulCount, &getclass);

		
/*		for(int i = 0;i<ulCount;i++)
		{
			LOGSERVERI(tag,"pTemplate %d, type is 0x%x, len is %d", i,pTemplate[i].type,pTemplate[i].ulValueLen);
			Print_Data((char *) tag,(unsigned char *) pTemplate[i].pValue,pTemplate[i].ulValueLen);
		}
*/
		if(!isCOKEK(pTemplate, ulCount))
		{
			if((getclass == CKO_SECRET_KEY && ret != CKK_SESSKEY_EXCHANGE) || ret == CKK_SM4 || ret == CKK_ZUC)
			{
				ret = checkIdAndSID(pTemplate,ulCount,&idindex,&sidindex);
				
				if(ret!=0)
				{
					if(ret == ulCount)
					{
						LOGSERVERI(tag,"findobjectinit template Error");
						return CKR_ARGUMENTS_BAD;
					}

					//check if the template is for BK
					if(sidindex !=INVALID_VALUE)
					{			
						memcpy(&tmp_struct.tmp_sid,pTemplate[sidindex].pValue,sizeof(CK_BYTE));
						if(tmp_struct.tmp_sid == CK_SESSKEY_PRESET_ID7)
						{
							LOGSERVERI(tag,"BK template");
							tmp_struct.tmp_sid = INVALID_VALUE;
							CK_BBOOL ttrue = CK_TRUE;
							CK_OBJECT_CLASS baseKeyClass = CKO_SECRET_KEY;
							CK_KEY_TYPE baseKeyType = CKK_SM4;
							
							CK_ATTRIBUTE findBaseKeyTemplate[] = {
								   {CKA_CLASS, &baseKeyClass, sizeof(baseKeyClass)},
								   {CKA_KEY_TYPE, &baseKeyType, sizeof(baseKeyType) },
								   {CKA_TRUSTED,&ttrue, sizeof(ttrue)}
							};
												
							mutex.Lock();
							ret = function_list_ptr->C_FindObjectsInit(hSession,findBaseKeyTemplate,sizeof(findBaseKeyTemplate)/sizeof(CK_ATTRIBUTE));
							mutex.Unlock();

							if(ret == CKR_OK){							
								map_tmpsid[hSession] = tmp_struct;
							}
							
							LOGSERVERI(tag,"%s OUT3 with ret 0x%lx,tmp_sid is 0x%x", __FUNCTION__,ret,tmp_struct.tmp_sid);

							return ret;		
						}
					}
					
					//store the value of id and sid
					if(idindex != INVALID_VALUE)
					{
						tmp_struct.tmp_id_len = pTemplate[idindex].ulValueLen;
						LOGSERVERI(tag,"tmp_id_len is %ld, idindex is %d", tmp_struct.tmp_id_len,idindex);
						
						memcpy(tmp_struct.tmp_id,(CK_BYTE_PTR)pTemplate[idindex].pValue,tmp_struct.tmp_id_len);
					}
				
					
					ulCountNew = ulCount-ret;
					CK_ATTRIBUTE_PTR pTemplate_new = (CK_ATTRIBUTE_PTR)malloc(ulCountNew*sizeof(CK_ATTRIBUTE));
					cutIDandSID(pTemplate,ulCount,pTemplate_new,&ulCountNew);

/*					for(int i = 0;i<ulCountNew;i++)
					{
						LOGSERVERI(tag,"pTemplate_new %d, type is 0x%lx, len is %lu", i,pTemplate_new[i].type,pTemplate_new[i].ulValueLen);
						Print_Data_I((char *) tag,(unsigned char *) pTemplate_new[i].pValue,pTemplate_new[i].ulValueLen);
					}
*/
					mutex.Lock();
					ret = function_list_ptr->C_FindObjectsInit(hSession,pTemplate_new,ulCountNew);
					mutex.Unlock();
					
					freeTemplate(&pTemplate_new,ulCountNew);

					if(ret == CKR_OK){							
						map_tmpsid[hSession] = tmp_struct;
					}
					
					LOGSERVERI(tag,"%s OUT2 with ret 0x%lx, tmp_id_len is %ld, tmp_sid is 0x%x", __FUNCTION__,ret,tmp_struct.tmp_id_len, tmp_struct.tmp_sid);
					return ret;
				}
			}
		}
	}
	
	LOGSERVERI(tag,"%s IN2",__FUNCTION__);
 	mutex.Lock();
	ret = function_list_ptr->C_FindObjectsInit(hSession,pTemplate,ulCount);
	mutex.Unlock();

	if(ret == CKR_OK){							
		map_tmpsid[hSession] = tmp_struct;
	}
	
	LOGSERVERI(tag,"%s OUT with ret 0x%lx", __FUNCTION__,ret);
	return ret;

}



/* HD_C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles.
 */
CK_RV P11func_SC::Adapter_C_FindObjects(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
	CK_RV ret = 0;
	int i=0,j=0;
	tmpSIDstruct tmp_struct;

	if(map_tmpsid.find(hSession) == map_tmpsid.end()){
		LOGSERVERE(tag,"find init not success!");
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	tmp_struct = map_tmpsid[hSession];
	 
	LOGSERVERI(tag,"%s IN, tmp_id_len is %ld", __FUNCTION__,tmp_struct.tmp_id_len);
	if((0 == tmp_struct.tmp_id_len)&&(INVALID_VALUE == tmp_struct.tmp_sid))
	{		
		mutex.Lock();
		ret = function_list_ptr->C_FindObjects(hSession,phObject,ulMaxObjectCount,pulObjectCount);
		mutex.Unlock();	
		
		LOGSERVERI(tag,"%s OUT with ret 0x%lx, ulObjectCount = %ld", __FUNCTION__,ret,*pulObjectCount);
		return ret;
	}
	
	CK_ULONG         ulObjectCount_tmp;
	CK_OBJECT_HANDLE_PTR phObject_tmp = (CK_OBJECT_HANDLE_PTR)malloc(ulMaxObjectCount*sizeof(CK_ULONG));
	if(NULL==phObject_tmp)
	{
		LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	
	CK_BYTE getnid[256];		
	CK_ULONG nidlen = 0;	
	CK_ATTRIBUTE pTemplate_getnid[] ={
		{CKA_ID, getnid, 256}
	};

	CK_BYTE has_sid = 0;
	CK_BYTE sid = INVALID_VALUE;
	CK_BYTE getid[256];
	CK_ULONG idlen = 0;	
	
	
	mutex.Lock();
	ret = function_list_ptr->C_FindObjects(hSession,phObject_tmp,ulMaxObjectCount,&ulObjectCount_tmp);
	mutex.Unlock();
	LOGSERVERI(tag, "find, count is %ld, ret = 0x%lx", ulObjectCount_tmp,ret);

	for(i=0;i<ulObjectCount_tmp;i++)
	{	
		memset(getnid,0,nidlen);
		memset(getid,0,sizeof(getid));
		
		mutex.Lock();
		ret = function_list_ptr->C_GetAttributeValue(hSession,phObject_tmp[i],pTemplate_getnid,1);
		mutex.Unlock();

		if(ret != CKR_OK)
		{
			LOGSERVERE(tag, "%s, C_GetAttributeValue ret = 0x%lx",__FUNCTION__,ret);
			
			free(phObject_tmp);
			phObject_tmp = NULL;
			return ret;
		}
		
		nidlen = pTemplate_getnid[0].ulValueLen;
		LOGSERVERI(tag,"index %d, GetAttributeValue, nidlen is %ld",i, nidlen);
		Print_Data_Server((char *)tag,getnid,nidlen);
		
		//get the real id and sid of the object, and then compare
		if(getnid[HASSIDFLAG_LOC] == HAS_SID)
		{
			LOGSERVERI(tag, "get object has sid");
			has_sid = HAS_SID;
			sid = getnid[SID_LOC];			
			idlen = nidlen - FLAG_LEN - SID_LEN;
			memcpy(getid,getnid + FLAG_LEN + SID_LEN,idlen);
		}
		else
		{	
			idlen = nidlen-FLAG_LEN;
			
			LOGSERVERI(tag, "get object no sid, idlen = %lu", idlen);
			memcpy(getid,getnid+FLAG_LEN,idlen);
		}
		
		LOGSERVERI(tag,"compare tmp_sid");
		
		if(tmp_struct.tmp_sid!=INVALID_VALUE)
		{
			if((has_sid != HAS_SID)||(sid != tmp_struct.tmp_sid))
			{
				LOGSERVERI(tag,"sid different");
				continue;
			}
		}

		
		LOGSERVERI(tag,"compare tmp_id");
			
		if(tmp_struct.tmp_id_len != 0)
		{
			if(tmp_struct.tmp_id_len!=idlen)
			{				
				LOGSERVERI(tag,"id len different, idlen = %ld, tmp_id_len = %ld",idlen,tmp_struct.tmp_id_len);
				continue;
			}
			
			if(memcmp(getid, tmp_struct.tmp_id, tmp_struct.tmp_id_len))
			{
				LOGSERVERI(tag,"id different");
				continue;				
			}
		}	
		
		phObject[j] = phObject_tmp[i];	
		j++;
	}
	*pulObjectCount = j;
	
	free(phObject_tmp);
	phObject_tmp = NULL;
	
	LOGSERVERI(tag,"%s OUT2 with ret 0x%lx,pulObjectCount = %lu", __FUNCTION__,ret, *pulObjectCount);
	return ret;

}



/* HD_C_FindObjectsFinal finishes a search for token and session
 * objects.
 */
CK_RV P11func_SC::Adapter_C_FindObjectsFinal(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{	
	LOGSERVERI(tag,"%s IN", __FUNCTION__);
	CK_RV ret = 0;

//	memset(tmp_id,0,sizeof(tmp_id));
	
  	mutex.Lock();
	ret = function_list_ptr->C_FindObjectsFinal(hSession);
	mutex.Unlock();

	if(ret == CKR_OK){
		map_tmpsid.erase(hSession);
		LOGSERVERI(tag,"map erase 0x%lx",hSession);
	}
	LOGSERVERI(tag,"%s OUT with ret 0x%lx", __FUNCTION__,ret);
	return ret;
}

/* Encryption and decryption */

/* HD_C_EncryptInit initializes an encryption operation. */
CK_RV P11func_SC::Adapter_C_EncryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{	
	LOGSERVERI(tag,"%s IN", __FUNCTION__);
	CK_RV ret = 0;
 	mutex.Lock();
	ret = function_list_ptr->C_EncryptInit(hSession,pMechanism,hKey);
	mutex.Unlock();
	
	LOGSERVERI(tag,"%s OUT with ret 0x%lx", __FUNCTION__,ret);
	return ret;

}



/* HD_C_Encrypt encrypts single-part data. */
CK_RV P11func_SC::Adapter_C_Encrypt(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
)
{
	LOGSERVERI(tag,"%s IN", __FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_Encrypt(hSession,pData,ulDataLen,pEncryptedData,pulEncryptedDataLen);
	mutex.Unlock();
	LOGSERVERI(tag,"%s OUT with ret 0x%lx", __FUNCTION__,ret);
	return ret;

}




/* HD_C_EncryptUpdate continues a multiple-part encryption
 * operation.
 */
CK_RV P11func_SC::Adapter_C_EncryptUpdate(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
)
{
	LOGSERVERI(tag,"%s IN", __FUNCTION__);

	CK_RV ret = 0;
  mutex.Lock();
	ret = function_list_ptr->C_EncryptUpdate(hSession,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
	mutex.Unlock();
	LOGSERVERI(tag,"%s OUT with ret 0x%lx", __FUNCTION__,ret);
	return ret;

}



/* HD_C_EncryptFinal finishes a multiple-part encryption
 * operation.
 */
CK_RV P11func_SC::Adapter_C_EncryptFinal(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
)
{
	LOGSERVERI(tag,"%s IN", __FUNCTION__);

	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_EncryptFinal(hSession,pLastEncryptedPart,pulLastEncryptedPartLen);
	mutex.Unlock();
	LOGSERVERI(tag,"%s OUT with ret 0x%lx", __FUNCTION__,ret);
	return ret;

}



/* HD_C_DecryptInit initializes a decryption operation. */
CK_RV P11func_SC::Adapter_C_DecryptInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
)
{
	LOGSERVERI(tag,"%s IN", __FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_DecryptInit(hSession,pMechanism,hKey);
	mutex.Unlock();
	LOGSERVERI(tag,"%s OUT with ret 0x%lx", __FUNCTION__,ret);
	return ret;

}



/* HD_C_Decrypt decrypts encrypted data in a single part. */
CK_RV P11func_SC::Adapter_C_Decrypt(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
)
{
	LOGSERVERI(tag,"%s IN", __FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_Decrypt(hSession,pEncryptedData,ulEncryptedDataLen,pData,pulDataLen);
	mutex.Unlock();
	LOGSERVERI(tag,"%s OUT with ret 0x%lx", __FUNCTION__,ret);
	return ret;

}



/* HD_C_DecryptUpdate continues a multiple-part decryption
 * operation.
 */
CK_RV P11func_SC::Adapter_C_DecryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
)
{
	LOGSERVERI(tag,"%s IN", __FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_DecryptUpdate(hSession,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
	mutex.Unlock();
	LOGSERVERI(tag,"%s OUT with ret 0x%lx", __FUNCTION__,ret);
	return ret;

}



/* HD_C_DecryptFinal finishes a multiple-part decryption
 * operation.
 */
CK_RV P11func_SC::Adapter_C_DecryptFinal(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{
	LOGSERVERI(tag,"%s IN", __FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_DecryptFinal(hSession,pLastPart,pulLastPartLen);
	mutex.Unlock();
	LOGSERVERI(tag,"%s OUT with ret 0x%lx", __FUNCTION__,ret);
	return ret;

}




/* Message digesting */

/* HD_C_DigestInit initializes a message-digesting operation. */
CK_RV P11func_SC::Adapter_C_DigestInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
 	mutex.Lock();
	ret = function_list_ptr->C_DigestInit(hSession,pMechanism);
	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_Digest digests data in a single part. */
CK_RV P11func_SC::Adapter_C_Digest(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
)
{
	CK_RV ret = 0;
	
	LOGSERVERI(tag, "%s IN", __FUNCTION__);
 	mutex.Lock();
	ret = function_list_ptr->C_Digest(hSession,pData,ulDataLen,pDigest,pulDigestLen);
	mutex.Unlock();

	LOGSERVERI(tag, "%s OUT, ret = 0x%lx", __FUNCTION__,ret);
	return ret;
}



/* HD_C_DigestUpdate continues a multiple-part message-digesting
 * operation.
 */
CK_RV P11func_SC::Adapter_C_DigestUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_DigestUpdate(hSession,pPart,ulPartLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested.
 */
CK_RV P11func_SC::Adapter_C_DigestKey(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_DigestKey(hSession,hKey);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_DigestFinal finishes a multiple-part message-digesting
 * operation.
 */
CK_RV P11func_SC::Adapter_C_DigestFinal(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_DigestFinal(hSession,pDigest,pulDigestLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;
}




/* Signing and MACing */

/* HD_C_SignInit initializes a signature (private key encryption)
 * operation, where the signature is (will be) an appendix to
 * the data, and plaintext cannot be recovered from the
 * signature.
 */
CK_RV P11func_SC::Adapter_C_SignInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signature key */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_SignInit(hSession,pMechanism,hKey);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	

	if((ret>= CKR_ERR_CHANNEL_INIT && ret<=CKR_ERR_CHANNEL_LOAD_ENGINE)
		||(ret == CKR_ERR_COOPERATE_TOKEN_NOT_READY))
	{
		ret = CKR_SC_NETWORK_ERR;
	}
	return ret;

}



/* HD_C_Sign signs (encrypts with private key) data in a single
 * part, where the signature is (will be) an appendix to the
 * data, and plaintext cannot be recovered from the signature.
 */
CK_RV P11func_SC::Adapter_C_Sign(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_Sign(hSession,pData,ulDataLen,pSignature,pulSignatureLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	

	if((ret>= CKR_ERR_CHANNEL_INIT && ret<=CKR_ERR_CHANNEL_LOAD_ENGINE)
		||(ret == CKR_ERR_COOPERATE_TOKEN_NOT_READY))
	{
		ret = CKR_SC_NETWORK_ERR;
	}
	return ret;

}



/* HD_C_SignUpdate continues a multiple-part signature operation,
 * where the signature is (will be) an appendix to the data,
 * and plaintext cannot be recovered from the signature.
 */
CK_RV P11func_SC::Adapter_C_SignUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_SignUpdate(hSession,pPart,ulPartLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_SignFinal finishes a multiple-part signature operation,
 * returning the signature.
 */
CK_RV P11func_SC::Adapter_C_SignFinal(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_SignFinal(hSession,pSignature,pulSignatureLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature.
 */
CK_RV P11func_SC::Adapter_C_SignRecoverInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_SignRecoverInit(hSession,pMechanism,hKey);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;
}




/* HD_C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature.
 */
CK_RV P11func_SC::Adapter_C_SignRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_SignRecover(hSession,pData,ulDataLen,pSignature,pulSignatureLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}




/* Verifying signatures and MACs */

/* HD_C_VerifyInit initializes a verification operation, where the
 * signature is an appendix to the data, and plaintext cannot
 * cannot be recovered from the signature (e.g. DSA).
 */
CK_RV P11func_SC::Adapter_C_VerifyInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_VerifyInit(hSession,pMechanism,hKey);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_Verify verifies a signature in a single-part operation,
 * where the signature is an appendix to the data, and plaintext
 * cannot be recovered from the signature.
 */
CK_RV P11func_SC::Adapter_C_Verify(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_Verify(hSession,pData,ulDataLen,pSignature,ulSignatureLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_VerifyUpdate continues a multiple-part verification
 * operation, where the signature is an appendix to the data,
 * and plaintext cannot be recovered from the signature.
 */
CK_RV P11func_SC::Adapter_C_VerifyUpdate(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_VerifyUpdate(hSession,pPart,ulPartLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_VerifyFinal finishes a multiple-part verification
 * operation, checking the signature.
 */
CK_RV P11func_SC::Adapter_C_VerifyFinal(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_VerifyFinal(hSession,pSignature,ulSignatureLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature.
 */
CK_RV P11func_SC::Adapter_C_VerifyRecoverInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_VerifyRecoverInit(hSession,pMechanism,hKey);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature.
 */
CK_RV P11func_SC::Adapter_C_VerifyRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_VerifyRecover(hSession,pSignature,ulSignatureLen,pData,pulDataLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;
}




/* Dual-function cryptographic operations */

/* HD_C_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation.
 */
CK_RV P11func_SC::Adapter_C_DigestEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_DigestEncryptUpdate(hSession,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation.
 */
CK_RV P11func_SC::Adapter_C_DecryptDigestUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_DecryptDigestUpdate(hSession,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation.
 */
CK_RV P11func_SC::Adapter_C_SignEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_SignEncryptUpdate(hSession,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation.
 */
CK_RV P11func_SC::Adapter_C_DecryptVerifyUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_DecryptVerifyUpdate(hSession,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}




/* Key management */

/* HD_C_GenerateKey generates a secret key, creating a new key
 * object.
 */
CK_RV P11func_SC::Adapter_C_GenerateKey(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
)
{
	CK_RV ret = 0;
	CK_ULONG ulCountnew = 0;
	LOGSERVERI(tag, "%s IN", __FUNCTION__);
	if(pMechanism->mechanism == CKM_SESSKEY_EXCHANGE_GEN)
	{		
		LOGSERVERI(tag, "%s, keyexchange", __FUNCTION__);
		CK_MECHANISM SessKeyExchangeMechanism = {CKM_ZUC_KEY_GEN, NULL, 0};		
		mutex.Lock();
		ret = Pointer_C_GenerateLocalSessKey(hSession, &SessKeyExchangeMechanism, pTemplate, ulCount, phKey);
		mutex.Unlock();

		return ret;
	}
	
//	CK_ATTRIBUTE_PTR pTemplate_new = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * ulCount);	
	CK_ATTRIBUTE_PTR pTemplate_new = NULL;

	ret = switchSecretKeyTemplate(pTemplate,ulCount,&pTemplate_new,&ulCountnew);

  	mutex.Lock();
	ret = function_list_ptr->C_GenerateKey(hSession,pMechanism,pTemplate_new,ulCountnew,phKey);
	mutex.Unlock();
	
	freeTemplate(&pTemplate_new,ulCountnew);
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_GenerateKeyPair generates a public-key/private-key pair,
 * creating new key objects.
 */
CK_RV P11func_SC::Adapter_C_GenerateKeyPair(
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
	CK_RV ret = 0;
	int i=0;
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	for(i=0;i<ulPublicKeyAttributeCount;i++)
	{
		if(pPublicKeyTemplate[i].type == CKA_ISEXCHANGEKEY)
		{	
			LOGSERVERI(tag,"%s IN1",__FUNCTION__);
			
//			CK_MECHANISM  ECCMechanism = {CKM_SM2_KEY_PAIR_GEN+2, NULL_PTR, 0};
			
			mutex.Lock();
			ret = Pointer_C_GenerateExchangeKeypair_sc(hSession, pMechanism,pPublicKeyTemplate, ulPublicKeyAttributeCount,
			pPrivateKeyTemplate, ulPrivateKeyAttributeCount,phPublicKey, phPrivateKey);
			mutex.Unlock();

			LOGSERVERI(tag,"%s OUT1,ret = 0x%lx",__FUNCTION__,ret);
			if((ret>= CKR_ERR_CHANNEL_INIT && ret<=CKR_ERR_CHANNEL_LOAD_ENGINE)
				||(ret == CKR_ERR_COOPERATE_TOKEN_NOT_READY))
			{
				ret = CKR_SC_NETWORK_ERR;
			}
			return ret;
		}
	}
	
	LOGSERVERI(tag,"%s IN2",__FUNCTION__);
  	mutex.Lock();
	ret = function_list_ptr->C_GenerateKeyPair(hSession,pMechanism,pPublicKeyTemplate,ulPublicKeyAttributeCount,
	 pPrivateKeyTemplate,ulPrivateKeyAttributeCount,phPublicKey,phPrivateKey);
	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);

	if((ret>= CKR_ERR_CHANNEL_INIT && ret<=CKR_ERR_CHANNEL_LOAD_ENGINE)
		||(ret == CKR_ERR_COOPERATE_TOKEN_NOT_READY))
	{
		ret = CKR_SC_NETWORK_ERR;
	}
	return ret;

}



/* HD_C_WrapKey wraps (i.e., encrypts) a key. */
CK_RV P11func_SC::Adapter_C_WrapKey(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
)
{
	CK_RV ret = 0;
	
	LOGSERVERI(tag, "%s IN, hWrappingKey = 0x%lx,hKey = 0x%lx",__FUNCTION__,hWrappingKey,hKey);
	if(pMechanism->mechanism == CKM_WRAP_SESSKEY)
	{		
		LOGSERVERI(tag,"%s, keyexchange",__FUNCTION__);
		mutex.Lock();		
		ret = Pointer_C_WrapLocalSessKey(hSession, pMechanism, hKey, pWrappedKey, pulWrappedKeyLen);
		mutex.Unlock();
		
		return ret;
	}
	
  	mutex.Lock();
	ret = function_list_ptr->C_WrapKey(hSession,pMechanism,hWrappingKey,hKey,pWrappedKey,pulWrappedKeyLen);
	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx, ulWrappedKeyLen = %lu",__FUNCTION__,ret, *pulWrappedKeyLen);
	return ret;

}



/* HD_C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object.
 */
CK_RV P11func_SC::Adapter_C_UnwrapKey(
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
	CK_RV ret = 0;
	
	if(pMechanism->mechanism == CKM_UNWRAP_SESSKEY)
	{	
		LOGSERVERI(tag,"%s, keyexchange",__FUNCTION__);
		mutex.Lock();
		ret = Pointer_C_UnwrapRemoteSessKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
		mutex.Unlock();
		
		return ret;
	}
	
	CK_OBJECT_CLASS key_class;
	CK_ATTRIBUTE_PTR pTemplate_new = NULL;
	CK_ULONG ulCountnew = 0;
	LOGSERVERI(tag, "%s IN",__FUNCTION__);

	CK_KEY_TYPE keytype = get_KeytypeAndClass(pTemplate,ulAttributeCount,&key_class); 

	if(key_class == CKO_SECRET_KEY)
	{

		LOGSERVERI(tag,"unwrap secret key");
//		pTemplate_new = (CK_ATTRIBUTE_PTR)malloc(ulAttributeCount*sizeof(CK_ATTRIBUTE));	
		ret = switchSecretKeyTemplate(pTemplate,ulAttributeCount,&pTemplate_new,&ulCountnew);

		
		if(ret == CKR_OK)
		{
			mutex.Lock();
			ret = function_list_ptr->C_UnwrapKey(hSession,pMechanism,hUnwrappingKey,pWrappedKey,
	ulWrappedKeyLen,pTemplate_new,ulCountnew,phKey);
			mutex.Unlock();
			
		}	

		LOGSERVERI(tag,"phKey:0x%lx",*phKey);

/*		for(int i = 0;i<ulCountnew;i++)
		{
			LOGSERVERI(tag,"pTemplate_new %d, type is 0x%lx, len is %lu", i,pTemplate_new[i].type,pTemplate_new[i].ulValueLen);
			Print_Data_I((char *) tag,(unsigned char *) pTemplate_new[i].pValue,pTemplate_new[i].ulValueLen);
		}
*/
		freeTemplate(&pTemplate_new,ulCountnew);

	}
	else
	{
	 	mutex.Lock();
		ret = function_list_ptr->C_UnwrapKey(hSession,pMechanism,hUnwrappingKey,pWrappedKey,
		ulWrappedKeyLen,pTemplate,ulAttributeCount,phKey);
		mutex.Unlock();
	}

	
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);
	return ret;

}



/* HD_C_DeriveKey derives a key from a base key, creating a new key
 * object.
 */
CK_RV P11func_SC::Adapter_C_DeriveKey(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_DeriveKey(hSession,pMechanism,hBaseKey,pTemplate,ulAttributeCount,phKey);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}


/* Random number generation */

/* HD_C_SeedRandom mixes additional seed material into the token's
 * random number generator.
 */
CK_RV P11func_SC::Adapter_C_SeedRandom(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_SeedRandom(hSession,pSeed,ulSeedLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_GenerateRandom generates random data. */
CK_RV P11func_SC::Adapter_C_GenerateRandom(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_BYTE_PTR       RandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
 	mutex.Lock();
	ret = function_list_ptr->C_GenerateRandom(hSession,RandomData,ulRandomLen);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}




/* Parallel function management */

/* HD_C_GetFunctionStatus is a legacy function; it obtains an
 * updated status of a function running in parallel with an
 * application.
 */
CK_RV P11func_SC::Adapter_C_GetFunctionStatus(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_GetFunctionStatus(hSession);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_CancelFunction is a legacy function; it cancels a function
 * running in parallel.
 */
CK_RV P11func_SC::Adapter_C_CancelFunction(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_CancelFunction(hSession);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;

}



/* HD_C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur.
 */
CK_RV P11func_SC::Adapter_C_WaitForSlotEvent(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
)
{
	LOGSERVERI(tag,"%s IN",__FUNCTION__);
	CK_RV ret = 0;
  	mutex.Lock();
	ret = function_list_ptr->C_WaitForSlotEvent(flags,pSlot,pRserved);
	mutex.Unlock();
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);	
	return ret;
}




/********************************
 *剩余口令剩余尝试次数
*/
CK_RV P11func_SC::Adapter_C_Extend_GetPinRemainCount
(
  CK_SESSION_HANDLE hSession,
  CK_ULONG_PTR pUiRemainCount
)
{
  CK_RV ret = 0;  
  
  CK_USER_TYPE userType=CKU_USER;
  CK_EXTEND_IN ExtIn_GetPinTime = {CK_EXTEND_GETPINTIME, &userType, sizeof(CK_USER_TYPE)};
  CK_EXTEND_OUT ExtOut_GetPinTime = {CK_EXTEND_GETPINTIME, pUiRemainCount, sizeof(int)};

  LOGSERVERI(tag,"%s IN", __FUNCTION__);

  mutex.Lock();
  ret = Pointer_C_CryptoExtend(hSession, &ExtIn_GetPinTime, &ExtOut_GetPinTime, NULL);
  mutex.Unlock();
  
  LOGSERVERI(tag, "%s OUT, rv = 0x%lx, count = %ld",__FUNCTION__,ret, *pUiRemainCount);
  return ret;
}



/********************************
 *获取密码卡状态
*/
CK_RV P11func_SC::Adapter_C_Extend_GetStatus
(
  CK_SLOT_ID slotID,
  CK_STATUS_ENUM_PTR pStatus
)
{	
	LOGSERVERI(tag,"%s IN", __FUNCTION__);
  	CK_RV ret = 0;
	CK_SESSION_HANDLE hSession;
	
	CK_EXTEND_IN ExtIn_SDStatus = {CK_EXTEND_GETSDSTATUS, NULL, 0};
	//CK_EXTEND_OUT ExtOut_SDStatus = {CK_EXTEND_GETSDSTATUS, NULL, 0};
	CK_UINT status = 0;
	CK_EXTEND_OUT ExtOut_SDStatus = {CK_EXTEND_GETSDSTATUS,  &status, sizeof(CK_UINT)};	
	
	int iLoginState = 0;
	CK_EXTEND_IN ExtIn_GetLoginState = {CK_EXTEND_GETLOGINSTATE, NULL, 0};
	CK_EXTEND_OUT ExtOut_GetLoginState = {CK_EXTEND_GETLOGINSTATE, &iLoginState, sizeof(iLoginState)};

	mutex.Lock();
	ret = function_list_ptr->C_OpenSession(slotID,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL_PTR,NULL_PTR,&hSession);
	mutex.Unlock();
	
	if(ret != CKR_OK)
	{		
		LOGSERVERI(tag, "%s OUT2, ret = 0x%lx",__FUNCTION__,ret);	
		return ret;
	}	

	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_SDStatus, &ExtOut_SDStatus, NULL);	
	mutex.Unlock();
	LOGSERVERI(tag,"status get from card is 0x%x",status);

	if(ret == CKR_DEVICE_REMOVED){
		*pStatus = CK_STATUS_ENUM_DEVICE_OFF;
	}
	else if(ret == CKR_PIN_LOCKED){
		*pStatus = CK_STATUS_ENUM_DEVICE_LOCKED;
	}

	else if(ret == CKR_OK){		
		switch(status)
		{
			case CK_CARD_STATUS_OPER_AUTH:
				*pStatus = CK_STATUS_ENUM_UNLOGIN;
				break;
			case CK_CARD_STATUS_USER:
				*pStatus = CK_STATUS_ENUM_LOGIN;
				break;
			case CK_CARD_STATUS_ERROR_USER_LOCKED:
				*pStatus = CK_STATUS_ENUM_DEVICE_LOCKED;
				break;
			case CK_CARD_STATUS_ERROR_DESTORY:
				*pStatus = CK_STATUS_ENUM_DEVICE_DESTROY;
				break;
			default:
				*pStatus = CK_STATUS_ENUM_DEVICE_ABNORMAL;
				break;				
		}	
	}	
	else{
		LOGSERVERE(tag,"get sd status fail, ret = 0x%lx",ret);

		*pStatus = CK_STATUS_ENUM_DEVICE_ABNORMAL;
	}
	
	mutex.Lock();
	ret = function_list_ptr->C_CloseSession(hSession);
	mutex.Unlock();

	if(ret != CKR_OK)
	{			
		LOGSERVERI(tag, "%s OUT3, ret = 0x%lx",__FUNCTION__,ret);	
		return ret;
	}
	
	LOGSERVERI(tag,"%s OUT, status is %d", __FUNCTION__, *pStatus);
	return CKR_OK;
}

/********************************
 *注册密码卡状态回调函数
*/
 CK_RV P11func_SC::Adapter_C_Extend_Register_Callback
(
  register_status_callback_func func
)
{
  return CKR_OK;
}

/********************************
 *注销密码卡状态回调函数
*/
 CK_RV P11func_SC::Adapter_C_Extend_Unregister_Callback
(

  register_status_callback_func func
)
{
  return CKR_OK;
}

/********************************
 *使用监听公钥导出协商密钥
*/
 CK_RV P11func_SC::Adapter_C_Extend_GetExchangeSessionKey
(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hSessionKey,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG_PTR pulEncryptedDataLen
)
{
	CK_RV ret = 0;
	CK_BYTE nSessKeyID = 0;
	CK_EXTEND_IN	ExtIn_GetExchangeSessKey = {CK_EXTEND_GETEXCHANGESESSKEY, &nSessKeyID, sizeof(CK_BYTE)};
	CK_EXTEND_OUT   ExtOut_GetExchangeSessKey = {CK_EXTEND_GETEXCHANGESESSKEY, pEncryptedData, *pulEncryptedDataLen};
	
	LOGSERVERI(tag,"%s IN", __FUNCTION__);

	//get attribute value	

	CK_ATTRIBUTE template_get[] = {
		{CKA_SESSKEY_ID, &nSessKeyID, sizeof(CK_BYTE)}
	};
		
	mutex.Lock();
	ret = function_list_ptr->C_GetAttributeValue(hSession,hSessionKey,template_get,sizeof(template_get)/sizeof(template_get[0]));
	mutex.Unlock();

	if(ret != CKR_OK)
	{
		LOGSERVERE(tag,"get sesskeyID fail,hSessionKey is 0x%lx",hSessionKey);
		return ret;
	}

	LOGSERVERI(tag, "%s, keyid is %d,hSessionKey is 0x%lx",__FUNCTION__,nSessKeyID,hSessionKey);	
	
	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_GetExchangeSessKey, &ExtOut_GetExchangeSessKey, NULL);
	mutex.Unlock();

	LOGSERVERI(tag, "%s OUT, ret = 0x%lx, hSession = 0x%lx",__FUNCTION__,ret, hSession);

	return ret;
}

/********************************
 *参数注销
*/
 CK_RV P11func_SC::Adapter_C_Extend_Destroy
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
 CK_RV P11func_SC::Adapter_C_Extend_Reset_Pin_With_OTP
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbOTPPIN,
  CK_ULONG ulOTPPINLen,
  CK_BYTE_PTR pbNewUserPIN,
  CK_ULONG ulNewUserPINLen
)
{
  	CK_RV ret = 0;
	unsigned char *pbBuffer = NULL;
	
  	CK_EXTEND_IN ExtIn_ReSetUserPin = {CK_EXTEND_RESET_USERPIN, NULL, 0};
	CK_EXTEND_OUT ExtOut_ReSetUserPin = {CK_EXTEND_RESET_USERPIN, NULL, 0};
	
	LOGSERVERI(tag,"%s IN", __FUNCTION__);

	pbBuffer = (unsigned char *)malloc(ulOTPPINLen+ ulNewUserPINLen + 2);
	if(NULL==pbBuffer)
	{
		LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	ExtIn_ReSetUserPin.pParameter = pbBuffer;
	*pbBuffer = ulOTPPINLen;
	memcpy(pbBuffer + OTPPIN_LEN_SIZE, pbOTPPIN, ulOTPPINLen);
	*(pbBuffer + OTPPIN_LEN_SIZE + ulOTPPINLen) = ulNewUserPINLen;
	memcpy(pbBuffer + OTPPIN_LEN_SIZE + ulOTPPINLen + OTPPIN_LEN_SIZE, pbNewUserPIN, ulNewUserPINLen);
	ExtIn_ReSetUserPin.ulParameterLen = OTPPIN_LEN_SIZE + ulOTPPINLen + OTPPIN_LEN_SIZE + ulNewUserPINLen;
	
	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_ReSetUserPin, &ExtOut_ReSetUserPin, NULL);
	mutex.Unlock();
	
	free(pbBuffer);
	pbBuffer = NULL;
		
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);
	
	return ret;
}

/********************************
 *重设OTP口令
*/
 CK_RV P11func_SC::Adapter_C_Extend_Reset_OTP
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbOTPMpk,
  CK_ULONG ulMpkLen,
  CK_BYTE_PTR pbMpkIV,
  CK_ULONG ulMpkIVLen
)

{
	CK_RV ret = 0;

	LOGSERVERI(tag,"%s IN", __FUNCTION__);

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
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

/********************************
 *获取剩余OTP解锁次数
*/
 CK_RV P11func_SC::Adapter_C_Extend_Get_OTP_Unlock_Count
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
 CK_RV P11func_SC::Adapter_C_Extend_Get_OTP_Remain_Count
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
 CK_RV P11func_SC::Adapter_C_Extend_DeriveSessionKey
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
	CK_RV ret = 0;

	LOGSERVERI(tag,"%s IN,hLocalKey 0x%lx,hRemoteKey 0x%lx,ulAttributeCount %ld",__FUNCTION__,hLocalKey,hRemoteKey,ulAttributeCount);
	mutex.Lock();	
	ret = Pointer_C_DeriveSessKey(hSession, pMechanism, hLocalKey, hRemoteKey, pTemplate, ulAttributeCount, phKey, pExchangeIV, pExchangeIVLen);
	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);
	//Print_Data((char *)tag, pExchangeIV,*pExchangeIVLen);
	return ret;
}

/********************************
 *协商会话密钥加密初始化
*/
 CK_RV P11func_SC::Adapter_C_Extend_EncryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG ulAttributeCount
)
{
	CK_RV ret = 0;
	CK_OBJECT_HANDLE hKey[1];
	CK_KEY_TYPE exchangetype = CKK_SESSKEY_EXCHANGE;
	CK_ULONG ulObjectCount = 0;
	
	LOGSERVERI(tag,"%s IN", __FUNCTION__);

	int i=0;
	for(i=0;i<ulAttributeCount;i++)
	{
		if(pTemplate[i].type == CKA_KEY_TYPE)
		{
			if(memcmp(pTemplate[i].pValue,&exchangetype,sizeof(CK_KEY_TYPE)))
			{
				return CKR_MECHANISM_INVALID;
			}
		}
	}
	
	mutex.Lock();  
	ret = function_list_ptr->C_FindObjectsInit(hSession, pTemplate, ulAttributeCount);
	mutex.Unlock();
	if(ret != CKR_OK)
	{ 	
		LOGSERVERE(tag,"%s, findobjectinit fail",__FUNCTION__);
	    return ret;
	}

	mutex.Lock();  
	ret = function_list_ptr->C_FindObjects(hSession, hKey, 1, &ulObjectCount);
	mutex.Unlock();
	if(ret != CKR_OK)
	{ 	
		LOGSERVERE(tag,"%s, findobject fail",__FUNCTION__);
	    return ret;
	}
		
	mutex.Lock();  
	ret = function_list_ptr->C_FindObjectsFinal(hSession);
	mutex.Unlock();

	if(ret != CKR_OK)
	{ 	
		LOGSERVERE(tag,"%s, findobjectfinal fail",__FUNCTION__);
	    return ret;
	}
	
	LOGSERVERI(tag, "%s, hKey is 0x%lx, num = %lu", __FUNCTION__,hKey[0], ulObjectCount);

	
	hKey_enc = hKey[0];

	if(ulObjectCount == 0)
	{
		LOGSERVERE(tag,"no encrypt sesskey");
		ret = CKR_KEY_HANDLE_INVALID;
	}
	
	LOGSERVERI(tag, "%s OUT, ret is 0x%lx", __FUNCTION__,ret);

	return ret;
}

/******************************
 *协商会话密钥解密初始化
*/
 CK_RV P11func_SC::Adapter_C_Extend_DecryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_ATTRIBUTE_PTR  pTemplate,        /* handle of decryption key */
  CK_ULONG ulAttributeCount
)
{
	CK_RV ret = 0; 
	CK_OBJECT_HANDLE hKey[1];
	CK_KEY_TYPE exchangetype = CKK_SESSKEY_EXCHANGE;
    CK_ULONG ulObjectCount = 0;
	
	LOGSERVERI(tag,"%s IN", __FUNCTION__);

	int i=0;
	for(i=0;i<ulAttributeCount;i++)
	{
		if(pTemplate[i].type == CKA_KEY_TYPE)
		{
			if(memcmp(pTemplate[i].pValue,&exchangetype,sizeof(CK_KEY_TYPE)))
			{
				return CKR_MECHANISM_INVALID;
			}
		}
	}

	mutex.Lock();  
	ret = function_list_ptr->C_FindObjectsInit(hSession, pTemplate, ulAttributeCount);
	mutex.Unlock();
	if(ret != CKR_OK)
	{	
		LOGSERVERE(tag,"%s, findobjectinit fail",__FUNCTION__);
		return ret;
	}

	mutex.Lock();  
	ret = function_list_ptr->C_FindObjects(hSession, hKey, 1, &ulObjectCount);
	mutex.Unlock();
	if(ret != CKR_OK)
	{	
		LOGSERVERE(tag,"%s, findobject fail",__FUNCTION__);
		return ret;
	}
		
	mutex.Lock();  
	ret = function_list_ptr->C_FindObjectsFinal(hSession);
	mutex.Unlock();

	hKey_dec = hKey[0];

	
	if(ulObjectCount == 0)
	{
		
		LOGSERVERE(tag,"no decrypt sesskey");
		ret = CKR_KEY_HANDLE_INVALID;
	}
	
	LOGSERVERI(tag, "%s OUT, ret is 0x%lx, hKey is 0x%lx", __FUNCTION__,ret,hKey_dec);
		

	return ret;
}

/********************************
 *协商会话密钥分步加密
*/
 CK_RV P11func_SC::Adapter_C_Extend_EncryptUpdate
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
	CK_RV ret = 0;
	
	CK_BYTE outdata_final[256] = {0};
    CK_ULONG outdatalen_final=sizeof(outdata_final);

	//change to standard iv(softcard use standard iv, while hd and jw card use customized iv)
	//Reference: <EEA3_EIA3_specification_v1_6> Chapter 3.3
	CK_BYTE sc_iv[16];
	memset(sc_iv,0,sizeof(sc_iv));
		
	memcpy(sc_iv,pIv,4);
	sc_iv[4] = (pIv[7]<<3) + (pIv[11]<<2);
	memcpy(sc_iv+8,sc_iv,8);	
	//
	
	CK_MECHANISM ZUCmechanism = {CKM_ZUC_EEA, sc_iv, ulIvLen};
	
	LOGSERVERD(tag,"%s IN, len is %lu", __FUNCTION__,*pulEncryptedPartLen);
	
 	mutex.Lock();
	ret = function_list_ptr->C_EncryptInit(hSession,&ZUCmechanism,hKey_enc);
	mutex.Unlock();
	
	LOGSERVERD(tag,"encinit: ret = 0x%lx, hkey is 0x%lx",ret,hKey_enc);

	mutex.Lock();
	ret = function_list_ptr->C_Encrypt(hSession,pPart,ulPartLen,pEncryptedPart,pulEncryptedPartLen);
	mutex.Unlock();

	if(pEncryptedPart == NULL)
	{
		LOGSERVERI(tag, "%s output buffer is null",__FUNCTION__);
		mutex.Lock();
		ret = function_list_ptr->C_EncryptFinal(hSession, outdata_final, &outdatalen_final);
		mutex.Unlock();
	}

	LOGSERVERD(tag,"%s OUT, enc: ret = 0x%lx, pulEncryptedPartLen = %lu",__FUNCTION__,ret,*pulEncryptedPartLen);
	LOGSERVERI(tag,"%s OUT",__FUNCTION__);

	return ret;
}

/********************************
 *协商会话密钥分步解密
*/
 CK_RV P11func_SC::Adapter_C_Extend_DecryptUpdate
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
	CK_RV ret = 0;

	CK_BYTE outdata_final[256] = {0};
	CK_ULONG outdatalen_final=sizeof(outdata_final);

	//change to standard iv(softcard use standard iv, while hd and jw card use customized iv)
	CK_BYTE sc_iv[16];
	memset(sc_iv,0,sizeof(sc_iv));

	memcpy(sc_iv,pIv,4);
	sc_iv[4] = (pIv[7]<<3) + (pIv[11]<<2);
	memcpy(sc_iv+8,sc_iv,8);

	CK_MECHANISM ZUCmechanism = {CKM_ZUC_EEA, sc_iv, ulIvLen};

	LOGSERVERD(tag,"%s IN,*pulPartLen = %lu", __FUNCTION__,*pulPartLen);

	mutex.Lock();
	ret = function_list_ptr->C_DecryptInit(hSession,&ZUCmechanism,hKey_dec);
	mutex.Unlock();

	LOGSERVERD(tag,"decinit: ret = 0x%lx",ret);

	mutex.Lock();
	ret = function_list_ptr->C_Decrypt(hSession,pEncryptedPart,ulEncryptedPartLen,pPart,pulPartLen);
	mutex.Unlock();

	if(pPart == NULL)
	{
		LOGSERVERI(tag, "%s output buffer is null",__FUNCTION__);
		mutex.Lock();
		ret = function_list_ptr->C_DecryptFinal(hSession, outdata_final, &outdatalen_final);
		mutex.Unlock();
	}

	LOGSERVERI(tag,"%s OUT1, ret = 0x%lx, pulPartLen = %lu",__FUNCTION__,ret,*pulPartLen);

	return ret;
}

/********************************
 *协商会话密钥分步加密结束
*/
 CK_RV P11func_SC::Adapter_C_Extend_EncryptFinalize
(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
)
{
	CK_RV ret = 0;
	return ret;
}

/********************************
 *协商会话密钥分步解密结束
*/
 CK_RV P11func_SC::Adapter_C_Extend_DecryptFinalize
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{
  	CK_RV ret = 0;

	return ret;
}

/********************************
 *SM2点乘
*/
 CK_RV P11func_SC::Adapter_C_Extend_PointMultiply
(

  CK_SESSION_HANDLE hSession,

  CK_MECHANISM_PTR pMechanism,

  CK_OBJECT_HANDLE hKey,

  CK_BYTE_PTR pOutData,

  CK_ULONG_PTR pOutLen
)
{
	CK_RV ret = 0;
	
	LOGSERVERI(tag,"%s IN", __FUNCTION__);

	mutex.Lock();
	ret = Pointer_C_PointMultiply(hSession,pMechanism,hKey,pOutData,pOutLen);
	mutex.Unlock();
	
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);

	return ret;
}

/********************************
 *重设TT口令
*/
 CK_RV P11func_SC::Adapter_C_Extend_Reset_TT
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbTTMpk,
  CK_ULONG ulMpkLen,
  CK_BYTE_PTR pbMpkIV,
  CK_ULONG ulMpkIVLen
)
{
	CK_RV ret = 0;
	LOGSERVERI(tag,"%s IN",__FUNCTION__);

	unsigned int remoteSetType = CKO_REMOTE_TT;
	CK_EXTEND_IN ExtIn_setData_Remote = {CK_EXTEND_REMOTE_SET_DATA, NULL, 0};
	CK_EXTEND_OUT ExtOut_setData_Remote = {CK_EXTEND_REMOTE_SET_DATA, NULL, 0};

	LOGSERVERD(tag,"mpklen is: %lu, ivlen is %lu", ulMpkLen,ulMpkIVLen);
	
	unsigned char* pbBuffer_T = NULL_PTR;
	ExtIn_setData_Remote.ulParameterLen = sizeof(remoteSetType) + ulMpkIVLen + ulMpkLen;
	pbBuffer_T=(unsigned char*)malloc(sizeof(unsigned char)*(ExtIn_setData_Remote.ulParameterLen));
	if(NULL==pbBuffer_T)
	{
		LOGSERVERE(tag, "%s, malloc fail",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	ExtIn_setData_Remote.pParameter = pbBuffer_T;

	memcpy(pbBuffer_T, &remoteSetType, sizeof(remoteSetType));
	memcpy(pbBuffer_T + sizeof(remoteSetType), pbMpkIV, ulMpkIVLen);
	memcpy(pbBuffer_T + sizeof(remoteSetType) + ulMpkIVLen, pbTTMpk, ulMpkLen);
	Print_Data_Server((char *) tag,(unsigned char *) pbBuffer_T,ExtIn_setData_Remote.ulParameterLen);
	
	mutex.Lock();	
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_setData_Remote, &ExtOut_setData_Remote, NULL);
	mutex.Unlock();

	free(pbBuffer_T);	
	pbBuffer_T = NULL;
	
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

/********************************
 *重设BK口令
*/
 CK_RV P11func_SC::Adapter_C_Extend_Reset_BK
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pbBKMpk,
  CK_ULONG ulMpkLen,
  CK_BYTE_PTR pbMpkIV,
  CK_ULONG ulMpkIVLen
)
{
	CK_RV ret = 0;
	
	LOGSERVERI(tag,"%s IN", __FUNCTION__);

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
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}


CK_RV P11func_SC::Adapter_C_Extend_Get_Special_Object_Version
(	
	CK_SESSION_HANDLE hSession,
	
	CK_OBJECT_CLASS objectClass,
	
	CK_BYTE_PTR pVersion,
	
	CK_ULONG_PTR pUlLen
) 
{
	CK_RV ret = 0;
	
	LOGSERVERI(tag,"%s IN", __FUNCTION__);
	
	CK_EXTEND_IN ExtIn_GetUpdateData_Version = {CK_EXTEND_REMOTE_GET_DATAVER, &objectClass, sizeof(objectClass)};
	CK_EXTEND_OUT ExtOut_GetUpdateData_Version = {CK_EXTEND_REMOTE_GET_DATAVER, pVersion, *pUlLen};

	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_GetUpdateData_Version, &ExtOut_GetUpdateData_Version, NULL);
	mutex.Unlock();

	*pUlLen = 4;
	
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);
	return ret;
}

CK_RV P11func_SC::Adapter_C_Extend_DestroyCard
(
		CK_SLOT_ID slotID,
		CK_BYTE_PTR prandomIn,
		CK_ULONG randomInLen,
		CK_BYTE_PTR prandomOut,
		CK_ULONG_PTR prandomOutLen
)
{
	CK_RV ret = 0;
	CK_SESSION_HANDLE hSession;
	CK_ULONG outlen = 0;
	if(prandomOutLen!=NULL_PTR){
		outlen = *prandomOutLen;
	}	
	CK_EXTEND_IN ExtIn_DoDestroy = {CK_EXTEND_DODESTROY, (void*)prandomIn, randomInLen};
	CK_EXTEND_OUT ExtOut_DoDestroy = {CK_EXTEND_DODESTROY, (void*)prandomOut, outlen};
	
	LOGSERVERI(tag,"%s IN", __FUNCTION__);
	
	mutex.Lock();
	ret = function_list_ptr->C_OpenSession(slotID,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL_PTR,NULL_PTR,&hSession);
	mutex.Unlock();
	if(ret != CKR_OK)
	{
		LOGSERVERE(tag,"opensession fail! ret = 0x%lx",ret);
		return ret;
	}
	
	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_DoDestroy, &ExtOut_DoDestroy, NULL);
	mutex.Unlock();
	
	if(prandomOutLen!=NULL_PTR){
		*prandomOutLen = DESTORYRND_LEN;
	}	

	mutex.Lock();
	function_list_ptr->C_CloseSession(hSession);
	mutex.Unlock();

	if(ret == CKR_OK)
	{		
		ucm_release(UcmHandle);
		ucm_session = 0;
		UcmHandle = NULL;
	}
	
	LOGSERVERI(tag, "%s OUT, ret = 0x%lx",__FUNCTION__,ret);
//	Print_Data((char *)tag,prandomOut,*prandomOutLen);

	return ret;
}

CK_RV P11func_SC::Adapter_C_Extend_Get_ExchangePubKey
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


CK_RV P11func_SC::Adapter_C_Extend_GetDevInfo
(
 CK_SLOT_ID slotID,
 const char *userName, 
 CK_IP_PARAMS_PTR cspp,
 CK_BYTE_PTR pDevInfo,
 CK_ULONG_PTR pUlDevInfoLen
)
{
	CK_RV ret = 0;
	ucm_dev_info_t devInfo;
	unsigned int idlen = 0;
	
	LOGSERVERI(tag,"%s IN, len is %lu", __FUNCTION__, *pUlDevInfoLen);
	
	//init

	ucm_ip_para_t ucm_cspp;

	memset(&ucm_cspp,0,sizeof(ucm_cspp));

	memcpy(ucm_cspp.ip,cspp->ip,UCM_MAX_IP_LEN);
	ucm_cspp.oWayPort = cspp->oWayPort;
	ucm_cspp.tWayPort = cspp->tWayPort;

	if(ucm_session == 0)
	{
	  	mutex.Lock();
		ret = function_list_ptr->C_OpenSession(slotID,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL_PTR,NULL_PTR,&ucm_session);
	  	mutex.Unlock();

		if(ret != CKR_OK)
		{		
			LOGSERVERE(tag,"%s, opensession error! ret = %ld, slotID is %lu",__FUNCTION__,ret,slotID);
			return ret;
		}

		
		mutex.Lock();
		ret = ucm_init_with_p11(&UcmHandle, (P11_HANDLE)(&ucm_session), userName, &ucm_cspp);
		mutex.Unlock();
		
		LOGSERVERI(tag,"%s, ucm_init_with_p11 ret = %ld", __FUNCTION__,ret);
		if(ret != CKR_OK)
		{
			LOGSERVERE(tag,"ucm_init error111!,ret  = 0x%lx", ret);
			LOGSERVERI(tag, "current session is 0x%lx,username is %s", ucm_session, userName);
			LOGSERVERI(tag, "ucm_cspp owayport: %d, twayport: %d", ucm_cspp.oWayPort,ucm_cspp.tWayPort);

			function_list_ptr->C_CloseSession(ucm_session);
			ucm_session = 0;
			return ret;
		}		
	}
			

	if(pDevInfo == NULL_PTR)
	{		
		mutex.Lock();
		ret = ucm_get_dev_id(UcmHandle, NULL_PTR, &idlen);
		mutex.Unlock();

		*pUlDevInfoLen = sizeof(ucm_dev_info_t) + idlen;
		
		LOGSERVERI(tag,"%s OUT0, UlDevInfoLen = %ld,UcmHandle = %d", __FUNCTION__,*pUlDevInfoLen, (int)UcmHandle);
		return ret;
	}

	if(*pUlDevInfoLen <= sizeof(devInfo))
	{		
		LOGSERVERI(tag,"%s OUT1", __FUNCTION__);
		return CKR_BUFFER_TOO_SMALL;
	}

	mutex.Lock();
	ret = ucm_get_dev_info(UcmHandle, &devInfo);
	mutex.Unlock();

	if(ret != CKR_OK)
	{
		LOGSERVERE(tag,"%s OUT4,ucm_get_dev_info fail,ret = 0x%lx,UcmHandle = %d", __FUNCTION__,ret,(int)UcmHandle);
		return ret;
	}
	

	//get id 	
	idlen = (*pUlDevInfoLen) - sizeof(ucm_dev_info_t);
	unsigned char* deviceid = NULL_PTR;

	deviceid = (unsigned char*)malloc(sizeof(unsigned char) * idlen);
	if(NULL==deviceid)
	{
		LOGSERVERE(tag,"%s, malloc fail",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	
	memset(deviceid,0,idlen);

	mutex.Lock();
	ret = ucm_get_dev_id(UcmHandle, deviceid, &idlen);
	mutex.Unlock();

	if(ret != CKR_OK)
	{
		LOGSERVERE(tag,"%s OUT2,get devid fail,ret = 0x%lx,idlen is %d,UcmHandle = %d", __FUNCTION__,ret,idlen,(int)UcmHandle);
		free(deviceid);
		deviceid = NULL;
		return ret;
	}

	
	*pUlDevInfoLen = sizeof(ucm_dev_info_t) + idlen;

	memcpy(pDevInfo,&devInfo,sizeof(devInfo));
	memcpy(pDevInfo+sizeof(devInfo),deviceid,idlen);
	Print_Data_Server((char *)tag,deviceid,idlen);
	free(deviceid);
	deviceid = NULL;
	LOGSERVERI(tag,"%s OUT3, UcmHandle = %d, session is 0x%lx", __FUNCTION__,(int)UcmHandle,ucm_session);
	
	return ret;
}

CK_RV P11func_SC::Adapter_C_Extend_DevSign
(
	CK_SLOT_ID slotID,
	CK_BYTE_PTR       pData,           /* the data to sign */
	CK_ULONG          ulDataLen,       /* count of bytes to sign */
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	CK_RV ret = 0;
	LOGSERVERI(tag,"%s IN, UcmHandle = %d, ulDataLen = %ld, pulSignatureLen = %lu", __FUNCTION__, (int)UcmHandle,ulDataLen, *pulSignatureLen);
	if(UcmHandle == NULL)
	{
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	
	mutex.Lock();
	ret = ucm_dev_sign(UcmHandle, pData,ulDataLen,pSignature,(unsigned int *)pulSignatureLen);
	mutex.Unlock();

	LOGSERVERI(tag,"%s OUT, ret = 0x%lx", __FUNCTION__, ret);
		
	return ret;
}

CK_RV P11func_SC::Adapter_C_Extend_Set_DestroyKey
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pDestroyKeyMpk,
	CK_ULONG ulMpkLen,
	CK_BYTE_PTR pbMpkIV,
	CK_ULONG ulMpkIVLen
)
{
	CK_RV ret = 0;
	
	LOGSERVERI(tag, "%s IN", __FUNCTION__);

	unsigned int remotevectorType = CKO_REMOTE_DESTORY_RND;
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
	memcpy(pbBuffer_T + sizeof(remotevectorType) + ulMpkIVLen, pDestroyKeyMpk, ulMpkLen);
	
	mutex.Lock();
	ret = Pointer_C_CryptoExtend(hSession, &ExtIn_vectorData_Remote, &ExtOut_vectorData_Remote, NULL);
	mutex.Unlock();

	free(pbBuffer_T);
	pbBuffer_T = NULL;
	LOGSERVERI(tag,"%s OUT, ret = 0x%lx", __FUNCTION__, ret);
	return ret;
}




CK_RV SC_C_DevProduct_Extend
(
        CK_CHAR token[CK_MAX_TOKEN_SIZE],
        CK_CHAR userName[CK_MAX_NAME_SIZE],
        CK_CHAR_PTR licRootCaCert[CK_MAX_CERTLIST_CNT],
        CK_UINT licRootCaCertLen[CK_MAX_CERTLIST_CNT],
        CK_IP_PARAMS_PTR licServer,
        CK_IP_PARAMS_PTR cspp,
        CK_SLOT_ID_PTR pSlotID
)
{
    CK_C_INITIALIZE_ARGS p11_init_args;
    CK_INITPARAMS scm_init_args;
    CK_ULONG ret;

    memset(&p11_init_args, 0, sizeof(CK_C_INITIALIZE_ARGS));
    memset(&scm_init_args, 0, sizeof(CK_INITPARAMS));

    scm_init_args.callback = tfStatusCallback1;
    GetPackageName *getPackageName = new GetPackageName();
    string packageNameall = getPackageName->GetName();

	char splittag = ':';
    vector<string> packArray = splitpack(packageNameall, splittag);
    string packageName = packArray[0];

//    LOGSERVERI(tag,"sc produce: packageName %s",packageName.c_str());

    strncpy((char *)scm_init_args.packageName, packageNameall.data(), packageName.size());

    p11_init_args.pReserved = &scm_init_args;

    Pointer_C_GetFunctionList_SC = (CK_RV(*)(CK_FUNCTION_LIST_PTR_PTR))libLoadManager->GetFuncPointer("C_GetFunctionList");
    Pointer_C_GetFunctionList_SC(&function_list_ptr);

    ret = function_list_ptr->C_Initialize(&p11_init_args);
    if(ret != CKR_OK && ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)
    {
        LOGSERVERE(tag, "%s, C_Initialize ret = 0x%lx", __FUNCTION__,ret);
        delete getPackageName;
		getPackageName = NULL;
        return ret;
    }
	if(ret == CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
		ret = function_list_ptr->C_Finalize(NULL);
		if(ret != CKR_OK)
		{
			LOGSERVERE(tag, "%s, finalize fail, ret = 0x%lx", __FUNCTION__,ret);
		}	
		ret = function_list_ptr->C_Initialize(&p11_init_args);
		if(ret != CKR_OK)
		{
			LOGSERVERE(tag, "%s, C_Initialize again fail, ret = 0x%lx", __FUNCTION__,ret);
		}	
	}	
	
    delete getPackageName;
	getPackageName = NULL;
    CK_SLOT_ID newSlotID = -1;

	CK_RV (*Point_C_DevProduct_Extend)
	(
			CK_CHAR token[CK_MAX_TOKEN_SIZE],
			CK_CHAR userName[CK_MAX_NAME_SIZE],
			CK_CHAR_PTR licRootCaCert[CK_MAX_CERTLIST_CNT],
			CK_UINT licRootCaCertLen[CK_MAX_CERTLIST_CNT],
			CK_IP_PARAMS_PTR licServer,
			CK_IP_PARAMS_PTR cspp,
			CK_SLOT_ID_PTR pSlotID
	);

	Point_C_DevProduct_Extend = (CK_RV(*)(CK_CHAR*,CK_CHAR*,CK_CHAR_PTR*,CK_UINT*,CK_IP_PARAMS_PTR,CK_IP_PARAMS_PTR,CK_SLOT_ID_PTR))libLoadManager->GetFuncPointer("C_DevProduce_Extend");
	if(NULL==Point_C_DevProduct_Extend)
	{
		LOGSERVERE(tag,"devproduct func not found!");
		return CKR_FUNCTION_FAILED;
	}

	
/*	LOGSERVERI(tag,"start produce sc,token:");
	Print_Data_Server((char *) tag,token,CK_MAX_TOKEN_SIZE);
	LOGSERVERI(tag,"username:");
	Print_Data_Server((char *) tag,userName,CK_MAX_NAME_SIZE);
	LOGSERVERI(tag,"licServer: oway: %d tway: %d",licServer->oWayPort,licServer->tWayPort);
	Print_Data_Server((char *) tag,licServer->ip,CK_MAX_IP_SIZE);
	LOGSERVERI(tag,"cspp: oway: %d tway: %d",licServer->oWayPort,licServer->tWayPort);
	Print_Data_Server((char *) tag,cspp->ip,CK_MAX_IP_SIZE);
*/	
	
	ret = Point_C_DevProduct_Extend(token, userName, licRootCaCert, licRootCaCertLen, licServer,cspp,&newSlotID);

    if(ret != 0)
    {
        LOGSERVERE(tag,"C_DevProduct_Extend Error, return 0x%lx",ret);
	
		if((ret>= CKR_ERR_CHANNEL_INIT && ret<=CKR_ERR_CHANNEL_LOAD_ENGINE)
			||(ret == CKR_ERR_COOPERATE_TOKEN_NOT_READY))
		{
			ret = CKR_SC_NETWORK_ERR;
		}
        return ret;
    }
    LOGSERVERI(tag, "C_DevProduct_Extend end,ret = 0x%lx",ret);

    *pSlotID = newSlotID;

	//add this new slot to slottable
  	CK_ULONG   ulCount = 1;
	P11Mapping p11Table;
	slotIDServer server;

	ret = function_list_ptr->C_GetSlotList(CK_TRUE, &newSlotID, &ulCount);
	server.des = "sc";
	if(ulCount != 1)
	{
		LOGSERVERE(tag,"error update slotlist!");
		return ret;
	}
	
	if(ret == CKR_OK)
	{
		server.slotID = newSlotID;
		p11Table.AddSlot(server);
		LOGSERVERI(tag, "add slotid %lu",newSlotID);
	}

	ucm_session = 0;
	UcmHandle = NULL;
	
    return ret;
 }
