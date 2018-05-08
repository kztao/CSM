/*************************************************
 Copyright (C),卫士通移动互联网事业部
 Author: wangjunren Version: V1.0.0 Date: 20180108
 Description: 
	本文件为P11的扩展函数定义文件
	本文件的函数定义符合C语言的编译和连接规约
 History: 
	 1. 
		Date:20180108
		Author:wangjunren
		Modification:创建初始版本
	 2. 
	 	Date:
		Author:
		Modification:
*************************************************/ 
#ifndef __PKCS11_EXTEND_H
#define __PKCS11_EXTEND_H

//ECC PKCS#11
#define CKA_VENDOR_DEFINED		0x80000000UL
#define CKM_VENDOR_DEFINED		0x80000000UL
#define CKK_VENDOR_DEFINED		0x80000000UL

//key common attribute CKA_ID
//应用只能使用事先约定好的值，且该字段只支持1个字节                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
//ECC Attributes
#define CKA_ECC_BITS_LEN		(CKA_VENDOR_DEFINED+1)
#define CKA_ECC_X_COORDINATE	(CKA_VENDOR_DEFINED+2)
#define CKA_ECC_Y_COORDINATE	(CKA_VENDOR_DEFINED+3)
#define CKA_ECC_PRIVATE			(CKA_VENDOR_DEFINED+4)

//ECC mechanism
#define CKM_ECC_KEY_PAIR_GEN	(CKM_VENDOR_DEFINED+1)
#define CKM_ECC_CALC			(CKM_VENDOR_DEFINED+2)

//ECC key type
#define CKK_ECC					(CKK_VENDOR_DEFINED+1)

//SSF33 mechanism
#define CKM_SSF33_KEY_GEN		(CKM_VENDOR_DEFINED+10)
#define CKM_SSF33_ECB			(CKM_VENDOR_DEFINED+11)
#define CKM_SSF33_CBC			(CKM_VENDOR_DEFINED+12)
#define CKM_SSF33_CBC_PAD		(CKM_VENDOR_DEFINED+13)
#define CKM_SSF33_ECB_PAD		(CKM_VENDOR_DEFINED+14)

//SSF33 key type
#define CKK_SSF33				(CKK_VENDOR_DEFINED+2)

//SM1 mechanism
#define CKM_SM1_KEY_GEN  		(CKM_VENDOR_DEFINED + 20)
#define CKM_SM1_ECB      		(CKM_VENDOR_DEFINED + 21)
#define CKM_SM1_CBC      		(CKM_VENDOR_DEFINED + 22)  
#define CKM_SM1_CBC_PAD  		(CKM_VENDOR_DEFINED + 23)
#define CKM_SM1_ECB_PAD  		(CKM_VENDOR_DEFINED + 24)

//SM1 key type
#define CKK_SM1          		(CKK_VENDOR_DEFINED + 3)


//SM4 mechanism
#define CKM_SM4_KEY_GEN  		(CKM_VENDOR_DEFINED + 40)
#define CKM_SM4_ECB      		(CKM_VENDOR_DEFINED + 41)
#define CKM_SM4_CBC      		(CKM_VENDOR_DEFINED + 42)  
#define CKM_SM4_CBC_PAD  		(CKM_VENDOR_DEFINED + 43)
#define CKM_SM4_ECB_PAD  		(CKM_VENDOR_DEFINED + 44)
#define CKM_SM4_OFB      		(CKM_VENDOR_DEFINED + 45)
#define CKM_SM4_OFB_PAD  		(CKM_VENDOR_DEFINED + 46)

//SM4 key type
#define CKK_SM4          		(CKK_VENDOR_DEFINED + 5)

//ZUC mechanism
#define CKM_ZUC_KEY_GEN  		(CKM_VENDOR_DEFINED + 50)
#define CKM_ZUC_CALC	 		(CKM_VENDOR_DEFINED + 51)
#define CKM_HASH_ZUC_CALC	 	(CKM_VENDOR_DEFINED + 52)

//ZUC key type
#define CKK_ZUC          		(CKK_VENDOR_DEFINED + 6)

//SM3 hmac mechanism
#define CKM_HMAC_SM3            	(CKM_VENDOR_DEFINED + 0xA001)     //pParameter is the key handle
#define CKM_HMAC_SM3_WITH_PRESET    (CKM_VENDOR_DEFINED + 0xA002)     //pParameter is the key
#define CKM_HMAC_SM3_KEY_GEN        (CKM_VENDOR_DEFINED + 0xA003)  

//SM3 key type
#define CKK_SM3          		(CKK_VENDOR_DEFINED + 8)

//HASH mechanism
#define CKM_HASH_CUSTOM 		(CKM_VENDOR_DEFINED + 30)
#define CKM_HASH_SM3 			(CKM_VENDOR_DEFINED + 31)

//exchange key mechanism
#define CKM_SESSKEY_EXCHANGE_GEN	(CKM_VENDOR_DEFINED+60)

//exchange key type
#define CKK_SESSKEY_EXCHANGE		(CKK_VENDOR_DEFINED + 7)


#define CKM_SM2_WRAP		(CKM_VENDOR_DEFINED+61)
#define CKM_SM2_UNWRAP		(CKM_VENDOR_DEFINED+62)
#define CKM_30RAYCOM_DERIVE	(CKM_VENDOR_DEFINED+63) //volte衍生会话密钥使用，异或操作

#define CK_CLEANFLAG_CRYPTO		1//Clean All Slot lock of Hash/Encrypt/Decrypt/Find

/*SM2 点乘*/
#define CKM_DERIVE_SM2_POINTMUL_1	(CKM_VENDOR_DEFINED+70)
#define CKM_DERIVE_SM2_POINTMUL_2	(CKM_VENDOR_DEFINED+71)

/*volte专用类型*/
#define CKO_REMOTE_TT         0x80000001
#define CKO_REMOTE_OTP        0x80000002
#define CKO_REMOTE_SECRET_KEY 0x80000003

#ifdef _WIN32
#include <windows.h>
#include <WinCrypt.h>
#else
#define ALG_CLASS_ANY                   (0)
#define ALG_CLASS_SIGNATURE             (1 << 13)
#define ALG_CLASS_MSG_ENCRYPT           (2 << 13)
#define ALG_CLASS_DATA_ENCRYPT          (3 << 13)
#define ALG_CLASS_HASH                  (4 << 13)
#define ALG_CLASS_KEY_EXCHANGE          (5 << 13)
#define ALG_CLASS_ALL                   (7 << 13)

#define AT_KEYEXCHANGE          1
#define AT_SIGNATURE            2
#endif

//定义用来记录密钥用途和容器名的特殊属性
#define	CKA_LOCATION_ATTRIBUTES	(CKA_VENDOR_DEFINED+501) //属性类型
typedef struct __LOCATION_ATTR_VALUE //属性结构体
{
	CK_UINT	keyspec;	//公钥、私钥、证书的位置标识。其值可能为AT_KEYEXCHANGE,
	//AT_SIGNATURE,CALG_ECC_SIGN,CALG_ECC_SIGN，CALG_ECC_KEYX
	CK_BYTE	szContainer[256];	//csp接口写入证书和密钥时的容器名，字符串
} LOCATION_ATTR_VALUE;
#define ALG_TYPE_ECC	(7 << 9)
#define ALG_SID_ECC_ANY	0
#define CALG_ECC_SIGN	(ALG_CLASS_SIGNATURE   | ALG_TYPE_ECC | ALG_SID_ECC_ANY)
#define CALG_ECC_KEYX	(ALG_CLASS_KEY_EXCHANGE| ALG_TYPE_ECC | ALG_SID_ECC_ANY)

//定义用于SM3运算的特殊机制参数
typedef struct __HASHPARM
{
	short	Len;   //pID所占位数，大端格式
	CK_BYTE	pID[16];
	CK_BYTE	pubKey[64];
} HASHPARM;

#define	WESTON_ECC_PUBKEY_VERIFY_LABEL "ForECCVerify" //用来计算Z值的特殊公钥属性
#define	WESTON_ECC_BITS_LEN	256 //用来计算Z值的特殊公钥属性

/******************************
*密码卡状态
*/
typedef enum CK_STATUS_ENUM
{
	CK_STATUS_ENUM_LOGIN,//卡已登录
	CK_STATUS_ENUM_DEVICE_OFF,//无卡
	CK_STATUS_ENUM_DEVICE_ERROR,//卡故障(非密码卡)
	CK_STATUS_ENUM_DEVICE_ABNORMAL,//卡异常(密码卡设备参数异常)
	CK_STATUS_ENUM_DEVICE_LOCKED,//卡已锁定
	CK_STATUS_ENUM_UNLOGIN,//卡未登录
	CK_STATUS_ENUM_ERROR_CLIENT,//软件客户端异常
	CK_STATUS_ENUM_ERROR_SERVER//软件服务端异常	
}CK_STATUS_ENUM,*CK_STATUS_ENUM_PTR;

/********************************
 *剩余口令剩余尝试次数
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_GetPinRemainCount)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession,
	CK_ULONG_PTR pUiRemainCount
);
#endif

/********************************
 *获取密码卡状态
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_GetStatus)
#ifdef CK_NEED_ARG_LIST
(
	CK_SLOT_ID slotID,
	CK_STATUS_ENUM_PTR pStatus
);
#endif

/********************************
 *注册密码卡状态回调函数
*/

typedef CK_RV (*register_status_callback_func)(CK_SLOT_ID slotID,CK_STATUS_ENUM status);

CK_PKCS11_FUNCTION_INFO(C_Extend_Register_Callback)
#ifdef CK_NEED_ARG_LIST
(
	CK_SLOT_ID slotID,
	register_status_callback_func func
);
#endif

/********************************
 *注销密码卡状态回调函数
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Unregister_Callback)
#ifdef CK_NEED_ARG_LIST
(
	CK_SLOT_ID slotID,
	CK_STATUS_ENUM_PTR pStatus
);
#endif

/********************************
 *使用监听公钥导出协商密钥
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_GetExchangeSessionKey)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pEncryptedData,
	CK_ULONG_PTR pulEncryptedDataLen
);
#endif

/********************************
 *参数注销
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Destroy)
#ifdef CK_NEED_ARG_LIST
(
	CK_SLOT_ID slotID,
	CK_BYTE_PTR containerName
);
#endif

/********************************
 *重设用户口令
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Reset_Pin_With_OTP)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pbOTPPIN,
	CK_ULONG ulOTPPINLen,
	CK_BYTE_PTR pbNewUserPIN,
	CK_ULONG ulNewUserPINLen
);
#endif

/********************************
 *重设OTP口令
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Reset_OTP)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR pbOTPMpk,
	CK_ULONG ulMpkLen,
	CK_BYTE_PTR pbMpkIV,
	CK_ULONG ulMpkIVLen
);
#endif

/********************************
 *获取剩余OTP解锁次数
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Get_OTP_Unlock_Count)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession,
	CK_ULONG_PTR pulCount
);
#endif

/********************************
 *获取剩余OTP尝试次数
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_Get_OTP_Remain_Count)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE hSession,
	CK_ULONG_PTR pulCount
);
#endif

/********************************
 *协商会话密钥加密初始化
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_DeriveSessionKey)
#ifdef CK_NEED_ARG_LIST
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
);
#endif

/********************************
 *协商会话密钥加密初始化
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_EncryptInit)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_ATTRIBUTE_PTR  pTemplate
);
#endif

/******************************
 *协商会话密钥解密初始化
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_DecryptInit)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_ATTRIBUTE_PTR  pTemplate        /* handle of decryption key */
);
#endif

/********************************
 *协商会话密钥分步加密
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_EncryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pIv,                /* encrypted iv */
  CK_ULONG          ulIvLen,            /* encrypted iv len */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
);
#endif

/********************************
 *协商会话密钥分步解密
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_DecryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pIv,                /* decrypted iv */
  CK_ULONG          ulIvLen,            /* decrypted iv len */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
);
#endif

/********************************
 *协商会话密钥分步加密结束
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_EncryptFinalize)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
);
#endif

/********************************
 *协商会话密钥分步解密结束
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_DecryptFinalize)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
);
#endif

/********************************
 *SM2点乘
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_PointMultiply)
#ifdef CK_NEED_ARG_LIST
(

  CK_SESSION_HANDLE hSession,

  CK_MECHANISM_PTR pMechanism,

  CK_OBJECT_HANDLE hKey,

  CK_BYTE_PTR pOutData,

  CK_ULONG_PTR pOutLen
);
#endif

/******************************
 *独占
*/

CK_PKCS11_FUNCTION_INFO(C_Extend_MonopolizeEnable)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID            slotID        /* the slot's ID */
);
#endif

/******************************
 *取消独占
*/
CK_PKCS11_FUNCTION_INFO(C_Extend_MonopolizeDisable)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID            slotID        /* the slot's ID */
);

#endif

#endif //__PKCS11_EXTEND_H
