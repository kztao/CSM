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

//ECC PKCS#11
#define CKA_VENDOR_DEFINED		0x80000000UL
#define CKM_VENDOR_DEFINED		0x80000000UL
#define CKK_VENDOR_DEFINED		0x80000000UL

//key common attribute CKA_ID
//ECC mechanism
#define CKM_SM2_KEY_PAIR_GEN (CKM_VENDOR_DEFINED+1)
#define CKM_SM2				 (CKM_VENDOR_DEFINED+2)

//ECC key type
#define CKK_SM2				 (CKK_VENDOR_DEFINED+1)

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
#define CKM_ZUC_KEY_GEN  (CKM_VENDOR_DEFINED + 50)
#define CKM_ZUC_EEA	 	 (CKM_VENDOR_DEFINED + 51)
#define CKM_ZUC_EIA		 (CKM_VENDOR_DEFINED + 52)

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


#define CKM_WRAP_SESSKEY	(CKM_VENDOR_DEFINED+61)
#define CKM_UNWRAP_SESSKEY	(CKM_VENDOR_DEFINED+62)
#define CKM_SESSKEY_DERIVE  (CKM_VENDOR_DEFINED+63)

#define CKM_DERIVE_SM2_POINTMUL_1	(CKM_VENDOR_DEFINED+70)
#define CKM_DERIVE_SM2_POINTMUL_2	(CKM_VENDOR_DEFINED+71)

/*volte专用类型*/
#define CKO_REMOTE_TT         0x80000001
#define CKO_REMOTE_OTP        0x80000002
#define CKO_REMOTE_SECRET_KEY 0x80000003
#define CKO_REMOTE_DESTORY_RND 0x80000004


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
	CK_STATUS_ENUM_ERROR_SERVER,//软件服务端异常	
	CK_STATUS_ENUM_DEVICE_DESTROY
}CK_STATUS_ENUM,*CK_STATUS_ENUM_PTR;

typedef CK_RV (*register_status_callback_func)(CK_SLOT_ID slotID,CK_STATUS_ENUM status);

#define CKA_SESSKEY_ID				(CKA_VENDOR_DEFINED+401)
#define CKA_ISEXCHANGEKEY			(CKA_VENDOR_DEFINED+403)


#define CK_SESSKEY_ID0	0
#define CK_SESSKEY_ID1	1
#define CK_SESSKEY_ID2	2
#define CK_SESSKEY_ID3	3
#define CK_SESSKEY_ID4	4
#define CK_SESSKEY_ID5	5
#define CK_SESSKEY_ID6	6
#define CK_SESSKEY_ID7	7
#define CK_SESSKEY_ID8	8
#define CK_SESSKEY_ID9	9
#define CK_SESSKEY_ID10	10
#define CK_SESSKEY_ID11	11
#define CK_SESSKEY_ID12	12
#define CK_SESSKEY_ID13	13
#define CK_SESSKEY_ID14	14
#define CK_SESSKEY_ID15	15

#define CK_SESSKEY_PRESET_ID0	0x10
#define CK_SESSKEY_PRESET_ID1	0x11
#define CK_SESSKEY_PRESET_ID2	0x12
#define CK_SESSKEY_PRESET_ID3	0x13
#define CK_SESSKEY_PRESET_ID4	0x14
#define CK_SESSKEY_PRESET_ID5	0x15
#define CK_SESSKEY_PRESET_ID6	0x16
#define CK_SESSKEY_PRESET_ID7	0x17

#define CK_MAX_IP_LEN 256
#define CK_STRING_END_0_LEN 1
#define CK_MAX_IP_SIZE (CK_MAX_IP_LEN + CK_STRING_END_0_LEN)
#define CK_MAX_TOKEN_SIZE 128
#define CK_MAX_CERTLIST_CNT 5
#define CK_MAX_NAME_SIZE 64

/**  The Event For CK_INFORM_CALLBACK  **/
#define CK_ERROR_ALG_CYC_TEST			0x00000000
#define CK_ERROR_USER_LOCKED			0x00000001
#define CK_ERROR_SO_LOCKED				0x00000002
#define CK_ERROR_CRYPT_SERVICE			0x00000003
#define CK_ERROR_CARD_DESTORY			0x00000004
#define CK_ERROR_CARD_REMOTE_DESTORY	0x00000005

/**  For Scm Call Back  **/
typedef int (*CK_INFORM_CALLBACK)(unsigned char event, unsigned int param);


#ifdef __ANDROID__
#define CK_MAX_PACKAGE_LEN 256
#endif


typedef struct CK_IP_PARAMS
{
    CK_CHAR ip[CK_MAX_IP_SIZE];
    CK_UINT oWayPort;
    CK_UINT tWayPort;
}CK_IP_PARAMS;

typedef CK_IP_PARAMS     CK_PTR  CK_IP_PARAMS_PTR;


/**  Init Para For C_Initialize  **/
typedef struct CK_INITPARAMS
{
#ifdef __ANDROID__
    CK_CHAR packageName[CK_MAX_PACKAGE_LEN];    /** Android App Package Name**/
#endif
    CK_INFORM_CALLBACK callback; /**Call Back For Cipher device**/
}CK_INITPARAMS;

typedef CK_INITPARAMS     CK_PTR  CK_INITPARAMS_PTR;


#define CK_MAX_SLOT_COUNT 3



