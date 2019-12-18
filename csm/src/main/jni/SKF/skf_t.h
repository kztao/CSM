//
// Created by wjr on 19-4-18.
//

#ifndef SKF_T_H
#define SKF_T_H

#ifdef WIN32
#define DEVAPI							__declspec(dllexport) __stdcall
#define SKF_DEVAPI						extern "C" ULONG __declspec(dllexport) __stdcall
#else
#define DEVAPI                          __attribute__((visibility("default")))
#define SKF_DEVAPI						__attribute__((visibility("default"))) extern "C" ULONG 
#endif

#define SAR_OK							0x00000000				//成功
#define SAR_FAIL						0x0A000001				//失败
#define SAR_UNKNOWNERR					0x0A000002				//异常错误
#define SAR_NOTSUPPORTYETERR			0x0A000003				//不支持的服务
#define SAR_FILEERR						0x0A000004				//文件操作错误
#define SAR_INVALIDHANDLEERR			0x0A000005				//无效的句柄
#define SAR_INVALIDPARAMERR				0x0A000006				//无效的参数
#define SAR_READFILEERR					0x0A000007				//读文件错误
#define SAR_WRITEFILEERR				0x0A000008				//写文件错误
#define SAR_NAMELENERR					0x0A000009				//文件名称错误
#define SAR_KEYUSAGEERR					0x0A00000A				//密钥用途错误
#define SAR_MODULUSLENERR				0x0A00000B				//模的长度错误
#define SAR_NOTINITIALIZEERR			0x0A00000C				//未初始化
#define SAR_OBJERR						0x0A00000D				//对象错误
#define SAR_MEMORYERR					0x0A00000E				//内存错误
#define SAR_TIMEOUTERR					0x0A00000F				//超时
#define SAR_INDATALENERR				0x0A000010				//输入数据长度错误
#define SAR_INDATAERR					0x0A000011				//输入数据错误
#define SAR_GENRANDERR					0x0A000012				//生成随机数错误
#define SAR_HASHOBJERR					0x0A000013				//HASH对象错误
#define SAR_HASHERR						0x0A000014				//HASH运算错误
#define SAR_GENRSAKEYRR					0x0A000015				//产生RSA密钥错误
#define SAR_RSAMODULUSLENERR			0x0A000016				//RSA密钥模长错误
#define SAR_CSPIMPRTPUBKEYERR			0x0A000017				//CSP服务导入公钥错误
#define SAR_RSAENCERR					0x0A000018				//RSA加密错误
#define SAR_RSADECERR					0x0A000019				//RSA解密错误
#define SAR_HASHNOTEQUALERR				0x0A00001A				//HASH值不相等
#define SAR_KEYNOTFOUNDERR				0x0A00001B				//密钥未发现
#define SAR_CERTNOTFOUNDERR				0x0A00001C				//证书未发现
#define SAR_NOTEXPORTERR				0x0A00001D				//对象未导出
#define SAR_DECRYPTPADERR				0x0A00001E				//解密时做补丁错误
#define SAR_MACLENERR					0x0A00001F				//MAC长度错误
#define SAR_BUFFER_TOO_SMALL			0x0A000020				//缓冲区不足
#define SAR_KEYINFOTYPEERR				0x0A000021				//密钥类型错误
#define SAR_NOT_EVENTERR				0x0A000022				//无事件错误
#define SAR_DEVICE_REMOVED				0x0A000023				//设备已移除
#define SAR_PIN_INCORRECT				0x0A000024				//PIN不正确
#define SAR_PIN_LOCKED					0x0A000025				//PIN被锁死
#define SAR_PIN_INVALID					0x0A000026				//PIN无效
#define SAR_PIN_LEN_RANGE				0x0A000027				//PIN长度错误
#define SAR_USER_ALREADY_LOGGED_IN		0x0A000028				//用户已经登录
#define SAR_USER_PIN_NOT_INITIALIZED	0x0A000029				//没有初始化用户口令
#define SAR_USER_TYPE_INVALID			0x0A00002A				//PIN类型错误
#define SAR_APPLICATION_NAME_INVALID	0x0A00002B				//应用名称无效
#define SAR_APPLICATION_EXISTS			0x0A00002C				//应用已经存在
#define SAR_USER_NOT_LOGGED_IN			0x0A00002D				//用户没有登录
#define SAR_APPLICATION_NOT_EXISTS		0x0A00002E				//应用不存在
#define SAR_FILE_ALREADY_EXIST			0x0A00002F				//文件已经存在
#define SAR_NO_ROOM						0x0A000030				//空间不足
#define SAR_FILE_NOT_EXIST				0x0A000031				//文件不存在
#define SAR_REACH_MAX_CONTAINER_COUNT	0x0A000032				//已达到最大可管理容器数

#define	IN
#define OUT

/*
*布尔类型定义
*/
#undef TRUE
#undef FALSE
#define TRUE			0x00000001	//布尔值为真
#define FALSE			0x00000000	//布尔值为假

/*
*基本数据类型
*/

typedef signed char         INT8;
typedef int					BOOL;

typedef signed short        INT16;
typedef signed int          INT32;
typedef unsigned char       UINT8;
typedef unsigned short      UINT16;
typedef unsigned int	    UINT32;

typedef UINT8				BYTE;
typedef char				CHAR;
typedef INT16				SHORT;
typedef UINT16				USHORT;
typedef long				LONG;
typedef unsigned long		ULONG;
typedef UINT32				UINT;
typedef UINT16				WORD;
typedef unsigned long		DWORD;
typedef UINT32				FLAGS;
typedef CHAR *				LPSTR;
typedef void *				HANDLE;

typedef HANDLE				DEVHANDLE;
typedef HANDLE				HAPPLICATION;
typedef HANDLE				HCONTAINER;

/*
*临界值定义
*/
#define MAX_IV_LEN			32		//初始化向量的最大长度
#define MAX_APP_NAME_LEN	21		//应用名最大长度
#define	MAX_FILE_NAME_LEN	32		//文件名最大长度
#define MAX_CONTAINER_NAME_LEN	64	//容器名最大长度
#define MIN_PIN_LEN			6		//最小的PIN长度

#define MAX_RSA_MODULUS_LEN 256		//RSA算法模数的最大长度
#define MAX_RSA_EXPONENT_LEN 4		//RSA算法指数的最大长度

#define ECC_MAX_XCOORDINATE_BITS_LEN 512	//ECC算法X座标的最大长度
#define ECC_MAX_YCOORDINATE_BITS_LEN 512	//ECC算法Y座标的最大长度
#define ECC_MAX_MODULUS_BITS_LEN 512		//ECC算法模数的最大长度

/*
 *算法标识符
 */
#define SGD_SM1_ECB		0x00000101	//SM1算法ECB加密模式
#define SGD_SM1_CBC		0x00000102	//SM1算法CBC加密模式
#define SGD_SM1_CFB		0x00000104	//SM1算法CFB加密模式
#define SGD_SM1_OFB		0x00000108	//SM1算法OFB加密模式
#define SGD_SM1_MAC		0x00000110	//SM1算法MAC运算
#define SGD_SSF33_ECB	0x00000201	//SSF33算法ECB加密模式
#define SGD_SSF33_CBC	0x00000202	//SSF33算法CBC加密模式
#define SGD_SSF33_CFB	0x00000204	//SSF33算法CFB加密模式
#define SGD_SSF33_OFB	0x00000208	//SSF33算法OFB加密模式
#define SGD_SSF33_MAC	0x00000210	//SSF33算法MAC运算
#define SGD_SMS4_ECB	0x00000401	//SMS4算法ECB加密模式
#define SGD_SMS4_CBC	0x00000402	//SMS4算法CBC加密模式
#define SGD_SMS4_CFB	0x00000404	//SMS4算法CFB加密模式
#define SGD_SMS4_OFB	0x00000408	//SMS4算法OFB加密模式
#define SGD_SMS4_MAC	0x00000410	//SMS4算法MAC运算
#define SGD_DES112_ECB	0x00001101	//DES112算法ECB运算,仅用于测试
/*	0x00000400-0x800000xx	为其它分组密码算法预留	*/

#define SGD_RSA			0x00010000	//RSA算法
#define SGD_SM2_1		0x00020100	//椭圆曲线签名算法
#define SGD_SM2_2		0x00020200	//椭圆曲线密钥交换协议
#define SGD_SM2_3		0x00020400	//椭圆曲线加密算法
/*	0x00000400～0x800000xx	为其它非对称密码算法预留	*/

#define SGD_SM3			0x00000001	//SM3杂凑算法
#define SGD_SHA1		0x00000002	//SHA1杂凑算法
#define SGD_SHA256		0x00000004	//SHA256杂凑算法

/*	0x00000010～0x000000FF	为其它密码杂凑算法预留	*/

/*
 *设备状态
 */
#define	DEV_ABSENT_STATE	0x00000000		//设备不存在
#define	DEV_PRESENT_STATE	0x00000001		//设备存在
#define DEV_UNKNOW_STATE        0x00000002     //设备状态未知

/*
 *密钥类型
 */
#define KT_PUBLIC_KEY		0x01		//公钥
#define KT_PRIVATE_KEY		0x02		//私钥
#define KT_SECRET_KEY		0x03		//密钥

/*
 *密钥应用类型
 */
#define AT_EXTERNAL_AUTHENTICATE_KEY	0x00000001		//用于设备对终端的认证

/*
 *权限类型
 */
#define SECURE_NEVER_ACCOUNT	0x00000000		//不允许
#define SECURE_ADM_ACCOUNT		0x00000001		//管理员权限
#define SECURE_USER_ACCOUNT		0x00000010		//用户权限
#define SECURE_EVERYONE_ACCOUNT	0x000000FF		//任何人
#define SECURE_ANYONE_ACCOUNT	0x000000FF		//任何人

/*
 *PIN类型
 */
#define ADMIN_TYPE				0				//管理员PIN
#define USER_TYPE				1				//用户PIN

/*
 *容器属性
*/
#define CONTAINER_PROPERTY_UNKNOWN  0
#define CONTAINER_PROPERTY_RSA      1
#define CONTAINER_PROPERTY_ECC      2


/*
 *版本
 */
typedef struct Struct_Version {
    BYTE	major;					//主版本号
    BYTE	minor;					//次版本号
} VERSION;

/*
 *设备信息
 */
typedef struct Struct_DEVINFO {
    VERSION Version;
    CHAR	Manufacturer[64];		//设备厂商信息
    CHAR	Issuer[64];				//应用发行者信息
    CHAR	Label[32];				//标签
    CHAR	SerialNumber[32];		//序列号
    VERSION HWVersion;				//设备硬件版本
    VERSION FirmwareVersion;		//设备本身固件版本
    ULONG	AlgSymCap;				//支持对称算法标志
    ULONG	AlgAsymCap;				//支持非对称算法标志
    ULONG	AlgHashCap;				//支持杂凑算法标志
    ULONG	DevAuthAlgId;			//设备认证采用的算法标识
    ULONG	TotalSpace;				//设备存储空间
    ULONG	FreeSpace;				//设备剩余空间
    ULONG	MaxECCBufferSize;		//能够处理的ECC加密数据大小
    ULONG	MaxBufferSize;			//能够处理的分组运算和杂凑运算的数据大小
    BYTE	Reserved[64];			//保留扩展
} DEVINFO, *PDEVINFO;

/*
 *RSA公钥交换数据块
 */
typedef struct Struct_RSAPUBLICKEYBLOB {
    ULONG	AlgID;									//算法标识号
    ULONG	BitLen;									//模数的实际位长度，必须是8的倍数
    BYTE	Modulus[MAX_RSA_MODULUS_LEN];			//模数n=p*q，实际长度为BitLen/8字节
    BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];	//公开密钥e， 一般为00010001
} RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

/*
 *RSA私钥交换数据块
 */
typedef struct Struct_RSAPRIVATEKEYBLOB {
    ULONG	AlgID;									//算法标识号
    ULONG	BitLen;									//模数的实际位长度，必须是8的倍数
    BYTE	Modulus[MAX_RSA_MODULUS_LEN];			//模数n=p*q，实际长度为BitLen/8字节
    BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];	//公开密钥e， 一般为00010001
    BYTE	PrivateExponent[MAX_RSA_MODULUS_LEN];	//私有密钥d，实际长度为BitLen/8字节
    BYTE	Prime1[MAX_RSA_MODULUS_LEN / 2];			//素数p，实际长度为BitLen/16字节
    BYTE	Prime2[MAX_RSA_MODULUS_LEN / 2];			//素数q，实际长度为BitLen/16字节
    BYTE	Prime1Exponent[MAX_RSA_MODULUS_LEN / 2];	//d mod (p-1)的值, 实际长度为BitLen/16字节
    BYTE	Prime2Exponent[MAX_RSA_MODULUS_LEN / 2];	//d mod (q-1)的值，实际长度为BitLen/16字节
    BYTE	Coefficient[MAX_RSA_MODULUS_LEN / 2];		//q模p的乘法逆元，实际长度为BitLen/16字节
} RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;

/*
 *ECC公钥交换数据块
 */
typedef struct Struct_ECCPUBLICKEYBLOB {
    //ULONG	AlgID;
    ULONG	BitLen;
    BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    BYTE	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

/*
 *ECC私钥交换数据块
 */
typedef struct Struct_ECCPRIVATEKEYBLOB {
    //ULONG	AlgID;
    ULONG	BitLen;
    BYTE	PrivateKey[ECC_MAX_MODULUS_BITS_LEN / 8];
}ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

typedef struct Struct_ECCCIPHERBLOB {
    BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    BYTE	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
    //BYTE	Cipher[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    //BYTE	Mac[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    BYTE    HASH[32];
    ULONG	CipherLen;
    BYTE    Cipher[1];
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

typedef struct Struct_ECCSIGNATUREBLOB {
    BYTE	r[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    BYTE	s[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

/*
 *分组密码参数
 */
typedef struct Struct_BLOCKCIPHERPARAM {
    BYTE	IV[MAX_IV_LEN];			//初始向量，MAX_IV_LEN为初始向量的最大长度
    ULONG	IVLen;					//初始向量实际长度，按字节计算
    ULONG	PaddingType;			//填充方式，0表示不填充，1表示按照PKCS#5方式进行填充
    ULONG	FeedBitLen;				//反馈值的位长度，按字节计算，只针对OFB、CFB模式
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

typedef struct SKF_ENVELOPEDKEYBLOB {
    ULONG Version;                  // 当前版本为 1
    ULONG ulSymmAlgID;              // 对称算法标识，限定ECB模式
    ULONG ulBits;					// 加密密钥对的密钥位长度
    BYTE cbEncryptedPriKey[64];     // 加密密钥对私钥的密文
    ECCPUBLICKEYBLOB PubKey;        // 加密密钥对的公钥
    ECCCIPHERBLOB ECCCipherBlob;    // 用保护公钥加密的对称密钥密文。
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

/*
typedef struct SKF_ENVELOPEDKEYBLOB{
	unsigned long ulAsymmAlgID;				//保护对称密钥的非对称算法标识
	unsigned long ulSymmAlgID;				//对称算法标识 必须为ECB模式
	unsigned char cbEncryptedPriKey[64];	//加密密钥对的私钥密文，其有效长度为(加密密钥对的密钥位长度+ 7)/8 私钥原文为ECCPRIVATEKEYBLOB结构中的PrivateKey
	ECCPUBLICKEYBLOB PubKey;				//加密密钥对的公钥
	ECCCIPHERBLOB ECCCipherBlob;			//对称密钥密文
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;
*/

/*
 *文件属性
 */
typedef struct Struct_FILEATTRIBUTE {
    CHAR	FileName[32];			//文件名
    ULONG	FileSize;				//文件大小
    ULONG	ReadRights;				//
    ULONG	WriteRights;			//写权限
} FILEATTRIBUTE, *PFILEATTRIBUTE;




/************************************************************************/
/*	1. 设备管理															*/
/*	SKF_WaitForDevEvent													*/
/*	SKF_EnumDev															*/
/*	SKF_ConnectDev														*/
/*	SKF_DisconnectDev													*/
/*	SKF_GetDevState														*/
/*	SKF_GetDevInfo														*/
/*	SKF_LockDev															*/
/*	SKF_UnlockDev														*/
/************************************************************************/

/*
 *	等待设备的插拔事件
 *	szDevName		[OUT]返回发生事件的设备名称
 *	pulDevNameLen	[IN,OUT]输入/输出参数，当输入时表示缓冲区长度，输出时表示设备名称的有效长度,长度包含字符串结束符
 *	pulEvent		[OUT]事件类型。1表示插入，2表示拔出
 *	备注: 该函数是阻塞调用的
 */
#define EVENT_DEVICE_INSERTED	0x0001
#define EVENT_DEVICE_REMOVED	0x0002


#endif // SKF_T_H