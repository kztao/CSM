

// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� SAFETYCARDLIB_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// SAFETYCARDLIB_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
#ifdef SAFETYCARDLIB_EXPORTS
#define SAFETYCARDLIB_API __declspec(dllexport) 
#else
#define SAFETYCARDLIB_API __declspec(dllimport)
#endif

#define DEVCALL				__stdcall	//__cdecl

#define	_GUIZHOU_CA_		0			//����CA����ECC���ܣ�ö���豸�������豸�޸ģ�ʵ��SKF_WaitForDevEvent()

#define SAR_OK							0x00000000				//�ɹ�
#define SAR_FAIL						0x0A000001				//ʧ��
#define SAR_UNKNOWNERR					0x0A000002				//�쳣����
#define SAR_NOTSUPPORTYETERR			0x0A000003				//��֧�ֵķ���
#define SAR_FILEERR						0x0A000004				//�ļ���������
#define SAR_INVALIDHANDLEERR			0x0A000005				//��Ч�ľ��
#define SAR_INVALIDPARAMERR				0x0A000006				//��Ч�Ĳ���
#define SAR_READFILEERR					0x0A000007				//���ļ�����
#define SAR_WRITEFILEERR				0x0A000008				//д�ļ�����
#define SAR_NAMELENERR					0x0A000009				//�ļ����ƴ���
#define SAR_KEYUSAGEERR					0x0A00000A				//��Կ��;����
#define SAR_MODULUSLENERR				0x0A00000B				//ģ�ĳ��ȴ���
#define SAR_NOTINITIALIZEERR			0x0A00000C				//δ��ʼ��
#define SAR_OBJERR						0x0A00000D				//�������
#define SAR_MEMORYERR					0x0A00000E				//�ڴ����
#define SAR_TIMEOUTERR					0x0A00000F				//��ʱ
#define SAR_INDATALENERR				0x0A000010				//�������ݳ��ȴ���
#define SAR_INDATAERR					0x0A000011				//�������ݴ���
#define SAR_GENRANDERR					0x0A000012				//�������������
#define SAR_HASHOBJERR					0x0A000013				//HASH�������
#define SAR_HASHERR						0x0A000014				//HASH�������
#define SAR_GENRSAKEYRR					0x0A000015				//����RSA��Կ����
#define SAR_RSAMODULUSLENERR			0x0A000016				//RSA��Կģ������
#define SAR_CSPIMPRTPUBKEYERR			0x0A000017				//CSP�����빫Կ����
#define SAR_RSAENCERR					0x0A000018				//RSA���ܴ���
#define SAR_RSADECERR					0x0A000019				//RSA���ܴ���
#define SAR_HASHNOTEQUALERR				0x0A00001A				//HASHֵ�����
#define SAR_KEYNOTFOUNDERR				0x0A00001B				//��Կδ����
#define SAR_CERTNOTFOUNDERR				0x0A00001C				//֤��δ����
#define SAR_NOTEXPORTERR				0x0A00001D				//����δ����
#define SAR_DECRYPTPADERR				0x0A00001E				//����ʱ����������
#define SAR_MACLENERR					0x0A00001F				//MAC���ȴ���
#define SAR_BUFFER_TOO_SMALL			0x0A000020				//����������
#define SAR_KEYINFOTYPEERR				0x0A000021				//��Կ���ʹ���
#define SAR_NOT_EVENTERR				0x0A000022				//���¼�����
#define SAR_DEVICE_REMOVED				0x0A000023				//�豸���Ƴ�
#define SAR_PIN_INCORRECT				0x0A000024				//PIN����ȷ
#define SAR_PIN_LOCKED					0x0A000025				//PIN������
#define SAR_PIN_INVALID					0x0A000026				//PIN��Ч
#define SAR_PIN_LEN_RANGE				0x0A000027				//PIN���ȴ���
#define SAR_USER_ALREADY_LOGGED_IN		0x0A000028				//�û��Ѿ���¼
#define SAR_USER_PIN_NOT_INITIALIZED	0x0A000029				//û�г�ʼ���û�����
#define SAR_USER_TYPE_INVALID			0x0A00002A				//PIN���ʹ���
#define SAR_APPLICATION_NAME_INVALID	0x0A00002B				//Ӧ��������Ч
#define SAR_APPLICATION_EXISTS			0x0A00002C				//Ӧ���Ѿ�����
#define SAR_USER_NOT_LOGGED_IN			0x0A00002D				//�û�û�е�¼
#define SAR_APPLICATION_NOT_EXISTS		0x0A00002E				//Ӧ�ò�����
#define SAR_FILE_ALREADY_EXIST			0x0A00002F				//�ļ��Ѿ�����
#define SAR_NO_ROOM						0x0A000030				//�ռ䲻��
#define SAR_FILE_NOT_EXIST				0x0A000031				//�ļ�������
#define SAR_REACH_MAX_CONTAINER_COUNT	0x0A000032				//�Ѵﵽ���ɹ���������

#define	IN
#define OUT

/*
*�������Ͷ���
*/
#undef TRUE
#undef FALSE
#define TRUE			0x00000001	//����ֵΪ��
#define FALSE			0x00000000	//����ֵΪ��

/*
*������������
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
*�ٽ�ֵ����
*/
#define MAX_IV_LEN			32		//��ʼ����������󳤶�
#define MAX_APP_NAME_LEN	21		//Ӧ������󳤶�
#define	MAX_FILE_NAME_LEN	32		//�ļ�����󳤶�
#define MAX_CONTAINER_NAME_LEN	64	//��������󳤶�
#define MIN_PIN_LEN			6		//��С��PIN����

#define MAX_RSA_MODULUS_LEN 256		//RSA�㷨ģ������󳤶�
#define MAX_RSA_EXPONENT_LEN 4		//RSA�㷨ָ������󳤶�

#define ECC_MAX_XCOORDINATE_BITS_LEN 512	//ECC�㷨X�������󳤶�
#define ECC_MAX_YCOORDINATE_BITS_LEN 512	//ECC�㷨Y�������󳤶�
#define ECC_MAX_MODULUS_BITS_LEN 512		//ECC�㷨ģ������󳤶�

/*
*�㷨��ʶ��
*/
#define SGD_SM1_ECB		0x00000101	//SM1�㷨ECB����ģʽ
#define SGD_SM1_CBC		0x00000102	//SM1�㷨CBC����ģʽ
#define SGD_SM1_CFB		0x00000104	//SM1�㷨CFB����ģʽ
#define SGD_SM1_OFB		0x00000108	//SM1�㷨OFB����ģʽ
#define SGD_SM1_MAC		0x00000110	//SM1�㷨MAC����
#define SGD_SSF33_ECB	0x00000201	//SSF33�㷨ECB����ģʽ
#define SGD_SSF33_CBC	0x00000202	//SSF33�㷨CBC����ģʽ
#define SGD_SSF33_CFB	0x00000204	//SSF33�㷨CFB����ģʽ
#define SGD_SSF33_OFB	0x00000208	//SSF33�㷨OFB����ģʽ
#define SGD_SSF33_MAC	0x00000210	//SSF33�㷨MAC����
#define SGD_SMS4_ECB	0x00000401	//SMS4�㷨ECB����ģʽ
#define SGD_SMS4_CBC	0x00000402	//SMS4�㷨CBC����ģʽ
#define SGD_SMS4_CFB	0x00000404	//SMS4�㷨CFB����ģʽ
#define SGD_SMS4_OFB	0x00000408	//SMS4�㷨OFB����ģʽ
#define SGD_SMS4_MAC	0x00000410	//SMS4�㷨MAC����
#define SGD_DES112_ECB	0x00001101	//DES112�㷨ECB����,�����ڲ���
/*	0x00000400-0x800000xx	Ϊ�������������㷨Ԥ��	*/

#define SGD_RSA			0x00010000	//RSA�㷨
#define SGD_SM2_1		0x00020100	//��Բ����ǩ���㷨
#define SGD_SM2_2		0x00020200	//��Բ������Կ����Э��
#define SGD_SM2_3		0x00020400	//��Բ���߼����㷨
/*	0x00000400��0x800000xx	Ϊ�����ǶԳ������㷨Ԥ��	*/

#define SGD_SM3			0x00000001	//SM3�Ӵ��㷨
#define SGD_SHA1		0x00000002	//SHA1�Ӵ��㷨
#define SGD_SHA256		0x00000004	//SHA256�Ӵ��㷨

/*	0x00000010��0x000000FF	Ϊ���������Ӵ��㷨Ԥ��	*/

/*
*�豸״̬
*/
#define	DEV_ABSENT_STATE	0x00000000		//�豸������
#define	DEV_PRESENT_STATE	0x00000001		//�豸����
#define DEV_UNKNOW_STATE        0x00000002     //�豸״̬δ֪

/*
*��Կ����
*/
#define KT_PUBLIC_KEY		0x01		//��Կ
#define KT_PRIVATE_KEY		0x02		//˽Կ
#define KT_SECRET_KEY		0x03		//��Կ

/*
*��ԿӦ������
*/
#define AT_extern "C"AL_AUTHENTICATE_KEY	0x00000001		//�����豸���ն˵���֤

/*
*Ȩ������
*/
#define SECURE_NEVER_ACCOUNT	0x00000000		//������
#define SECURE_ADM_ACCOUNT		0x00000001		//����ԱȨ��
#define SECURE_USER_ACCOUNT		0x00000010		//�û�Ȩ��
#define SECURE_EVERYONE_ACCOUNT	0x000000FF		//�κ���
#define SECURE_ANYONE_ACCOUNT	0x000000FF		//�κ���

/*
*PIN����
*/
#define ADMIN_TYPE				0				//����ԱPIN
#define USER_TYPE				1				//�û�PIN

/*
*��������
*/
#define CONTAINER_PROPERTY_UNKNOWN  0
#define CONTAINER_PROPERTY_RSA      1
#define CONTAINER_PROPERTY_ECC      2



/*
*�汾
*/
typedef struct Struct_Version {
	BYTE	major;					//���汾��
	BYTE	minor;					//�ΰ汾��
} VERSION;

/*
*�豸��Ϣ
*/
typedef struct Struct_DEVINFO {
	VERSION Version;
	CHAR	Manufacturer[64];		//�豸������Ϣ
	CHAR	Issuer[64];				//Ӧ�÷�������Ϣ
	CHAR	Label[32];				//��ǩ
	CHAR	SerialNumber[32];		//���к�
	VERSION HWVersion;				//�豸Ӳ���汾
	VERSION FirmwareVersion;		//�豸�����̼��汾
	ULONG	AlgSymCap;				//֧�ֶԳ��㷨��־
	ULONG	AlgAsymCap;				//֧�ַǶԳ��㷨��־
	ULONG	AlgHashCap;				//֧���Ӵ��㷨��־
	ULONG	DevAuthAlgId;			//�豸��֤���õ��㷨��ʶ
	ULONG	TotalSpace;				//�豸�洢�ռ�
	ULONG	FreeSpace;				//�豸ʣ��ռ�
	ULONG	MaxECCBufferSize;		//�ܹ�������ECC�������ݴ�С
	ULONG	MaxBufferSize;			//�ܹ������ķ���������Ӵ���������ݴ�С
	BYTE	Reserved[64];			//������չ
} DEVINFO, *PDEVINFO;

/*
*RSA��Կ�������ݿ�
*/
typedef struct Struct_RSAPUBLICKEYBLOB {
	ULONG	AlgID;									//�㷨��ʶ��
	ULONG	BitLen;									//ģ����ʵ��λ���ȣ�������8�ı���
	BYTE	Modulus[MAX_RSA_MODULUS_LEN];			//ģ��n=p*q��ʵ�ʳ���ΪBitLen/8�ֽ�
	BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];	//������Կe�� һ��Ϊ00010001
} RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

/*
*RSA˽Կ�������ݿ�
*/
typedef struct Struct_RSAPRIVATEKEYBLOB {
	ULONG	AlgID;									//�㷨��ʶ��
	ULONG	BitLen;									//ģ����ʵ��λ���ȣ�������8�ı���
	BYTE	Modulus[MAX_RSA_MODULUS_LEN];			//ģ��n=p*q��ʵ�ʳ���ΪBitLen/8�ֽ�
	BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];	//������Կe�� һ��Ϊ00010001
	BYTE	PrivateExponent[MAX_RSA_MODULUS_LEN];	//˽����Կd��ʵ�ʳ���ΪBitLen/8�ֽ�
	BYTE	Prime1[MAX_RSA_MODULUS_LEN / 2];			//����p��ʵ�ʳ���ΪBitLen/16�ֽ�
	BYTE	Prime2[MAX_RSA_MODULUS_LEN / 2];			//����q��ʵ�ʳ���ΪBitLen/16�ֽ�
	BYTE	Prime1Exponent[MAX_RSA_MODULUS_LEN / 2];	//d mod (p-1)��ֵ, ʵ�ʳ���ΪBitLen/16�ֽ�
	BYTE	Prime2Exponent[MAX_RSA_MODULUS_LEN / 2];	//d mod (q-1)��ֵ��ʵ�ʳ���ΪBitLen/16�ֽ�
	BYTE	Coefficient[MAX_RSA_MODULUS_LEN / 2];		//qģp�ĳ˷���Ԫ��ʵ�ʳ���ΪBitLen/16�ֽ�
} RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;

/*
*ECC��Կ�������ݿ�
*/
typedef struct Struct_ECCPUBLICKEYBLOB {
	//ULONG	AlgID;
	ULONG	BitLen;
	BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];
	BYTE	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN / 8];
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

/*
*ECC˽Կ�������ݿ�
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
*�����������
*/
typedef struct Struct_BLOCKCIPHERPARAM {
	BYTE	IV[MAX_IV_LEN];			//��ʼ������MAX_IV_LENΪ��ʼ��������󳤶�
	ULONG	IVLen;					//��ʼ����ʵ�ʳ��ȣ����ֽڼ���
	ULONG	PaddingType;			//��䷽ʽ��0��ʾ����䣬1��ʾ����PKCS#5��ʽ�������
	ULONG	FeedBitLen;				//����ֵ��λ���ȣ����ֽڼ��㣬ֻ���OFB��CFBģʽ
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

typedef struct Struct_ENVELOPEDKEYBLOB {
	ULONG Version;                  // ��ǰ�汾Ϊ 1
	ULONG ulSymmAlgID;              // �Գ��㷨��ʶ���޶�ECBģʽ
	ULONG ulBits;					// ������Կ�Ե���Կλ����
	BYTE cbEncryptedPriKey[64];     // ������Կ��˽Կ������
	ECCPUBLICKEYBLOB PubKey;        // ������Կ�ԵĹ�Կ
	ECCCIPHERBLOB ECCCipherBlob;    // �ñ�����Կ���ܵĶԳ���Կ���ġ�
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

/*
*�ļ�����
*/
typedef struct Struct_FILEATTRIBUTE {
	CHAR	FileName[32];			//�ļ���
	ULONG	FileSize;				//�ļ���С
	ULONG	ReadRights;				// 
	ULONG	WriteRights;			//дȨ��
} FILEATTRIBUTE, *PFILEATTRIBUTE;

// �����Ǵ� SafetyCardLib.dll ������
class CSafetyCardLib {
public:
	CSafetyCardLib(void);
	// TODO:  �ڴ��������ķ�����
};

#define EVENT_DEVICE_INSERTED	0x0001
#define EVENT_DEVICE_REMOVED	0x0002

#ifdef __cplusplus
extern "C"
{
#endif

	/************************************************************************/
	/*	1. �豸����															*/
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
	*	�ȴ��豸�Ĳ���¼�
	*	szDevName		[OUT]���ط����¼����豸����
	*	pulDevNameLen	[IN,OUT]����/���������������ʱ��ʾ���������ȣ����ʱ��ʾ�豸���Ƶ���Ч����,���Ȱ����ַ���������
	*	pulEvent		[OUT]�¼����͡�1��ʾ���룬2��ʾ�γ�
	*	��ע: �ú������������õ�
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_WaitForDevEvent(
		OUT LPSTR szDevName,
		OUT ULONG *pulDevNameLen,
		OUT ULONG *pulEvent
	);
	/*
	*	ȡ���ȴ��豸�Ĳ���¼�
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_CancelWaitForDevEvent();
	/*
	*	��õ�ǰϵͳ�е��豸�б�
	*	bPresent		[IN]ΪTRUE��ʾȡ��ǰ�豸״̬Ϊ���ڵ��豸�б���ΪFALSE��ʾȡ��ǰ����֧�ֵ��豸�б�
	*	szNameList		[OUT]�豸�����б�������ò���ΪNULL������pulSize��������Ҫ���ڴ�ռ��С��ÿ���豸�������Ե���'\0'��������˫'\0'��ʾ�б��Ľ���
	*	pulSize			[IN,OUT]��������������豸�����б��Ļ��������ȣ��������������szNameList����Ҫ�Ŀռ��С
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_EnumDev(
		IN BOOL bPresent,
		OUT LPSTR szNameList,
		OUT ULONG* pulSize
	);

	/*
	*	ͨ���豸���������豸�������豸�ľ��
	*	szName		[IN]�豸����
	*	phDev		[OUT]�����豸�������
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ConnectDev(
		IN LPSTR szName,
		OUT DEVHANDLE* phDev
	);

	/*
	*	�Ͽ�һ���Ѿ����ӵ��豸�����ͷž����
	*	hDev		[IN]�����豸ʱ���ص��豸���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_DisConnectDev(
		IN DEVHANDLE hDev
	);

	/*
	*	��ȡ�豸�Ƿ���ڵ�״̬
	*	szDevName	[IN]��������
	*	pulDevState	[OUT]�����豸״̬
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_GetDevState(
		IN  LPSTR	 szDevName,
		OUT ULONG* pulDevState
	);

	/*
	*	�����豸��ǩ
	*	hDev		[IN]�����豸ʱ���ص��豸���
	*	szLabel		[OUT]�豸��ǩ�ַ��������ַ���ӦС��32�ֽ�
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_SetLabel(
		IN DEVHANDLE hDev,
		IN LPSTR szLabel);

	/*
	*	��ȡ�豸��һЩ������Ϣ�������豸��ǩ��������Ϣ��֧�ֵ��㷨��
	*	hDev		[IN]�����豸ʱ���ص��豸���
	*	pDevInfo	[OUT]�����豸��Ϣ
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_GetDevInfo(
		IN DEVHANDLE	hDev,
		OUT PDEVINFO	pDevInfo
	);

	/*
	*	����豸�Ķ�ռʹ��Ȩ
	*	hDev		[IN]�����豸ʱ���ص��豸���
	*	ulTimeOut	[IN]��ʱʱ�䣬��λΪ���롣���Ϊ0xFFFFFFFF��ʾ���޵ȴ�
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_LockDev(
		IN DEVHANDLE	hDev,
		IN ULONG ulTimeOut
	);

	/*
	*	�ͷŶ��豸�Ķ�ռʹ��Ȩ
	*	hDev		[IN]�����豸ʱ���ص��豸���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_UnlockDev(
		IN DEVHANDLE	hDev
	);


	/************************************************************************/
	/*  2. ���ʿ���				                                            */
	/*	SKF_ChangeDevAuthKey												*/
	/*	SKF_DevAuth															*/
	/*	SKF_ChangePIN														*/
	/*	SKF_GetPINInfo														*/
	/*	SKF_VerifyPIN														*/
	/*	SKF_UnblockPIN														*/
	/*	SKF_ClearSecureState												*/
	/************************************************************************/

	/*
	*	�����豸��֤��Կ
	*	hDev		[IN]����ʱ���ص��豸���
	*	pbKeyValue	[IN]��Կֵ
	*	ulKeyLen	[IN]��Կ����
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ChangeDevAuthKey(
		IN DEVHANDLE	hDev,
		IN BYTE		*pbKeyValue,
		IN ULONG		ulKeyLen
	);

	/*
	*	�豸��֤���豸��Ӧ�ó������֤
	*	hDev			[IN]����ʱ���ص��豸���
	*	pbAuthData		[IN]��֤����
	*	ulLen			[IN]��֤���ݵĳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_DevAuth(
		IN DEVHANDLE	hDev,
		IN BYTE*		pbAuthData,
		IN ULONG		ulLen
	);

	/*
	*	�޸�PIN�������޸�Admin��User��PIN�����ԭPIN���󣬷���ʣ�����Դ�������ʣ�����Ϊ0ʱ����ʾPIN�Ѿ�������
	*	hApplication	[IN]Ӧ�þ��
	*	ulPINType		[IN]PIN���ͣ�����ΪADMIN_TYPE=0����USER_TYPE=1
	*	szOldPIN		[IN]ԭPINֵ
	*	szNewPIN		[IN]��PINֵ
	*	pulRetryCount	[OUT]���������Դ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ChangePIN(
		IN HAPPLICATION	hApplication,
		IN ULONG			ulPINType,
		IN LPSTR			szOldPIN,
		IN LPSTR			szNewPIN,
		OUT ULONG*		pulRetryCount
	);

	/*
	*	��ȡPIN����Ϣ������������Դ�������ǰʣ�����Դ������Լ���ǰPIN���Ƿ�Ϊ����Ĭ��PIN��
	*	hApplication		[IN]Ӧ�þ��
	*	ulPINType			[IN]PIN����
	*	pulMaxRetryCount	[OUT]������Դ���
	*	pulRemainRetryCount	[OUT]��ǰʣ�����Դ�������Ϊ0ʱ��ʾ������
	*	pbDefaultPin		[OUT]�Ƿ�Ϊ����Ĭ��PIN��
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_GetPINInfo(
		IN HAPPLICATION	hApplication,
		IN ULONG			ulPINType,
		OUT ULONG*		pulMaxRetryCount,
		OUT ULONG*		pulRemainRetryCount,
		OUT BOOL*			pbDefaultPin
	);

	/*
	*	У��PIN�롣У��ɹ��󣬻�����Ӧ��Ȩ�ޣ����PIN����󣬻᷵��PIN������Դ����������Դ���Ϊ0ʱ��ʾPIN���Ѿ�����
	*	hApplication	[IN]Ӧ�þ��
	*	ulPINType		[IN]PIN���ͣ�����ΪADMIN_TYPE=0����USER_TYPE=1
	*	szPIN			[IN]PINֵ
	*	pulRetryCount	[OUT]�����󷵻ص����Դ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_VerifyPIN(
		IN HAPPLICATION	hApplication,
		IN ULONG			ulPINType,
		IN LPSTR			szPIN,
		OUT ULONG*		pulRetryCount
	);

	/*
	*	���û���PIN��������ͨ�����øú����������û�PIN�롣
	*	�������û�PIN�뱻���ó���ֵ���û�PIN������Դ���Ҳ�ָ���ԭֵ��
	*	hApplication	[IN]Ӧ�þ��
	*	szAdminPIN		[IN]����ԱPIN��
	*	szNewUserPIN	[IN]�µ��û�PIN��
	*	pulRetryCount	[OUT]����ԱPIN�����ʱ������ʣ�����Դ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_UnblockPIN(
		IN HAPPLICATION	hApplication,
		IN LPSTR			szAdminPIN,
		IN LPSTR			szNewUserPIN,
		OUT ULONG*		pulRetryCount
	);

	/*
	*	���Ӧ�õ�ǰ�İ�ȫ״̬
	*	hApplication	[IN]Ӧ�þ��
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ClearSecureState(
		IN HAPPLICATION	hApplication
	);

	/************************************************************************/
	/*  3. Ӧ�ù���				                                            */
	/*	SKF_CreateApplication												*/
	/*	SKF_EnumApplication													*/
	/*	SKF_DeleteApplication												*/
	/*	SKF_OpenApplication													*/
	/*	SKF_CloseApplication												*/
	/************************************************************************/

	/*
	*	����һ��Ӧ��
	*	hDev					[IN]�����豸ʱ���ص��豸���
	*	szAppName				[IN]Ӧ������
	*	szAdminPIN				[IN]����ԱPIN
	*	dwAdminPinRetryCount	[IN]����ԱPIN������Դ���
	*	szUserPIN				[IN]�û�PIN
	*	dwAdminPinRetryCount	[IN]�û�PIN������Դ���
	*	dwCreateFileRights		[IN]�ڸ�Ӧ���´����ļ���������Ȩ��
	*	hAppObject			[OUT]Ӧ�õľ��
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_CreateApplication(
		IN DEVHANDLE		hDev,
		IN LPSTR			szAppName,
		IN LPSTR			szAdminPIN,
		IN DWORD			dwAdminPinRetryCount,
		IN LPSTR			szUserPIN,
		IN DWORD			dwUserPinRetryCount,
		IN DWORD			dwCreateFileRights,
		OUT HAPPLICATION*	hAppObject
	);

	/*
	*	ö���豸�������ڵ�����Ӧ��
	*	hDev			[IN]�����豸ʱ���ص��豸���
	*	szAppName		[OUT]����Ӧ�������б�, ����ò���Ϊ�գ�����pulSize��������Ҫ���ڴ�ռ��С��
	*						 ÿ��Ӧ�õ������Ե���'\0'��������˫'\0'��ʾ�б��Ľ�����
	*	pulSize			[IN,OUT]�������������Ӧ�����ƵĻ��������ȣ��������������szAppName��ռ�õĵĿռ��С
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_EnumApplication(
		IN DEVHANDLE		hDev,
		OUT LPSTR			szAppName,
		OUT ULONG*		pulSize
	);

	/*
	*	ɾ��ָ����Ӧ��
	*	hDev			[IN]�����豸ʱ���ص��豸���
	*	szAppName		[IN]Ӧ������
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_DeleteApplication(
		IN DEVHANDLE		hDev,
		IN LPSTR			szAppName
	);

	/*
	*	��ָ����Ӧ��
	*	hDev			[IN]�����豸ʱ���ص��豸���
	*	szAppName		[IN]Ӧ������
	*	hAppObject	[OUT]Ӧ�õľ��
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_OpenApplication(
		IN DEVHANDLE		hDev,
		IN LPSTR			szAppName,
		OUT HAPPLICATION*	hAppObject
	);

	/*
	*	�ر�Ӧ�ò��ͷ�Ӧ�þ��
	*	hApplication	[IN]Ӧ�õľ��
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_CloseApplication(
		IN HAPPLICATION	hApplication
	);


	/************************************************************************/
	/*  4. �ļ�����				                                            */
	/*	SKF_CreateFile														*/
	/*	SKF_DeleteFile														*/
	/*	SKF_EnumFiles														*/
	/*	SKF_GetFileInfo														*/
	/*	SKF_ReadFile														*/
	/*	SKF_WriteFile														*/
	/************************************************************************/

	/*
	*	����һ���ļ��������ļ�ʱҪָ���ļ������ƣ���С���Լ��ļ��Ķ�дȨ��
	*	hApplication		[IN]Ӧ�þ��
	*	szFileName			[IN]�ļ����ƣ����Ȳ��ô���32���ֽ�
	*	ulFileSize			[IN]�ļ���С
	*	ulReadRights		[IN]�ļ���Ȩ��
	*	ulWriteRights		[IN]�ļ�дȨ��
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_CreateFile(
		IN HAPPLICATION	hApplication,
		IN LPSTR			szFileName,
		IN ULONG			ulFileSize,
		IN ULONG			ulReadRights,
		IN ULONG			ulWriteRights
	);

	/*
	*	ɾ��ָ���ļ����ļ�ɾ�����ļ���д���������Ϣ����ʧ���ļ����豸�е�ռ�õĿռ佫���ͷš�
	*	hApplication		[IN]Ҫɾ���ļ����ڵ�Ӧ�þ��
	*	szFileName			[IN]Ҫɾ���ļ�������
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_DeleteFile(
		IN HAPPLICATION	hApplication,
		IN LPSTR			szFileName
	);

	/*
	*	ö��һ��Ӧ���´��ڵ������ļ�
	*	hApplication		[IN]Ӧ�õľ��
	*	szFileList			[OUT]�����ļ������б����ò���Ϊ�գ���pulSize�����ļ���Ϣ����Ҫ�Ŀռ��С��ÿ���ļ������Ե���'\0'��������˫'\0'��ʾ�б��Ľ�����
	*	pulSize				[OUT]����Ϊ���ݻ������Ĵ�С�����Ϊʵ���ļ����ƵĴ�С
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_EnumFiles(
		IN HAPPLICATION	hApplication,
		OUT LPSTR			szFileList,
		OUT ULONG*		pulSize
	);

	/*
	*	��ȡӦ���ļ���������Ϣ�������ļ��Ĵ�С��Ȩ�޵�
	*	hApplication		[IN]�ļ�����Ӧ�õľ��
	*	szFileName			[IN]�ļ�����
	*	pFileInfo			[OUT]�ļ���Ϣ��ָ���ļ����Խṹ��ָ��
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_GetFileInfo(
		IN HAPPLICATION		hApplication,
		IN LPSTR				szFileName,
		OUT FILEATTRIBUTE*	pFileInfo
	);

	/*
	*	��ȡ�ļ�����
	*	hApplication		[IN]�ļ����ڵ�Ӧ�þ��
	*	szFileName			[IN]�ļ���
	*	ulOffset			[IN]�ļ���ȡƫ��λ��
	*	ulSize				[IN]Ҫ��ȡ�ĳ���
	*	pbOutData			[OUT]�������ݵĻ�����
	*	pulOutLen			[OUT]�����ʾ�����Ļ�������С�������ʾʵ�ʶ�ȡ���ص����ݴ�С
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ReadFile(
		IN HAPPLICATION	hApplication,
		IN LPSTR			szFileName,
		IN ULONG			ulOffset,
		IN ULONG			ulSize,
		OUT BYTE*			pbOutData,
		OUT ULONG*		pulOutLen
	);

	/*
	*	д���ݵ��ļ���
	*	hApplication		[IN]�ļ����ڵ�Ӧ�þ��
	*	szFileName			[IN]�ļ���
	*	ulOffset			[IN]д���ļ���ƫ����
	*	pbData				[IN]д�����ݻ�����
	*	ulSize				[IN]д�����ݵĴ�С
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_WriteFile(
		IN HAPPLICATION	hApplication,
		IN LPSTR			szFileName,
		IN ULONG			ulOffset,
		IN BYTE*			pbData,
		IN ULONG			ulSize
	);


	/************************************************************************/
	/*  5. ��������				                                            */
	/*	SKF_CreateContainer													*/
	/*	SKF_DeleteContainer													*/
	/*	SKF_OpenContainer													*/
	/*	SKF_CloseContainer													*/
	/*	SKF_EnumContainer													*/
	/*	SKF_GetContainerType												*/
	/************************************************************************/

	/*
	*	��Ӧ���½���ָ�����Ƶ������������������
	*	hApplication		[IN]Ӧ�þ��
	*	szContainerName		[IN]ASCII�ַ�������ʾ���������������ƣ��������Ƶ���󳤶Ȳ��ܳ���64�ֽ�
	*	phContainer			[OUT]�����������������������
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_CreateContainer(
		IN HAPPLICATION	hApplication,
		IN LPSTR			szContainerName,
		OUT HCONTAINER*	phContainer
	);

	/*
	*	��Ӧ����ɾ��ָ�����Ƶ��������ͷ�������ص���Դ
	*	hApplication		[IN]Ӧ�þ��
	*	szContainerName		[IN]ָ��ɾ������������
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_DeleteContainer(
		IN HAPPLICATION	hApplication,
		IN LPSTR			szContainerName
	);

	/*
	*	��ȡ�������
	*	hApplication		[IN]Ӧ�þ��
	*	szContainerName		[IN]��������
	*	phContainer			[OUT]�������������ľ��
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_OpenContainer(
		IN HAPPLICATION	hApplication,
		IN LPSTR			szContainerName,
		OUT HCONTAINER*	phContainer
	);

	/*
	*	�ر�������������ͷ�������������Դ
	*	hContainer			[OUT]�������
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_CloseContainer(
		IN HCONTAINER hContainer
	);

	/*
	*	ö��Ӧ���µ������������������������б�
	*	hApplication		[IN]Ӧ�þ��
	*	szContainerName		[OUT]ָ�����������б�������������˲���ΪNULLʱ��pulSize��ʾ������������Ҫ�������ĳ��ȣ�����˲�����ΪNULLʱ���������������б���ÿ���������Ե���'\0'Ϊ�������б���˫'\0'����
	*	pulSize				[OUT]����ǰ��ʾszContainerName�������ĳ��ȣ��������������б��ĳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_EnumContainer(
		IN HAPPLICATION	hApplication,
		OUT LPSTR			szContainerName,
		OUT ULONG*		pulSize
	);

	/*
	*	��������	��ȡ����������
	*	hContainer	[IN]���������
	*	pulContainerType	[OUT] ��õ��������͡�ָ��ָ���ֵΪ0��ʾδ������δ�������ͻ���Ϊ��������Ϊ1��ʾΪRSA������Ϊ2��ʾΪSM2������
	*
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_GetContainerType(IN HCONTAINER hContainer,
		OUT ULONG *pulContainerType);
	/************************************************************************/
	/*  6. �������				                                            */
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
	*	����ָ�����ȵ������
	*	hDev			[IN] �豸���
	*	pbRandom		[OUT] ���ص������
	*	ulRandomLen		[IN] ���������
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_GenRandom(
		IN DEVHANDLE hDev,
		OUT BYTE *pbRandom,
		IN ULONG ulRandomLen
	);

	/*
	*	���豸����RSA��Կ�Բ��������
	*	hDev			[IN] �豸���
	*	ulBitsLen		[IN] ��Կģ��
	*	pBlob			[OUT] ���ص�˽Կ���ݽṹ
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_GenExtRSAKey(
		IN DEVHANDLE hDev,
		IN ULONG ulBitsLen,
		OUT RSAPRIVATEKEYBLOB* pBlob
	);

	/*
	*	����RSAǩ����Կ�Բ����ǩ����Կ
	*	hContainer		[IN] �������
	*	ulBitsLen		[IN] ��Կģ��
	*	pBlob			[OUT] ���ص�RSA��Կ���ݽṹ
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_GenRSAKeyPair(
		IN HCONTAINER hContainer,
		IN ULONG ulBitsLen,
		OUT RSAPUBLICKEYBLOB *pBlob
	);

	/*
	*	����RSA���ܹ�˽Կ��
	*	hContainer		[IN] �������
	*	ulSymAlgId		[IN] �Գ��㷨��Կ��ʶ
	*	pbWrappedKey	[IN] ʹ�ø�������ǩ����Կ�����ĶԳ��㷨��Կ
	*	ulWrappedKeyLen	[IN] �����ĶԳ��㷨��Կ����
	*	pbEncryptedData	[IN] �Գ��㷨��Կ������RSA����˽Կ��˽Կ�ĸ�ʽ��ѭPKCS #1 v2.1: RSA Cryptography Standard�е�˽Կ��ʽ����
	*	ulEncryptedDataLen	[IN] �Գ��㷨��Կ������RSA���ܹ�˽Կ�Գ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ImportRSAKeyPair(
		IN HCONTAINER hContainer,
		IN ULONG ulSymAlgId,
		IN BYTE *pbWrappedKey,
		IN ULONG ulWrappedKeyLen,
		IN BYTE *pbEncryptedData,
		IN ULONG ulEncryptedDataLen
	);

	/*
	*	ʹ��hContainerָ��������ǩ��˽Կ����ָ������pbData��������ǩ����ǩ����Ľ����ŵ�pbSignature������������pulSignLenΪǩ���ĳ���
	*	hContainer		[IN] ����ǩ����˽Կ�����������
	*	pbData			[IN] ��ǩ��������
	*	ulDataLen		[IN] ǩ�����ݳ��ȣ�Ӧ������RSA��Կģ��-11
	*	pbSignature		[OUT] ���ǩ������Ļ�����ָ�룬���ֵΪNULL������ȡ��ǩ���������
	*	pulSigLen		[IN,OUT] ����Ϊǩ�������������С�����Ϊǩ���������
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_RSASignData(
		IN HANDLE hContainer,
		IN BYTE *pbData,
		IN ULONG ulDataLen,
		OUT BYTE *pbSignature,
		OUT ULONG *pulSigLen
	);

	/*
	*	��֤RSAǩ������pRSAPubKeyBlob�ڵĹ�Կֵ�Դ���ǩ���ݽ�����ǩ��
	*	hDev			[IN] �����豸ʱ���ص��豸���
	*	pRSAPubKeyBlob	[IN] RSA��Կ���ݽṹ
	*	pbData			[IN] ����֤ǩ��������
	*	ulDataLen		[IN] ���ݳ��ȣ�Ӧ�����ڹ�Կģ��-11
	*	pbSignature		[IN] ����֤��ǩ��ֵ
	*	ulSigLen		[IN] ǩ��ֵ���ȣ�����Ϊ��Կģ��
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_RSAVerify(
		IN DEVHANDLE			hDev,
		IN RSAPUBLICKEYBLOB*	pRSAPubKeyBlob,
		IN BYTE*				pbData,
		IN ULONG				ulDataLen,
		IN BYTE*				pbSignature,
		IN ULONG				ulSigLen
	);

	/*
	*	���ɻỰ��Կ�����ⲿ��Կ���������
	*	hContainer		[IN] �������
	*	ulAlgID			[IN] �Ự��Կ���㷨��ʶ
	*	pPubKey			[IN] ���ܻỰ��Կ��RSA��Կ���ݽṹ
	*	pbData			[OUT] �����ļ��ܻỰ��Կ���ģ�����PKCS#1v1.5��Ҫ���װ
	*	pulDataLen		[OUT] ���ص������ݳ���
	*	hSessionKeyObject	[OUT] ��������Կ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_RSAExportSessionKey(
		IN HCONTAINER hContainer,
		IN ULONG ulAlgID,
		IN RSAPUBLICKEYBLOB* pPubKey,
		OUT BYTE* pbData,
		OUT ULONG* pulDataLen,
		OUT HANDLE* hSessionKeyObject
	);

	/*
	*	ʹ���ⲿ�����RSA��Կ��������������Կ���㲢������
	*	hDev			[IN] �豸���
	*	pRSAPubKeyBlob	[IN] RSA��Կ���ݽṹ
	*	pbInput			[IN] ָ��������ԭʼ���ݻ�����
	*	ulInputLen		[IN] ������ԭʼ���ݵĳ��ȣ�����Ϊ��Կģ��
	*	pbOutput		[OUT] ָ��RSA��Կ������������������ò���ΪNULL������pulOutputLen������������ʵ�ʳ���
	*	pulOutputLen	[OUT] ����ǰ��ʾpbOutput�������ĳ��ȣ�����RSA��Կ��������ʵ�ʳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ExtRSAPubKeyOperation(
		IN DEVHANDLE hDev,
		IN RSAPUBLICKEYBLOB* pRSAPubKeyBlob,
		IN BYTE* pbInput,
		IN ULONG ulInputLen,
		OUT BYTE* pbOutput,
		OUT ULONG* pulOutputLen
	);

	/*
	*	ֱ��ʹ���ⲿ�����RSA˽Կ������������˽Կ���㲢������
	*	hDev			[IN] �豸���
	*	pRSAPriKeyBlob	[IN] RSA˽Կ���ݽṹ
	*	pbInput			[IN] ָ����������ݻ�����
	*	ulInputLen		[IN] ���������ݵĳ��ȣ�����Ϊ��Կģ��
	*	pbOutput		[OUT] RSA˽Կ������������ò���ΪNULL������pulOutputLen������������ʵ�ʳ���
	*	pulOutputLen	[OUT] ����ǰ��ʾpbOutput�������ĳ��ȣ�����RSA˽Կ��������ʵ�ʳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ExtRSAPriKeyOperation(
		IN DEVHANDLE hDev,
		IN RSAPRIVATEKEYBLOB* pRSAPriKeyBlob,
		IN BYTE* pbInput,
		IN ULONG ulInputLen,
		OUT BYTE* pbOutput,
		OUT ULONG* pulOutputLen
	);

	/*
	*	����ECCǩ����Կ�Բ����ǩ����Կ��
	*	hContainer		[IN] �������
	*	ulBitsLen		[IN] ��Կģ��
	*	pBlob			[OUT] ����ECC��Կ���ݽṹ
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_GenECCKeyPair(
		IN HCONTAINER hContainer,
		IN ULONG ulAlgId,
		OUT ECCPUBLICKEYBLOB *pBlob
	);

	/*
	*	����ECC��˽Կ��
	*	hContainer		[IN] �������
	*	pbWrapedData	[IN] ���ܱ�����ECC���ܹ�˽Կ������
	*	ulWrapedLen		[IN] ���ݳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ImportECCKeyPair(
		IN HCONTAINER hContainer,
		IN PENVELOPEDKEYBLOB pEnvelopedKeyBlob
	);

	/*
	*	ECC����ǩ��������ECC�㷨��ָ��˽ԿhKey����ָ������pbData��������ǩ����ǩ����Ľ����ŵ�pbSignature������������pulSignLenΪǩ��ֵ�ĳ���
	*	hContainer		[IN] ����ǩ����˽Կ�����������
	*	pbData			[IN] ��ǩ��������
	*	ulDataLen		[IN] ��ǩ�����ݳ��ȣ�����С����Կģ��
	*	pbSignature		[OUT] ǩ��ֵ��ΪNULLʱ���ڻ��ǩ��ֵ�ĳ���
	*	pulSigLen		[IN,OUT] ����ǩ��ֵ���ȵ�ָ��
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ECCSignData(
		IN HANDLE hContainer,
		IN BYTE *pbData,
		IN ULONG ulDataLen,
		OUT PECCSIGNATUREBLOB pSignature
	);

	/*
	*	��ECC��Կ�����ݽ�����ǩ
	*	hDev			[IN] �豸���
	*	pECCPubKeyBlob	[IN] ECC��Կ���ݽṹ
	*	pbData			[IN] ����֤ǩ��������
	*	ulDataLen		[IN] ���ݳ���
	*	pbSignature		[IN] ����֤��ǩ��ֵ
	*	ulSigLen		[IN] ǩ��ֵ����
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ECCVerify(
		IN DEVHANDLE			hDev,
		IN ECCPUBLICKEYBLOB*	pECCPubKeyBlob,
		IN BYTE*				pbData,
		IN ULONG				ulDataLen,
		IN PECCSIGNATUREBLOB pSignature
	);

	/*
	*	���ɻỰ��Կ�����ⲿ��Կ���������
	*	hContainer		[IN] �������
	*	ulAlgID			[IN] �Ự��Կ���㷨��ʶ
	*	pPubKey			[IN] �ⲿ����Ĺ�Կ�ṹ
	*	pbData			[OUT] �����ļ��ܻỰ��Կ����
	*	hSessionKeyObject	[OUT] �Ự��Կ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ECCExportSessionKey(
		IN HCONTAINER hContainer,
		IN ULONG ulAlgID,
		IN ECCPUBLICKEYBLOB* pPubKey,
		OUT PECCCIPHERBLOB pData,
		OUT HANDLE* hSessionKeyObject
	);

	/*
	*	ʹ���ⲿ�����ECC��Կ�������������������㲢������
	*	hDev			[IN] �豸���
	*	pECCPubKeyBlob	[IN] ECC��Կ���ݽṹ
	*	pbPlainText		[IN] �����ܵ���������
	*	ulPlainTextLen	[IN] �������������ݵĳ���
	*	pbCipherText	[OUT] ָ���������ݻ�����������ò���ΪNULL������pulCipherTextLen�����������ݵ�ʵ�ʳ���
	*	pulCipherTextLen[OUT] ����ǰ��ʾpbCipherText�������ĳ��ȣ������������ݵ�ʵ�ʳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ExtECCEncrypt(
		IN DEVHANDLE hDev,
		IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
		IN BYTE* pbPlainText,
		IN ULONG ulPlainTextLen,
		OUT PECCCIPHERBLOB pbCipherText
	);

	/*
	*	ʹ���ⲿ�����ECC˽Կ�������������������㲢������
	*	hDev			[IN] �豸���
	*	pRSAPriKeyBlob	[IN] ECC˽Կ���ݽṹ
	*	pbInput			[IN] �����ܵ���������
	*	ulInputLen		[IN] �������������ݵĳ���
	*	pbOutput		[OUT] �����������ݣ�����ò���ΪNULL������pulPlainTextLen�����������ݵ�ʵ�ʳ���
	*	pulOutputLen	[OUT] ����ǰ��ʾpbPlainText�������ĳ��ȣ������������ݵ�ʵ�ʳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ExtECCDecrypt(
		IN DEVHANDLE hDev,
		IN ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
		IN PECCCIPHERBLOB pbCipherText,
		OUT BYTE* pbPlainText,
		OUT ULONG* pulPlainTextLen
	);

	/*
	*	ʹ���ⲿ�����ECC˽Կ������������ǩ�����㲢��������
	*	hDev			[IN] �豸���
	*	pRSAPriKeyBlob	[IN] ECC˽Կ���ݽṹ
	*	pbData			[IN] ��ǩ������
	*	ulDataLen		[IN] ��ǩ�����ݵĳ���
	*	pbSignature		[OUT] ǩ��ֵ������ò���ΪNULL������pulSignatureLen����ǩ�������ʵ�ʳ���
	*	pulSignatureLen	[OUT] ����ǰ��ʾpbSignature�������ĳ��ȣ�����ǩ�������ʵ�ʳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ExtECCSign(
		IN DEVHANDLE hDev,
		IN ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
		IN BYTE* pbData,
		IN ULONG ulDataLen,
		OUT PECCSIGNATUREBLOB pSignature
	);

	/*
	*	�ⲿʹ�ô����ECC��Կ��ǩ����֤
	*	hDev			[IN] �豸���
	*	pECCPubKeyBlob	[IN] ECC��Կ���ݽṹ
	*	pbData			[IN] ����֤����
	*	ulDataLen		[IN] ����֤���ݵĳ���
	*	pbSignature		[OUT] ǩ��ֵ
	*	ulSignLen		[OUT] ǩ��ֵ�ĳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ExtECCVerify(
		IN DEVHANDLE hDev,
		IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
		IN BYTE* pbData,
		IN ULONG ulDataLen,
		IN PECCSIGNATUREBLOB pSignature
	);

	/*
	*	ʹ��ECC��ԿЭ���㷨��Ϊ����Ự��Կ������Э�̲�����������ʱECC��Կ�ԵĹ�Կ��Э�̾��
	*	hContainer		[IN] �������
	*	ulAlgId			[IN] �Ự��Կ�㷨��ʶ
	*	pTempECCPubKeyBlob	[OUT] ������ʱECC��Կ
	*	pbID			[IN] ���𷽵�ID
	*	ulIDLen			[IN] ����ID�ĳ��ȣ�������32
	*	phAgreementHandle	[OUT] ���ص���ԿЭ�̾��
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_GenerateAgreementDataWithECC(
		IN HCONTAINER hContainer,
		IN ULONG ulAlgId,
		OUT ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
		IN BYTE* pbID,
		IN ULONG ulIDLen,
		OUT HANDLE *phAgreementHandle
	);

	/*
	*	ʹ��ECC��ԿЭ���㷨������Э�̲���������Ự��Կ�������ʱECC��Կ�Թ�Կ�������ز�������Կ���
	*	hContainer					[IN] �������
	*	ulAlgId						[IN] �Ự��Կ�㷨��ʶ
	*	pSponsorECCPubKeyBlob		[IN] ���𷽵�ECC��Կ
	*	pSponsorTempECCPubKeyBlob	[IN] ���𷽵���ʱECC��Կ
	*	pTempECCPubKeyBlob			[OUT] ��Ӧ������ʱECC��Կ
	*	pbID						[IN] ��Ӧ����ID
	*	ulIDLen						[IN] ��Ӧ��ID�ĳ��ȣ�������32
	*	pbSponsorID					[IN] ���𷽵�ID
	*	ulSponsorIDLen				[IN] ����ID�ĳ��ȣ�������32
	*	phKeyHandle					[OUT] ���صĶԳ��㷨��Կ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_GenerateAgreementDataAndKeyWithECC(
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
	);

	/*
	*	ʹ��ECC��ԿЭ���㷨��ʹ������Э�̾������Ӧ����Э�̲�������Ự��Կ��ͬʱ���ػỰ��Կ���
	*	hAgreementHandle			[IN] ��ԿЭ�̾��
	*	pECCPubKeyBlob				[IN] �ⲿ�������Ӧ��ECC��Կ
	*	pTempECCPubKeyBlob			[IN] �ⲿ�������Ӧ����ʱECC��Կ
	*	pbID						[IN] ��Ӧ����ID
	*	ulIDLen						[IN] ��Ӧ��ID�ĳ��ȣ�������32
	*	phKeyHandle					[OUT] ���ص���Կ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_GenerateKeyWithECC(
		IN HANDLE hAgreementHandle,
		IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
		IN ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
		IN BYTE* pbID,
		IN ULONG ulIDLen,
		OUT HANDLE *phKeyHandle
	);

	/*
	*	���������е�ǩ����Կ���߼��ܹ�Կ
	*	hContainer		[IN] �������
	*	bSignFlag		[IN] TRUE��ʾ����ǩ����Կ��FALSE��ʾ�������ܹ�Կ
	*	pbBlob			[OUT] ָ��RSA��Կ�ṹ��RSAPUBLICKEYBLOB������ECC��Կ�ṹ��ECCPUBLICKEYBLOB��������˲���ΪNULLʱ����pulBlobLen����pbBlob�ĳ���
	*	pulBlobLen		[IN,OUT] ����ʱ��ʾpbBlob�ĳ��ȣ����ص�����Կ�ṹ�Ĵ�С
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ExportPublicKey(
		IN HCONTAINER hContainer,
		IN BOOL bSignFlag,
		OUT BYTE* pbBlob,
		OUT ULONG* pulBlobLen
	);

	/*
	*	����Ự��Կ
	*	hContainer		[IN] �������
	*	ulAlgID			[IN] �Ự��Կ���㷨��ʶ
	*	pbWrapedData	[IN] Ҫ���������
	*	ulWrapedLen		[IN] ���ݳ���
	*	phKey			[OUT] ���ػỰ��Կ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ImportSessionKey(
		IN HCONTAINER hContainer,
		IN ULONG ulAlgID,
		IN BYTE *pbWrapedData,
		IN ULONG ulWrapedLen,
		OUT HANDLE* phKey
	);

	/*
	*	�������ĶԳ���Կ��������Կ���
	*	hDev			[IN] �豸���
	*	pbKey			[IN] ָ��Ự��Կֵ�Ļ�����
	*	ulAlgID			[IN] �Ự��Կ���㷨��ʶ
	*	phKey			[OUT] ���ػỰ��Կ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_SetSymmKey(
		IN DEVHANDLE hDev,
		IN BYTE* pbKey,
		IN ULONG ulAlgID,
		OUT HANDLE* phKey
	);

	/*
	*	���ݼ��ܳ�ʼ�����������ݼ��ܵ��㷨��ز�����
	*	hKey			[IN] ������Կ���
	*	EncryptParam	[IN] ���������㷨��ز������㷨��ʶ�š���Կ���ȡ���ʼ��������ʼ�������ȡ���䷽��������ģʽ������ֵ��λ����
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_EncryptInit(
		IN HANDLE hKey,
		IN BLOCKCIPHERPARAM EncryptParam
	);

	/*
	*	��һ�������ݵļ��ܲ�����
	��ָ��������Կ��ָ�����ݽ��м��ܣ������ܵ�����ֻ����һ�����飬���ܺ�����ı��浽ָ���Ļ������С�
	SKF_Encryptֻ�Ե����������ݽ��м��ܣ��ڵ���SKF_Encrypt֮ǰ���������SKF_EncryptInit��ʼ�����ܲ�����
	SKF_Encypt�ȼ����ȵ���SKF_EncryptUpdate�ٵ���SKF_EncryptFinal��
	*	hKey			[IN] ������Կ���
	*	pbData			[IN] ����������
	*	ulDataLen		[IN] ���������ݳ���
	*	pbEncryptedData [OUT] ���ܺ�����ݻ�����ָ��
	*	pulEncryptedLen [IN,OUT] ���룬�����Ļ�������С����������ؼ��ܺ������
	����
	*	�ɹ�: SAR_OK
	*	ʧ��: SAR_FAIL SAR_MEMORYERR SAR_UNKNOWNERR  SAR_INVALIDPARAMERR SAR_BUFFER_TOO_SMALL
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_Encrypt(
		HANDLE	hKey,
		BYTE*		pbData,
		ULONG		ulDataLen,
		BYTE*		pbEncryptedData,
		ULONG*	pulEncryptedLen
	);

	/*
	*	����������ݵļ��ܲ�����
	��ָ��������Կ��ָ�����ݽ��м��ܣ������ܵ����ݰ���������飬���ܺ�����ı��浽ָ���Ļ������С�
	SKF_EncryptUpdate�Զ���������ݽ��м��ܣ��ڵ���SKF_EncryptUpdate֮ǰ���������SKF_EncryptInit��ʼ�����ܲ�����
	�ڵ���SKF_EncryptUpdate֮�󣬱������SKF_EncryptFinal�������ܲ�����
	*	hKey			[IN] ������Կ���
	*	pbData			[IN] ����������
	*	ulDataLen		[IN] ���������ݳ���
	*	pbEncryptedData [OUT] ���ܺ�����ݻ�����ָ��
	*	pulEncryptedLen [OUT] ���ؼ��ܺ�����ݳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_EncryptUpdate(
		IN HANDLE		hKey,
		IN BYTE*		pbData,
		IN ULONG		ulDataLen,
		OUT BYTE*		pbEncryptedData,
		OUT ULONG*	pulEncryptedLen
	);

	/*
	*	��������������ݵļ��ܣ�����ʣ����ܽ����
	�ȵ���SKF_EncryptInit��ʼ�����ܲ�����
	�ٵ���SKF_EncryptUpdate�Զ���������ݽ��м��ܣ�
	������SKF_EncryptFinal��������������ݵļ��ܡ�
	*	hKey			[IN] ������Կ���
	*	pbEncryptedData [OUT] ���ܽ���Ļ�����
	*	pulEncryptedLen [OUT] ���ܽ���ĳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_EncryptFinal(
		IN HANDLE hKey,
		OUT BYTE *pbEncryptedData,
		OUT ULONG *pulEncryptedDataLen
	);

	/*
	*	���ݽ��ܳ�ʼ�������ý�����Կ��ز�����
	����SKF_DecryptInit֮�󣬿��Ե���SKF_Decrypt�Ե����������ݽ��н��ܣ�
	Ҳ���Զ�ε���SKF_DecryptUpdate֮���ٵ���SKF_DecryptFinal��ɶԶ���������ݵĽ��ܡ�
	*	hKey [IN] ������Կ���
	*	DecryptParam [IN] ���������㷨��ز������㷨��ʶ�š���Կ���ȡ���ʼ��������ʼ�������ȡ���䷽��������ģʽ������ֵ��λ����
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_DecryptInit(
		IN HANDLE hKey,
		IN BLOCKCIPHERPARAM DecryptParam
	);

	/*
	*	�����������ݵĽ��ܲ���
	��ָ��������Կ��ָ�����ݽ��н��ܣ������ܵ�����ֻ����һ�����飬���ܺ�����ı��浽ָ���Ļ�������
	SKF_Decryptֻ�Ե����������ݽ��н��ܣ��ڵ���SKF_Decrypt֮ǰ���������SKF_DecryptInit��ʼ�����ܲ���
	SKF_Decypt�ȼ����ȵ���SKF_DecryptUpdate�ٵ���SKF_DecryptFinal
	*	hKey			[IN] ������Կ���
	*	pbEncryptedData [IN] ����������
	*	ulEncryptedLen	[IN] ���������ݳ���
	*	pbData			[OUT] ָ����ܺ�����ݻ�����ָ�룬��ΪNULLʱ�ɻ�ý��ܺ�����ݳ���
	*	pulDataLen		[IN��OUT] ���ؽ��ܺ�����ݳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_Decrypt(
		IN HANDLE hKey,
		IN BYTE*	pbEncryptedData,
		IN ULONG	ulEncryptedLen,
		OUT BYTE* pbData,
		OUT ULONG* pulDataLen
	);

	/*
	*	����������ݵĽ��ܲ�����
	��ָ��������Կ��ָ�����ݽ��н��ܣ������ܵ����ݰ���������飬���ܺ�����ı��浽ָ���Ļ������С�
	SKF_DecryptUpdate�Զ���������ݽ��н��ܣ��ڵ���SKF_DecryptUpdate֮ǰ���������SKF_DecryptInit��ʼ�����ܲ�����
	�ڵ���SKF_DecryptUpdate֮�󣬱������SKF_DecryptFinal�������ܲ�����
	*	hKey			[IN] ������Կ���
	*	pbEncryptedData [IN] ����������
	*	ulEncryptedLen	[IN] ���������ݳ���
	*	pbData			[OUT] ָ����ܺ�����ݻ�����ָ��
	*	pulDataLen		[IN��OUT] ���ؽ��ܺ�����ݳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_DecryptUpdate(
		IN HANDLE hKey,
		IN BYTE*	pbEncryptedData,
		IN ULONG	ulEncryptedLen,
		OUT BYTE* pbData,
		OUT ULONG* pulDataLen
	);

	/*
	*	��������������ݵĽ��ܡ�
	*	hKey				[IN] ������Կ���
	*	pbPlainText			[OUT] ָ����ܽ���Ļ�����������˲���ΪNULLʱ����pulPlainTextLen���ؽ��ܽ���ĳ���
	*	pulDecyptedDataLen	[IN��OUT] ����ʱ��ʾpbPlainText�������ĳ��ȣ����ؽ��ܽ���ĳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_DecryptFinal(
		IN HANDLE hKey,
		OUT BYTE *pbPlainText,
		OUT ULONG *pulPlainTextLen
	);

	/*
	*	��ʼ����Ϣ�Ӵռ��������ָ��������Ϣ�Ӵյ��㷨��
	*	hDev			[IN] �����豸ʱ���ص��豸���
	*	ulAlgID			[IN] �Ӵ��㷨��ʶ
	*	phHash			[OUT] �Ӵն�����
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_DigestInit(
		IN DEVHANDLE	hDev,
		IN ULONG		ulAlgID,
		IN ECCPUBLICKEYBLOB *pPubKey,
		IN unsigned char *pucID,
		IN ULONG ulIDLen,
		OUT HANDLE*	phHash
	);
	/*
	*	�Ե�һ�������Ϣ�����Ӵռ��㡣
	*	hHash			[IN] �Ӵն�����
	*	pbData			[IN] ָ����Ϣ���ݵĻ�����
	*	ulDataLen		[IN] ��Ϣ���ݵĳ���
	*	pbHashData		[OUT] �Ӵ����ݻ�����ָ�룬���˲���ΪNULLʱ����pulHashLen�����Ӵս���ĳ���
	*	pulHashLen		[IN��OUT] ����ʱ��ʾpbHashData�������ĳ��ȣ������Ӵս���ĳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_Digest(
		IN HANDLE hHash,
		IN BYTE *pbData,
		IN ULONG ulDataLen,
		OUT BYTE *pbHashData,
		OUT ULONG *pulHashLen
	);

	/*
	*	�Զ���������Ϣ�����Ӵռ��㡣
	*	hHash			[IN] �Ӵն�����
	*	pbPart			[IN] ָ����Ϣ���ݵĻ�����
	*	ulPartLen		[IN] ��Ϣ���ݵĳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_DigestUpdate(
		IN HANDLE hHash,
		IN BYTE *pbData,
		IN ULONG ulDataLen
	);

	/*
	*	�������������Ϣ���Ӵռ�����������Ӵձ��浽ָ���Ļ�������
	*	hHash			[IN] ��ϣ������
	*	pHashData		[OUT] ���ص��Ӵ����ݻ�����ָ�룬����˲���NULLʱ����pulHashLen�����Ӵս���ĳ���
	*	pulHashLen		[IN��OUT] ����ʱ��ʾ�Ӵս���ĳ��ȣ������Ӵ����ݵĳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_DigestFinal(
		IN HANDLE hHash,
		OUT BYTE *pHashData,
		OUT ULONG *pulHashLen
	);

	/*
	*	��ʼ����Ϣ��֤�������������ü�����Ϣ��֤�����Կ��������������Ϣ��֤������
	*	hKey			[IN] ������Ϣ��֤�����Կ���
	*	MacParam		[IN] ��Ϣ��֤������ز�����������ʼ��������ʼ�������ȡ���䷽����
	*	phMac			[OUT] ��Ϣ��֤�������
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_MacInit(
		IN HANDLE hKey,
		IN BLOCKCIPHERPARAM* MacParam,
		OUT HANDLE *phMac
	);

	/*
	*	SKF_Mac���㵥һ�������ݵ���Ϣ��֤�롣
	*	hMac			[IN] ��Ϣ��֤����
	*	pbData			[IN] ָ����������ݵĻ�����
	*	ulDataLen		[IN] ���������ݵĳ���
	*	pbMacData		[OUT] ָ�������Mac���������˲���ΪNULLʱ����pulMacLen���ؼ����Mac����ĳ���
	*	pulMacLen		[IN��OUT] ����ʱ��ʾpbMacData�������ĳ��ȣ����ؼ���Mac����ĳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_Mac(
		IN HANDLE hMac,
		IN BYTE * pbData,
		IN ULONG ulDataLen,
		OUT BYTE *pbMacData,
		OUT ULONG *pulMacLen
	);

	/*
	*	�������������ݵ���Ϣ��֤�롣
	*	hMac			[IN] ��Ϣ��֤����
	*	pbData			[IN] ָ����������ݵĻ�����
	*	plDataLen		[IN] ���������ݵĳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_MacUpdate(
		IN HANDLE hMac,
		IN BYTE*	pbData,
		IN ULONG	ulDataLen
	);

	/*
	*	��������������ݵ���Ϣ��֤��������
	*	hMac			[IN] ��Ϣ��֤����
	*	pbMacData		[OUT] ָ����Ϣ��֤��Ļ����������˲���ΪNULLʱ����pulMacDataLen������Ϣ��֤�뷵�صĳ���
	*	pulMacDataLen	[OUT] ����ʱ��ʾ��Ϣ��֤�뻺��������󳤶ȣ�������Ϣ��֤��ĳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_MacFinal(
		IN HANDLE hMac,
		OUT BYTE*	pbMacData,
		OUT ULONG* pulMacDataLen
	);

	/*
	*	�رջỰ��Կ���Ӵա���Ϣ��֤������
	*	hHandle			[IN] Ҫ�رյĶ�����
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_CloseHandle(
		IN HANDLE hHandle
	);

	/*
	*	������ֱ�ӷ��͸��豸�������ؽ��
	*	hDev			[IN] �豸���
	*	pbCommand		[IN] �豸����
	*	ulCommandLen	[IN] �����
	*	pbData			[OUT] ���ؽ������
	*	pulDataLen		[OUT] ����ʱ��ʾ������ݻ��������ȣ����ʱ��ʾ�������ʵ�ʳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_Transmit(
		IN DEVHANDLE hDev,
		IN BYTE* pbCommand,
		IN ULONG ulCommandLen,
		OUT BYTE* pbData,
		OUT ULONG* pulDataLen
	);

	/*
	*	�������е���ǩ��֤����߼���֤��
	*	hContainer		[IN] �������
	*	bSignFlag		[IN] TRUE��ʾ����ǩ��֤�飬FALSE��ʾ�������֤��
	*	pbCert			[IN] ָ��֤�����ݵĻ�����
	*	ulCertLen		[IN] ֤�����ݵĳ���
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ImportCertificate(
		IN HCONTAINER hContainer,
		IN BOOL bSignFlag,
		IN BYTE* pbCert,
		IN ULONG ulCertLen
	);

	/*
	*	���������е�ǩ��֤����߼���֤��
	*	hContainer		[IN] �������
	*	bSignFlag		[IN] TRUE��ʾ����ǩ��֤�飬FALSE��ʾ��������֤��
	*	pbCert			[OUT] ָ��֤�����ݵĻ�����
	*	pulCertLen		[IN,OUT] ����ʱ��ʾpbCert�ĳ��ȣ����ص���֤��Ĵ�С
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ExportCertificate(
		IN HCONTAINER hContainer,
		IN BOOL bSignFlag,
		OUT BYTE* pbCert,
		IN OUT ULONG* pulCertLen
	);

	/*
	*	��ȡ����������
	*	hContainer		[IN] �������
	*	pulConProperty	[OUT] ��õ��������ԡ�ָ��ָ���ֵΪ0��ʾδ֪����δ�������Ի���Ϊ��������Ϊ1��ʾΪRSA������Ϊ2��ʾΪECC������
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_GetContainerProperty(
		IN HCONTAINER hContainer,
		OUT ULONG *pulConProperty
	);

#if _GUIZHOU_CA_
	/*
	*  ECC˽Կ����
	*  hContainer  [IN] �������
	*  bSignFlag  [IN] false -- ����˽Կ  true -- ǩ��˽Կ
	*  pCipherText  [IN] �������ݽṹ
	*  pbData    [OUT] ָ����ܽ���Ļ�����,���ֵΪNULL������ȡ�ý��ܺ����ݳ���
	*  pbDataLen  [OUT] ����ʱ��ʾpbData�ĳ��ȣ����ؽ������ݵĴ�С
	*/
	extern "C" SAFETYCARDLIB_API ULONG DEVCALL SKF_ECCDecrypt(
		HCONTAINER hContainer, 
		BOOL bSignFlag, 
		PECCCIPHERBLOB pCipherText, 
		BYTE *pbData, 
		ULONG *pbDataLen
	);
#endif

#ifdef __cplusplus
};
#endif