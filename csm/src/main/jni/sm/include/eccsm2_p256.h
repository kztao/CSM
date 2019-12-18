/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: eccsm2_p256.h
文件描述: SM2接口[电科院接口]
创 建 者: 张文科 罗影
创建时间: 2014年11月10日
修改历史:
1. 2014年11月10日	张文科 罗影		创建文件 
*******************************************************************************/
#ifndef _ECC_SM2_P256_H
#define _ECC_SM2_P256_H


/* ------------------------ 头文件包含区 开始 ------------------------------- */
 

/* ======================== 头文件包含区 结束 =============================== */


#ifdef __cplusplus
extern "C" {
#endif
	
#ifndef ECC_BITS
#define ECC_BITS		    256					/* ECC模长比特数	*/  
#endif

#define ECCref_MAX_BITS		256						/* 256	*/ 
#define ECCref_MAX_LEN		((ECCref_MAX_BITS+7)/8)	/*  32	*/  
	
/* ECC参数结构	*/
typedef struct 
{
	unsigned char  p[ECCref_MAX_LEN];	/* 模数p		*/
	unsigned char  a[ECCref_MAX_LEN];	/* 参数a		*/
	unsigned char  b[ECCref_MAX_LEN];	/* 参数b		*/
	unsigned char gx[ECCref_MAX_LEN];	/* G点的x坐标	*/
	unsigned char gy[ECCref_MAX_LEN];	/* G点的y坐标	*/
	unsigned char  n[ECCref_MAX_LEN];	/* G点的阶		*/
	unsigned int len;				/* 参数位长		*/
} ECCrefCurveParam;
	
	
/* ECC公钥结构	*/
typedef struct 
{
	unsigned int bits;				/* 参数位长		*/
	unsigned char  x[ECCref_MAX_LEN];	/* Q点的x坐标	*/
	unsigned char  y[ECCref_MAX_LEN];	/* Q点的y坐标	*/
} ECCrefPublicKey;
	
	
/* ECC私钥结构	*/
typedef struct 
{
	unsigned int bits;				/* 参数位长		*/
	unsigned char D[ECCref_MAX_LEN];	/* 私钥			*/
} ECCrefPrivateKey;
	
	
/* ECC签名结构	*/
typedef struct 
{
	unsigned char r[ECCref_MAX_LEN];	/* r值			*/
	unsigned char s[ECCref_MAX_LEN];	/* s值			*/
} ECCSignature; 
	
	
/* ECC加密值结构 */
typedef struct 
{
	unsigned char x[ECCref_MAX_LEN];	/* C1点的x坐标	*/
	unsigned char y[ECCref_MAX_LEN];	/* C1点的y坐标	*/
	unsigned char C[ECCref_MAX_LEN];	/* 密文值C2		*/	
//	int  C2_Len;						/* C2字节数,等于明文长度*/
	unsigned char M[ECCref_MAX_LEN];	/* HASH值C3		*/
} ECCCipher;
	 

/*******************************************************************************
函 数 名:	SM2_GenerateRandom
功能描述:	生成随机数
说    明:	-
注    意:	-
参数说明: 
	pucRandom	(out)	随机数
	uiLength	(in)	随机数字节长度 
返 回 值:  0 (成功), < 0 (失败)
修改历史: 
    1. 2014年11月10日	张文科 罗影		创建函数
*******************************************************************************/

int SM2_GenerateRandom(unsigned int uiLength, unsigned char *pucRandom); 


/*******************************************************************************
函 数 名:	SM2_Verify
功能描述:	SM2验证签名
说    明:	用ECC公钥对明文和签名值在指定曲线上进行验证运算。
注    意:	函数内部完成SM3杂凑运算。对原文的杂凑运算，在函数内部完成。
参数说明:  
	pucDataInput(in)	外部输入的数据
	uiInputLength(in)	输入的数据长度
	pucID		(in)	签名者的ID值（需要与签名时使用的一致）
	uiIDLength	(in)	签名者的ID长度
	pucPublicKey(in)	外部ECC公钥结构
	pucSignature(in)	缓冲区指针，用于存放输入的签名数据
返 回 值:  0 (成功), < 0 (失败)
修改历史: 
    1. 2014年11月10日	张文科 罗影		创建函数
*******************************************************************************/

int SM2_Verify_sm2(unsigned char *pucDataInput,unsigned int  uiInputLength,
			   unsigned char *pucID, unsigned int uiIDLength,
			   ECCrefPublicKey *pucPublicKey,ECCSignature *pucSignature);
 

/*******************************************************************************
函 数 名:	SM2_Encrypt
功能描述:	SM2加密
说    明:	用ECC公钥对明文在指定曲线上进行加密运算。
注    意:	需要外部指定随机数，以统一加密结果。
参数说明: 
	pucDataInput	(in)	外部输入的数据，定长32字节，如不足32字节调用者填充
	uiInputLength	(in)	输入的数据长度，定长32字节
	pucPublicKey	(in)	外部ECC公钥结构 
	pucRandom		(in)	指定公钥加密时使用的随机数
	uiRandomLength	(in)	随机数长度，定长32字节
	pucEncData		(out)	缓冲区指针，用于存放输出的数据密文 
返 回 值:  0 (成功), < 0 (失败)
修改历史: 
    1. 2014年11月10日	张文科 罗影		创建函数
*******************************************************************************/
int SM2_Encrypt_sm2(unsigned char *pucDataInput,unsigned int  uiInputLength,
				ECCrefPublicKey *pucPublicKey, unsigned char *pucRandom,
				unsigned int uiRandomLength, ECCCipher *pucEncData);



/* 其他接口 （暂时未实现）*/

int EccMakeKey(unsigned char *sk, unsigned int sk_len, 
			   unsigned char *pk, unsigned int *pk_len, int type);


int EccDecrypt(ECCCipher *cipher, unsigned int cipher_len, 
			   ECCrefPrivateKey *ssk, unsigned int ssk_len, 
			   unsigned char *plain, unsigned int *plain_len);

int SM2_EccSign(unsigned char *pt,unsigned int ptlen,
				unsigned char *pucID, unsigned int IDLen,
				ECCrefPrivateKey *sk,ECCrefPublicKey *pECCPK,
				unsigned char *random, 
				ECCSignature *sign,unsigned int *sign_len);



#ifdef __cplusplus
}
#endif

#endif/* _SM2_H_... */ 
