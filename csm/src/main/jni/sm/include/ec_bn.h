#ifndef _EC_SM2_BN_H
#define _EC_SM2_BN_H

#include "mm_types.h"


#define ECC_BITS		    256					/* ECC模长比特数	*/  
#define ECC_BLOCK_LEN		((ECC_BITS+7)/8)	/* ECC分组长度字节数*/ 

#define ECCref_MAX_BITS		ECC_BITS			/* 256	*/ 
#define ECCref_MAX_LEN		ECC_BLOCK_LEN		/*  32	*/ 
 
/* ECC参数结构	*/
typedef struct 
{
    BYTE  p[ECC_BLOCK_LEN];	/* 模数p		*/
	BYTE  a[ECC_BLOCK_LEN];	/* 参数a		*/
	BYTE  b[ECC_BLOCK_LEN];	/* 参数b		*/
	BYTE gx[ECC_BLOCK_LEN];	/* G点的x坐标	*/
	BYTE gy[ECC_BLOCK_LEN];	/* G点的y坐标	*/
	BYTE  n[ECC_BLOCK_LEN];	/* G点的阶		*/
	u32_t len;				/* 参数位长		*/
} ECCrefCurveParam;
  

/* ECC公钥结构	*/
typedef struct 
{
	u32_t bits;				/* 参数位长		*/
	BYTE  x[ECC_BLOCK_LEN];	/* Q点的x坐标	*/
	BYTE  y[ECC_BLOCK_LEN];	/* Q点的y坐标	*/
} ECCrefPublicKey;


/* ECC私钥结构	*/
typedef struct 
{
	u32_t bits;				/* 参数位长		*/
	BYTE D[ECC_BLOCK_LEN];	/* 私钥			*/
} ECCrefPrivateKey;


/* ECC签名结构	*/
typedef struct 
{
	BYTE r[ECC_BLOCK_LEN];	/* r值			*/
	BYTE s[ECC_BLOCK_LEN];	/* s值			*/
} ECCSignature; 


/* ECC加密值结构 */
typedef struct 
{
	BYTE x[ECC_BLOCK_LEN];	/* C1点的x坐标	*/
	BYTE y[ECC_BLOCK_LEN];	/* C1点的y坐标	*/
	BYTE C[ECC_BLOCK_LEN];	/* 密文值C2		*/	
//	int  C2_Len;			/* C2字节数		*/
	BYTE M[ECC_BLOCK_LEN];	/* HASH值C3		*/
} ECCCipher;
 

#endif
