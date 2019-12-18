#ifndef _EC_SM2_BN_H
#define _EC_SM2_BN_H

#include "mm_types.h"


#define ECC_BITS		    256					/* ECCģ��������	*/  
#define ECC_BLOCK_LEN		((ECC_BITS+7)/8)	/* ECC���鳤���ֽ���*/ 

#define ECCref_MAX_BITS		ECC_BITS			/* 256	*/ 
#define ECCref_MAX_LEN		ECC_BLOCK_LEN		/*  32	*/ 
 
/* ECC�����ṹ	*/
typedef struct 
{
    BYTE  p[ECC_BLOCK_LEN];	/* ģ��p		*/
	BYTE  a[ECC_BLOCK_LEN];	/* ����a		*/
	BYTE  b[ECC_BLOCK_LEN];	/* ����b		*/
	BYTE gx[ECC_BLOCK_LEN];	/* G���x����	*/
	BYTE gy[ECC_BLOCK_LEN];	/* G���y����	*/
	BYTE  n[ECC_BLOCK_LEN];	/* G��Ľ�		*/
	u32_t len;				/* ����λ��		*/
} ECCrefCurveParam;
  

/* ECC��Կ�ṹ	*/
typedef struct 
{
	u32_t bits;				/* ����λ��		*/
	BYTE  x[ECC_BLOCK_LEN];	/* Q���x����	*/
	BYTE  y[ECC_BLOCK_LEN];	/* Q���y����	*/
} ECCrefPublicKey;


/* ECC˽Կ�ṹ	*/
typedef struct 
{
	u32_t bits;				/* ����λ��		*/
	BYTE D[ECC_BLOCK_LEN];	/* ˽Կ			*/
} ECCrefPrivateKey;


/* ECCǩ���ṹ	*/
typedef struct 
{
	BYTE r[ECC_BLOCK_LEN];	/* rֵ			*/
	BYTE s[ECC_BLOCK_LEN];	/* sֵ			*/
} ECCSignature; 


/* ECC����ֵ�ṹ */
typedef struct 
{
	BYTE x[ECC_BLOCK_LEN];	/* C1���x����	*/
	BYTE y[ECC_BLOCK_LEN];	/* C1���y����	*/
	BYTE C[ECC_BLOCK_LEN];	/* ����ֵC2		*/	
//	int  C2_Len;			/* C2�ֽ���		*/
	BYTE M[ECC_BLOCK_LEN];	/* HASHֵC3		*/
} ECCCipher;
 

#endif
