/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
�ļ�����: sm2_type.h
�ļ�����: SM2��������
�� �� ��: ���Ŀ� ��Ӱ
����ʱ��: 2014��10��24��
�޸���ʷ:
1. 2014��10��24��	���Ŀ� ��Ӱ		�����ļ� 
*******************************************************************************/

#ifndef _SM2_TYPE_H
#define _SM2_TYPE_H


/* ------------------------ ͷ�ļ������� ��ʼ ------------------------------- */
#include "mm_types.h"
#include "mm_sm_cfg.h"

/* ======================== ͷ�ļ������� ���� =============================== */
 

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------ �����궨���� ��ʼ ------------------------------- */
	
	
#define SM3_HASH_VALUE_LEN	32	/* HASHֵ�ֽڳ���	*/
#define ECC_BLOCK_LEN		32	/* ��Բ���߹�ģ		*/
#define ECC_RAND_NUM_LEN	32	/* ��������ֽڳ���	*/

#ifdef MM_SM2_CIPHPER_HAS_TAG	/* ������Ҫtagʱ��tag��Ϊ1������tag��Ϊ0 */
#define CT_TAG_LEN			1
#else
#define CT_TAG_LEN			0
#endif


/* ======================== �����궨���� ���� =============================== */


/* ------------------------ �������Ͷ����� ��ʼ ----------------------------- */
	
/*
SM2��Բ���߹�Կ�����㷨�Ƽ����߲���
������256λ ��Բ���߷��̣�y2 = x3 + ax + b��
���߲�����
p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
a = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
b = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
Gx= 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
Gy= BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
*/

/*ECC�����ṹ*/ 
typedef struct ecc_parameter_st
{
	BYTE	p[ECC_BLOCK_LEN];	/* ģ��p		*/
	BYTE	a[ECC_BLOCK_LEN];	/* ����a		*/
	BYTE	b[ECC_BLOCK_LEN];	/* ����b		*/
	BYTE	Gx[ECC_BLOCK_LEN];	/* G���x����	*/
	BYTE	Gy[ECC_BLOCK_LEN];	/* G���y����	*/
	BYTE	Gn[ECC_BLOCK_LEN];	/* G��Ľ�		*/
}ECCParameter;
	
/*ECC��Կ�ṹ*/
typedef struct ecc_public_key_st
{
	BYTE Qx[ECC_BLOCK_LEN];		/* x���� */
	BYTE Qy[ECC_BLOCK_LEN];		/* y���� */
}ECC_PUBLIC_KEY;
	
/*ECC˽Կ�ṹ*/
#ifndef DEF_ECC_PRIVATE_KEY
typedef struct ecc_private_key_st
{
	BYTE Ka[ECC_BLOCK_LEN];		/* ˽Կ��Ϣ */
}ECC_PRIVATE_KEY;
#define DEF_ECC_PRIVATE_KEY
#endif
	
/* ECCǩ��ֵ�ṹ */
typedef struct ecc_signature_st
{
	BYTE r[ECC_BLOCK_LEN];	/* ǩ����r��Ϣ */
	BYTE s[ECC_BLOCK_LEN];	/* ǩ����s��Ϣ */
} ECC_SIGNATURE;
	

/** ECC����ֵ�ṹ **/
typedef struct ecc_encryption_st
{  
	BYTE C1[ECC_BLOCK_LEN*2];	/** C1���(x,y)���� **/
	BYTE C2[ECC_BLOCK_LEN];  /** �����ĵȳ������1K�ֽ� **/
	BYTE C3[ECC_BLOCK_LEN];
} ECC_ENCRYPTION;
	



/*��ԿЭ�̲���*/	
typedef struct KaParameter_st
{
	BYTE			* p_anti_id;		/*�Է�ID		*/
	int				  anti_id_len;		/*....ID�ֽڳ���*/
	ECC_PUBLIC_KEY	* p_anti_pk;		/*....��Կ		*/
	
	BYTE			* p_self_id;		/*����ID		*/
	int				  self_id_len;		/*....ID�ֽڳ���*/
	ECC_PUBLIC_KEY	* p_self_pk;		/*....��Կ		*/
	ECC_PRIVATE_KEY	* p_self_sk;		/*....˽Կ		*/
	int				  self_is_initiator;/*....�Ƿ�Ϊ����*/
		
	int				  reserved[8];		/*�����ֶ�*/
}KaParameter;	

/*��ԿЭ��ʱ�Ľ�������*/
typedef ECC_PUBLIC_KEY ECC_KA_EX_DATA;

 
 
/* ======================== �������Ͷ����� ���� ============================= */


/* ------------------------ ����ԭ���ⲿ������ ��ʼ ------------------------- */

/* ======================== ����ԭ���ⲿ������ ���� ========================= */


/* ------------------------ �����ⲿ���������� ��ʼ ------------------------- */

/* ======================== �����ⲿ���������� ���� ========================= */
 
#ifdef __cplusplus
}
#endif

#endif/* _SM2_TYPE_H */


