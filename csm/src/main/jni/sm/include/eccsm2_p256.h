/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
�ļ�����: eccsm2_p256.h
�ļ�����: SM2�ӿ�[���Ժ�ӿ�]
�� �� ��: ���Ŀ� ��Ӱ
����ʱ��: 2014��11��10��
�޸���ʷ:
1. 2014��11��10��	���Ŀ� ��Ӱ		�����ļ� 
*******************************************************************************/
#ifndef _ECC_SM2_P256_H
#define _ECC_SM2_P256_H


/* ------------------------ ͷ�ļ������� ��ʼ ------------------------------- */
 

/* ======================== ͷ�ļ������� ���� =============================== */


#ifdef __cplusplus
extern "C" {
#endif
	
#ifndef ECC_BITS
#define ECC_BITS		    256					/* ECCģ��������	*/  
#endif

#define ECCref_MAX_BITS		256						/* 256	*/ 
#define ECCref_MAX_LEN		((ECCref_MAX_BITS+7)/8)	/*  32	*/  
	
/* ECC�����ṹ	*/
typedef struct 
{
	unsigned char  p[ECCref_MAX_LEN];	/* ģ��p		*/
	unsigned char  a[ECCref_MAX_LEN];	/* ����a		*/
	unsigned char  b[ECCref_MAX_LEN];	/* ����b		*/
	unsigned char gx[ECCref_MAX_LEN];	/* G���x����	*/
	unsigned char gy[ECCref_MAX_LEN];	/* G���y����	*/
	unsigned char  n[ECCref_MAX_LEN];	/* G��Ľ�		*/
	unsigned int len;				/* ����λ��		*/
} ECCrefCurveParam;
	
	
/* ECC��Կ�ṹ	*/
typedef struct 
{
	unsigned int bits;				/* ����λ��		*/
	unsigned char  x[ECCref_MAX_LEN];	/* Q���x����	*/
	unsigned char  y[ECCref_MAX_LEN];	/* Q���y����	*/
} ECCrefPublicKey;
	
	
/* ECC˽Կ�ṹ	*/
typedef struct 
{
	unsigned int bits;				/* ����λ��		*/
	unsigned char D[ECCref_MAX_LEN];	/* ˽Կ			*/
} ECCrefPrivateKey;
	
	
/* ECCǩ���ṹ	*/
typedef struct 
{
	unsigned char r[ECCref_MAX_LEN];	/* rֵ			*/
	unsigned char s[ECCref_MAX_LEN];	/* sֵ			*/
} ECCSignature; 
	
	
/* ECC����ֵ�ṹ */
typedef struct 
{
	unsigned char x[ECCref_MAX_LEN];	/* C1���x����	*/
	unsigned char y[ECCref_MAX_LEN];	/* C1���y����	*/
	unsigned char C[ECCref_MAX_LEN];	/* ����ֵC2		*/	
//	int  C2_Len;						/* C2�ֽ���,�������ĳ���*/
	unsigned char M[ECCref_MAX_LEN];	/* HASHֵC3		*/
} ECCCipher;
	 

/*******************************************************************************
�� �� ��:	SM2_GenerateRandom
��������:	���������
˵    ��:	-
ע    ��:	-
����˵��: 
	pucRandom	(out)	�����
	uiLength	(in)	������ֽڳ��� 
�� �� ֵ:  0 (�ɹ�), < 0 (ʧ��)
�޸���ʷ: 
    1. 2014��11��10��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

int SM2_GenerateRandom(unsigned int uiLength, unsigned char *pucRandom); 


/*******************************************************************************
�� �� ��:	SM2_Verify
��������:	SM2��֤ǩ��
˵    ��:	��ECC��Կ�����ĺ�ǩ��ֵ��ָ�������Ͻ�����֤���㡣
ע    ��:	�����ڲ����SM3�Ӵ����㡣��ԭ�ĵ��Ӵ����㣬�ں����ڲ���ɡ�
����˵��:  
	pucDataInput(in)	�ⲿ���������
	uiInputLength(in)	��������ݳ���
	pucID		(in)	ǩ���ߵ�IDֵ����Ҫ��ǩ��ʱʹ�õ�һ�£�
	uiIDLength	(in)	ǩ���ߵ�ID����
	pucPublicKey(in)	�ⲿECC��Կ�ṹ
	pucSignature(in)	������ָ�룬���ڴ�������ǩ������
�� �� ֵ:  0 (�ɹ�), < 0 (ʧ��)
�޸���ʷ: 
    1. 2014��11��10��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

int SM2_Verify_sm2(unsigned char *pucDataInput,unsigned int  uiInputLength,
			   unsigned char *pucID, unsigned int uiIDLength,
			   ECCrefPublicKey *pucPublicKey,ECCSignature *pucSignature);
 

/*******************************************************************************
�� �� ��:	SM2_Encrypt
��������:	SM2����
˵    ��:	��ECC��Կ��������ָ�������Ͻ��м������㡣
ע    ��:	��Ҫ�ⲿָ�����������ͳһ���ܽ����
����˵��: 
	pucDataInput	(in)	�ⲿ��������ݣ�����32�ֽڣ��粻��32�ֽڵ��������
	uiInputLength	(in)	��������ݳ��ȣ�����32�ֽ�
	pucPublicKey	(in)	�ⲿECC��Կ�ṹ 
	pucRandom		(in)	ָ����Կ����ʱʹ�õ������
	uiRandomLength	(in)	��������ȣ�����32�ֽ�
	pucEncData		(out)	������ָ�룬���ڴ��������������� 
�� �� ֵ:  0 (�ɹ�), < 0 (ʧ��)
�޸���ʷ: 
    1. 2014��11��10��	���Ŀ� ��Ӱ		��������
*******************************************************************************/
int SM2_Encrypt_sm2(unsigned char *pucDataInput,unsigned int  uiInputLength,
				ECCrefPublicKey *pucPublicKey, unsigned char *pucRandom,
				unsigned int uiRandomLength, ECCCipher *pucEncData);



/* �����ӿ� ����ʱδʵ�֣�*/

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
