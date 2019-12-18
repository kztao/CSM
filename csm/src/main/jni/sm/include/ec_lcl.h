#ifndef EC_LCL_H
#define EC_LCL_H

#include "sm2_bn.h"
#include "sm2_type.h"

/**
// //ECCоƬ�����ṹ
// struct ecc_parameter_st
// {
//     unsigned char p[ECC_BLOCK_LEN];		//ģ��p
// 	unsigned char a[ECC_BLOCK_LEN];		//����a
// 	unsigned char b[ECC_BLOCK_LEN];		//����b
// 	unsigned char Gx[ECC_BLOCK_LEN];	//G���x����
// 	unsigned char Gy[ECC_BLOCK_LEN];	//G���y����
// 	unsigned char Gn[ECC_BLOCK_LEN];	//G��Ľ�
// };
// 
// //ECC��Կ�ṹ
// struct ecc_public_key_st
// {
// 	unsigned char Qx[ECC_BLOCK_LEN];		//Q���x����
// 	unsigned char Qy[ECC_BLOCK_LEN];		//Q���y����
// };
// 
// //ECC˽Կ�ṹ
// struct ecc_private_key_st
// {
// 	unsigned char Ka[ECC_BLOCK_LEN];		//˽ԿKa
// };
// 
// //ECCǩ��ֵ�ṹ
// struct ecc_signature_st
// {
// 	unsigned char r[ECC_BLOCK_LEN];	
// 	unsigned char s[ECC_BLOCK_LEN];	
// };
// 
// //ECC����ֵ�ṹ
// struct ecc_encryption_st
// {  
// 	unsigned char C1[ECC_BLOCK_LEN*2];	//C1���(x,y)����
// 	unsigned char C2[ECC_BLOCK_LEN];  //�����ĵȳ������1K�ֽ�
//     unsigned char C3[ECC_BLOCK_LEN];
// };
**/

typedef struct ec_point_st {
	BIGNUM X;
	BIGNUM Y;	
	BIGNUM Z;	   /* Jacobian projective coordinates:
	* (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
	int Z_is_one; /* enable optimized point arithmetics for special case */
} EC_POINT;

//typedef struct ec_point_st EC_POINT;

typedef struct ec_group_st {
	
	BIGNUM field; 
	/* Field specification.
	* For curves over GF(p), this is the modulus. */
	
	u32_t field_top;	/* Field length	*/ 
	
	BIGNUM a,b; 
	/* Curve coefficients.
	* (Here the assumption is that BIGNUMs can be used
	* or abused for all kinds of fields, not just GF(p).)
	* For characteristic  > 3,  the curve is defined
	* by a Weierstrass equation of the form
	*     y^2 = x^3 + a*x + b.
	*/
	EC_POINT generator; /* Generator */
	BIGNUM order;
	
	u32_t order_top;	/* Order length	*/ 
	
	BIGNUM RR;
	BIGNUM Ni;     /* R*(1/R mod N) - N*Ni = 1
	* (Ni is only stored for bignum algorithm) */
	u32_t n0;   /* least significant word of Ni */
	
	
	BIGNUM field_data2; 
} EC_GROUP;

//typedef struct ec_group_st EC_GROUP;

// typedef struct ec_point_st EC_POINT;
// typedef struct ec_group_st EC_GROUP;
// typedef struct ecc_parameter_st ECCParameter; 
// typedef struct ecc_public_key_st ECC_PUBLIC_KEY; 
// typedef struct ecc_private_key_st ECC_PRIVATE_KEY; 
// typedef struct ecc_signature_st ECC_SIGNATURE; 
// typedef struct ecc_encryption_st ECC_ENCRYPTION;




#define Z_VALUE_LEN 32
#define ECC_RAND_NUM_LEN	32/** ��������ֽڳ��� **/
//typedef unsigned char BYTE;

typedef struct KaInnerParam_st
{
	int		self_is_initiator;
//	int		reverse_cpy;//buf
	EC_POINT pt_self_pk;
	EC_POINT pt_anti_pk;//buf
	BIGNUM	sm2_bn_self_sk;//buf
	//	BIGNUM  sm2_bn_x_self_trunc;//buf 
	BIGNUM	sm2_bn_t_self;
	BYTE	self_z_value[Z_VALUE_LEN];
	BYTE	anti_z_value[Z_VALUE_LEN];
}KaInnerPara;

/**
// typedef struct KaParameter_st//��ԿЭ�̲���
// {
// 	BYTE			* p_anti_id;		//�Է�ID
// 	int				  anti_id_len;		//....ID�ֽڳ���
// 	ECC_PUBLIC_KEY	* p_anti_pk;		//....��Կ
// 	
// 	BYTE			* p_self_id;		//����ID
// 	int				  self_id_len;		//....ID�ֽڳ���
// 	ECC_PUBLIC_KEY	* p_self_pk;		//....��Կ
// 	ECC_PRIVATE_KEY	* p_self_sk;		//....˽Կ
// 	int				  self_is_initiator;//....�Ƿ�Ϊ���𷽣��뷢����Ե�����Ӧ����
// 	
// 	int				  reserved[8];		//�����ֶ�
// }KaParameter;
**/

typedef struct SM2_EC_GROUP_st
{
	EC_GROUP		ecgrp;
	ECCParameter	ecprm;
//	KaParameter		kaprm;
	KaInnerPara		kainr;
} SM2_EC_GROUP;

 

#endif

