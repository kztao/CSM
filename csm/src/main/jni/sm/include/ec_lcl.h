#ifndef EC_LCL_H
#define EC_LCL_H

#include "sm2_bn.h"
#include "sm2_type.h"

/**
// //ECC芯片参数结构
// struct ecc_parameter_st
// {
//     unsigned char p[ECC_BLOCK_LEN];		//模数p
// 	unsigned char a[ECC_BLOCK_LEN];		//参数a
// 	unsigned char b[ECC_BLOCK_LEN];		//参数b
// 	unsigned char Gx[ECC_BLOCK_LEN];	//G点的x坐标
// 	unsigned char Gy[ECC_BLOCK_LEN];	//G点的y坐标
// 	unsigned char Gn[ECC_BLOCK_LEN];	//G点的阶
// };
// 
// //ECC公钥结构
// struct ecc_public_key_st
// {
// 	unsigned char Qx[ECC_BLOCK_LEN];		//Q点的x坐标
// 	unsigned char Qy[ECC_BLOCK_LEN];		//Q点的y坐标
// };
// 
// //ECC私钥结构
// struct ecc_private_key_st
// {
// 	unsigned char Ka[ECC_BLOCK_LEN];		//私钥Ka
// };
// 
// //ECC签名值结构
// struct ecc_signature_st
// {
// 	unsigned char r[ECC_BLOCK_LEN];	
// 	unsigned char s[ECC_BLOCK_LEN];	
// };
// 
// //ECC加密值结构
// struct ecc_encryption_st
// {  
// 	unsigned char C1[ECC_BLOCK_LEN*2];	//C1点的(x,y)坐标
// 	unsigned char C2[ECC_BLOCK_LEN];  //和明文等长，最大1K字节
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
#define ECC_RAND_NUM_LEN	32/** 随机数的字节长度 **/
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
// typedef struct KaParameter_st//秘钥协商参数
// {
// 	BYTE			* p_anti_id;		//对方ID
// 	int				  anti_id_len;		//....ID字节长度
// 	ECC_PUBLIC_KEY	* p_anti_pk;		//....公钥
// 	
// 	BYTE			* p_self_id;		//己方ID
// 	int				  self_id_len;		//....ID字节长度
// 	ECC_PUBLIC_KEY	* p_self_pk;		//....公钥
// 	ECC_PRIVATE_KEY	* p_self_sk;		//....私钥
// 	int				  self_is_initiator;//....是否为发起方（与发起方相对的是响应方）
// 	
// 	int				  reserved[8];		//保留字段
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

