/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: sm2_type.h
文件描述: SM2数据类型
创 建 者: 张文科 罗影
创建时间: 2014年10月24日
修改历史:
1. 2014年10月24日	张文科 罗影		创建文件 
*******************************************************************************/

#ifndef _SM2_TYPE_H
#define _SM2_TYPE_H


/* ------------------------ 头文件包含区 开始 ------------------------------- */
#include "mm_types.h"
#include "mm_sm_cfg.h"

/* ======================== 头文件包含区 结束 =============================== */
 

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------ 公共宏定义区 开始 ------------------------------- */
	
	
#define SM3_HASH_VALUE_LEN	32	/* HASH值字节长度	*/
#define ECC_BLOCK_LEN		32	/* 椭圆曲线规模		*/
#define ECC_RAND_NUM_LEN	32	/* 随机数的字节长度	*/

#ifdef MM_SM2_CIPHPER_HAS_TAG	/* 密文需要tag时，tag长为1，否则tag长为0 */
#define CT_TAG_LEN			1
#else
#define CT_TAG_LEN			0
#endif


/* ======================== 公共宏定义区 结束 =============================== */


/* ------------------------ 公共类型定义区 开始 ----------------------------- */
	
/*
SM2椭圆曲线公钥密码算法推荐曲线参数
素数域256位 椭圆曲线方程：y2 = x3 + ax + b。
曲线参数：
p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
a = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
b = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
Gx= 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
Gy= BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
*/

/*ECC参数结构*/ 
typedef struct ecc_parameter_st
{
	BYTE	p[ECC_BLOCK_LEN];	/* 模数p		*/
	BYTE	a[ECC_BLOCK_LEN];	/* 参数a		*/
	BYTE	b[ECC_BLOCK_LEN];	/* 参数b		*/
	BYTE	Gx[ECC_BLOCK_LEN];	/* G点的x坐标	*/
	BYTE	Gy[ECC_BLOCK_LEN];	/* G点的y坐标	*/
	BYTE	Gn[ECC_BLOCK_LEN];	/* G点的阶		*/
}ECCParameter;
	
/*ECC公钥结构*/
typedef struct ecc_public_key_st
{
	BYTE Qx[ECC_BLOCK_LEN];		/* x坐标 */
	BYTE Qy[ECC_BLOCK_LEN];		/* y坐标 */
}ECC_PUBLIC_KEY;
	
/*ECC私钥结构*/
#ifndef DEF_ECC_PRIVATE_KEY
typedef struct ecc_private_key_st
{
	BYTE Ka[ECC_BLOCK_LEN];		/* 私钥信息 */
}ECC_PRIVATE_KEY;
#define DEF_ECC_PRIVATE_KEY
#endif
	
/* ECC签名值结构 */
typedef struct ecc_signature_st
{
	BYTE r[ECC_BLOCK_LEN];	/* 签名的r信息 */
	BYTE s[ECC_BLOCK_LEN];	/* 签名的s信息 */
} ECC_SIGNATURE;
	

/** ECC加密值结构 **/
typedef struct ecc_encryption_st
{  
	BYTE C1[ECC_BLOCK_LEN*2];	/** C1点的(x,y)坐标 **/
	BYTE C2[ECC_BLOCK_LEN];  /** 和明文等长，最大1K字节 **/
	BYTE C3[ECC_BLOCK_LEN];
} ECC_ENCRYPTION;
	



/*密钥协商参数*/	
typedef struct KaParameter_st
{
	BYTE			* p_anti_id;		/*对方ID		*/
	int				  anti_id_len;		/*....ID字节长度*/
	ECC_PUBLIC_KEY	* p_anti_pk;		/*....公钥		*/
	
	BYTE			* p_self_id;		/*己方ID		*/
	int				  self_id_len;		/*....ID字节长度*/
	ECC_PUBLIC_KEY	* p_self_pk;		/*....公钥		*/
	ECC_PRIVATE_KEY	* p_self_sk;		/*....私钥		*/
	int				  self_is_initiator;/*....是否为发起方*/
		
	int				  reserved[8];		/*保留字段*/
}KaParameter;	

/*密钥协商时的交换数据*/
typedef ECC_PUBLIC_KEY ECC_KA_EX_DATA;

 
 
/* ======================== 公共类型定义区 结束 ============================= */


/* ------------------------ 函数原型外部声明区 开始 ------------------------- */

/* ======================== 函数原型外部声明区 结束 ========================= */


/* ------------------------ 变量外部引用声明区 开始 ------------------------- */

/* ======================== 变量外部引用声明区 结束 ========================= */
 
#ifdef __cplusplus
}
#endif

#endif/* _SM2_TYPE_H */


