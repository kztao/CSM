/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: sm2.h
文件描述: SM2接口
创 建 者: 张文科 罗影
创建时间: 2014年10月24日
修改历史:
1. 2014年10月24日	张文科 罗影		创建文件 
*******************************************************************************/
#ifndef _SM2_H_787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
#define _SM2_H_787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498


/* ------------------------ 头文件包含区 开始 ------------------------------- */
#include "mm_types.h"
#include "sm2_type.h"
/* ======================== 头文件包含区 结束 =============================== */


#ifdef __cplusplus
extern "C" {
#endif
	
/* ------------------------ 公共宏定义区 开始 ------------------------------- */


/* ======================== 公共类型定义区 结束 ============================= */


/* ------------------------ 函数原型外部声明区 开始 ------------------------- */

/*******************************************************************************
函 数 名:	ECC_GenerateRandNumber
功能描述:	生成随机数
说    明:	-
注    意:	1. 可以不提供随机数种子（即种子为NULL，长度为零）。
			2. 但建议提供随机数种子（即种子非NULL，长度非零）。
参数说明: 
	p_rand		(out)	随机数
	rand_len	(in)	随机数字节长度
	p_seed		(in)	用于生成随机数的种子 
	seed_len	(in)	种子字节长度 
返 回 值:  1 (成功), <=0 (失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/

MM_API int ECC_GenerateRandNumber(BYTE *p_rand,mm_u32_t rand_len, 
						   BYTE *p_seed, mm_u32_t seed_len);
	

/*******************************************************************************
函 数 名:	ECC_Init
功能描述:	初始化 
说    明:	-
注    意:	曲线参数 p_param 若为NULL，则使用标准推荐的参数，见 sm2_type.h 。
			初始化得到的句柄是后续一系列操作的基础。各种操作的执行步骤概括如下：

第 1 步 初始化		ECC_Init(***)

第 2 步 实际操作

		2.1 若加/解密	
			2.1.1 若加密	ECES_Encryption(***)
			2.1.2 若解密	ECES_Decryption(***)

		2.2 若签名与验证
			2.1.1 若签名	ECC_GetValueE( ... e);
							ECDSA_Signature(... e ...);
						  或
							ECC_GetUserValueZ(... z);
							ECDSA_SignatureFull(... z ...);

			2.1.2 若验证	ECC_GetValueE( ... e);
							ECDSA_Verification(... e ...);
						  或
							ECC_GetUserValueZ(... z);
							ECDSA_VerificationFull(... z ...);

		2.3 若密钥协商	 
							ECKA_SetKaParam(***); 
							ECKA_CalcKaExData(***); 
							ECKA_GetKaKey(***);

第 3 步 反初始化	ECC_Unit(***)

参数说明: 
	p_param(in)	曲线参数 
返 回 值:  非NULL (成功), NULL (失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/

MM_API mm_handle ECC_Init(	ECCParameter *p_param);


/*******************************************************************************
函 数 名:	ECC_Unit
功能描述:	反初始化 
说    明:	-
注    意:	1. 本步骤将销毁句柄，因此执行后句柄为悬垂指针，不可用。
			2. 所有操作执行完毕后进行此步骤
参数说明: 
	h		(in)	句柄
返 回 值:	1 (成功), <=0 (失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/

MM_API int ECC_Unit( mm_handle h);	 


/*******************************************************************************
函 数 名:	ECC_GenerateKeyPair
功能描述:	产生密钥对 
说    明:	-
注    意:	随机产生密钥对 
参数说明: 
	h		(in/out)句柄 
	p_pk	(out)	公钥 
	p_sk	(out)	私钥
返 回 值:  1 (成功), <=0 (失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/	

MM_API int ECC_GenerateKeyPair(mm_handle h, 
						ECC_PUBLIC_KEY *p_pk, ECC_PRIVATE_KEY *p_sk); 
	
	
/*******************************************************************************
函 数 名:	ECDSA_Signature
功能描述:	签名 (缺少A1,A2步骤)
说    明:	-
注    意:	1. 此接口没有进行A1,A2两个步骤，所以需要外面进行
				步骤A1: M`= Z || M，其中M为待签名的普通消息，Z为用户的可辨别标识
						Z值的计算可以使用 ECC_GetUserValueZ( )
				步骤A2: 计算e = Hash(M`)，其中 Hash 为 SM3 HASH 运算； 
			2. 此接口的输入消息是杂凑值e, 而不是普通的消息；
				调用 ECC_GetValueE( ) 可完成A1,A2步骤，得到的e值送入本接口 
			3. 若随机数 rand 非NULL，则使用此随机数；否则内部生成随机数，
			4. 完整的签名步骤
				ECC_GetValueE( ... e);
				ECDSA_Signature(... e ...);
			  或
				ECC_GetUserValueZ(... z);
				ECDSA_SignatureFull(... z ...);
参数说明: 
	h		(in/out)句柄  
	e		(in)	特定杂凑值
	p_sk	(in)	私钥
	p_sign	(out)	签名值
	rand	(in)	随机数
返 回 值:  1 (成功), <=0 (失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/

MM_API int ECDSA_Signature(mm_handle h, BYTE e[SM3_HASH_VALUE_LEN], 
					ECC_PRIVATE_KEY *p_sk, ECC_SIGNATURE *p_sign, 
					BYTE rand[ECC_RAND_NUM_LEN]);

	
/*******************************************************************************
函 数 名:	ECDSA_SignatureFull
功能描述:	完整的签名 
说    明:	-
注    意:	1. 此接口执行完整的签名 
			2. 此接口的输入消息 p_msg 是任意普通消息  
			3. z 是用户的可辨别标识，调用 ECC_GetUserValueZ( ) 可得到
			4. 若随机数 rand 非NULL，则使用此随机数；否则内部生成随机数
参数说明: 
	h		(in/out)句柄  
	z		(in)	用户的可辨别标识（Z值） 
	p_msg	(in)	待签名的普通消息
	msg_len	(in)	普通消息的长度
	p_sk	(in)	私钥
	p_sign	(out)	签名值
	rand	(in)	随机数
返 回 值:  1 (成功), <=0 (失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/

MM_API int ECDSA_SignatureFull(mm_handle h, BYTE z[SM3_HASH_VALUE_LEN], 
						BYTE *p_msg, mm_u32_t msg_len, 
						ECC_PRIVATE_KEY *p_sk, ECC_SIGNATURE *p_sign, 
						BYTE rand[ECC_BLOCK_LEN] );


/*******************************************************************************
函 数 名:	ECC_GetValueE
功能描述:	获取签名前的待签名e值 
说    明:	-
注    意:	1. 曲线参数 p_param 若为NULL，则使用标准推荐的参数，见 sm2_type.h 。
			2. 计算得到的e值，是 ECDSA_Signature()的输入值e
			3. 用户ID 为用户标示，如 "ALICE123@YAHOO.COM" 
			4. 待签名的消息可为任意普通消息，如 "message digest"   
参数说明: 
	p_ecprm	(in)	椭圆曲线参数 
	p_id	(in)	用户ID
	id_len	(in)	ID字节长度
	p_msg	(in)	待签名的普通消息
	msg_len	(in)	普通消息的长度
	p_pk(in)		公钥
	e(out)			签名前的待签名e值 
返 回 值:  1 (成功), <=0 (失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/

MM_API int ECC_GetValueE(	ECCParameter *p_ecprm, BYTE *p_id,  mm_u32_t id_len, 
					BYTE *p_msg, mm_u32_t msg_len, ECC_PUBLIC_KEY *p_pk, 
					BYTE e[SM3_HASH_VALUE_LEN] );


/*******************************************************************************
函 数 名:	ECC_GetUserValueZ
功能描述:	计算用户的可辨别标识（Z值）
说    明:	-
注    意:	1. 曲线参数 p_param 若为NULL，则使用标准推荐的参数，见 sm2_type.h 。
			2. 椭圆曲线参数 p_ecprm 同 ECC_Init() 输入的椭圆曲线参数  
			3. 用户ID 为用户标示，如 "ALICE123@YAHOO.COM" 
参数说明: 
	p_ecprm	(in)	椭圆曲线参数 
	p_id	(in)	用户ID
	id_len	(in)	ID字节长度
	z		(out)	用户的可辨别标识（Z值） 
返 回 值:  1 (成功), <=0 (失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/

MM_API int ECC_GetUserValueZ(ECCParameter *p_ecprm, BYTE *p_id, mm_u32_t id_len, 
					  ECC_PUBLIC_KEY *p_pk,  BYTE z[SM3_HASH_VALUE_LEN] );


/*******************************************************************************
函 数 名:	ECDSA_Verification
功能描述:	验证签名 (缺少B3,B4步骤)
说    明:	-
注    意:	1. 此接口没有进行B3,B4两个步骤，所以需要外面进行
				步骤B3: M`= Z || M，其中M为待签名的普通消息，Z为用户可辨别标识
						Z值的计算可以使用 ECC_GetUserValueZ( )
				步骤B4: 计算e = Hash(M`)，其中 Hash 为 SM3 HASH 运算； 
			2. 此接口的输入消息是杂凑值e, 而不是普通的消息；
				调用 ECC_GetValueE( ) 可完成B3,B4步骤，得到的e值送入本接口 
			3. 完整的验签步骤为 
				ECC_GetValueE( ... e);
				ECDSA_Verification(... e ...);
				或
				ECC_GetUserValueZ(... z);
				ECDSA_VerificationFull(... z ...);
参数说明: 
	h		(in/out)句柄  
	e		(in)	特定杂凑值
	p_pk	(in)	公钥
	p_sign	(in)	签名值 
返 回 值:  1 (验证签名成功), <=0 (验证签名失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/
 
MM_API int ECDSA_Verification(mm_handle h, BYTE e[SM3_HASH_VALUE_LEN], 
					   ECC_PUBLIC_KEY *p_pk, ECC_SIGNATURE *p_sign );
	
	
/*******************************************************************************
函 数 名:	ECDSA_VerificationFull
功能描述:	完整的验签 
说    明:	-
注    意:	1. 此接口的输入消息 p_msg 是任意普通消息  
			2. z 是用户的可辨别标识，调用 ECC_GetUserValueZ( ) 可得到 
			3. 完整的验签步骤为 
				ECC_GetValueE( ... e);
				ECDSA_Verification(... e ...);
			或
				ECC_GetUserValueZ(... z);
				ECDSA_VerificationFull(... z ...);
参数说明: 
	h		(in/out)句柄  
	z		(in)	用户的可辨别标识（Z值） 
	p_msg	(in)	待签名的普通消息
	msg_len	(in)	普通消息的长度
	p_pk	(in)	公钥
	p_sign	(in)	签名值 
返 回 值:  1 (验证签名成功), <=0 (验证签名失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/

MM_API int ECDSA_VerificationFull(mm_handle h, BYTE z[SM3_HASH_VALUE_LEN], 
		BYTE *p_msg, mm_u32_t msg_len, ECC_PUBLIC_KEY *p_pk, 
		ECC_SIGNATURE *p_sign);
	

/*******************************************************************************
函 数 名:	ECES_Encryption
功能描述:	加密
说    明:	-
注    意:	1. 明密文长度不相同，两者的关系是
				调用 GET_ENC_DATA_LEN(pt_len) 得到对应的密文长度
				调用 GET_DEC_DATA_LEN(ct_len) 得到对应的明文长度  
			2. 若随机数 rand 非NULL，则使用此随机数；否则内部生成随机数
参数说明: 
	h		(in/out)句柄  
	p_pt	(in)	明文
	pt_len	(in)	明文字节长度 
	p_pk	(in)	公钥
	p_ct	(out)	密文
	rand	(in)	随机数
返 回 值:  1 (成功), <=0 (失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/


MM_API int	ECES_Encryption(mm_handle h, BYTE *p_pt, mm_u32_t pt_len, 
					ECC_PUBLIC_KEY *p_pk, BYTE *p_ct, 
					BYTE rand[ECC_RAND_NUM_LEN]);
	
/*
ECES加密得到的密文结构如下
typedef struct EncDataFmt_st
{  
	BYTE tag;//值为04, 
	BYTE c1x[ECC_BLOCK_LEN];//C1点的x坐标,32字节,(C1是掩盖随机数的曲线上的点)
	BYTE c1y[ECC_BLOCK_LEN];//C1点的y坐标,32字节,(C1是掩盖随机数的曲线上的点)
	BYTE  c2[pt_len];		//C2是核心密文,字节长度为明文长度
	BYTE  C3[32];			//C3是Hash值, 32字节
}EncDataFmt;
//如不要tag，需在 mm_sm_cfg.h 里不定义 MM_SM2_CIPHPER_HAS_TAG
*/

/*SM2 ECES 加密算法 明文长度和密文长度的关系 
	如果密文有一个字节的 tag ，	密文长度 = 明文长度 + 97
	如果密文没有 tag ，			密文长度 = 明文长度 + 96
*/
#define GET_ENC_DATA_LEN(pt_len)\
( (pt_len) + (ECC_BLOCK_LEN * 2 + CT_TAG_LEN + SM3_HASH_VALUE_LEN) ) 

#define GET_DEC_DATA_LEN(ct_len)\
	( (ct_len) - (ECC_BLOCK_LEN * 2 + CT_TAG_LEN + SM3_HASH_VALUE_LEN) ) 

/*******************************************************************************
函 数 名:	ECES_Decryption
功能描述:	解密
说    明:	-
注    意:	1. 明密文长度不相同，两者的关系是
				调用 GET_ENC_DATA_LEN(pt_len) 得到对应的密文长度
				调用 GET_DEC_DATA_LEN(ct_len) 得到对应的明文长度   
参数说明: 
	h		(in/out)句柄  
	p_ct	(in)	密文
	ct_len	(in)	密文字节长度 
	p_sk	(in)	私钥
	p_pt	(out)	明文 
返 回 值:  1 (成功), <=0 (失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/
	
MM_API int ECES_Decryption(mm_handle h, BYTE *p_ct, mm_u32_t ct_len, 
					ECC_PRIVATE_KEY *p_sk, BYTE *p_pt );
	

/*******************************************************************************
函 数 名:	ECKA_SetKaParam
功能描述:	密钥协商时设置参数
说    明:	-
注    意:	1. 注意正确设置密钥协商参数
			2. 密钥协商的流程如下（省略初始化和反初始化步骤） 
UserA								##		UserB
(1) 设置密钥协商参数 kapA			##		设置密钥协商参数 kapB
(2) ECKA_SetKaParam(.kapA.);		##		ECKA_SetKaParam( . kapB .);	
(3) ECKA_CalcKaExData(. ExDataA.);	##		ECKA_CalcKaExData( . ExDataB . );
(4) 双方交换数据		ExDataA   <---->    ExDataB
(5) ECKA_GetKaKey( ExDataB, KeyA);	##		ECKA_GetKaKey( ExDataA, KeyB);
	其中 KeyA == KeyB 为协商得到的共享密钥
参数说明: 
	h		(in/out)句柄  
	p_ka	(in)	密钥协商的相关参数 
返 回 值:  1 (成功), <=0 (失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/

MM_API int ECKA_SetKaParam(mm_handle	h, KaParameter *p_ka);
	

/*******************************************************************************
函 数 名:	ECKA_SetKaParam
功能描述:	密钥协商时获取用于交换的数据
说    明:	-
注    意:	1. 计算得到的交换数据将发送给对方
			2. 若随机数 rand 非NULL，则使用此随机数；否则内部生成随机数
			3. 密钥协商的执行流程见 ECKA_SetKaParam 的描述
参数说明: 
	h		(in/out)句柄  
	p_ex_data (out)	交换数据 
	rand	(in)	随机数  
返 回 值:  1 (成功), <=0 (失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/

MM_API int ECKA_CalcKaExData(	mm_handle h, ECC_KA_EX_DATA *p_ex_data, 
						BYTE rand[ECC_RAND_NUM_LEN]);

	
/*******************************************************************************
函 数 名:	ECKA_GetKaKey
功能描述:	密钥协商时获取协商密钥
说    明:	-
注    意:	1. 密钥协商的执行流程见 ECKA_SetKaParam 的描述
参数说明: 
	h			(in/out)句柄  
	p_ex_data	(in)	交换数据（对方提供）
	key_len		(in)	协商密钥的字节长度
	p_share_key	(out)	协商密钥
返 回 值:  1 (成功), <=0 (失败)
修改历史: 
    1. 2014年10月24日	张文科 罗影		创建函数
*******************************************************************************/

MM_API int ECKA_GetKaKey(	mm_handle h, ECC_KA_EX_DATA *p_ex_data, mm_u32_t key_len, 
					BYTE *p_share_key);


/* ======================== 函数原型外部声明区 结束 ========================= */


/* ------------------------ 变量外部引用声明区 开始 ------------------------- */

/* ======================== 变量外部引用声明区 结束 ========================= */

#ifdef __cplusplus
}
#endif

#endif/* _SM2_H_... */ 
