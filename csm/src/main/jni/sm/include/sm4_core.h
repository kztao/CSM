/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: sm4_core.h
文件描述: SM4内部核心接口
创 建 者: 张文科 罗影
创建时间: 2014年10月29日
修改历史:
1. 2014年10月29日	张文科 罗影		创建文件 
*******************************************************************************/
#ifndef _SM4_CORE_H
#define _SM4_CORE_H



/* ------------------------ 头文件包含区 开始 ------------------------------- */

#include "mm_types.h"

/* ======================== 头文件包含区 结束 =============================== */


#ifdef __cplusplus
extern "C" {
#endif
	

/* ------------------------ 公共宏定义区 开始 ------------------------------- */

/* . . . . . . . . . . . .  SM4可配置区域 开始 . . . . . . . . . . . . . . .  */
	

 
#define SM4_USE_MID_TABLE	/* 定义之，则使用中表法，否则使用小表 */
//#define SM4_UNROLL
/* ........................ SM4可配置区域 结束 .............................. */
 

#define SM4_BLOCK_LEN	16		/* SMS4 分组长度 16字节(128比特) */
#define SM4_KEY_LEN		16		/* SMS4 密钥长度 16字节(128比特) */
#define SM4_SKEY_NUM	32		/* SMS4 子密钥个数	*/
 

typedef struct crypto_sm4_ctx
{	
	mm_u32_t	not_aligned_tm;			/* 数据未按照分块大小对齐的次数 */
	mm_u32_t	key_length;				/* 必须是16字节 */
	mm_u32_t	num;
	mm_u8_t	*	p_mem;					/* 记录查表法的表数据 */
	mm_u32_t	key_enc[SM4_SKEY_NUM];	/* 加密子密钥 */
	mm_u32_t	key_dec[SM4_SKEY_NUM];	/* 解密子密钥 */
	mm_u8_t		pre_ct[SM4_BLOCK_LEN];	/* 记录上一次的密文，首次设置时是IV */
	mm_u8_t		counter[SM4_BLOCK_LEN];

}sm4_ctx;

#define SM4_GET_ENC_SKEY(p)	(((sm4_ctx*)p)->key_enc)
#define SM4_GET_DEC_SKEY(p)	(((sm4_ctx*)p)->key_dec)
#define SM4_GET_PRE_CT(p)	(((sm4_ctx*)p)->pre_ct) 


 
/* ======================== 公共类型定义区 结束 ============================= */
	
	
/* ------------------------ 函数原型外部声明区 开始 ------------------------- */

	
/*******************************************************************************
函 数 名:	sm4_key_expand
功能描述:	密钥扩展
说    明:	
注    意:	1. 将输入密钥扩展为32个加密子密钥和32个解密子密钥
			2. 解密子密钥是加密子密钥的逆序 
参数说明: 
	ch_key	(in)	密钥
	enc_rk	(out)	加密子密钥 
	dec_rk	(out)	解密子密钥 
返 回 值:	>=1 [成功]，<=0 [失败]
修改历史: 
    1. 2014年10月29日	张文科 罗影		创建函数
*******************************************************************************/ 

mm_i32_t  sm4_key_expand(	mm_u8_t  ch_key[SM4_KEY_LEN], 
						mm_u32_t enc_rk[SM4_SKEY_NUM], 
						mm_u32_t dec_rk[SM4_SKEY_NUM] );


// MM_INLINE mm_i32_t crypto_sm4_expand_key(	sm4_ctx *ctx, 
// 										const mm_u8_t *in_key, 
// 										mm_u32_t key_len/* = SM4_KEY_LEN */)
// {
// 	return sm4_key_expand((mm_u8_t *)in_key, SM4_GET_ENC_SKEY(ctx), 
// 		SM4_GET_DEC_SKEY(ctx));
// } 
/*******************************************************************************
函 数 名:	sm4_enc_dec
功能描述:	加密或者解密一个分组
说    明:	-
注    意:	1. 若加密，则使用加密子密钥
			   若解密，则使用解密子密钥
			   解密子密钥是加密子密钥的逆序
			2. 子密钥来至于sm4_key_expand() 
参数说明: 
	p_ch_text_in	(in)	明文
	rk				(in)	子密钥 
	p_ch_text_out	(out)	密文 
返 回 值:	>=1 [成功]，<=0 [失败]
修改历史: 
    1. 2014年10月29日	张文科 罗影		创建函数
*******************************************************************************/ 
mm_void_t sm4_enc_dec(	mm_u32_t rk[SM4_SKEY_NUM], 
						mm_u8_t  p_ch_text_in[SM4_BLOCK_LEN], 
						mm_u8_t  p_ch_text_out[SM4_BLOCK_LEN]);   

MM_INLINE mm_void_t  sm4_encrypt(	sm4_ctx *ctx, 
								mm_u8_t ct_out[SM4_BLOCK_LEN], 
								mm_u8_t pt_in[SM4_BLOCK_LEN])  
{
	//sm4_enc_dec(SM4_GET_ENC_SKEY(ctx), ct_out, pt_in);
	sm4_enc_dec(SM4_GET_ENC_SKEY(ctx), pt_in, ct_out);
}

MM_INLINE mm_void_t  sm4_decrypt(	sm4_ctx *ctx, 
								mm_u8_t pt_out[SM4_BLOCK_LEN], 
								mm_u8_t ct_in[SM4_BLOCK_LEN])  
{
	//sm4_enc_dec(SM4_GET_DEC_SKEY(ctx), pt_out, ct_in);
	sm4_enc_dec(SM4_GET_DEC_SKEY(ctx), ct_in, pt_out );
}

//-------------------------------------------------------------------



/* ======================== 函数原型外部声明区 结束 ========================= */


/* ------------------------ 变量外部引用声明区 开始 ------------------------- */

/* ======================== 变量外部引用声明区 结束 ========================= */
 
#ifdef __cplusplus
}
#endif

#endif/*#ifndef _SM4_CORE_H */ 
