/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
�ļ�����: sm4_core.h
�ļ�����: SM4�ڲ����Ľӿ�
�� �� ��: ���Ŀ� ��Ӱ
����ʱ��: 2014��10��29��
�޸���ʷ:
1. 2014��10��29��	���Ŀ� ��Ӱ		�����ļ� 
*******************************************************************************/
#ifndef _SM4_CORE_H
#define _SM4_CORE_H



/* ------------------------ ͷ�ļ������� ��ʼ ------------------------------- */

#include "mm_types.h"

/* ======================== ͷ�ļ������� ���� =============================== */


#ifdef __cplusplus
extern "C" {
#endif
	

/* ------------------------ �����궨���� ��ʼ ------------------------------- */

/* . . . . . . . . . . . .  SM4���������� ��ʼ . . . . . . . . . . . . . . .  */
	

 
#define SM4_USE_MID_TABLE	/* ����֮����ʹ���б�������ʹ��С�� */
//#define SM4_UNROLL
/* ........................ SM4���������� ���� .............................. */
 

#define SM4_BLOCK_LEN	16		/* SMS4 ���鳤�� 16�ֽ�(128����) */
#define SM4_KEY_LEN		16		/* SMS4 ��Կ���� 16�ֽ�(128����) */
#define SM4_SKEY_NUM	32		/* SMS4 ����Կ����	*/
 

typedef struct crypto_sm4_ctx
{	
	mm_u32_t	not_aligned_tm;			/* ����δ���շֿ��С����Ĵ��� */
	mm_u32_t	key_length;				/* ������16�ֽ� */
	mm_u32_t	num;
	mm_u8_t	*	p_mem;					/* ��¼����ı����� */
	mm_u32_t	key_enc[SM4_SKEY_NUM];	/* ��������Կ */
	mm_u32_t	key_dec[SM4_SKEY_NUM];	/* ��������Կ */
	mm_u8_t		pre_ct[SM4_BLOCK_LEN];	/* ��¼��һ�ε����ģ��״�����ʱ��IV */
	mm_u8_t		counter[SM4_BLOCK_LEN];

}sm4_ctx;

#define SM4_GET_ENC_SKEY(p)	(((sm4_ctx*)p)->key_enc)
#define SM4_GET_DEC_SKEY(p)	(((sm4_ctx*)p)->key_dec)
#define SM4_GET_PRE_CT(p)	(((sm4_ctx*)p)->pre_ct) 


 
/* ======================== �������Ͷ����� ���� ============================= */
	
	
/* ------------------------ ����ԭ���ⲿ������ ��ʼ ------------------------- */

	
/*******************************************************************************
�� �� ��:	sm4_key_expand
��������:	��Կ��չ
˵    ��:	
ע    ��:	1. ��������Կ��չΪ32����������Կ��32����������Կ
			2. ��������Կ�Ǽ�������Կ������ 
����˵��: 
	ch_key	(in)	��Կ
	enc_rk	(out)	��������Կ 
	dec_rk	(out)	��������Կ 
�� �� ֵ:	>=1 [�ɹ�]��<=0 [ʧ��]
�޸���ʷ: 
    1. 2014��10��29��	���Ŀ� ��Ӱ		��������
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
�� �� ��:	sm4_enc_dec
��������:	���ܻ��߽���һ������
˵    ��:	-
ע    ��:	1. �����ܣ���ʹ�ü�������Կ
			   �����ܣ���ʹ�ý�������Կ
			   ��������Կ�Ǽ�������Կ������
			2. ����Կ������sm4_key_expand() 
����˵��: 
	p_ch_text_in	(in)	����
	rk				(in)	����Կ 
	p_ch_text_out	(out)	���� 
�� �� ֵ:	>=1 [�ɹ�]��<=0 [ʧ��]
�޸���ʷ: 
    1. 2014��10��29��	���Ŀ� ��Ӱ		��������
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



/* ======================== ����ԭ���ⲿ������ ���� ========================= */


/* ------------------------ �����ⲿ���������� ��ʼ ------------------------- */

/* ======================== �����ⲿ���������� ���� ========================= */
 
#ifdef __cplusplus
}
#endif

#endif/*#ifndef _SM4_CORE_H */ 
