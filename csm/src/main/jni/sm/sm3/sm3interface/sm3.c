/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
�ļ�����: sm3.c
�ļ�����: SM3�Ӵ��㷨ʵ��
�� �� ��: ���Ŀ� ��Ӱ
����ʱ��: 2014��10��30��
�޸���ʷ:
1. 2014��10��30��   ���Ŀ� ��Ӱ     �����ļ� 
*******************************************************************************/


/* ------------------------ ͷ�ļ������� ��ʼ ------------------------------- */

#include "mm_macro.h"
#include "sm3.h"
 


/* ======================== ͷ�ļ������� ���� =============================== */


/* ------------------------ �����궨���� ��ʼ ------------------------------- */
 

/* ======================== �����궨���� ���� =============================== */


/* ------------------------ �������Ͷ����� ��ʼ ----------------------------- */
 

/* ======================== �������Ͷ����� ���� ============================= */


/*******************************************************************************
�� �� ��:   sm3_init
��������:   ��ʼ��SM3 
˵    ��:   ����ʽ������Ϣ�Ӵ�ֵ�ĵ� 1 ��
ע    ��:   ����ʽ������Ϣ�Ӵ�ֵ�����ϸ������²���ִ��
            �� 1 �� sm3_init(***);          // ��ʼ��
            �� 2 �� while(msg_not_end){
                        sm3_process(***);   // ��Ϣ�ɷֶ�����
                    }
            �� 3 �� sm3_unit(***);          // ����Ӵ�ֵ
����˵��:   -
�� �� ֵ:  ������ [�ɹ�],  NULL [ʧ��]
�޸���ʷ: 
    1. 2014��10��30��   ���Ŀ� ��Ӱ     ��������
    2. 2015�� 2�� 4��   ���Ŀ� ��Ӱ     �޸ĺ����ӿ�
*******************************************************************************/
 
mm_handle sm3_init( )
{
    mm_sm3_ctx *p = (mm_sm3_ctx *)MM_MALLOC(sizeof(mm_sm3_ctx)); 
    
    if ( MM_VALID_PT(p) )
    {
        sm3_init_core(p);
    } 
    return p; 
}


/*******************************************************************************
�� �� ��:   sm3_process
��������:   ������Ϣ  
˵    ��:   ����ʽ������Ϣ�Ӵ�ֵ�ĵ� 2 ��
ע    ��:   ����ʽ���㲽��� sm3_init() ��˵�� 
����˵��: 
    h(in/out):  ��� 
    p_data(in): ���Ӵ����� 
    len(in):    ���Ӵ����ݵĳ���
�� �� ֵ:  �ɹ�����MM_OK��ʧ�ܷ���MM_ERROR����������.
�޸���ʷ: 
    1. 2014��10��30��   ���Ŀ� ��Ӱ     ��������
    2. 2015�� 2�� 4��   ���Ŀ� ��Ӱ     �޸ĺ����ӿ�
*******************************************************************************/

mm_i32_t sm3_process(mm_handle h, mm_u8_t* p_data, mm_u32_t len)
{
    mm_i32_t flag = -1;

    if( MM_VALID_PT(h) && MM_VALID_PT(p_data) )
    {
        sm3_process_core((mm_sm3_ctx *)h, p_data, len);
        flag = 1;
    }
    return flag;
}


/*******************************************************************************
�� �� ��:   sm3_unit
��������:   ����Ӵգ����������Ӵ�ֵ 
˵    ��:   1. ����ʽ������Ϣ�Ӵ�ֵ�ĵ� 3 ��
            2. �Ӵ�ֵ����Ϊ 32 �ֽ�
            3. h ��ִ�б�������Ϊ����ָ�룬�������á� 
ע    ��:   ����ʽ���㲽��� mm_sm3_init() ��˵�� 
����˵��: 
    h   (in/out)���  
    md  (out)   �Ӵ�ֵ 
�� �� ֵ:  -
�޸���ʷ: 
    1. 2014��10��30��   ���Ŀ� ��Ӱ     ��������
    2. 2015�� 2�� 4��   ���Ŀ� ��Ӱ     �޸ĺ����ӿ�
*******************************************************************************/

mm_i32_t sm3_unit(mm_handle h, mm_u8_t md[SM3_HASH_BYTE_SZ])
{
    mm_i32_t flag = -1;

    if( MM_VALID_PT(h) && MM_VALID_PT(md) )
    {
        sm3_unit_core((mm_sm3_ctx *)h, md);
        MM_MEMSET(h, 0x00, sizeof(mm_sm3_ctx));
        MM_FREE(h);
        flag = 1;
    }
    return flag;
}
 

/*******************************************************************************
�� �� ��:   sm3_hash
��������:   һ��ʽ������Ϣ�Ӵ�ֵ 
˵    ��:   �Ӵ�ֵ����Ϊ 32 �ֽ�
ע    ��:   һ��ʽ������Ϣ�Ӵ�ֵֻ��ִ�� sm3_hash(***)
����˵��: 
    p_data  (in)    ���Ӵ����� 
    len     (in)    ���Ӵ����ݵĳ���
    md      (out)   �Ӵ�ֵ 
�� �� ֵ:  1 [�ɹ�], <-0 [ʧ��]
�޸���ʷ: 
    1. 2014��10��30��   ���Ŀ� ��Ӱ     ��������
    2. 2015�� 2�� 4��   ���Ŀ� ��Ӱ     �޸ĺ����ӿ�
*******************************************************************************/

mm_i32_t sm3_hash(mm_u8_t *p_data, mm_u32_t len, mm_u8_t md[SM3_HASH_BYTE_SZ])
{
    mm_i32_t flag = -1;
    
    if( MM_VALID_PT(p_data) && MM_VALID_PT(md) )
    {
        sm3_hash_core(p_data, len, md);
        flag = 1;
    }
    return flag;
}

void sm3_hmac_starts(mm_sm3_hmac_ctx *ctx, mm_u8_t *key, mm_i32_t keylen)
{
	void *sm3_handle = NULL;
	mm_i32_t i = 0;
    mm_u8_t sum[SM3_HASH_BYTE_SZ];

    memset(sum, 0, SM3_HASH_BYTE_SZ);

    if (keylen > 64)
	{
        sm3_hash(key, keylen, sum);
        keylen = SM3_HASH_BYTE_SZ;
        //keylen = ( is224 ) ? 28 : 32;
        key = sum;
    }

    memset(ctx->ipad, 0x36, 64);
    memset(ctx->opad, 0x5C, 64);

    for (i = 0; i < keylen; i++) 
	{
        ctx->ipad[i] = (mm_u8_t) (ctx->ipad[i] ^ key[i]);
        ctx->opad[i] = (mm_u8_t) (ctx->opad[i] ^ key[i]);
    }

    sm3_handle = sm3_init();
    sm3_process(sm3_handle, ctx->ipad, 64);
    ctx->handle = sm3_handle;

    memset(sum, 0, sizeof(sum));
	
	return;
}

/*
 * SM3 HMAC process buffer
 */
void sm3_hmac_update(mm_sm3_hmac_ctx *ctx, mm_u8_t *input, mm_i32_t ilen)
{
    sm3_process(ctx->handle, input, ilen);
	
	return;
}

/*
 * SM3 HMAC final digest
 */
void sm3_hmac_finish(mm_sm3_hmac_ctx *ctx, mm_u8_t output[SM3_HASH_BYTE_SZ])
{
	void* sm3_handle = NULL;
	mm_i32_t hlen = 0;
    mm_u8_t tmpbuf[SM3_HASH_BYTE_SZ];

    memset(tmpbuf, 0, SM3_HASH_BYTE_SZ);
    hlen = SM3_HASH_BYTE_SZ;

    sm3_unit(ctx->handle, tmpbuf);
	sm3_handle = sm3_init();
    ctx->handle = sm3_handle;
    sm3_process(ctx->handle, ctx->opad, 64);
    sm3_process(ctx->handle, tmpbuf, hlen);
    sm3_unit(ctx->handle,output);

    memset(tmpbuf, 0, sizeof(tmpbuf));
	
	return;
}

/*
 * output = HMAC-SM#( hmac key, input buffer )
 */
void sm3_hmac(mm_u8_t *key, mm_i32_t keylen,
			mm_u8_t *input, mm_i32_t ilen,
			mm_u8_t output[SM3_HASH_BYTE_SZ]) {
	mm_sm3_hmac_ctx ctx;

    sm3_hmac_starts(&ctx, key, keylen);
    sm3_hmac_update(&ctx, input, ilen);
    sm3_hmac_finish(&ctx, output);

    memset(&ctx, 0, sizeof(mm_sm3_hmac_ctx));
}
 

