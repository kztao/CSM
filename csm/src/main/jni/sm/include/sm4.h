/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
�ļ�����: sm4.h
�ļ�����: SM4�ӿ�
�� �� ��: ���Ŀ� ��Ӱ
����ʱ��: 2014��10��29��
�޸���ʷ:
1. 2014��10��29��	���Ŀ� ��Ӱ		�����ļ� 
2. 2015�� 6��18��	���Ŀ� ��Ӱ		����OFBģʽ 
3. 2016�� 1��25��	���Ŀ� ��Ӱ		����OFBģʽ�����ӽ����쳣������
*******************************************************************************/
#ifndef _SM4_H_B8B3937FD32C922F
#define _SM4_H_B8B3937FD32C922F


/* ------------------------ ͷ�ļ������� ��ʼ ------------------------------- */
#include "mm_types.h"

/* ======================== ͷ�ļ������� ���� =============================== */


#ifdef __cplusplus
extern "C" {
#endif
	

/* ------------------------ �����궨���� ��ʼ ------------------------------- */

#define SM4_BLOCK_LEN	16		/* SMS4 ���鳤�� 16�ֽ�(128����) */
#define SM4_KEY_LEN		16		/* SMS4 ��Կ���� 16�ֽ�(128����) */
#define SM4_CBC_MAC		0

/* ======================== �������Ͷ����� ���� ============================= */
	
	
/* ------------------------ ����ԭ���ⲿ������ ��ʼ ------------------------- */

/*******************************************************************************
�� �� ��:	sm4_init
��������:	��������ʼ��SM4���
˵    ��:	-
ע    ��:	���ϸ������²���ִ��
	step 1	h = sm4_init( key ) // ����
	step 2	while( mession_complete == FALSE) {//����ӽ�������ʱ
			2.1	sm4_set_iv(h, iv)	//����IV, ��ECB��������IV
			2.2	while( msg_not_end ) {
						sm4_ecb_encrypt(h, ...)
					or	sm4_ecb_decrypt(h, ...)
					or	sm4_cbc_encrypt(h, ...)
					or	sm4_cbc_decrypt(h, ...)
					or	sm4_ofb_encrypt(h, ...)
					or	sm4_ofb_decrypt(h, ...) 
				}//2.2 end
			}//step2 end
	step 3	sm4_unit(h)// ����

����˵��: 
	key		(in)	��Կ 
�� �� ֵ:  �����ΪNULL (�ɹ�), ���ΪNULL (ʧ��)
�޸���ʷ: 
    1. 2014��10��29��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

MM_API mm_handle sm4_init(mm_u8_t key[SM4_KEY_LEN] );


/*******************************************************************************
�� �� ��:	sm4_unit
��������:	����SM4���
˵    ��:	-
ע    ��:	����������SMS4��װ���ݣ����ִ�к� p_sms4 Ϊ����ָ�룬�����á�
����˵��: 
	h		(in)	��� 
�� �� ֵ:	-
�޸���ʷ: 
    1. 2014��10��29��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

MM_API mm_void_t sm4_unit( mm_handle h );


/*******************************************************************************
�� �� ��:	sm4_set_iv
��������:	���ó�ʼ������ (ECB������)
˵    ��:	-
ע    ��:	1. ECBģʽ�����ʼ������
			2. ��ʼ�µļ��ܻ��߽���ʱӦ����IV
����˵��: 
	h		(in)	��� 
�� �� ֵ:	-
�޸���ʷ: 
    1. 2014��10��29��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

MM_API mm_i32_t sm4_set_iv(mm_handle h, mm_u8_t iv[SM4_BLOCK_LEN] );


/*******************************************************************************
�� �� ��:	sm4_ecb_encryt
��������:	ECBģʽ����
˵    ��:	-
ע    ��:	1. �����ĳ��ȱ����Ƿ����С��������, ���㲿�ֵ������������
			2. ǿ�ҽ��� ���������� ����16�ֽڱ߽����
			3. �����ĳ������
����˵��: 
	h		(in/out)��� 
	p_pt	(in)	���� 
	pt_len	(in)	���ĳ��� 
	p_ct	(out)	���� 
�� �� ֵ:	>=1 [�ɹ�]��<=0 [ʧ��]
�޸���ʷ: 
    1. 2014��10��29��	���Ŀ� ��Ӱ		��������
*******************************************************************************/ 

MM_API mm_i32_t	sm4_ecb_encrypt(mm_handle h, mm_u8_t *p_pt, mm_u32_t pt_len, 
								mm_u8_t *p_ct );


/*******************************************************************************
�� �� ��:	sm4_ecb_decrypt
��������:	ECBģʽ����
˵    ��:	-
ע    ��:	1. �����ĳ��ȱ����Ƿ����С��������, ���㲿�ֵ������������
			2. ǿ�ҽ��� ���������� ����16�ֽڱ߽����
			3. �����ĳ������
����˵��: 
	h		(in/out)��� 
	p_ct	(in)	���� 
	ct_len	(in)	���ĳ��� 
	p_pt	(out)	���� 
�� �� ֵ:	>=1 [�ɹ�]��<=0 [ʧ��]
�޸���ʷ: 
    1. 2014��10��29��	���Ŀ� ��Ӱ		��������
*******************************************************************************/ 

MM_API mm_i32_t	sm4_ecb_decrypt(mm_handle h, mm_u8_t *p_ct, mm_u32_t ct_len, 
								mm_u8_t *p_pt);


/*******************************************************************************
�� �� ��:	sm4_cbc_encrypt
��������:	CBCģʽ����
˵    ��:	-
ע    ��:	1. �����ĳ��ȱ����Ƿ����С��������, ���㲿�ֵ������������
			2. ǿ�ҽ��� ���������� ����16�ֽڱ߽����
			3. �����ĳ������
			4. ��ʼ�µ�CBC����ģʽǰһ��Ҫ����IV��sm4_set_iv(***)
����˵��: 
	h		(in/out)��� 
	p_pt	(in)	���� 
	pt_len	(in)	���ĳ��� 
	p_ct	(out)	���� 
�� �� ֵ:	>=1 [�ɹ�]��<=0 [ʧ��]
�޸���ʷ: 
    1. 2014��10��29��	���Ŀ� ��Ӱ		��������
*******************************************************************************/ 

MM_API mm_i32_t	sm4_cbc_encrypt(mm_handle h, mm_u8_t *p_pt, mm_u32_t pt_len, 
								mm_u8_t *p_ct );


/*******************************************************************************
�� �� ��:	sm4_cbc_decrypt
��������:	CBCģʽ����
˵    ��:	-
ע    ��:	1. �����ĳ��ȱ����Ƿ����С��������, ���㲿�ֵ������������
			2. ǿ�ҽ��� ���������� ����16�ֽڱ߽����
			3. �����ĳ������
			4. ��ʼ�µ�CBC����ģʽǰһ��Ҫ����IV��sm4_set_iv(***)
����˵��: 
	h		(in/out)��� 
	p_ct	(in)	���� 
	ct_len	(in)	���ĳ��� 
	p_pt	(out)	���� 
�� �� ֵ:	>=1 [�ɹ�]��<=0 [ʧ��]
�޸���ʷ: 
    1. 2014��10��29��	���Ŀ� ��Ӱ		��������
*******************************************************************************/ 

MM_API mm_i32_t	sm4_cbc_decrypt(mm_handle h, mm_u8_t *p_ct, mm_u32_t ct_len, 
								mm_u8_t *p_pt );


/*******************************************************************************
�� �� ��:	sm4_ofb_encrypt
��������:	OFBģʽ����
˵    ��:	-
ע    ��:	1. �������һ�ε��ñ�����ʱ�������ĳ��Ȳ��Ƿ����С����������
			   ������������±��뱣֤���ĳ����Ƿ����С����������
			2. ǿ�ҽ��� ���������� ����16�ֽڱ߽����
			3. �����ĳ������
����˵��: 
	h		(in/out)��� 
	p_pt	(in)	���� 
	pt_len	(in)	���ĳ��� 
	p_ct	(out)	���� 
�� �� ֵ:	>=1 [�ɹ�]��<=0 [ʧ��]
�޸���ʷ: 
    1. 2015�� 6��18��	���Ŀ� ��Ӱ		��������
	2. 2016�� 1��25��	���Ŀ� ��Ӱ		����OFBģʽ�����ӽ����쳣������
			not_aligned_tm ����ش������ô������� 
*******************************************************************************/ 

MM_API mm_i32_t sm4_ofb_encrypt(mm_handle h, mm_u8_t *p_pt, mm_u32_t pt_len, 
								mm_u8_t *p_ct );


/*******************************************************************************
�� �� ��:	sm4_ofb_decrypt
��������:	OFBģʽ����
˵    ��:	-
ע    ��:	1. �������һ�ε��ñ�����ʱ�������ĳ��Ȳ��Ƿ����С����������
			   ������������±��뱣֤���ĳ����Ƿ����С����������
			2. ǿ�ҽ��� ���������� ����16�ֽڱ߽����
			3. �����ĳ������
����˵��: 
	h		(in/out)��� 
	p_ct	(in)	���� 
	ct_len	(in)	���ĳ��� 
	p_pt	(out)	���� 
�� �� ֵ:	>=1 [�ɹ�]��<=0 [ʧ��]
�޸���ʷ: 
    1. 2015�� 6��18��	���Ŀ� ��Ӱ		��������
    2. 2016�� 1��25��	���Ŀ� ��Ӱ		����OFBģʽ�����ӽ����쳣������
				not_aligned_tm ����ش������ô������� 
*******************************************************************************/ 

MM_API mm_i32_t sm4_ofb_decrypt(mm_handle h, mm_u8_t *p_ct, mm_u32_t ct_len, 
								mm_u8_t *p_pt );


// ʹ��C-MACģʽ����ժҪ
//ecb mac
MM_API mm_i32_t sm4_cmac(mm_handle h_ctx,
			mm_u8_t *inData, mm_i32_t inDatalen,
			mm_u8_t outData[SM4_BLOCK_LEN]);

MM_API mm_i32_t sm4_cmac_process(mm_handle sm4_handle, 
			mm_u8_t *pin, mm_i32_t ilen,
			mm_u8_t pInOut[SM4_BLOCK_LEN]);
//-------------------------------------------------------------------


/* ======================== ����ԭ���ⲿ������ ���� ========================= */



/* ------------------------ �����ⲿ���������� ��ʼ ------------------------- */

/* ======================== �����ⲿ���������� ���� ========================= */

#ifdef __cplusplus
}
#endif

#endif/*#ifndef _SM4_H_... */