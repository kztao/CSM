#include "mm_macro.h" 
#include "kdf.h"
#include "sm3_core.h" 

/* 32bit: u8[0]||u8[1]||u8[2]||u8[3] += 0 || 0 || 0 || 1 */
#define INC_32BIT(u8)\
	for ( j = 3; j >= 0; j-- ){ if( ++u8[j] ) { break; } } 


/*******************************************************************************
�� �� ��:	kdf
��������:	��Կ��������
˵    ��:	���������Щ��������������Щ��������������Щ���������������
			��flag	��	0			��	1			��	2			��
			������	��	KDF			��	H1			��	H2			��
			��len	����Կ�ֽڳ���	��n�ı��س���	��	n�ı��س���	��
			��p_out	��  ������Կ	��	H1���ַ���	��	H2���ַ���	��
			���������ة��������������ة��������������ة���������������
ע    ��:	��������H1��H2�Ĺ��ܣ���ô��Ҫע�����¼��㣺
			(a) ������ֻ�����ַ���Ha = Ha1 || ... || Ha!.hlen/v.��
				��ֻ��ɲ���1������5��ǰ�벿�֣�
			(b)	����5�ĺ�벿�ֺͲ���6�����������װ
				����5:	SM2_BN_hex2bn(sm2_bn_ha, p_out);
				����6:	sm2_bn_sub(n_sub_one, n, one);
						sm2_bn_mod(sm2_bn_tmp, sm2_bn_ha, n_sub_one);
						sm2_bn_add(sm2_bn_res, sm2_bn_tmp, one);
����˵��: 
	p_out			(out)	������� 
	p_data			(in)	��������
	data_byte_len	(in)	�������ݵ��ֽڳ��� 
	len				(in)	����
	flag			(in)	���ܱ�ʶ 0/1/2
�� �� ֵ:  1 (�ɹ�), <=0 (ʧ��)
�޸���ʷ: 
1. 2015�� 9�� 1��	���Ŀ� ��Ӱ		��������
*******************************************************************************/ 
int key_assist(BYTE *p_out, BYTE *p_data, int data_byte_len, int len, int flag)
{
	int j; 
	mm_sm3_ctx x, x_md;
	BYTE ctr[SM3_HASH_BYTE_SZ] = {0x0,0x0,0x0,0x01}; /* ���Ǽ�������SM3��� */
 
	if(		( flag != ASSIST_FUNC_KDF )
		&&	( flag != ASSIST_FUNC_H1  )  
		&&	( flag != ASSIST_FUNC_H2  ) ) /* flag ==0,1,2 */
	{
		return -1;
	} 

	sm3_init_core(&x); 

	if( flag != ASSIST_FUNC_KDF )/* H1��H2���һ���ֽ�0x1��0x2��KDF���� */
	{
		BYTE tag = (BYTE)flag;
		len = 8 * ( ( 5 * len + 31 ) / 32 ); /* H1��H2�ĳ���ӦΪ��ֵ */
		sm3_process_core(&x, &tag, 1);
	}
 
	sm3_process_core(&x, p_data, data_byte_len);  

	while( len > 0 )
	{ 
		MM_MEMCPY(&x_md, &x, sizeof(mm_sm3_ctx));/* x������ǰ����Ӵ���Ϣ */
		sm3_process_core(&x_md, ctr, 4); 

		if( len >= SM3_HASH_BYTE_SZ )
		{
			sm3_unit_core(&x_md, p_out );
		}
		else
		{
			sm3_unit_core(&x_md, ctr );/* ����ת����ctr */
			MM_MEMCPY(p_out, ctr, len); 
		}

		len -= SM3_HASH_BYTE_SZ;
		p_out += SM3_HASH_BYTE_SZ; 
		INC_32BIT(ctr); /* 32bit���Լ� */
	} 

	/* clear data */
	MM_MEMSET(&x,		0x00, sizeof(mm_sm3_ctx));
	MM_MEMSET(&x_md,	0x00, sizeof(mm_sm3_ctx));
	MM_MEMSET(ctr,		0x00, sizeof(ctr)); 
	return 1;
} 