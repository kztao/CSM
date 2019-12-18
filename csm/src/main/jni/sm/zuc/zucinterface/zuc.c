/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
�ļ�����: zuc.c
�ļ�����: zuc�Լ�����㷨��ʵ�ִ���
�� �� ��: ���Ŀ� ��Ӱ
����ʱ��: 2015��1��19��
�޸���ʷ:
1. 2015��1��19��	���Ŀ� ��Ӱ		�����ļ� 
*******************************************************************************/
#include "mm_memory.h"
#include "mm_macro.h"
#include "zuc_core.h"
#include "eea3.h"
#include "eia3.h" 
#include "zuc.h"

/*..............................................................................

�� 1 �� ZUC �㷨�������֮���������㷨

	ZUC �㷨��������������
	@ zuc_init		������������ʼ��
	@ zuc_enc_dec	�������ܻ����
	@ zuc_unit		��������

..............................................................................*/

mm_handle zuc_init( mm_u8_t key[ZUC_KEY_LEN], mm_u8_t iv[ZUC_IV_LEN])
{
	zuc_ctx *p = NULL;
	if (	MM_VALID_PT( key ) 
		&&	MM_VALID_PT( iv )   )
	{
		p = MM_MALLOC(sizeof(zuc_ctx));
		if(MM_VALID_PT(p))
		{ 
			zuc_init_core(p, key, iv);
		}
	}  

	return p;
}


mm_void_t zuc_unit( mm_handle h )
{
	if ( MM_VALID_PT( h )  )
	{
		zuc_unit_core((zuc_ctx*)h);
		MM_FREE(h);
	}
}
 

mm_i32_t zuc_enc_dec(mm_handle h, mm_u8_t *p_in, mm_u32_t len, mm_u8_t *p_out)
{
	if (	MM_VALID_PT( h ) 
		&&	MM_VALID_PT( p_in ) 
		&&	MM_VALID_PT( p_out )    )
	{
		return zuc_enc_dec_core((zuc_ctx *)h, p_in, len, p_out );
	}
	return -1;
}


/*..............................................................................

�� 2 �� EEA3�㷨�����������֮�㷨�Ļ������㷨

	EEA3 �㷨�����ĸ�������
	@ eea3			���� һ��ʽִ��EEA3���ܻ����
	@ eea3_init		���� ����ʽִ��EEA3�ĵ�һ������
	@ eea3_process	���� ����ʽִ��EEA3�ĵڶ������ܻ����
	@ eea3_unit		���� ����ʽִ��EEA3�ĵ���������
..............................................................................*/
 

MM_API mm_i32_t eea3(mm_u8_t ck[EEA3_CK_LEN], mm_u32_t count, mm_u32_t bearer,  
					 mm_u32_t direction, mm_u8_t* p_in, mm_u32_t bit_len, 
					 mm_u8_t* p_out)
{
	if (	MM_VALID_PT( ck ) 
		&&	MM_VALID_PT( p_in ) 
		&&	MM_VALID_PT( p_out )    )
	{ 
		zuc_ctx eea;
			
		eea3_init_core( &eea, ck, count, bearer, direction);
		eea3_process_core( &eea, p_in, bit_len, p_out);
		eea3_unit_core(&eea);
			
		return 1; 
	}
	return -1; 
}

 
mm_handle eea3_init( mm_u8_t ck[EEA3_CK_LEN], mm_u32_t count, 
						   mm_u32_t bearer, mm_u32_t direction)
{
	zuc_ctx *p = NULL;
	if (	MM_VALID_PT( ck )  )
	{
		p = MM_MALLOC(sizeof(zuc_ctx));
		if(MM_VALID_PT(p))
		{ 
			eea3_init_core(p, ck, count, bearer, direction);
		}
	}   

	return p; 
}


mm_i32_t eea3_process(mm_handle h, mm_u8_t *p_in, mm_u32_t bit_len,
					  mm_u8_t *p_out )
{
	if (	MM_VALID_PT( h ) 
		&&	MM_VALID_PT( p_in ) 
		&&	MM_VALID_PT( p_out )    )
	{
		return eea3_process_core( (zuc_ctx*)h, p_in, bit_len, p_out);
	}
	return -1; 
}

mm_void_t eea3_unit( mm_handle h )
{
	if ( MM_VALID_PT( h )  )
	{
		eea3_unit_core((zuc_ctx*)h);
		MM_FREE(h);
	}
}
 
/*..............................................................................

�� 3 �� EIA3�㷨�����������֮�㷨���������㷨

	EEA3 �㷨�����ĸ�������
	@ eia3			���� һ��ʽִ��EIA3���ܻ����
	@ eia3_init		���� ����ʽִ��EIA3�ĵ�һ������
	@ eia3_process	���� ����ʽִ��EIA3�ĵڶ���������Ϣ
	@ eia3_unit		���� ����ʽִ��EIA3�ĵ��������� 
..............................................................................*/

mm_i32_t eia3( mm_u8_t ik[EIA3_IK_LEN], mm_u32_t count, 
			  mm_u32_t bearer, mm_u32_t direction, 
			  mm_u8_t* p_msg, mm_u32_t bit_len, mm_u8_t mac[EIA3_MAC_LEN])
{
	if (	MM_VALID_PT( ik ) 
		&&	MM_VALID_PT( p_msg ) 
		&&	MM_VALID_PT( mac )    )
	{ 
		zuc_ctx ctx;
			
		eia3_init_core( &ctx, ik, count, bearer, direction);
		eia3_process_core( &ctx, p_msg, bit_len);
		eia3_unit_core(&ctx, mac);
			
		return 1; 
	}
	return -1; 
}
   
MM_API mm_handle eia3_init( mm_u8_t ik[EIA3_IK_LEN], mm_u32_t count, 
						   mm_u32_t bearer, mm_u32_t direction )
{
	zuc_ctx *p = NULL;
	if (	MM_VALID_PT( ik )  )
	{
		p = MM_MALLOC(sizeof(zuc_ctx));
		if(MM_VALID_PT(p))
		{ 
			eia3_init_core2(p, ik, count, bearer, direction);
		}
	}   
	
	return p; 
}

 
mm_i32_t eia3_process( mm_handle h, mm_u8_t* p_msg, mm_u32_t bit_len )
{
	if (	MM_VALID_PT( h ) 
		&&	MM_VALID_PT( p_msg )   )
	{
		return eia3_process_core2( (zuc_ctx*)h, p_msg, bit_len); 
	}
	return -1; 
}


/*******************************************************************************
�� �� ��:	eia3_unit
��������:	����ʼ�� EIA3
˵    ��:	����ʽִ��EIA3�ĵ�����
ע    ��:	����������ʽִ�в���� eia3_init ��˵��
			���������پ���ķ�װ���ݣ�ִ�к���Ϊ����ָ�룬������ΪNULL��
����˵��: 
	h		(in)	��� 
	mac		(out)	MACֵ 
�� �� ֵ:	>=1 [�ɹ�]��<=0 [ʧ��]
�޸���ʷ: 
    1. 2015��1��19��	���Ŀ� ��Ӱ		��������
*******************************************************************************/
 
mm_void_t eia3_unit(mm_handle h , mm_u8_t mac[EIA3_MAC_LEN])
{
	if (	MM_VALID_PT( h ) 
		&&	MM_VALID_PT( mac ) )
	{
		eia3_unit_core2((zuc_ctx*)h, mac);
		MM_FREE(h);
	}
}
 
