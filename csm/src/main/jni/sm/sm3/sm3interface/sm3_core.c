/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
�ļ�����: sm3.c
�ļ�����: SM3�Ӵ��㷨ʵ��
�� �� ��: ���Ŀ� ��Ӱ
����ʱ��: 2014��10��30��
�޸���ʷ:
1. 2014��10��30��	���Ŀ� ��Ӱ		�����ļ� 
*******************************************************************************/

/* ------------------------ ͷ�ļ������� ��ʼ ------------------------------- */


#include "mm_macro.h"
#include "sm3_core.h"
#include "sm3_locl.h"
  

/* ======================== ͷ�ļ������� ���� =============================== */


/* ------------------------ �����궨���� ��ʼ ------------------------------- */
 

/* ======================== �����궨���� ���� =============================== */


/* ------------------------ �������Ͷ����� ��ʼ ----------------------------- */
 
static mm_u32_t cst_t[64] = {
0x79cc4519,0xf3988a32,0xe7311465,0xce6228cb,
0x9cc45197,0x3988a32f,0x7311465e,0xe6228cbc,
0xcc451979,0x988a32f3,0x311465e7,0x6228cbce,
0xc451979c,0x88a32f39,0x11465e73,0x228cbce6,
0x9d8a7a87,0x3b14f50f,0x7629ea1e,0xec53d43c,
0xd8a7a879,0xb14f50f3,0x629ea1e7,0xc53d43ce,
0x8a7a879d,0x14f50f3b,0x29ea1e76,0x53d43cec,
0xa7a879d8,0x4f50f3b1,0x9ea1e762,0x3d43cec5,
0x7a879d8a,0xf50f3b14,0xea1e7629,0xd43cec53,
0xa879d8a7,0x50f3b14f,0xa1e7629e,0x43cec53d,
0x879d8a7a,0x0f3b14f5,0x1e7629ea,0x3cec53d4,
0x79d8a7a8,0xf3b14f50,0xe7629ea1,0xcec53d43,
0x9d8a7a87,0x3b14f50f,0x7629ea1e,0xec53d43c,
0xd8a7a879,0xb14f50f3,0x629ea1e7,0xc53d43ce,
0x8a7a879d,0x14f50f3b,0x29ea1e76,0x53d43cec,
0xa7a879d8,0x4f50f3b1,0x9ea1e762,0x3d43cec5
};

/* ======================== �������Ͷ����� ���� ============================= */
 


/*******************************************************************************
�� �� ��:	sm3_init_core
��������:	��ʼ��SM3 
˵    ��:	����ʽ������Ϣ�Ӵ�ֵ�ĵ� 1 ��
ע    ��:	1. ���������ӿڲ������
			2. ����ʽ������Ϣ�Ӵ�ֵ�����ϸ������²���ִ��
			�� 1 �� sm3_init_core(***);			// ��ʼ��
			�� 2 �� while(msg_not_end){
						sm3_process_core(***);	// ��Ϣ�ɷֶ�����
					}
			�� 3 �� sm3_unit_core(***);			// ����Ӵ�ֵ
����˵��: 
	p(in/out):  SM3 ��װ����  
�� �� ֵ:  -
�޸���ʷ: 
    1. 2014��10��30��	���Ŀ� ��Ӱ		��������
    2. 2015�� 2�� 4��	���Ŀ� ��Ӱ		�޸ĺ����ӿ�
*******************************************************************************/
mm_void_t sm3_init_core(mm_sm3_ctx *p)
{  
	p->total_len_l = p->total_len_h = p->res_len = 0;
	p->s[0] = 0x7380166f; 
	p->s[1] = 0x4914b2b9; 
	p->s[2] = 0x172442d7; 
	p->s[3] = 0xda8a0600; 
	p->s[4] = 0xa96f30bc; 
	p->s[5] = 0x163138aa; 
	p->s[6] = 0xe38dee4d; 
	p->s[7] = 0xb0fb0e4e; 
}    


/*******************************************************************************
�� �� ��:	sm3_block_core
��������:	����������
˵    ��:	ÿ�������С512���أ�����num������
ע    ��:	1. ���������ӿڲ������
			2. ����ʽ������Ϣ�Ӵ�ֵ�Ĳ���μ� sm3_init_core ��˵�� 
����˵��: 
	p		(in/out)SM3��װ����  
	p_data	(in)	��������
	num		(in)	�������
�� �� ֵ:  -
�޸���ʷ: 
    1. 2014��10��30��	���Ŀ� ��Ӱ		��������
    2. 2015�� 2�� 4��	���Ŀ� ��Ӱ		�޸ĺ����ӿ�
*******************************************************************************/

mm_void_t sm3_block_core (mm_sm3_ctx *p, mm_u8_t *p_data, mm_i32_t num)
{ 
	register mm_u32_t	a,b,c,d,e,f,g,h,s1,s2;
	mm_u32_t	w[68];
	mm_i32_t	i;  

	while ( num-- > 0 ) 
	{ 
#ifdef CALC_W_IN_ROUND_LOOP
		/* ֻ����ǰ4��W����W[0] - W[3] */
		GET_W_0_15(w, p_data, 0); 
		GET_W_0_15(w, p_data, 1); 
		GET_W_0_15(w, p_data, 2); 
		GET_W_0_15(w, p_data, 3); 

		a = p->s[0]; b = p->s[1]; c = p->s[2]; d = p->s[3];
		e = p->s[4]; f = p->s[5]; g = p->s[6]; h = p->s[7]; 
 
		/*  0 - 11 �� */
		FOUR_ROUND_00_11( 0,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_00_11( 4,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_00_11( 8,a,b,c,d,e,f,g,h,w);
	
		/* 12 - 15 �� */
		FOUR_ROUND_12_15(12,a,b,c,d,e,f,g,h,w);

		/* 16 - 63 �� */
#ifdef SM3_UNROLL
		FOUR_ROUND_16_63(16,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(20,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(24,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(28,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(32,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(36,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(40,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(44,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(48,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(52,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(56,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(60,a,b,c,d,e,f,g,h,w);  
#else	/* else #ifdef SM3_UNROLL */ 
		/* 16 - 63 �� */
		i = 16;
		while (i < 64 )
		{
			FOUR_ROUND_16_63( i,a,b,c,d,e,f,g,h,w);
			i += 4;
		} 
#endif  /* end #ifdef SM3_UNROLL */ 

#else	/* else #ifdef CALC_W_IN_ROUND_LOOP */

		i = 0;
		while ( i < 16 )
		{
			GET_W_0_15(w, p_data, i); 
			i++;
		} 
		while ( i < 68 )
		{
			GET_W_16_67(w, i);
			i++;
		} 

		a = p->s[0]; b = p->s[1]; c = p->s[2]; d = p->s[3];
		e = p->s[4]; f = p->s[5]; g = p->s[6]; h = p->s[7]; 

#ifdef SM3_UNROLL
		/* round  0 - 15 */
		FOUR_ROUND_00_15( 0,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_00_15( 4,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_00_15( 8,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_00_15(12,a,b,c,d,e,f,g,h,w);

		/* round 16 - 63 */
		FOUR_ROUND_16_63(16,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(20,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(24,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(28,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(32,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(36,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(40,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(44,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(48,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(52,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(56,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(60,a,b,c,d,e,f,g,h,w);  
#else /* else #ifdef SM3_UNROLL */ 
		i = 0;
		while ( i < 16 )
		{
			FOUR_ROUND_00_15( i,a,b,c,d,e,f,g,h,w);
			i += 4;
		}
		while (i < 64 )
		{
			FOUR_ROUND_16_63( i,a,b,c,d,e,f,g,h,w);
			i += 4;
		} 
#endif  /* end #ifdef SM3_UNROLL */ 
#endif	/* end #ifdef CALC_W_IN_ROUND_LOOP */	
		p->s[0] ^= a; p->s[1] ^= b; p->s[2] ^= c; p->s[3] ^= d;
		p->s[4] ^= e; p->s[5] ^= f; p->s[6] ^= g; p->s[7] ^= h;
		
		p_data += SM3_BLOCK_SZ;
	} 
}
 

/*******************************************************************************
�� �� ��:	sm3_process_core
��������:	������ӵ���Ϣ 
˵    ��:	����ʽ������Ϣ�Ӵ�ֵ�ĵ� 2 ��
ע    ��:	1. ���������ӿڲ������
			2. ����ʽ������Ϣ�Ӵ�ֵ�Ĳ���μ� sm3_init_core ��˵�� 
����˵��: 
	p		(in/out)SM3��װ����  
	p_data	(in)	��Ϣ����  
	len		(in)	��Ϣ���ݳ���  
�� �� ֵ:  -
�޸���ʷ: 
    1. 2014��10��30��	���Ŀ� ��Ӱ		��������
    2. 2015�� 2�� 4��	���Ŀ� ��Ӱ		�޸ĺ����ӿ�
*******************************************************************************/
mm_void_t sm3_process_core(mm_sm3_ctx *p, mm_u8_t *p_data, mm_u32_t len)
{ 
	mm_u32_t pre_low;
//	mm_u8_t *p_buf = p->res_data; 
	
	if ( !len )/* len == 0 */
	{
		return;
	}

	/* ��¼�����ܳ��� */
	pre_low = p->total_len_l;
	p->total_len_l += (len << 3);
	if ( p->total_len_l < pre_low )		
	{
		p->total_len_h++;  
	}
	
	/*ֻ��res-len����ʱ�Ż���ֺ�res_bufһ������ݵ���� */
	if ( p->res_len )
	{ 
		mm_u32_t b_make_one_block = (len + p->res_len >= SM3_BLOCK_SZ) ;
		mm_u32_t copy_len = b_make_one_block ? SM3_BLOCK_SZ - p->res_len : len;
		MM_MEMCPY( p->res_data + p->res_len, p_data, copy_len);

		if( b_make_one_block )
		{
			sm3_block_core (p, p->res_data, 1);
		}
		p->res_len = (p->res_len + copy_len) % SM3_BLOCK_SZ;
		len    -= copy_len;
		p_data += copy_len; 
	}
	
	/* ���鴦���������� */
	if ( len >= SM3_BLOCK_SZ )
	{
		mm_i32_t loop_num = len / SM3_BLOCK_SZ;
		sm3_block_core (p, p_data, loop_num ),
		p_data += loop_num * SM3_BLOCK_SZ,
		len  %= SM3_BLOCK_SZ;
	}
	
	/* ����һ������ݱ����ڻ����� */
	if ( len )
	{
		MM_MEMCPY (p->res_data, p_data, len);
		p->res_len = len;
	} 
} 


/*******************************************************************************
�� �� ��:	sm3_unit_core
��������:	�����Ӵգ������Ӵ�ֵ 
˵    ��:	����ʽ������Ϣ�Ӵ�ֵ�ĵ� 3 ��
ע    ��:	1. ���������ӿڲ������
			2. ����ʽ������Ϣ�Ӵ�ֵ�Ĳ���μ� sm3_init_core ��˵�� 
����˵��: 
	p		(in/out)SM3��װ����  
	md		(out)	�Ӵ�ֵ  
�� �� ֵ:  -
�޸���ʷ: 
    1. 2014��10��30��	���Ŀ� ��Ӱ		��������
    2. 2015�� 2�� 4��	���Ŀ� ��Ӱ		�޸ĺ����ӿ�
*******************************************************************************/
mm_void_t sm3_unit_core(mm_sm3_ctx *p,mm_u8_t md[SM3_HASH_BYTE_SZ] )
{
	mm_u8_t *p_buf = p->res_data;
	mm_u32_t i, n = p->res_len;
	
	p_buf[n++]=0x80;	/* There always is a room for one */

	if ( n > SM3_BLOCK_SZ - 8 )
	{
		MM_MEMSET(p_buf + n, 0x00, SM3_BLOCK_SZ - n );
		n = 0;
		sm3_block_core(p, p_buf, 1);
	}
	
	MM_MEMSET (p_buf + n, 0x00, SM3_BLOCK_SZ - 8 - n ); 
	MM_STORE_U32H(p->total_len_h, p_buf + SM3_BLOCK_SZ - 8 ); 
	MM_STORE_U32H(p->total_len_l, p_buf + SM3_BLOCK_SZ - 4 ); 
	sm3_block_core (p, p_buf, 1); 

	for (i = 0; i < 8; i++)
	{
		MM_STORE_U32H(p->s[i], md + (i<<2));
	} 
	MM_MEMSET(p, 0x00, sizeof(mm_sm3_ctx));
} 


/*******************************************************************************
�� �� ��:	sm3_hash_core
��������:	һ��ʽ������Ϣ�Ӵ�ֵ 
˵    ��:	�Ӵ�ֵ����Ϊ 32 �ֽ�
ע    ��:	һ��ʽ������Ϣ�Ӵ�ֵֻ��ִ�� sm3_hash(***)
����˵��: 
	p_data	(in):	���Ӵ����� 
	len		(in):	���Ӵ����ݳ���
	md		(out):	�Ӵ�ֵ 
�� �� ֵ:  -
�޸���ʷ: 
    1. 2014��10��30��	���Ŀ� ��Ӱ		��������
    2. 2015�� 2�� 4��	���Ŀ� ��Ӱ		�޸ĺ����ӿ�
*******************************************************************************/
mm_void_t sm3_hash_core(mm_u8_t *p_data, u32_t len, mm_u8_t md[SM3_HASH_BYTE_SZ])
{
	mm_sm3_ctx ctx;  
	sm3_init_core(&ctx); 
	sm3_process_core(&ctx ,p_data, len);
	sm3_unit_core(&ctx, md); 
}
