/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
�ļ����: mm_sm3.c
�ļ�����: SM3�Ӵ��㷨ʵ��
�� �� ��: ���Ŀ� ��Ӱ
����ʱ��: 2014��8��22��
�޸���ʷ:
1. 2014��8��22��	���Ŀ� ��Ӱ		�����ļ� 
*******************************************************************************/

/* ------------------------ ͷ�ļ����� ��ʼ ------------------------------- */
#ifdef MM_NEED_PRINT_DATA
#include <stdio.h>
#endif
#include "mm_basic_fun.h" 
#include "mm_macro.h"

#ifdef USE_STD_LIB
#include "timers.h"
#endif

/* ======================== ͷ�ļ����� ���� =============================== */
 

/*******************************************************************************
�� �� ��:	str_len
��������:	��ȡ�ַ���
˵    ��:	-
ע    ��:	-
����˵��: 
	p_str(in):	�ַ�ָ�� 
�� �� ֵ:  �ַ���
�޸���ʷ: 
    1. 2014��10��24��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

u32_t str_len ( const char * p_str )
{
	const char *eos = p_str;
	
	while( *eos++ ) ;

	return( (u32_t)(eos - p_str - 1) );
}


/*******************************************************************************
�� �� ��:	data_is_zero
��������:	����Ƿ�ȫ�� 
˵    ��:	-
ע    ��:	-
����˵��: 
	p(in):		���ָ��
    len(in):	����ֽڳ��� 
�� �� ֵ:  1 (��ʾ���ȫ��)�� 0(��ʾ��ݲ���ȫ��)
�޸���ʷ: 
    1. 2014��10��24��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

int data_is_zero(void* p_data, int len)
{
	int i;
	char *p = (char*)p_data;
	if(p == NULL || len <= 0 )
	{
		return 0;
	}

	for (  i = 0;i<len;i++)
	{
		if ( p[i] != 0 )
			return 0;
	}
	return 1; 
}


/*******************************************************************************
�� �� ��:	data_xor
��������:	������ 
˵    ��:	p_des[j] = p_src1[j] xor p_src2[j], j=0,1,2,...,len-1
ע    ��:	-
����˵��: 
	p_des(out):	Ŀ�����ָ��
    p_src1(in):	Դ���ָ��1
	p_src2(in):	Դ���ָ��2
�� �� ֵ:  1 (�ɹ�)�� <=0(ʧ��)
�޸���ʷ: 
    1. 2014��10��24��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

int data_xor(void* p_des, void* p_src1, void* p_src2, int len)
{ 
	int i;
	char *p_ch_des  = (char*)p_des;
	char *p_ch_src1 = (char*)p_src1;
	char *p_ch_src2 = (char*)p_src2; 

	for (  i = 0;i<len;i++)
	{
		*p_ch_des++= *p_ch_src1++ ^ *p_ch_src2++; 
	}
	return 1;  
}


/*******************************************************************************
�� �� ��:	data_and
��������:	��������� 
˵    ��:	p_des[j] = p_src1[j] and p_src2[j], j=0,1,2,...,len-1
ע    ��:	-
����˵��: 
	p_des(out):	Ŀ�����ָ��
    p_src1(in):	Դ���ָ��1
	p_src2(in):	Դ���ָ��2
�� �� ֵ:  1 (�ɹ�)�� <=0(ʧ��)
�޸���ʷ: 
    1. 2014��10��24��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

int data_and(void* p_des, void* p_src1, void* p_src2, int len)
{ 
	int i;
	char *p_ch_des  = ((char*)p_des);
	char *p_ch_src1 = (char*)p_src1;
	char *p_ch_src2 = (char*)p_src2;
		
	for (  i = 0;i<len;i++)
	{
		*p_ch_des++= *p_ch_src1++ & *p_ch_src2++; 
	}  
	return 1;  
}
 

/*******************************************************************************
�� �� ��:	print_data_dbg
��������:	��ȡʱ�䣨��Ҫ���������������ӣ�
˵    ��:	�� c����� _CRTIMP time_t __cdecl time(time_t *)�ķ�װ
ע    ��:	-
����˵��:	�޲��� 
�� �� ֵ:	ʱ��
�޸���ʷ: 
    1. 2014��10��24��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

mm_u32_t get_time()
{
#ifdef USE_STD_LIB
//#include "timers.h"
	TIMER_VARS;
	TIMER_START();
	return (mm_u32_t)(TICKS());
#else
	return 0;
#endif

}


/*******************************************************************************
�� �� ��:	print_data_dbg
��������:	��ӡ��� 
˵    ��:	ֻ���ڶ��� MM_NEED_PRINT_DATA ʱ����Ч
ע    ��:	-
����˵��: 
	p_data(in):	���ӡ���
    len(in):	����ֽڳ���
	p_msg(in):	��ӡʱ���ӵ�ע����Ϣ
	inv_prt(in):�Ƿ������ӡ���
�� �� ֵ:  ��
�޸���ʷ: 
    1. 2014��10��24��	���Ŀ� ��Ӱ		��������
*******************************************************************************/

void print_data_dbg(void * p_data, int len, char *msg, int inv_prt)
{ 
#ifdef MM_NEED_PRINT_DATA

	int i;
	BYTE * p = (BYTE *)p_data, data;
	if(msg != NULL )
	{
		printf("\n\n��%s��", msg);
	}
	
	for(  i = 0; i < len; i++)    
	{
		if( i % 4 == 0 )
		{
			printf(" ");
		}
		if( i % 32 == 0 )
		{
			printf("\n");
		}
		
		data = inv_prt ? p[len-1-i] : p[i]; 
		printf("%02x",data); 
	}  
	printf("\n");
#endif
}


#ifndef USE_STD_LID 
void* sm2_memset( void *dst, int val, unsigned int count )
{
	void *start = dst;
	while (count--) 
	{
		*(char *)dst = (char)val;
		dst = (char *)dst + 1;
	} 
	return(start);
}


int sm2_memcmp ( const void * buf1, const void * buf2, unsigned int count )
{
	if (!count)
		return(0); 

	while ( --count && *(char *)buf1 == *(char *)buf2 ) 
	{
		buf1 = (char *)buf1 + 1;
		buf2 = (char *)buf2 + 1;
	} 
	return( *((unsigned char *)buf1) - *((unsigned char *)buf2) );
}


void * sm2_memcpy ( void * dst, const void * src, unsigned int count )
{
	void * ret = dst; 
	while (count--) 
	{
		*(char *)dst = *(char *)src;
		dst = (char *)dst + 1;
		src = (char *)src + 1;
	} 
	return(ret);
}
#endif
