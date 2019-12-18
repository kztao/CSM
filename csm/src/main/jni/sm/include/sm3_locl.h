/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
�ļ�����: sm3.c
�ļ�����: SM3�Ӵ��㷨��
�� �� ��: ���Ŀ� ��Ӱ
����ʱ��: 2014��10��30��
�޸���ʷ:
1. 2014��10��30��	���Ŀ� ��Ӱ		�����ļ� 
*******************************************************************************/
#ifndef _SM3_LOCL_H_AD259C6F012EE32A 
#define _SM3_LOCL_H_AD259C6F012EE32A
/* ------------------------ ͷ�ļ������� ��ʼ ------------------------------- */
 
//#include "mm_macro.h" 
  

/* ======================== ͷ�ļ������� ���� =============================== */


/* ------------------------ �����궨���� ��ʼ ------------------------------- */

/* -------------- �������� ��ʼ --------------------- */

/* ����չ��W[*]�ļ���ŵ�64�ֵ��ֺ������棬���Լ������ݵĴ洢�ͼ��� */
//#define CALC_W_IN_ROUND_LOOP

/* ����⿪��� */ 
#define SM3_UNROLL				

/* ============== �������� ���� ===================== */

/*ѭ������nλ
	20141216 luoying
	�� n >= 32 ʱ����ͬCPU�Ľ��Ϳ��ܲ�һ����
	intel��ȡ n mod 32 ��Ϊ��λ��
	�е���õ���λ���Ϊ 0 ֵ
*/ 

/*
	ROTL(x,n) �� x<<<n
	SM3_LOAD_U32 �����ݼ���
*/
#if ( defined(_MSC_VER) )
#include <stdlib.h>
#define	ROTL(x,n)	(_lrotl(x,n)) 
#define SWAP(x)		(_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
#define SM3_LOAD_U32(u32, p8)  ( (u32) = SWAP(*((mm_u32_t *)(p8))) )  
#else 
#define ROTL(x,n)	( ((x) << ((n)&0x1F)) | ( (x) >> (32-((n)&0x1F)) ) ) 
#define SM3_LOAD_U32(u32, p8) MM_LOAD_U32H(u32, p8)
#endif 

/*P0����*/
#define P0(x) ( ROTL(x,  9) ^ ROTL(x, 17) ^ (x) ) 

/*P1����*/
#define P1(x) ( ROTL(x, 15) ^ ROTL(x, 23) ^ (x) )  

/*FF����*/
#define F_0_15( x, y, z)	((x)^(y)^(z)) 
#define F_16_63(x, y, z)	(((x) & (y)) | ((x) & (z)) | ((y) & (z))) 

/*GG����*/
#define G_0_15(x, y, z)		F_0_15( x, y, z)
#define G_16_63(x, y, z)	(((x) & (y)) | ((~x) & (z))) 


/*��Ϣ��չ����*/
#define GET_W_0_15( w, data, i) SM3_LOAD_U32((w)[i], data + ((i)<<2))
#define GET_W_16_67(w, i) \
{\
	s1 = w[i-16] ^ w[i-9] ^ ROTL( w[i-3],15 );\
	w[i] = P1( s1 ) ^ ROTL(w[i-13],7) ^ w[i-6];\
}
 
#if (defined (CALC_W_IN_ROUND_LOOP))
/*ѹ��������һ��*/
#define	ROUND_00_11(i,a,b,c,d,e,f,g,h, w)\
{\
	GET_W_0_15(w, p_data, i+4);\
	s2  = ROTL(a,12);\
	s1  = s2 + e + cst_t[i];\
	s2 ^= s1 = ROTL(s1, 7);\
	d  += F_0_15(a, b, c) + s2 + ( w[i] ^ w[i+4] );\
	h  += G_0_15(e, f, g) + s1 + w[i];\
	b   = ROTL(b, 9);\
	f   = ROTL(f, 19);\
	h   = P0(h);\
}  
/* ���� GET_W_16_67()����ʹ����S1������Ӧ�ȼ��㣬����S1���ݽ����ƻ� */
#define	ROUND_12_15(i,a,b,c,d,e,f,g,h, w)\
{\
	GET_W_16_67(w, i+4);\
	s2  = ROTL(a,12);\
	s1  = s2 + e + cst_t[i];\
	s2 ^= s1 = ROTL(s1, 7);\
	d  += F_0_15(a, b, c) + s2 + ( w[i] ^ w[i+4] );\
	h  += G_0_15(e, f, g) + s1 + w[i];\
	b   = ROTL(b, 9);\
	f   = ROTL(f, 19);\
	h   = P0(h);\
} 
#define	ROUND_16_63(i,a,b,c,d,e,f,g,h, w)\
{\
	GET_W_16_67(w, i+4);\
	s2  = ROTL(a,12);\
	s1  = s2 + e + cst_t[i];\
	s2 ^= s1 = ROTL(s1, 7);\
	d  += F_16_63(a, b, c) + s2 + ( w[i] ^ w[i+4] );\
	h  += G_16_63(e, f, g) + s1 + w[i];\
	b   = ROTL(b, 9);\
	f   = ROTL(f, 19);\
	h   = P0(h);\
}  
 
#define FOUR_ROUND_00_11(i, a, b, c, d, e, f, g, h, w)\
{\
	ROUND_00_11( i  ,a,b,c,d,e,f,g,h,w);\
	ROUND_00_11( i+1,d,a,b,c,h,e,f,g,w);\
	ROUND_00_11( i+2,c,d,a,b,g,h,e,f,w);\
	ROUND_00_11( i+3,b,c,d,a,f,g,h,e,w);\
}
#define FOUR_ROUND_12_15(i, a, b, c, d, e, f, g, h, w)\
{\
	ROUND_12_15( i  ,a,b,c,d,e,f,g,h,w);\
	ROUND_12_15( i+1,d,a,b,c,h,e,f,g,w);\
	ROUND_12_15( i+2,c,d,a,b,g,h,e,f,w);\
	ROUND_12_15( i+3,b,c,d,a,f,g,h,e,w);\
}
#define FOUR_ROUND_16_63(i, a, b, c, d, e, f, g, h, w)\
{\
	ROUND_16_63( i  ,a,b,c,d,e,f,g,h,w);\
	ROUND_16_63( i+1,d,a,b,c,h,e,f,g,w);\
	ROUND_16_63( i+2,c,d,a,b,g,h,e,f,w);\
	ROUND_16_63( i+3,b,c,d,a,f,g,h,e,w);\
} 
#else/* #if !(defined (CALC_W_IN_ROUND_LOOP))*/
 
/*ѹ��������һ��*/
#define	ROUND_00_15(i,a,b,c,d,e,f,g,h, w)\
{\
	s2  = ROTL(a,12);\
	s1  = s2 + e + cst_t[i];\
	s2 ^= s1 = ROTL(s1, 7);\
	d  += F_0_15(a, b, c) + s2 + ( w[i] ^ w[i+4] );\
	h  += G_0_15(e, f, g) + s1 + w[i];\
	b   = ROTL(b, 9);\
	f   = ROTL(f, 19);\
	h   = P0(h);\
} 

#define	ROUND_16_63(i,a,b,c,d,e,f,g,h, w)\
{\
	s2  = ROTL(a,12);\
	s1  = s2 + e + cst_t[i];\
	s2 ^= s1 = ROTL(s1, 7);\
	d  += F_16_63(a, b, c) + s2 + ( w[i] ^ w[i+4] );\
	h  += G_16_63(e, f, g) + s1 + w[i];\
	b   = ROTL(b, 9);\
	f   = ROTL(f, 19);\
	h   = P0(h);\
}  


#define FOUR_ROUND_00_15(i, a, b, c, d, e, f, g, h, w)\
{\
	ROUND_00_15( i  ,a,b,c,d,e,f,g,h,w);\
	ROUND_00_15( i+1,d,a,b,c,h,e,f,g,w);\
	ROUND_00_15( i+2,c,d,a,b,g,h,e,f,w);\
	ROUND_00_15( i+3,b,c,d,a,f,g,h,e,w);\
}

#define FOUR_ROUND_16_63(i, a, b, c, d, e, f, g, h, w)\
{\
	ROUND_16_63( i  ,a,b,c,d,e,f,g,h,w);\
	ROUND_16_63( i+1,d,a,b,c,h,e,f,g,w);\
	ROUND_16_63( i+2,c,d,a,b,g,h,e,f,w);\
	ROUND_16_63( i+3,b,c,d,a,f,g,h,e,w);\
}  
#endif/* end #if (defined (CALC_W_IN_ROUND_LOOP))*/
/* ======================== �����궨���� ���� =============================== */


/* ------------------------ �������Ͷ����� ��ʼ ----------------------------- */
 

/* ======================== �������Ͷ����� ���� ============================= */
  
#endif