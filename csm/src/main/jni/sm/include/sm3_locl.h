/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: sm3.c
文件描述: SM3杂凑算法宏
创 建 者: 张文科 罗影
创建时间: 2014年10月30日
修改历史:
1. 2014年10月30日	张文科 罗影		创建文件 
*******************************************************************************/
#ifndef _SM3_LOCL_H_AD259C6F012EE32A 
#define _SM3_LOCL_H_AD259C6F012EE32A
/* ------------------------ 头文件包含区 开始 ------------------------------- */
 
//#include "mm_macro.h" 
  

/* ======================== 头文件包含区 结束 =============================== */


/* ------------------------ 公共宏定义区 开始 ------------------------------- */

/* -------------- 可配置区 开始 --------------------- */

/* 将扩展字W[*]的计算放到64轮的轮函数里面，可以减少数据的存储和加载 */
//#define CALC_W_IN_ROUND_LOOP

/* 代码解开与否 */ 
#define SM3_UNROLL				

/* ============== 可配置区 结束 ===================== */

/*循环左移n位
	20141216 luoying
	当 n >= 32 时，不同CPU的解释可能不一样，
	intel是取 n mod 32 作为移位数
	有的则得到移位结果为 0 值
*/ 

/*
	ROTL(x,n) ： x<<<n
	SM3_LOAD_U32 ：数据加载
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

/*P0函数*/
#define P0(x) ( ROTL(x,  9) ^ ROTL(x, 17) ^ (x) ) 

/*P1函数*/
#define P1(x) ( ROTL(x, 15) ^ ROTL(x, 23) ^ (x) )  

/*FF函数*/
#define F_0_15( x, y, z)	((x)^(y)^(z)) 
#define F_16_63(x, y, z)	(((x) & (y)) | ((x) & (z)) | ((y) & (z))) 

/*GG函数*/
#define G_0_15(x, y, z)		F_0_15( x, y, z)
#define G_16_63(x, y, z)	(((x) & (y)) | ((~x) & (z))) 


/*消息扩展函数*/
#define GET_W_0_15( w, data, i) SM3_LOAD_U32((w)[i], data + ((i)<<2))
#define GET_W_16_67(w, i) \
{\
	s1 = w[i-16] ^ w[i-9] ^ ROTL( w[i-3],15 );\
	w[i] = P1( s1 ) ^ ROTL(w[i-13],7) ^ w[i-6];\
}
 
#if (defined (CALC_W_IN_ROUND_LOOP))
/*压缩函数的一轮*/
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
/* 由于 GET_W_16_67()里面使用了S1，所以应先计算，否则S1数据将被破坏 */
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
 
/*压缩函数的一轮*/
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
/* ======================== 公共宏定义区 结束 =============================== */


/* ------------------------ 公共类型定义区 开始 ----------------------------- */
 

/* ======================== 公共类型定义区 结束 ============================= */
  
#endif