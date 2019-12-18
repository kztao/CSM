/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: mm_macro.h
文件描述: 密码算法底层常用宏定义
创 建 者: 张文科 罗影
创建时间: 2014年10月24日
修改历史:
1. 2014年10月24日	张文科 罗影		创建文件 
*******************************************************************************/

#ifndef _MM_MACRO_H
#define _MM_MACRO_H 

/* ------------------------ 头文件包含区 开始 ------------------------------- */
  
#include "mm_config.h"

#ifdef USE_STD_LIB
#include <memory.h>
#if (__APPLE__ || __MACH__)
#include <stdlib.h>
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif
#endif
/* ======================== 头文件包含区 结束 =============================== */

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------ 公共宏定义区 开始 ------------------------------- */

 

/* 常用值定义 */
#ifndef FALSE 
#	define FALSE	0
#endif
#ifndef TRUE 
#	define TRUE		1 
#endif
#ifndef NULL 
#	define NULL		0
#endif


#define MM_VALID_PT(pt)		( (pt) != NULL )
#define MM_INVALID_PT(pt)	( (pt) == NULL )

#define MIN(x,y)	((x) >  (y)  ? (y)  : (x))
#define MAX(x,y)	((x) <  (y)  ? (y)  : (x))
 




	/*函数类宏定义*/ 

#ifdef USE_STD_LIB
#define MM_MALLOC	malloc
#define MM_FREE(pt)		if ((pt) != NULL) { free(pt);(pt) = NULL;}/* 内存释放 */
#define MM_MEMSET	memset
#define MM_MEMCMP	memcmp
#define MM_MEMCPY	memcpy
#else
#include "mm_basic_fun.h"
#define MM_MALLOC	malloc
#define MM_FREE(pt)	if ((pt) != NULL) { free(pt);(pt) = NULL;}
#define MM_MEMSET	sm2_memset
#define MM_MEMCMP	sm2_memcmp
#define MM_MEMCPY	sm2_memcpy	
#endif




#if (MM_ENDIAN_TYPE == MM_LITTLE_ENDIAN)

/* 双字u32x 存储到 四字节 p_chars */ 
#define MM_STORE_U32H(u32x, p_chars) \
{	(p_chars)[0] = (BYTE)((u32x)>>24); \
	(p_chars)[1] = (BYTE)((u32x)>>16); \
	(p_chars)[2] = (BYTE)((u32x)>> 8); \
	(p_chars)[3] = (BYTE)((u32x)    );	}


/*四字节p_chars 加载到 双字u32x */
#define MM_LOAD_U32H(u32x, p_chars) \
{	u32x= ((u32_t)((p_chars)[0])<<24) \
		| ((u32_t)((p_chars)[1])<<16) \
		| ((u32_t)((p_chars)[2])<< 8) \
		| ((u32_t)((p_chars)[3])    );	}


/* 字u16x 存储到 两字节 p_chars */ 
#define MM_STORE_U16H(u16x, p_chars) \
{	(p_chars)[0] = (BYTE)((u16x)>> 8); \
	(p_chars)[1] = (BYTE)((u16x)    );	}

/*两字节p_chars 加载到 字u16x */
#define MM_LOAD_U16H(u16x, p_chars) \
{	u16x= ((u32_t)((p_chars)[0])<< 8) \
		| ((u32_t)((p_chars)[1])    );	}


#elif (MM_ENDIAN_TYPE == MM_BIG_ENDIAN)

#define MM_STORE_U32H(u32x, p_ui8)	MM_MEMCPY(p_ui8,   &(u32x), 4) 
#define MM_LOAD_U32H(u32x, p_ui8)	MM_MEMCPY(&(u32x), p_ui8,   4)

#define MM_STORE_U16H(u16x, p_ui8)	MM_MEMCPY(p_ui8,   &(u16x), 2) 
#define MM_LOAD_U16H( u16x, p_ui8)	MM_MEMCPY(&(u16x), p_ui8,   2)
#else
#error User must define right endianess of smX.
#endif 

/* ======================== 公共宏定义区 结束 =============================== */


/* ------------------------ 函数原型外部声明区 开始 ------------------------- */

/* ======================== 函数原型外部声明区 结束 ========================= */


/* ------------------------ 变量外部引用声明区 开始 ------------------------- */

/* ======================== 变量外部引用声明区 结束 ========================= */
 
#ifdef __cplusplus
}
#endif
#endif

