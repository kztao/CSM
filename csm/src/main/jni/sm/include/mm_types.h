/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
�ļ����: mm_types.h
�ļ�����: �����㷨ʹ�õ�������Ͷ���
�� �� ��: ���Ŀ� ��Ӱ
����ʱ��: 2014��10��24��
�޸���ʷ:
1. 2014��10��24��	���Ŀ� ��Ӱ		�����ļ� 
*******************************************************************************/

#ifndef _MM_TYPES_H_
#define _MM_TYPES_H_

/* ------------------------ ͷ�ļ����� ��ʼ ------------------------------- */

#include "mm_config.h"  


/* ======================== ͷ�ļ����� ���� =============================== */

#ifdef __cplusplus
extern "C" {
#endif
/* ------------------------ ���غ궨���� ��ʼ ------------------------------- */

/* MM_API ���� */                                         
#if ( MM_OS_TYPE == MM_OS_TYPE_WINDOWS )
#	if ( defined(MM_DLLEXPORT) )
#		define MM_API __declspec(dllexport)
#	endif
#	if ( defined(MM_DLLIMPORT) )
#		define MM_API extern __declspec(dllimport)
#	endif
#	if ( !defined(MM_DLLEXPORT) &&  !defined(MM_DLLIMPORT) )
#		define MM_API extern
#	endif
#else
#	define MM_API extern
#endif /*#if ( MM_OS_TYPE == MM_OS_TYPE_WINDOWS )*/


/* MM_INLINE ���� */  
#if (MM_OS_TYPE == MM_OS_TYPE_WINDOWS)
#	define MM_INLINE		static __inline
#elif (MM_OS_TYPE == MM_OS_TYPE_LINUX)
#	define MM_INLINE		static inline  
#else
#	define MM_INLINE            
#endif  /*#if (MM_OS_TYPE == MM_OS_TYPE_WINDOWS)*/


/* ������� ���� */

/* 64λ������ */ 
#if (	(MM_CPU_TYPE == MM_X86_64 )	\
	||	(MM_CPU_TYPE == MM_MIPS_64)	\
||	(MM_CPU_TYPE == MM_PPC_64 )	)   
typedef unsigned long int		mm_u64_t;			/* 64λ�޷������ */
typedef long int				mm_i64_t;			/* 64λ�з������ */
#	define mm_HAVE_64
#elif (	(MM_CPU_TYPE == MM_X86_32 )	\
	||	(MM_CPU_TYPE == MM_MIPS_32)	\
	||	(MM_CPU_TYPE == MM_PPC_32 )	\
	||	(MM_CPU_TYPE == MM_ARM_32 )	)    
#	if (	MM_OS_TYPE == MM_OS_TYPE_WINDOWS)
#if defined(WIN32) || defined(WIN64)
typedef unsigned __int64		mm_u64_t;			/* 64λ�޷������ */
typedef signed __int64			mm_i64_t;			/* 64λ�з������ */
#else
//linux need to use long long
typedef unsigned long		mm_u64_t;			/* 64λ�޷������ */
typedef signed long			mm_i64_t;			/* 64λ�з������ */
#endif
#		define MM_HAVE_64
#	elif (	(MM_OS_TYPE == MM_OS_TYPE_VXWORKS) \
	||	(MM_OS_TYPE == MM_OS_TYPE_LINUX)  \
	||	(MM_OS_TYPE == MM_OS_TYPE_LINUX_KERNEL))
typedef unsigned long long		mm_u64_t;			/* 64λ�޷������ */
typedef long long				mm_i64_t;			/* 64λ�з������ */
#		define MM_HAVE_64
#endif	/* if (	MM_OS_TYPE == MM_OS_TYPE_WINDOWS)*/
#endif	/*#if (	(MM_CPU_TYPE == MM_X86_64 )...*/


// /* 16λ��Ƭ��DSP long Ϊ32λ */
// #if ((MM_CPU_TYPE == MM_MCU_16) || (MM_CPU_TYPE == MM_DSP_16))
// 	typedef unsigned long int	mm_u32_t;			/* 32λ�޷������ */
// 	typedef long int			mm_i32_t;			/* 32λ�з������ */
// #else 
// 	typedef unsigned int		mm_u32_t;			/* 32λ�޷������ */
// 	typedef int					mm_i32_t;			/* 32λ�з������ */
// #endif/*#if ((MM_CPU_TYPE == MM_MCU_16) ... */

typedef unsigned int			u32_t;				/* 32λ�޷������ */
typedef unsigned int			mm_u32_t;			/* 32λ�޷������ */
typedef int						mm_i32_t;			/* 32λ�з������ */ 


typedef unsigned short int		mm_u16_t;			/* 16λ�޷������ */
typedef short int				mm_i16_t;			/* 16λ�з������ */


#if (MM_CPU_TYPE != MM_DSP_16) /* 16λDSP charΪ16λ */
typedef unsigned char			BYTE;				/* 8λ�޷������ */
typedef unsigned char			mm_u8_t;			/* 8λ�޷������ */
typedef char					mm_i8_t;			/* 8λ�з������ */
#else 
#	error MM_CPU_TYPE is MM_DSP_16
#endif

typedef float					mm_f32_t;			/* 32λ�������� */
typedef double					mm_f64_t;			/* 64λ�������� */  
typedef void					mm_void_t;			/* ��ֵ��		*/
typedef void					*mm_handle;			/* ���			*/


/* ======================== ���غ궨���� ���� =============================== */


/* ------------------------ �������Ͷ����� ��ʼ ----------------------------- */

/* ======================== �������Ͷ����� ���� ============================= */


/* ------------------------ �ⲿ���������� ��ʼ ----------------------------- */

/* ======================== �ⲿ���������� ���� ============================= */


/* ------------------------ ���غ���ԭ�������� ��ʼ ------------------------- */

/* ======================== ���غ���ԭ�������� ���� ========================= */



/* ------------------------ ȫ�ֱ��������� ��ʼ ----------------------------- */

/* ======================== ȫ�ֱ��������� ���� ============================= */


/* ------------------------ �ֲ����������� ��ʼ ----------------------------- */

/* ======================== �ֲ����������� ���� ============================= */

 

#ifdef __cplusplus
}
#endif
 
#endif /* _MM_TYPES_H_ */
