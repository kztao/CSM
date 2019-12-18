/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: mm_config.h
文件描述: 密码算法底层配置
创 建 者: 张文科 罗影
创建时间: 2014年10月24日
修改历史:
1. 2014年10月24日	张文科 罗影		创建文件 
*******************************************************************************/

#ifndef _MM_CONFIG_H_
#define _MM_CONFIG_H_
 

/* ------------------------ 头文件包含区 开始 ------------------------------- */
 
/* ======================== 头文件包含区 结束 =============================== */

#ifdef __cplusplus
extern "C" {
#endif
/* ------------------------ 公共宏定义区 开始 ------------------------------- */


/* 配置可更改区域 开始 */

#define MM_CPU_TYPE				MM_X86_32 /*MM_X86_64 */
#define MM_OS_TYPE				MM_OS_TYPE_WINDOWS  /*MM_OS_TYPE_LINUX  */

#define USE_STD_LIB				/* 允许使用标准库函数 */
//#undef USE_STD_LIB				/* 无法使用标准库函数 */

/* 配置可更改区域 结束 */


/* 处理器类型 */
#define MM_MCU_16				0   /* 16位MCU */
#define MM_DSP_16 				1   /* 16位DSP */
#define MM_MCU_32				2   /* 32位MCU */
#define MM_DSP_32				3   /* 32位DSP */
#define MM_X86_32				4   /* 32位X86 */
#define MM_MIPS_32				5   /* 32位MIPS */ 
#define MM_PPC_32				6   /* 32位POWER PC */
#define MM_ARM_32				7   /* 32位ARM */   
#define MM_X86_64				8   /* 64位X86 */
#define MM_MIPS_64				9   /* 64位MIPS */  
#define MM_PPC_64				10  /* 64位POWER PC */

/* 字节序 */   
#define MM_LITTLE_ENDIAN		1   /* 小端模式 */
#define MM_BIG_ENDIAN			2	/* 大端模式 */

/* 操作系统类型 */
#define MM_OS_TYPE_NONE			0
#define MM_OS_TYPE_VXWORKS		1
#define MM_OS_TYPE_WINDOWS		2
#define MM_OS_TYPE_LINUX		3
#define MM_OS_TYPE_LINUX_KERNEL	4

// /* 操作系统版本 */
// #define MM_OS_VXWORKS_V55		0
// #define MM_OS_VXWORKS_V62		1
// #define MM_OS_VXWORKS_V67		2
  

#if (MM_CPU_TYPE == MM_MIPS_32) || (MM_CPU_TYPE == MM_MIPS_64)
	#define MM_ENDIAN_TYPE		MM_BIG_ENDIAN	
#else
	#define MM_ENDIAN_TYPE		MM_LITTLE_ENDIAN	
#endif

/* 如果大小端无法识别或者识别异常，请在这里配置正确的大小端模式 */
//#define MM_ENDIAN_TYPE		MM_BIG_ENDIAN	
//#define MM_ENDIAN_TYPE		MM_LITTLE_ENDIAN
	
/* ======================== 公共宏定义区 结束 =============================== */


/* ------------------------ 函数原型外部声明区 开始 ------------------------- */

/* ======================== 函数原型外部声明区 结束 ========================= */


/* ------------------------ 变量外部引用声明区 开始 ------------------------- */

/* ======================== 变量外部引用声明区 结束 ========================= */
 
#ifdef __cplusplus
}
#endif
#endif 

