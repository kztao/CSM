/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
�ļ�����: mm_config.h
�ļ�����: �����㷨�ײ�����
�� �� ��: ���Ŀ� ��Ӱ
����ʱ��: 2014��10��24��
�޸���ʷ:
1. 2014��10��24��	���Ŀ� ��Ӱ		�����ļ� 
*******************************************************************************/

#ifndef _MM_CONFIG_H_
#define _MM_CONFIG_H_
 

/* ------------------------ ͷ�ļ������� ��ʼ ------------------------------- */
 
/* ======================== ͷ�ļ������� ���� =============================== */

#ifdef __cplusplus
extern "C" {
#endif
/* ------------------------ �����궨���� ��ʼ ------------------------------- */


/* ���ÿɸ������� ��ʼ */

#define MM_CPU_TYPE				MM_X86_32 /*MM_X86_64 */
#define MM_OS_TYPE				MM_OS_TYPE_WINDOWS  /*MM_OS_TYPE_LINUX  */

#define USE_STD_LIB				/* ����ʹ�ñ�׼�⺯�� */
//#undef USE_STD_LIB				/* �޷�ʹ�ñ�׼�⺯�� */

/* ���ÿɸ������� ���� */


/* ���������� */
#define MM_MCU_16				0   /* 16λMCU */
#define MM_DSP_16 				1   /* 16λDSP */
#define MM_MCU_32				2   /* 32λMCU */
#define MM_DSP_32				3   /* 32λDSP */
#define MM_X86_32				4   /* 32λX86 */
#define MM_MIPS_32				5   /* 32λMIPS */ 
#define MM_PPC_32				6   /* 32λPOWER PC */
#define MM_ARM_32				7   /* 32λARM */   
#define MM_X86_64				8   /* 64λX86 */
#define MM_MIPS_64				9   /* 64λMIPS */  
#define MM_PPC_64				10  /* 64λPOWER PC */

/* �ֽ��� */   
#define MM_LITTLE_ENDIAN		1   /* С��ģʽ */
#define MM_BIG_ENDIAN			2	/* ���ģʽ */

/* ����ϵͳ���� */
#define MM_OS_TYPE_NONE			0
#define MM_OS_TYPE_VXWORKS		1
#define MM_OS_TYPE_WINDOWS		2
#define MM_OS_TYPE_LINUX		3
#define MM_OS_TYPE_LINUX_KERNEL	4

// /* ����ϵͳ�汾 */
// #define MM_OS_VXWORKS_V55		0
// #define MM_OS_VXWORKS_V62		1
// #define MM_OS_VXWORKS_V67		2
  

#if (MM_CPU_TYPE == MM_MIPS_32) || (MM_CPU_TYPE == MM_MIPS_64)
	#define MM_ENDIAN_TYPE		MM_BIG_ENDIAN	
#else
	#define MM_ENDIAN_TYPE		MM_LITTLE_ENDIAN	
#endif

/* �����С���޷�ʶ�����ʶ���쳣����������������ȷ�Ĵ�С��ģʽ */
//#define MM_ENDIAN_TYPE		MM_BIG_ENDIAN	
//#define MM_ENDIAN_TYPE		MM_LITTLE_ENDIAN
	
/* ======================== �����궨���� ���� =============================== */


/* ------------------------ ����ԭ���ⲿ������ ��ʼ ------------------------- */

/* ======================== ����ԭ���ⲿ������ ���� ========================= */


/* ------------------------ �����ⲿ���������� ��ʼ ------------------------- */

/* ======================== �����ⲿ���������� ���� ========================= */
 
#ifdef __cplusplus
}
#endif
#endif 

