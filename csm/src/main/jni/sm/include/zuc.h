/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: zuc.h
文件描述: zuc接口
创 建 者: 张文科 罗影
创建时间: 2015年1月19日
修改历史:
1. 2015年1月19日	张文科 罗影		创建文件 
*******************************************************************************/
#ifndef _ZUC_H_AFB5807FD32C1CAF
#define _ZUC_H_AFB5807FD32C1CAF



/* ------------------------ 头文件包含区 开始 ------------------------------- */

#include "mm_types.h"

/* ======================== 头文件包含区 结束 =============================== */


#ifdef __cplusplus
extern "C" {
#endif
	

/* ------------------------ 公共宏定义区 开始 ------------------------------- */
 
#define ZUC_KEY_LEN		16		/* ZUC  密钥字节数		*/
#define ZUC_IV_LEN		16		/* ZUC  初始化向量字节数*/ 
#define EEA3_CK_LEN		16		/* EEA3 机密性密钥字节数*/
#define EIA3_IK_LEN		16		/* EIA3 完整性密钥字节数*/
#define EIA3_MAC_LEN	4		/* EIA3 的MAC字节数		*/ 

/* ======================== 公共类型定义区 结束 ============================= */
	

/* ------------------------ 函数原型外部声明区 开始 ------------------------- */
	

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/ 
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/ 

/*..............................................................................

第 0 节 说明

	函数声明区包含三个部分函数：
	@ 第 1 节 ZUC 算法——祖冲之序列密码算法
	@ 第 2 节 EEA3算法——基于祖冲之算法的机密性算法
	@ 第 3 节 EIA3算法——基于祖冲之算法的完整性算法

..............................................................................*/
	

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/ 
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/ 

/*..............................................................................

第 1 节 ZUC 算法——祖冲之序列密码算法

	ZUC 算法包含三个函数：
	@ zuc_init		——创建并初始化
	@ zuc_enc_dec	——加密或解密
	@ zuc_unit		——销毁

..............................................................................*/

/*******************************************************************************
函 数 名:	zuc_init
功能描述:	创建并初始化ZUC算法句柄
说    明:	-
注    意:	请严格按照以下步骤执行
	step 1	h = zuc_init(... )		// 创建
	step 2	while( msg_not_end ) {	
				zuc_enc_dec(h, ...)	// 加密或解密
			}
	step 3	zuc_unit(h)				// 销毁

参数说明: 
	key		(in)	密钥	   16字节
	iv		(in)	初始化向量 16字节
返 回 值:  句柄不为NULL (成功), 句柄为NULL (失败)
修改历史: 
    1. 2015年1月19日	张文科 罗影		创建函数
*******************************************************************************/

MM_API mm_handle zuc_init( mm_u8_t key[ZUC_KEY_LEN], mm_u8_t iv[ZUC_IV_LEN]);

 
/*******************************************************************************
函 数 名:	zuc_enc_dec
功能描述:	利用zuc加密或解密
说    明:	-
注    意:	1. 当整个执行过程中只需调用本函数一次时
				bit_len 可以不是 8 的倍数，即数据可以是不完整的字节。
			2. 当需要反复调用本函数时，
				第一次至倒数第二次调用时，bit_len需是8的倍数，即数据是完整的字节
				最后一次的 bit_len 可以不是 8 的倍数，即数据可以是不完整的字节。
			3. 如果不满足以上说明，将报错。
参数说明: 
	h		(in/out)句柄 
	p_in	(in)	输入数据 
	bit_len	(in)	数据比特长度 
	p_out	(out)	输出数据 
返 回 值:	>=1 [成功]，<=0 [失败]
修改历史: 
    1. 2014年10月29日	张文科 罗影		创建函数
*******************************************************************************/ 

MM_API mm_i32_t	zuc_enc_dec(mm_handle h, mm_u8_t *p_in, mm_u32_t bit_len, 
							mm_u8_t *p_out );


/*******************************************************************************
函 数 名:	zuc_unit
功能描述:	反初始化ZUC算法
说    明:	-
注    意:	1. 本步将销毁句柄的封装数据；执行后句柄为悬垂指针，建议置为NULL。
参数说明: 
	h		(in)	句柄 
返 回 值:	-
修改历史: 
    1. 2015年1月19日	张文科 罗影		创建函数
*******************************************************************************/
MM_API mm_void_t zuc_unit( mm_handle h ); 


/******************************************************************************/
/******************************************************************************/
/******************************************************************************/ 
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/ 

/*..............................................................................

第 2 节 EEA3算法——基于祖冲之算法的机密性算法

	EEA3 算法包含四个函数：
	@ eea3			—— 一段式执行EEA3加密或解密
	@ eea3_init		—— 三段式执行EEA3的第一步创建
	@ eea3_process	—— 三段式执行EEA3的第二步加密或解密
	@ eea3_unit		—— 三段式执行EEA3的第三步销毁
..............................................................................*/

/*******************************************************************************
函 数 名:	eea3
功能描述:	EEA3加密解密 （一段式）
说    明:	一段式执行 EEA3 
注    意:	bit_len 可以不是 8 的倍数，即数据可以是不完整的字节。
参数说明: 
	ck		(in)	机密性密钥	（128比特）
	count	(in)	计数器		（32比特）
	bearer	(in)	承载层标识	（5比特）
	direction(in)	传输方向标识（1比特）
	p_in	(in)	输入数据 
	bit_len	(in)	数据的比特长度 
	p_out	(out)	输出数据 
返 回 值:	>=1 [成功]，<=0 [失败]
修改历史: 
    1. 2015年1月19日	张文科 罗影		创建函数
*******************************************************************************/ 

MM_API mm_i32_t eea3(mm_u8_t ck[EEA3_CK_LEN], mm_u32_t count, mm_u32_t bearer,  
					 mm_u32_t direction, mm_u8_t* p_in, mm_u32_t bit_len, 
					 mm_u8_t* p_out);


/*******************************************************************************
函 数 名:	eea3_init
功能描述:	创建并初始化eea3算法句柄
说    明:	三段式执行EEA3的第一步
注    意:	请严格按照以下步骤执行
	step 1	h = eea3_init_mode(... )// 创建
	step 2	while( msg_not_end ) {	
				eea3_process(h, ...)// 加密或解密
			}
	step 3	eea3_unit(h)			// 销毁

参数说明:  
	ck		(in)	机密性密钥	（128比特）
	count	(in)	计数器		（32比特）
	bearer	(in)	承载层标识	（5比特）
	direction(in)	传输方向标识（1比特） 
返 回 值:  句柄不为NULL (成功), 句柄为NULL (失败)
修改历史: 
    1. 2015年1月19日	张文科 罗影		创建函数 
*******************************************************************************/

MM_API mm_handle eea3_init( mm_u8_t ck[EEA3_CK_LEN], mm_u32_t count, 
						   mm_u32_t bearer, mm_u32_t direction);


/*******************************************************************************
函 数 名:	eea3_process
功能描述:	利用zuc-eea3加密或解密
说    明:	三段式执行EEA3的第二步
注    意:	1. 完整的三段式执行步骤见 eea3_init 的说明
			2. 当整个执行过程中只需调用本函数一次时
				bit_len 可以不是 8 的倍数，即数据可以是不完整的字节。
			3. 当需要反复调用本函数时，
				第一次至倒数第二次调用时，bit_len需是8的倍数，即数据是完整的字节
				最后一次的 bit_len 可以不是 8 的倍数，即数据可以是不完整的字节。
			4. 如果不满足以上说明，将报错。
参数说明: 
	h		(in/out)句柄  
	p_in	(in)	输入数据 
	bit_len	(in)	数据的比特长度 
	p_out	(out)	输出数据 
返 回 值:	>=1 [成功]，<=0 [失败]
修改历史: 
    1. 2015年1月19日	张文科 罗影		创建函数
*******************************************************************************/  
 
MM_API mm_i32_t	eea3_process(mm_handle h, mm_u8_t *p_in, mm_u32_t bit_len, 
							 mm_u8_t *p_out );


/*******************************************************************************
函 数 名:	eea3_unit
功能描述:	反初始化 EEA3
说    明:	三段式执行EEA3的第三步
注    意:	完整的三段式执行步骤见 eea3_init 的说明
			本步将销毁句柄的封装数据；执行后句柄为悬垂指针，建议置为NULL。
参数说明: 
	h		(in)	句柄 
返 回 值:	-
修改历史: 
    1. 2015年1月19日	张文科 罗影		创建函数
*******************************************************************************/
  
MM_API mm_void_t eea3_unit( mm_handle h ); 


/******************************************************************************/
/******************************************************************************/
/******************************************************************************/ 
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/ 

/*..............................................................................

第 3 节 EIA3算法——基于祖冲之算法的完整性算法

	EEA3 算法包含四个函数：
	@ eia3			—— 一段式执行EIA3完整性校验码计算
	@ eia3_init		—— 三段式执行EIA3的第一步创建
	@ eia3_process	—— 三段式执行EIA3的第二步处理消息
	@ eia3_unit		—— 三段式执行EIA3的第三步销毁 
..............................................................................*/


 
/*******************************************************************************
函 数 名:	eia3
功能描述:	EIA3 MAC （一段式）
说    明:	一段式执行 EIA3 
注    意:	bit_len 可以不是 8 的倍数，即数据可以是不完整的字节。
参数说明:  
	ik		(in)	完整性密钥	（128比特）
	count	(in)	计数器		（32比特）
	bearer	(in)	承载层标识	（5比特）
	direction(in)	传输方向标识（1比特）
	p_msg	(in)	数据 
	bit_len	(in)	数据的比特长度 
	mac		(out)	MAC值 
返 回 值:	>=1 [成功]，<=0 [失败]
修改历史: 
    1. 2015年1月19日	张文科 罗影		创建函数
*******************************************************************************/ 

MM_API mm_i32_t eia3(mm_u8_t ik[EIA3_IK_LEN], mm_u32_t count, mm_u32_t bearer, 
					 mm_u32_t direction, mm_u8_t* p_msg, mm_u32_t bit_len, 
					 mm_u8_t mac[EIA3_MAC_LEN]);
  

/*******************************************************************************
函 数 名:	eia3_init
功能描述:	EIA3 初始化
说    明:	三段式执行EIA3的第一步
注    意:	请严格按照以下步骤执行
	step 1	h = eia3_init( key )	// 初始化
	step 2	while( msg_not_end ) {
				eia3_process(h, ...)// 处理消息 
			}
	step 3	eia3_unit()				// 反初始化
参数说明:  
	ik		(in)	完整性密钥	（128比特）
	count	(in)	计数器		（32比特）
	bearer	(in)	承载层标识	（5比特）
	direction(in)	传输方向标识（1比特） 
返 回 值:  句柄不为NULL (成功), 句柄为NULL (失败)
修改历史: 
    1. 2015年1月19日	张文科 罗影		创建函数
*******************************************************************************/

MM_API mm_handle eia3_init(mm_u8_t ik[EIA3_IK_LEN], mm_u32_t count,
						   mm_u32_t bearer, mm_u32_t direction ); 


/*******************************************************************************
函 数 名:	eia3_process
功能描述:	EIA3 处理消息
说    明:	三段式执行EIA3的第二步
注    意:	完整的三段式执行步骤见 eia3_init 的说明
			1. 当整个执行过程中只需调用本函数一次时
				bit_len 可以不是 8 的倍数，即数据可以是不完整的字节。
			2. 当需要反复调用本函数时，
				第一次至倒数第二次调用时，bit_len需是8的倍数，即数据是完整的字节
				最后一次的 bit_len 可以不是 8 的倍数，即数据可以是不完整的字节。
			3. 如果不满足以上说明，将报错。
参数说明: 
	h		(in)	句柄 
	p_msg	(in)	数据 
	bit_len	(in)	数据的比特长 

返 回 值:	>=1 [成功]，<=0 [失败]
修改历史: 
    1. 2015年1月19日	张文科 罗影		创建函数
*******************************************************************************/

MM_API mm_i32_t eia3_process( mm_handle h, mm_u8_t* p_msg, mm_u32_t bit_len );


/*******************************************************************************
函 数 名:	eia3_unit
功能描述:	反初始化 EIA3
说    明:	三段式执行EIA3的第三步
注    意:	完整的三段式执行步骤见 eia3_init 的说明
			本步将销毁句柄的封装数据；执行后句柄为悬垂指针，建议置为NULL。
参数说明: 
	h		(in)	句柄 
	mac		(out)	MAC值 
返 回 值:	>=1 [成功]，<=0 [失败]
修改历史: 
    1. 2015年1月19日	张文科 罗影		创建函数
*******************************************************************************/
 
MM_API mm_void_t eia3_unit(mm_handle h , mm_u8_t mac[EIA3_MAC_LEN]);



/* ======================== 函数原型外部声明区 结束 ========================= */


/* ------------------------ 变量外部引用声明区 开始 ------------------------- */

/* ======================== 变量外部引用声明区 结束 ========================= */
 
#ifdef __cplusplus
}
#endif

#endif/*#ifndef _***_H_... */
