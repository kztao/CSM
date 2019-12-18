/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: eia3.h
文件描述: eia3接口
创 建 者: 张文科 罗影
创建时间: 2015年1月19日
修改历史:
1. 2015年1月19日	张文科 罗影		创建文件 
*******************************************************************************/
#ifndef _EIA3_H_AD5980753A5B49C0
#define _EIA3_H_AD5980753A5B49C0


/* ------------------------ 头文件包含区 开始 ------------------------------- */
#include "mm_types.h"
#include "zuc_core.h"
/* ======================== 头文件包含区 结束 =============================== */


#ifdef __cplusplus
extern "C" {
#endif
	

/* ------------------------ 公共宏定义区 开始 ------------------------------- */

#define EIA3_IK_LEN		16		/* EIA3 的完整性密钥字节数	*/ 
#define EIA3_MAC_LEN	4		/* EIA3 的MAC字节数			*/ 
 

/* ======================== 公共类型定义区 结束 ============================= */
	
	
/* ------------------------ 函数原型外部声明区 开始 ------------------------- */

/*******************************************************************************
函 数 名:	eia3_init
功能描述:	EIA3 初始化
说    明:	三段式执行EIA3的第一步
注    意:	请严格按照以下步骤执行
	step 1	h = eia3_init_core( ... ) // 初始化
	step 2	while( msg_not_end ) {
				eia3_process_core(h, ...) // 加密 
			}
	step 3	eia3_unit_core() // 反初始化
参数说明: 
	p		(in/out)ZUC结构体 
	ik		(in)	完整性密钥	（128比特）
	count	(in)	计数器		（32比特）
	bearer	(in)	承载层标识	（5比特）
	direction(in)	传输方向标识（1比特） 
返 回 值:	>=1 [成功]，<=0 [失败]
修改历史: 
    1. 2015年1月19日	张文科 罗影		创建函数
*******************************************************************************/
mm_i32_t eia3_init_core(zuc_ctx *p, mm_u8_t ik[EIA3_IK_LEN], 
				   mm_u32_t count, mm_u32_t bearer, mm_u32_t direction ); 


/*******************************************************************************
函 数 名:	eia3_process
功能描述:	EIA3 加密
说    明:	三段式执行EIA3的第二步
注    意:	完整的三段式执行步骤见 eia3_init 的说明
参数说明: 
	p		(in/out)ZUC结构体 
	p_in	(in)	明文 
	byte_len(in)	明文的字节长 
	p_out	(out)	密文 
返 回 值:	-
修改历史: 
    1. 2015年1月19日	张文科 罗影		创建函数
*******************************************************************************/

mm_i32_t eia3_process_core( zuc_ctx *p, mm_u8_t* p_msg, mm_u32_t byte_len ); 


/*******************************************************************************
函 数 名:	eia3_unit
功能描述:	反初始化 EIA3
说    明:	三段式执行EIA3的第三步
注    意:	完整的三段式执行步骤见 eia3_init 的说明
参数说明: 
	p		(in/out)ZUC结构体 
	mac		(out)	MAC值 
返 回 值:	-
修改历史: 
    1. 2015年1月19日	张文科 罗影		创建函数
*******************************************************************************/
 
mm_i32_t eia3_unit_core(zuc_ctx *p , mm_u8_t mac[EIA3_MAC_LEN]);



mm_i32_t eia3_init_core2(zuc_ctx *p, mm_u8_t ik[EIA3_IK_LEN], 
				   mm_u32_t count, mm_u32_t bearer, mm_u32_t direction ); 

 
mm_i32_t eia3_process_core2( zuc_ctx *p, mm_u8_t* p_msg, mm_u32_t byte_len ); 
 
mm_i32_t eia3_unit_core2(zuc_ctx *p , mm_u8_t mac[EIA3_MAC_LEN]);
 
//-------------------------------------------------------------------


/* ======================== 函数原型外部声明区 结束 ========================= */



/* ------------------------ 变量外部引用声明区 开始 ------------------------- */

/* ======================== 变量外部引用声明区 结束 ========================= */

#ifdef __cplusplus
}
#endif

#endif/*#ifndef _***_H_*** */
