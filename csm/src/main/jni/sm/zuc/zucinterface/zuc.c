/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: zuc.c
文件描述: zuc以及相关算法的实现代码
创 建 者: 张文科 罗影
创建时间: 2015年1月19日
修改历史:
1. 2015年1月19日	张文科 罗影		创建文件 
*******************************************************************************/
#include "mm_memory.h"
#include "mm_macro.h"
#include "zuc_core.h"
#include "eea3.h"
#include "eia3.h" 
#include "zuc.h"

/*..............................................................................

第 1 节 ZUC 算法——祖冲之序列密码算法

	ZUC 算法包含三个函数：
	@ zuc_init		——创建并初始化
	@ zuc_enc_dec	——加密或解密
	@ zuc_unit		——销毁

..............................................................................*/

mm_handle zuc_init( mm_u8_t key[ZUC_KEY_LEN], mm_u8_t iv[ZUC_IV_LEN])
{
	zuc_ctx *p = NULL;
	if (	MM_VALID_PT( key ) 
		&&	MM_VALID_PT( iv )   )
	{
		p = MM_MALLOC(sizeof(zuc_ctx));
		if(MM_VALID_PT(p))
		{ 
			zuc_init_core(p, key, iv);
		}
	}  

	return p;
}


mm_void_t zuc_unit( mm_handle h )
{
	if ( MM_VALID_PT( h )  )
	{
		zuc_unit_core((zuc_ctx*)h);
		MM_FREE(h);
	}
}
 

mm_i32_t zuc_enc_dec(mm_handle h, mm_u8_t *p_in, mm_u32_t len, mm_u8_t *p_out)
{
	if (	MM_VALID_PT( h ) 
		&&	MM_VALID_PT( p_in ) 
		&&	MM_VALID_PT( p_out )    )
	{
		return zuc_enc_dec_core((zuc_ctx *)h, p_in, len, p_out );
	}
	return -1;
}


/*..............................................................................

第 2 节 EEA3算法——基于祖冲之算法的机密性算法

	EEA3 算法包含四个函数：
	@ eea3			—— 一段式执行EEA3加密或解密
	@ eea3_init		—— 三段式执行EEA3的第一步创建
	@ eea3_process	—— 三段式执行EEA3的第二步加密或解密
	@ eea3_unit		—— 三段式执行EEA3的第三步销毁
..............................................................................*/
 

MM_API mm_i32_t eea3(mm_u8_t ck[EEA3_CK_LEN], mm_u32_t count, mm_u32_t bearer,  
					 mm_u32_t direction, mm_u8_t* p_in, mm_u32_t bit_len, 
					 mm_u8_t* p_out)
{
	if (	MM_VALID_PT( ck ) 
		&&	MM_VALID_PT( p_in ) 
		&&	MM_VALID_PT( p_out )    )
	{ 
		zuc_ctx eea;
			
		eea3_init_core( &eea, ck, count, bearer, direction);
		eea3_process_core( &eea, p_in, bit_len, p_out);
		eea3_unit_core(&eea);
			
		return 1; 
	}
	return -1; 
}

 
mm_handle eea3_init( mm_u8_t ck[EEA3_CK_LEN], mm_u32_t count, 
						   mm_u32_t bearer, mm_u32_t direction)
{
	zuc_ctx *p = NULL;
	if (	MM_VALID_PT( ck )  )
	{
		p = MM_MALLOC(sizeof(zuc_ctx));
		if(MM_VALID_PT(p))
		{ 
			eea3_init_core(p, ck, count, bearer, direction);
		}
	}   

	return p; 
}


mm_i32_t eea3_process(mm_handle h, mm_u8_t *p_in, mm_u32_t bit_len,
					  mm_u8_t *p_out )
{
	if (	MM_VALID_PT( h ) 
		&&	MM_VALID_PT( p_in ) 
		&&	MM_VALID_PT( p_out )    )
	{
		return eea3_process_core( (zuc_ctx*)h, p_in, bit_len, p_out);
	}
	return -1; 
}

mm_void_t eea3_unit( mm_handle h )
{
	if ( MM_VALID_PT( h )  )
	{
		eea3_unit_core((zuc_ctx*)h);
		MM_FREE(h);
	}
}
 
/*..............................................................................

第 3 节 EIA3算法——基于祖冲之算法的完整性算法

	EEA3 算法包含四个函数：
	@ eia3			—— 一段式执行EIA3加密或解密
	@ eia3_init		—— 三段式执行EIA3的第一步创建
	@ eia3_process	—— 三段式执行EIA3的第二步处理消息
	@ eia3_unit		—— 三段式执行EIA3的第三步销毁 
..............................................................................*/

mm_i32_t eia3( mm_u8_t ik[EIA3_IK_LEN], mm_u32_t count, 
			  mm_u32_t bearer, mm_u32_t direction, 
			  mm_u8_t* p_msg, mm_u32_t bit_len, mm_u8_t mac[EIA3_MAC_LEN])
{
	if (	MM_VALID_PT( ik ) 
		&&	MM_VALID_PT( p_msg ) 
		&&	MM_VALID_PT( mac )    )
	{ 
		zuc_ctx ctx;
			
		eia3_init_core( &ctx, ik, count, bearer, direction);
		eia3_process_core( &ctx, p_msg, bit_len);
		eia3_unit_core(&ctx, mac);
			
		return 1; 
	}
	return -1; 
}
   
MM_API mm_handle eia3_init( mm_u8_t ik[EIA3_IK_LEN], mm_u32_t count, 
						   mm_u32_t bearer, mm_u32_t direction )
{
	zuc_ctx *p = NULL;
	if (	MM_VALID_PT( ik )  )
	{
		p = MM_MALLOC(sizeof(zuc_ctx));
		if(MM_VALID_PT(p))
		{ 
			eia3_init_core2(p, ik, count, bearer, direction);
		}
	}   
	
	return p; 
}

 
mm_i32_t eia3_process( mm_handle h, mm_u8_t* p_msg, mm_u32_t bit_len )
{
	if (	MM_VALID_PT( h ) 
		&&	MM_VALID_PT( p_msg )   )
	{
		return eia3_process_core2( (zuc_ctx*)h, p_msg, bit_len); 
	}
	return -1; 
}


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
 
mm_void_t eia3_unit(mm_handle h , mm_u8_t mac[EIA3_MAC_LEN])
{
	if (	MM_VALID_PT( h ) 
		&&	MM_VALID_PT( mac ) )
	{
		eia3_unit_core2((zuc_ctx*)h, mac);
		MM_FREE(h);
	}
}
 
