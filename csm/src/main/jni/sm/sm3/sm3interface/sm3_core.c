/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: sm3.c
文件描述: SM3杂凑算法实现
创 建 者: 张文科 罗影
创建时间: 2014年10月30日
修改历史:
1. 2014年10月30日	张文科 罗影		创建文件 
*******************************************************************************/

/* ------------------------ 头文件包含区 开始 ------------------------------- */


#include "mm_macro.h"
#include "sm3_core.h"
#include "sm3_locl.h"
  

/* ======================== 头文件包含区 结束 =============================== */


/* ------------------------ 公共宏定义区 开始 ------------------------------- */
 

/* ======================== 公共宏定义区 结束 =============================== */


/* ------------------------ 公共类型定义区 开始 ----------------------------- */
 
static mm_u32_t cst_t[64] = {
0x79cc4519,0xf3988a32,0xe7311465,0xce6228cb,
0x9cc45197,0x3988a32f,0x7311465e,0xe6228cbc,
0xcc451979,0x988a32f3,0x311465e7,0x6228cbce,
0xc451979c,0x88a32f39,0x11465e73,0x228cbce6,
0x9d8a7a87,0x3b14f50f,0x7629ea1e,0xec53d43c,
0xd8a7a879,0xb14f50f3,0x629ea1e7,0xc53d43ce,
0x8a7a879d,0x14f50f3b,0x29ea1e76,0x53d43cec,
0xa7a879d8,0x4f50f3b1,0x9ea1e762,0x3d43cec5,
0x7a879d8a,0xf50f3b14,0xea1e7629,0xd43cec53,
0xa879d8a7,0x50f3b14f,0xa1e7629e,0x43cec53d,
0x879d8a7a,0x0f3b14f5,0x1e7629ea,0x3cec53d4,
0x79d8a7a8,0xf3b14f50,0xe7629ea1,0xcec53d43,
0x9d8a7a87,0x3b14f50f,0x7629ea1e,0xec53d43c,
0xd8a7a879,0xb14f50f3,0x629ea1e7,0xc53d43ce,
0x8a7a879d,0x14f50f3b,0x29ea1e76,0x53d43cec,
0xa7a879d8,0x4f50f3b1,0x9ea1e762,0x3d43cec5
};

/* ======================== 公共类型定义区 结束 ============================= */
 


/*******************************************************************************
函 数 名:	sm3_init_core
功能描述:	初始化SM3 
说    明:	三段式计算消息杂凑值的第 1 步
注    意:	1. 调用者做接口参数检测
			2. 三段式计算消息杂凑值，请严格按照以下步骤执行
			第 1 步 sm3_init_core(***);			// 初始化
			第 2 步 while(msg_not_end){
						sm3_process_core(***);	// 消息可分多次添加
					}
			第 3 步 sm3_unit_core(***);			// 输出杂凑值
参数说明: 
	p(in/out):  SM3 封装数据  
返 回 值:  -
修改历史: 
    1. 2014年10月30日	张文科 罗影		创建函数
    2. 2015年 2月 4日	张文科 罗影		修改函数接口
*******************************************************************************/
mm_void_t sm3_init_core(mm_sm3_ctx *p)
{  
	p->total_len_l = p->total_len_h = p->res_len = 0;
	p->s[0] = 0x7380166f; 
	p->s[1] = 0x4914b2b9; 
	p->s[2] = 0x172442d7; 
	p->s[3] = 0xda8a0600; 
	p->s[4] = 0xa96f30bc; 
	p->s[5] = 0x163138aa; 
	p->s[6] = 0xe38dee4d; 
	p->s[7] = 0xb0fb0e4e; 
}    


/*******************************************************************************
函 数 名:	sm3_block_core
功能描述:	处理多个分组
说    明:	每个分组大小512比特，处理num个分组
注    意:	1. 调用者做接口参数检测
			2. 三段式计算消息杂凑值的步骤参见 sm3_init_core 的说明 
参数说明: 
	p		(in/out)SM3封装数据  
	p_data	(in)	分组数据
	num		(in)	分组个数
返 回 值:  -
修改历史: 
    1. 2014年10月30日	张文科 罗影		创建函数
    2. 2015年 2月 4日	张文科 罗影		修改函数接口
*******************************************************************************/

mm_void_t sm3_block_core (mm_sm3_ctx *p, mm_u8_t *p_data, mm_i32_t num)
{ 
	register mm_u32_t	a,b,c,d,e,f,g,h,s1,s2;
	mm_u32_t	w[68];
	mm_i32_t	i;  

	while ( num-- > 0 ) 
	{ 
#ifdef CALC_W_IN_ROUND_LOOP
		/* 只计算前4个W，即W[0] - W[3] */
		GET_W_0_15(w, p_data, 0); 
		GET_W_0_15(w, p_data, 1); 
		GET_W_0_15(w, p_data, 2); 
		GET_W_0_15(w, p_data, 3); 

		a = p->s[0]; b = p->s[1]; c = p->s[2]; d = p->s[3];
		e = p->s[4]; f = p->s[5]; g = p->s[6]; h = p->s[7]; 
 
		/*  0 - 11 轮 */
		FOUR_ROUND_00_11( 0,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_00_11( 4,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_00_11( 8,a,b,c,d,e,f,g,h,w);
	
		/* 12 - 15 轮 */
		FOUR_ROUND_12_15(12,a,b,c,d,e,f,g,h,w);

		/* 16 - 63 轮 */
#ifdef SM3_UNROLL
		FOUR_ROUND_16_63(16,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(20,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(24,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(28,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(32,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(36,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(40,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(44,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(48,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(52,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(56,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(60,a,b,c,d,e,f,g,h,w);  
#else	/* else #ifdef SM3_UNROLL */ 
		/* 16 - 63 轮 */
		i = 16;
		while (i < 64 )
		{
			FOUR_ROUND_16_63( i,a,b,c,d,e,f,g,h,w);
			i += 4;
		} 
#endif  /* end #ifdef SM3_UNROLL */ 

#else	/* else #ifdef CALC_W_IN_ROUND_LOOP */

		i = 0;
		while ( i < 16 )
		{
			GET_W_0_15(w, p_data, i); 
			i++;
		} 
		while ( i < 68 )
		{
			GET_W_16_67(w, i);
			i++;
		} 

		a = p->s[0]; b = p->s[1]; c = p->s[2]; d = p->s[3];
		e = p->s[4]; f = p->s[5]; g = p->s[6]; h = p->s[7]; 

#ifdef SM3_UNROLL
		/* round  0 - 15 */
		FOUR_ROUND_00_15( 0,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_00_15( 4,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_00_15( 8,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_00_15(12,a,b,c,d,e,f,g,h,w);

		/* round 16 - 63 */
		FOUR_ROUND_16_63(16,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(20,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(24,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(28,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(32,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(36,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(40,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(44,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(48,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(52,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(56,a,b,c,d,e,f,g,h,w);
		FOUR_ROUND_16_63(60,a,b,c,d,e,f,g,h,w);  
#else /* else #ifdef SM3_UNROLL */ 
		i = 0;
		while ( i < 16 )
		{
			FOUR_ROUND_00_15( i,a,b,c,d,e,f,g,h,w);
			i += 4;
		}
		while (i < 64 )
		{
			FOUR_ROUND_16_63( i,a,b,c,d,e,f,g,h,w);
			i += 4;
		} 
#endif  /* end #ifdef SM3_UNROLL */ 
#endif	/* end #ifdef CALC_W_IN_ROUND_LOOP */	
		p->s[0] ^= a; p->s[1] ^= b; p->s[2] ^= c; p->s[3] ^= d;
		p->s[4] ^= e; p->s[5] ^= f; p->s[6] ^= g; p->s[7] ^= h;
		
		p_data += SM3_BLOCK_SZ;
	} 
}
 

/*******************************************************************************
函 数 名:	sm3_process_core
功能描述:	处理添加的消息 
说    明:	三段式计算消息杂凑值的第 2 步
注    意:	1. 调用者做接口参数检测
			2. 三段式计算消息杂凑值的步骤参见 sm3_init_core 的说明 
参数说明: 
	p		(in/out)SM3封装数据  
	p_data	(in)	消息数据  
	len		(in)	消息数据长度  
返 回 值:  -
修改历史: 
    1. 2014年10月30日	张文科 罗影		创建函数
    2. 2015年 2月 4日	张文科 罗影		修改函数接口
*******************************************************************************/
mm_void_t sm3_process_core(mm_sm3_ctx *p, mm_u8_t *p_data, mm_u32_t len)
{ 
	mm_u32_t pre_low;
//	mm_u8_t *p_buf = p->res_data; 
	
	if ( !len )/* len == 0 */
	{
		return;
	}

	/* 记录比特总长度 */
	pre_low = p->total_len_l;
	p->total_len_l += (len << 3);
	if ( p->total_len_l < pre_low )		
	{
		p->total_len_h++;  
	}
	
	/*只有res-len非零时才会出现和res_buf一起凑数据的情况 */
	if ( p->res_len )
	{ 
		mm_u32_t b_make_one_block = (len + p->res_len >= SM3_BLOCK_SZ) ;
		mm_u32_t copy_len = b_make_one_block ? SM3_BLOCK_SZ - p->res_len : len;
		MM_MEMCPY( p->res_data + p->res_len, p_data, copy_len);

		if( b_make_one_block )
		{
			sm3_block_core (p, p->res_data, 1);
		}
		p->res_len = (p->res_len + copy_len) % SM3_BLOCK_SZ;
		len    -= copy_len;
		p_data += copy_len; 
	}
	
	/* 按块处理输入数据 */
	if ( len >= SM3_BLOCK_SZ )
	{
		mm_i32_t loop_num = len / SM3_BLOCK_SZ;
		sm3_block_core (p, p_data, loop_num ),
		p_data += loop_num * SM3_BLOCK_SZ,
		len  %= SM3_BLOCK_SZ;
	}
	
	/* 不足一块的数据保存在缓存中 */
	if ( len )
	{
		MM_MEMCPY (p->res_data, p_data, len);
		p->res_len = len;
	} 
} 


/*******************************************************************************
函 数 名:	sm3_unit_core
功能描述:	结束杂凑，返回杂凑值 
说    明:	三段式计算消息杂凑值的第 3 步
注    意:	1. 调用者做接口参数检测
			2. 三段式计算消息杂凑值的步骤参见 sm3_init_core 的说明 
参数说明: 
	p		(in/out)SM3封装数据  
	md		(out)	杂凑值  
返 回 值:  -
修改历史: 
    1. 2014年10月30日	张文科 罗影		创建函数
    2. 2015年 2月 4日	张文科 罗影		修改函数接口
*******************************************************************************/
mm_void_t sm3_unit_core(mm_sm3_ctx *p,mm_u8_t md[SM3_HASH_BYTE_SZ] )
{
	mm_u8_t *p_buf = p->res_data;
	mm_u32_t i, n = p->res_len;
	
	p_buf[n++]=0x80;	/* There always is a room for one */

	if ( n > SM3_BLOCK_SZ - 8 )
	{
		MM_MEMSET(p_buf + n, 0x00, SM3_BLOCK_SZ - n );
		n = 0;
		sm3_block_core(p, p_buf, 1);
	}
	
	MM_MEMSET (p_buf + n, 0x00, SM3_BLOCK_SZ - 8 - n ); 
	MM_STORE_U32H(p->total_len_h, p_buf + SM3_BLOCK_SZ - 8 ); 
	MM_STORE_U32H(p->total_len_l, p_buf + SM3_BLOCK_SZ - 4 ); 
	sm3_block_core (p, p_buf, 1); 

	for (i = 0; i < 8; i++)
	{
		MM_STORE_U32H(p->s[i], md + (i<<2));
	} 
	MM_MEMSET(p, 0x00, sizeof(mm_sm3_ctx));
} 


/*******************************************************************************
函 数 名:	sm3_hash_core
功能描述:	一段式计算消息杂凑值 
说    明:	杂凑值长度为 32 字节
注    意:	一段式计算消息杂凑值只需执行 sm3_hash(***)
参数说明: 
	p_data	(in):	待杂凑数据 
	len		(in):	待杂凑数据长度
	md		(out):	杂凑值 
返 回 值:  -
修改历史: 
    1. 2014年10月30日	张文科 罗影		创建函数
    2. 2015年 2月 4日	张文科 罗影		修改函数接口
*******************************************************************************/
mm_void_t sm3_hash_core(mm_u8_t *p_data, u32_t len, mm_u8_t md[SM3_HASH_BYTE_SZ])
{
	mm_sm3_ctx ctx;  
	sm3_init_core(&ctx); 
	sm3_process_core(&ctx ,p_data, len);
	sm3_unit_core(&ctx, md); 
}
