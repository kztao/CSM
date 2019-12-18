/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: sm3.c
文件描述: SM3杂凑算法实现
创 建 者: 张文科 罗影
创建时间: 2014年10月30日
修改历史:
1. 2014年10月30日   张文科 罗影     创建文件 
*******************************************************************************/


/* ------------------------ 头文件包含区 开始 ------------------------------- */

#include "mm_macro.h"
#include "sm3.h"
 


/* ======================== 头文件包含区 结束 =============================== */


/* ------------------------ 公共宏定义区 开始 ------------------------------- */
 

/* ======================== 公共宏定义区 结束 =============================== */


/* ------------------------ 公共类型定义区 开始 ----------------------------- */
 

/* ======================== 公共类型定义区 结束 ============================= */


/*******************************************************************************
函 数 名:   sm3_init
功能描述:   初始化SM3 
说    明:   三段式计算消息杂凑值的第 1 步
注    意:   三段式计算消息杂凑值，请严格按照以下步骤执行
            第 1 步 sm3_init(***);          // 初始化
            第 2 步 while(msg_not_end){
                        sm3_process(***);   // 消息可分多次添加
                    }
            第 3 步 sm3_unit(***);          // 输出杂凑值
参数说明:   -
返 回 值:  非零句柄 [成功],  NULL [失败]
修改历史: 
    1. 2014年10月30日   张文科 罗影     创建函数
    2. 2015年 2月 4日   张文科 罗影     修改函数接口
*******************************************************************************/
 
mm_handle sm3_init( )
{
    mm_sm3_ctx *p = (mm_sm3_ctx *)MM_MALLOC(sizeof(mm_sm3_ctx)); 
    
    if ( MM_VALID_PT(p) )
    {
        sm3_init_core(p);
    } 
    return p; 
}


/*******************************************************************************
函 数 名:   sm3_process
功能描述:   处理消息  
说    明:   三段式计算消息杂凑值的第 2 步
注    意:   三段式计算步骤见 sm3_init() 的说明 
参数说明: 
    h(in/out):  句柄 
    p_data(in): 待杂凑数据 
    len(in):    待杂凑数据的长度
返 回 值:  成功返回MM_OK，失败返回MM_ERROR或其他负数.
修改历史: 
    1. 2014年10月30日   张文科 罗影     创建函数
    2. 2015年 2月 4日   张文科 罗影     修改函数接口
*******************************************************************************/

mm_i32_t sm3_process(mm_handle h, mm_u8_t* p_data, mm_u32_t len)
{
    mm_i32_t flag = -1;

    if( MM_VALID_PT(h) && MM_VALID_PT(p_data) )
    {
        sm3_process_core((mm_sm3_ctx *)h, p_data, len);
        flag = 1;
    }
    return flag;
}


/*******************************************************************************
函 数 名:   sm3_unit
功能描述:   完成杂凑，返回最终杂凑值 
说    明:   1. 三段式计算消息杂凑值的第 3 步
            2. 杂凑值长度为 32 字节
            3. h 在执行本函数后为悬垂指针，不可再用。 
注    意:   三段式计算步骤见 mm_sm3_init() 的说明 
参数说明: 
    h   (in/out)句柄  
    md  (out)   杂凑值 
返 回 值:  -
修改历史: 
    1. 2014年10月30日   张文科 罗影     创建函数
    2. 2015年 2月 4日   张文科 罗影     修改函数接口
*******************************************************************************/

mm_i32_t sm3_unit(mm_handle h, mm_u8_t md[SM3_HASH_BYTE_SZ])
{
    mm_i32_t flag = -1;

    if( MM_VALID_PT(h) && MM_VALID_PT(md) )
    {
        sm3_unit_core((mm_sm3_ctx *)h, md);
        MM_MEMSET(h, 0x00, sizeof(mm_sm3_ctx));
        MM_FREE(h);
        flag = 1;
    }
    return flag;
}
 

/*******************************************************************************
函 数 名:   sm3_hash
功能描述:   一段式计算消息杂凑值 
说    明:   杂凑值长度为 32 字节
注    意:   一段式计算消息杂凑值只需执行 sm3_hash(***)
参数说明: 
    p_data  (in)    待杂凑数据 
    len     (in)    待杂凑数据的长度
    md      (out)   杂凑值 
返 回 值:  1 [成功], <-0 [失败]
修改历史: 
    1. 2014年10月30日   张文科 罗影     创建函数
    2. 2015年 2月 4日   张文科 罗影     修改函数接口
*******************************************************************************/

mm_i32_t sm3_hash(mm_u8_t *p_data, mm_u32_t len, mm_u8_t md[SM3_HASH_BYTE_SZ])
{
    mm_i32_t flag = -1;
    
    if( MM_VALID_PT(p_data) && MM_VALID_PT(md) )
    {
        sm3_hash_core(p_data, len, md);
        flag = 1;
    }
    return flag;
}

void sm3_hmac_starts(mm_sm3_hmac_ctx *ctx, mm_u8_t *key, mm_i32_t keylen)
{
	void *sm3_handle = NULL;
	mm_i32_t i = 0;
    mm_u8_t sum[SM3_HASH_BYTE_SZ];

    memset(sum, 0, SM3_HASH_BYTE_SZ);

    if (keylen > 64)
	{
        sm3_hash(key, keylen, sum);
        keylen = SM3_HASH_BYTE_SZ;
        //keylen = ( is224 ) ? 28 : 32;
        key = sum;
    }

    memset(ctx->ipad, 0x36, 64);
    memset(ctx->opad, 0x5C, 64);

    for (i = 0; i < keylen; i++) 
	{
        ctx->ipad[i] = (mm_u8_t) (ctx->ipad[i] ^ key[i]);
        ctx->opad[i] = (mm_u8_t) (ctx->opad[i] ^ key[i]);
    }

    sm3_handle = sm3_init();
    sm3_process(sm3_handle, ctx->ipad, 64);
    ctx->handle = sm3_handle;

    memset(sum, 0, sizeof(sum));
	
	return;
}

/*
 * SM3 HMAC process buffer
 */
void sm3_hmac_update(mm_sm3_hmac_ctx *ctx, mm_u8_t *input, mm_i32_t ilen)
{
    sm3_process(ctx->handle, input, ilen);
	
	return;
}

/*
 * SM3 HMAC final digest
 */
void sm3_hmac_finish(mm_sm3_hmac_ctx *ctx, mm_u8_t output[SM3_HASH_BYTE_SZ])
{
	void* sm3_handle = NULL;
	mm_i32_t hlen = 0;
    mm_u8_t tmpbuf[SM3_HASH_BYTE_SZ];

    memset(tmpbuf, 0, SM3_HASH_BYTE_SZ);
    hlen = SM3_HASH_BYTE_SZ;

    sm3_unit(ctx->handle, tmpbuf);
	sm3_handle = sm3_init();
    ctx->handle = sm3_handle;
    sm3_process(ctx->handle, ctx->opad, 64);
    sm3_process(ctx->handle, tmpbuf, hlen);
    sm3_unit(ctx->handle,output);

    memset(tmpbuf, 0, sizeof(tmpbuf));
	
	return;
}

/*
 * output = HMAC-SM#( hmac key, input buffer )
 */
void sm3_hmac(mm_u8_t *key, mm_i32_t keylen,
			mm_u8_t *input, mm_i32_t ilen,
			mm_u8_t output[SM3_HASH_BYTE_SZ]) {
	mm_sm3_hmac_ctx ctx;

    sm3_hmac_starts(&ctx, key, keylen);
    sm3_hmac_update(&ctx, input, ilen);
    sm3_hmac_finish(&ctx, output);

    memset(&ctx, 0, sizeof(mm_sm3_hmac_ctx));
}
 

