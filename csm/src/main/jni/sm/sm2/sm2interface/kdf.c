#include "mm_macro.h" 
#include "kdf.h"
#include "sm3_core.h" 

/* 32bit: u8[0]||u8[1]||u8[2]||u8[3] += 0 || 0 || 0 || 1 */
#define INC_32BIT(u8)\
	for ( j = 3; j >= 0; j-- ){ if( ++u8[j] ) { break; } } 


/*******************************************************************************
函 数 名:	kdf
功能描述:	密钥辅助函数
说    明:	┌───┬───────┬───────┬───────┐
			│flag	│	0			│	1			│	2			│
			│功能	│	KDF			│	H1			│	H2			│
			│len	│密钥字节长度	│n的比特长度	│	n的比特长度	│
			│p_out	│  导出密钥	│	H1的字符串	│	H2的字符串	│
			└───┴───────┴───────┴───────┘
注    意:	如果是完成H1和H2的功能，那么需要注意以下几点：
			(a) 本函数只生成字符串Ha = Ha1 || ... || Ha!.hlen/v.，
				即只完成步骤1至步骤5的前半部分，
			(b)	步骤5的后半部分和步骤6需外面继续封装
				步骤5:	SM2_BN_hex2bn(sm2_bn_ha, p_out);
				步骤6:	sm2_bn_sub(n_sub_one, n, one);
						sm2_bn_mod(sm2_bn_tmp, sm2_bn_ha, n_sub_one);
						sm2_bn_add(sm2_bn_res, sm2_bn_tmp, one);
参数说明: 
	p_out			(out)	输出数据 
	p_data			(in)	输入数据
	data_byte_len	(in)	输入数据的字节长度 
	len				(in)	长度
	flag			(in)	功能标识 0/1/2
返 回 值:  1 (成功), <=0 (失败)
修改历史: 
1. 2015年 9月 1日	张文科 罗影		创建函数
*******************************************************************************/ 
int key_assist(BYTE *p_out, BYTE *p_data, int data_byte_len, int len, int flag)
{
	int j; 
	mm_sm3_ctx x, x_md;
	BYTE ctr[SM3_HASH_BYTE_SZ] = {0x0,0x0,0x0,0x01}; /* 既是计数又是SM3输出 */
 
	if(		( flag != ASSIST_FUNC_KDF )
		&&	( flag != ASSIST_FUNC_H1  )  
		&&	( flag != ASSIST_FUNC_H2  ) ) /* flag ==0,1,2 */
	{
		return -1;
	} 

	sm3_init_core(&x); 

	if( flag != ASSIST_FUNC_KDF )/* H1和H2需加一个字节0x1或0x2，KDF则无 */
	{
		BYTE tag = (BYTE)flag;
		len = 8 * ( ( 5 * len + 31 ) / 32 ); /* H1和H2的长度应为此值 */
		sm3_process_core(&x, &tag, 1);
	}
 
	sm3_process_core(&x, p_data, data_byte_len);  

	while( len > 0 )
	{ 
		MM_MEMCPY(&x_md, &x, sizeof(mm_sm3_ctx));/* x保留了前面的杂凑信息 */
		sm3_process_core(&x_md, ctr, 4); 

		if( len >= SM3_HASH_BYTE_SZ )
		{
			sm3_unit_core(&x_md, p_out );
		}
		else
		{
			sm3_unit_core(&x_md, ctr );/* 需先转存至ctr */
			MM_MEMCPY(p_out, ctr, len); 
		}

		len -= SM3_HASH_BYTE_SZ;
		p_out += SM3_HASH_BYTE_SZ; 
		INC_32BIT(ctr); /* 32bit的自加 */
	} 

	/* clear data */
	MM_MEMSET(&x,		0x00, sizeof(mm_sm3_ctx));
	MM_MEMSET(&x_md,	0x00, sizeof(mm_sm3_ctx));
	MM_MEMSET(ctr,		0x00, sizeof(ctr)); 
	return 1;
} 