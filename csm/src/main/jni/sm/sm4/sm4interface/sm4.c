
#include <stdlib.h>
#include <string.h> 
#include "sm4.h"
#include "sm4_core.h"  
#include "mm_macro.h"

#define SM4_VALID_LEN(len) ( ( (len) % SM4_BLOCK_LEN ) == 0 )  
#define SAFE_FREE(ptr)  { if (ptr != NULL) { free(ptr); ptr = NULL;} }

/** 注意 des = des XOR src **/
#define XOR_128BIT_2(des, src)\
{\
	((mm_u32_t *)des)[0] ^= ((mm_u32_t *)src)[0];\
	((mm_u32_t *)des)[1] ^= ((mm_u32_t *)src)[1];\
	((mm_u32_t *)des)[2] ^= ((mm_u32_t *)src)[2];\
	((mm_u32_t *)des)[3] ^= ((mm_u32_t *)src)[3];\
}

/** 注意 des = src1 XOR src2 **/
#define XOR_128BIT_3(des, src1, src2)\
{\
	((mm_u32_t *)des)[0] = ((mm_u32_t *)src1)[0] ^ ((mm_u32_t *)src2)[0];\
	((mm_u32_t *)des)[1] = ((mm_u32_t *)src1)[1] ^ ((mm_u32_t *)src2)[1];\
	((mm_u32_t *)des)[2] = ((mm_u32_t *)src1)[2] ^ ((mm_u32_t *)src2)[2];\
	((mm_u32_t *)des)[3] = ((mm_u32_t *)src1)[3] ^ ((mm_u32_t *)src2)[3];\
}

/** 注意 des = src1 XOR src2 @ bytes **/
#define XOR_BYTES(des, src1, src2, len)\
{\
	mm_u32_t tmp_i;\
	for (tmp_i = 0;tmp_i<(len); tmp_i++){\
	(des)[tmp_i] = (src1)[tmp_i] ^ (src2)[tmp_i];\
	}\
}

mm_handle sm4_init(	mm_u8_t key[SM4_KEY_LEN] ) 
{
	sm4_ctx *p = NULL;
	if ( MM_VALID_PT( key )  )
	{
		p = (sm4_ctx*)MM_MALLOC(sizeof(sm4_ctx));
		if( MM_VALID_PT(p))
		{ 	
			MM_MEMSET(p, 0x00, sizeof(sm4_ctx));
			sm4_key_expand(key, SM4_GET_ENC_SKEY(p), SM4_GET_DEC_SKEY(p)); 
		}
	}
	return p;
}

mm_void_t sm4_unit( mm_handle h )
{
	if ( MM_VALID_PT( h )  )
	{
		MM_MEMSET(h, 0x00, sizeof(sm4_ctx));
		MM_FREE(h);
	}
}

mm_i32_t  sm4_set_iv( mm_handle h, mm_u8_t iv[SM4_BLOCK_LEN] )
{
	if ( MM_VALID_PT( h ) && MM_VALID_PT( iv ) )
	{
		MM_MEMCPY( SM4_GET_PRE_CT(h), iv, SM4_BLOCK_LEN); 
		((sm4_ctx*)h)->not_aligned_tm = 0;//20160125 fix
		return 1;
	} 
	return -1; 
}

mm_i32_t sm4_ecb_encrypt(mm_handle h, mm_u8_t *pin, mm_u32_t len, mm_u8_t *pout)
{
	if (	MM_VALID_PT( h ) 
		&&	MM_VALID_PT( pin ) 
		&&  MM_VALID_PT( pout ) 
		&&	SM4_VALID_LEN(len )	 )
	{  
		mm_u32_t *p_enc_rk = SM4_GET_ENC_SKEY(h);
		while ( len > 0 )
		{ 
			sm4_enc_dec(p_enc_rk, pin, pout );
			pin  += SM4_BLOCK_LEN;
			pout += SM4_BLOCK_LEN;
			len	 -= SM4_BLOCK_LEN;
		} 
		return 1; 			
	} 
	return -1;
}

/**  使用ECB模式解密 **/
mm_i32_t sm4_ecb_decrypt(mm_handle h, mm_u8_t *pin, mm_u32_t len, mm_u8_t *pout)
{
	if (	MM_VALID_PT( h ) 
		&&	MM_VALID_PT( pin ) 
		&&  MM_VALID_PT( pout ) 
		&&	SM4_VALID_LEN(len )	 )
	{  	
		mm_u32_t *p_dec_rk = SM4_GET_DEC_SKEY(h);
		while ( len > 0 )
		{ 
			sm4_enc_dec(p_dec_rk, pin, pout );
			pin  += SM4_BLOCK_LEN;
			pout += SM4_BLOCK_LEN;
			len	 -= SM4_BLOCK_LEN;
		} 
		return 1; 			
	} 
	return -1; 
}


/**  使用CBC模式加密 **/
mm_i32_t sm4_cbc_encrypt(mm_handle h, mm_u8_t *pin, mm_u32_t len, mm_u8_t *pout)
{
	if (	MM_VALID_PT( h ) 
		&&	MM_VALID_PT( pin ) 
		&&  MM_VALID_PT( pout ) 
		&&	SM4_VALID_LEN(len )	 )
	{ 
		mm_u32_t *p_enc_rk = SM4_GET_ENC_SKEY(h);
		mm_u8_t  *p_pre_ct = SM4_GET_PRE_CT(h); 
	
		while ( len )  
		{
			XOR_128BIT_2(p_pre_ct, pin);   
			sm4_enc_dec(p_enc_rk, p_pre_ct, pout  );  
			MM_MEMCPY(p_pre_ct, pout, SM4_BLOCK_LEN); 
			
			pout += SM4_BLOCK_LEN;
			pin  += SM4_BLOCK_LEN;
			len  -= SM4_BLOCK_LEN; 
		} 
		return 1;
	} 
	return -1; 
}

mm_i32_t sm4_cbc_decrypt(mm_handle h, mm_u8_t *pin, mm_u32_t len, mm_u8_t *pout)
{
	if (	MM_VALID_PT( h ) 
		&&	MM_VALID_PT( pin ) 
		&&  MM_VALID_PT( pout ) 
		&&	SM4_VALID_LEN(len )	 )
	{ 
		mm_u32_t *p_dec_rk = SM4_GET_DEC_SKEY(h);
		mm_u8_t  *p_pre_ct = SM4_GET_PRE_CT(h);  

		while (len) 
		{ 
			sm4_enc_dec(p_dec_rk, pin, pout ); 		
			XOR_128BIT_2(pout, p_pre_ct);  
			MM_MEMCPY(p_pre_ct, pin, SM4_BLOCK_LEN); 
				
			pin  += SM4_BLOCK_LEN;
			pout += SM4_BLOCK_LEN;
			len  -= SM4_BLOCK_LEN; 
		}
		return 1;
	}
	return -1; 
} 




/**  使用OFB模式加密 **/
mm_i32_t sm4_ofb_encrypt(mm_handle h, mm_u8_t *pin, mm_u32_t len, mm_u8_t *pout)
{
	mm_i32_t flag = MM_VALID_PT(h) && MM_VALID_PT(pin) &&  MM_VALID_PT(pout);
	if ( !flag )
	{
		return -1;
	} 
	else if(((sm4_ctx*)h)->not_aligned_tm )
	{
		return -2;/* 只能在最后一次调用时允许长度不是16字节的整数倍 */
	}
	else
	{ 
		mm_i32_t times = (mm_i32_t)(len >> 4);/* times = len / SM4_BLOCK_LEN */
		mm_u32_t *p_enc_rk = SM4_GET_ENC_SKEY(h);
		mm_u8_t  pre_ct[SM4_BLOCK_LEN]; 

		MM_MEMCPY( pre_ct, SM4_GET_PRE_CT(h), SM4_BLOCK_LEN);

		while ( times-- )  
		{ 
			sm4_enc_dec(p_enc_rk, pre_ct, pre_ct  );  
			XOR_128BIT_3(pout, pre_ct, pin);  
			pout += SM4_BLOCK_LEN;
			pin  += SM4_BLOCK_LEN; 
		} 

		len &= 0x0F;//20160125 fix
		if ( len )
		{
			sm4_enc_dec(p_enc_rk, pre_ct, pre_ct  );  
			XOR_BYTES(pout, pre_ct, pin, len);
			((sm4_ctx*)h)->not_aligned_tm++;
		}

		MM_MEMCPY( SM4_GET_PRE_CT(h), pre_ct, SM4_BLOCK_LEN);
		return 1;
	}  
}

/**  使用OFB模式解密 **/
mm_i32_t sm4_ofb_decrypt(mm_handle h, mm_u8_t *pin, mm_u32_t len, mm_u8_t *pout)
{
	return sm4_ofb_encrypt(h, pin, len, pout);
}

static mm_i32_t xor_crypt(mm_u8_t *inOrOutData, mm_u32_t inDataLength, mm_u8_t *key, mm_u32_t keyLength)
{
	mm_i32_t i = 0;
	
	if(inOrOutData == NULL || key == NULL){  
        return -1;
    } 

	//xor
	for (i = 0; i < inDataLength; i++)
	{
		inOrOutData[i]^=key[i];
	}

	return 0;
}

#if 0
mm_i32_t sm4_cmac(mm_handle sm4_handle,	mm_u8_t *pin, mm_i32_t ilen, mm_u8_t pout[SM4_BLOCK_LEN]) 
{
	int ret = -1;
    int i,outl;
    int ps_size = 0;
    mm_u8_t* p_crypt_data = NULL; 
    int p_crypt_data_len = 0;
    mm_u8_t H_tmp[SM4_BLOCK_LEN] = {0};

    mm_u8_t tmp_data[SM4_BLOCK_LEN] = {0};
    int blockCount = 0;
	
	if(NULL == pin || NULL == sm4_handle || 0 == ilen)
	{
		return -1;
	}
	
    /* 先进行填充，无论是否16字节对齐，都进行8000的填充 */
    ps_size = SM4_BLOCK_LEN - (ilen % SM4_BLOCK_LEN);
	p_crypt_data_len = ilen + ps_size;
	p_crypt_data = (mm_u8_t*)malloc(p_crypt_data_len);
	if(NULL == p_crypt_data)
	{
       ret = -1;
       goto out;
	}

	memset(p_crypt_data, 0, p_crypt_data_len);
	memcpy(p_crypt_data, pin, ilen);
	p_crypt_data[ilen] = (mm_u8_t)(0x80);

	blockCount = p_crypt_data_len / SM4_BLOCK_LEN;
	for (i=0; i<blockCount; i++) 
	{
        ret = xor_crypt(H_tmp, SM4_BLOCK_LEN, p_crypt_data+ i * SM4_BLOCK_LEN, SM4_BLOCK_LEN);
        if(0 != ret)
        {
           SAFE_FREE(p_crypt_data);
		   return -1;
        }
        memcpy(tmp_data, H_tmp, SM4_BLOCK_LEN);
#if SM4_CBC_MAC
		ret = sm4_cbc_encrypt(sm4_handle, tmp_data, SM4_BLOCK_LEN, H_tmp);
#else
		ret = sm4_ecb_encrypt(sm4_handle, tmp_data, SM4_BLOCK_LEN, H_tmp);
#endif
		if(ret < 0)
		{
			SAFE_FREE(p_crypt_data);
			return -1;
		}
	}
	memcpy(pout, H_tmp, SM4_BLOCK_LEN);

	return 0;
}

/* p.s.: 长度需要是16字节的倍数，需要传入之前计算得到的中间结果 */
mm_i32_t sm4_cmac_process(mm_handle sm4_handle,	mm_u8_t *pin, mm_i32_t ilen, mm_u8_t pInOut[SM4_BLOCK_LEN]) 
{
	int ret = -1;
	int i = 0;
	mm_u8_t H_tmp[SM4_BLOCK_LEN] = {0};

	mm_u8_t tmp_data[SM4_BLOCK_LEN] = {0};
	int blockCount = 0;
	
	if(NULL == pin || NULL == sm4_handle || 0 == ilen)
	{
		return -1;
	}
	
	memcpy(H_tmp, pInOut, SM4_BLOCK_LEN);
	blockCount = ilen / SM4_BLOCK_LEN;
	for (i=0; i<blockCount; i++) 
	{
		ret = xor_crypt(H_tmp, SM4_BLOCK_LEN, pin+ i * SM4_BLOCK_LEN, SM4_BLOCK_LEN);
		if(0 != ret)
		{
			return -1;
		}
		memcpy(tmp_data, H_tmp, SM4_BLOCK_LEN);
#if SM4_CBC_MAC
		ret = sm4_cbc_encrypt(sm4_handle, tmp_data, SM4_BLOCK_LEN, H_tmp);
#else
		ret = sm4_ecb_encrypt(sm4_handle, tmp_data, SM4_BLOCK_LEN, H_tmp);
#endif
		if(ret < 0)
		{
			return -1;
		}
	}
	
	memcpy(pInOut, H_tmp, SM4_BLOCK_LEN);

	return 0;
}
#endif

#define SM4_CRYPT_DATA_LEN  0x8000
mm_i32_t sm4_cmac(mm_handle sm4_handle,	mm_u8_t *pin, mm_i32_t ilen, mm_u8_t pout[SM4_BLOCK_LEN]) 
{
	int ret = -1;
    int i = 0;
    //mm_u8_t H_tmp[SM4_BLOCK_LEN] = {0};

    mm_u8_t tmp_data[SM4_CRYPT_DATA_LEN] = {0};
    int blockCount = 0;
	
	if(NULL == pin || NULL == sm4_handle || 0 == ilen || ilen > SM4_CRYPT_DATA_LEN)
	{
		return -1;
	}

	if((ilen % SM4_BLOCK_LEN) != 0)
	{
		return -1;
	}
    
	//blockCount = ilen / SM4_BLOCK_LEN;
	//memcpy(tmp_data, pin, ilen);
	ret = sm4_cbc_encrypt(sm4_handle, pin, ilen, tmp_data);
	if(ret < 0)
	{
		return -1;
	}

	memcpy(pout, &tmp_data[ilen-SM4_BLOCK_LEN], SM4_BLOCK_LEN);
	return 0;
}

/* p.s.: 长度需要是16字节的倍数，需要传入之前计算得到的中间结果 */
mm_i32_t sm4_cmac_process(mm_handle sm4_handle,	mm_u8_t *pin, mm_i32_t ilen, mm_u8_t pInOut[SM4_BLOCK_LEN]) 
{
	int ret = -1;
	int i = 0;

	mm_u8_t tmp_data[SM4_CRYPT_DATA_LEN] = {0};
    int blockCount = 0;
	
	if(NULL == pin || NULL == sm4_handle || 0 == ilen || ilen > SM4_CRYPT_DATA_LEN)
	{
		return -1;
	}

	if((ilen % SM4_BLOCK_LEN) != 0)
	{
		return -1;
	}
    
	//blockCount = ilen / SM4_BLOCK_LEN;
	//memcpy(tmp_data, pin, ilen);
	ret = sm4_cbc_encrypt(sm4_handle, pin, ilen, tmp_data);
	if(ret < 0)
	{
		return -1;
	}

	memcpy(pInOut, &tmp_data[ilen-SM4_BLOCK_LEN], SM4_BLOCK_LEN);
	return 0;
}

