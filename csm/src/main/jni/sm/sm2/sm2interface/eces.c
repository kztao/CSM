#include "mm_basic_fun.h"
#include "eces.h"
#include "ec.h"
#include "ec_lcl.h" 
#include "ec_general.h"
#include "sm2.h"
#include "sm3_core.h"
#include "kdf.h" 
#include "mm_sm_cfg.h"

/**
// //ECC加密值结构
// typedef struct EncDataFmt_st
// {  
// 	BYTE tag;//04 
// 	BYTE c1[ECC_BLOCK_LEN*2];
//  BYTE c2[0];//C2长度为明文长度
//  BYTE C3[SM3_HASH_VALUE_LEN];//C2结束后就是C3, C3长度为 SM3_HASH_VALUE_LEN
// }EncDataFmt;
**/

/*从密文中获取相关信息*/

#ifdef MM_SM2_CIPHPER_HAS_TAG
#define CIPHER_TAG_LEN	1	/*   有TAG的情况 */
#else
#define CIPHER_TAG_LEN	0	/* 没有TAG的情况 */
#endif

#define GET_TAG_FRM_CIPHER(p_cipher)	(p_cipher)
#define GET_C1_FRM_CIPHER(p_cipher)		((p_cipher)+CIPHER_TAG_LEN)
#define GET_C3_FRM_CIPHER(p_cipher)		(GET_C1_FRM_CIPHER(p_cipher) + ECC_BLOCK_LEN*2)
#define GET_C2_FRM_CIPHER(p_cipher)     (GET_C3_FRM_CIPHER(p_cipher) + ECC_BLOCK_LEN)
 
#if 0
void error_log(void *p1, int len1, void *p2, int len2 )
{
	static int err_counter = 0;//debug
	int i;
	char name[256];
	FILE *fp = NULL;
	sprintf(name, "d:\\zdbg\\enc_%04d.txt", err_counter++);
	fp = fopen(name, "wt");

	for (i = 0; i<len1;i++)
	{
		if(i%32 == 0)fprintf(fp, "\n");
		if(i%4 == 0)fprintf(fp, " "); 
		fprintf(fp, "%02x", ((mm_u8_t*)p1)[i]);
	}

	fprintf(fp, "\n@@@@@@@@\n");
	for (i = 0; i<len2;i++)
	{
		if(i%32 == 0)fprintf(fp, "\n");
		if(i%4 == 0)fprintf(fp, " "); 
		fprintf(fp, "%02x", ((mm_u8_t*)p2)[i]);
	}
	 
	fclose(fp);
}
#endif

/**
//	函数功能:  余因子h为 1						       //
//      ECES加密运算(p域)                  //
//	函数参数:						       //
//      group:in,曲线参数                  //
//		plain:in,明文					       //
//		p_pk:in,ECC公钥
//   int plain_len  明文长度	               //							
//		加密结果
//  ECC_ENCRYPTION *p_enc_res   加密值
//    BYTE *c1, 长度是32+32
//     BYTE *c2, 和明文等长
//      BYTE *c3  和杂凑算法输出等长，此处选用32

//
//	函数返回:							   //
//		0, 1       						   //
**/
//result_len	= ECC_BLOCK_LEN * 2 + 1 + SM3_HASH_VALUE_LEN + plain_len
//				= plain_len + 97
 

/*
加密算法
输入：	M （消息）
		klen 消息M的比特长度 
输出：	C（密文）
步骤：
A1：用随机数发生器产生随机数k∈[1,n-1]；
A2：计算点C1=[k]G=(x1,y1)，将C1转换为比特串；
A3：计算点S=[h]PB，若S是无穷远点，则报错并退出；
A4：计算点[k]PB=(x2,y2)，将坐标x2、y2 转换为比特串；
A5：计算t=KDF(x2 ∥ y2, klen)，若t为全0比特串，则返回A1；
A6：计算C2 = M ⊕ t；
A7：计算C3 = Hash(x2 ∥ M ∥ y2)；
A8：输出密文C = C1 ∥ C2 ∥ C3。
*/

/* 多倍点的计算采用以下方式：
	(1) 定义了 MM_SM2_USE_ALG18_TABLE, 则采用ALG18算法
	(2) 未定义 MM_SM2_USE_ALG18_TABLE, 则采用原来的算法，即两次WNAF，ALG16
	flag = 1表示使用ALG18算法，flag = 0表示不使用ALG18算法 
*/
 
int ECES_encrypt(EC_GROUP *group, BYTE *plain, int plain_len, ECC_PUBLIC_KEY *p_pk, 	
					BYTE *enc_data, BYTE rand_num[ECC_BLOCK_LEN], int flag )
{
	  
	int ret, fail_time = 0, table_id;
	EC_POINT R, Q;
	BIGNUM x1, y1, x2, y2;
	BIGNUM k={ /** tmp debug 固定了k值  **/
		0x3736A2F4, 0xF6779C59, 0xBDCEE36B, 0x692153D0, 
		0xA9877CC6,	0x2A474002,	0xDF32E521,	0x39F0A0BC, 0x0, 0x0};
	mm_sm3_ctx x;
	BYTE kdf_in[ECC_BLOCK_LEN*2], x2_byte[ECC_BLOCK_LEN], y2_byte[ECC_BLOCK_LEN];
	BYTE *p = NULL, *kdf_out = NULL, kdf_out0[64]; 
 


	kdf_out = ( plain_len < sizeof(kdf_out0) ) ? kdf_out0 : (BYTE*)MM_MALLOC(plain_len);
	if( kdf_out == NULL )
	{
		return -2;
	}

#ifdef MM_SM2_CIPHPER_HAS_TAG
	p = GET_TAG_FRM_CIPHER(enc_data);
	*p = 0x04;/*未压缩点的特殊标识符*/ 
#endif

	/** 初始化公钥 **/
	EC_load_pt(&Q, p_pk);
	
	EcPointMapToMontgomery(&Q, group);
    Q.Z_is_one = 1;//luoying add
	table_id = ec_load_tables_a18(group, &Q);

again:
	/** A1：用随机数发生器产生随机数k∈[1,n-1]； **/
	if( (rand_num != NULL ) && (fail_time > 0 ) )
	{
		MM_FREE(kdf_out);
		return -3;/** 外部输入随机数时，如果出现异常则直接退出 **/
	}

//    SM2_BN_load_bn(&k, rand_num);  
	if( rand_num != NULL ) 
	{
		SM2_BN_load_bn(&k, rand_num); 	 
	}
	else
	{	/** tmp debug 固定了k值 **/
		//SM2_BN_init(&k); 
		//GenerateRandom1((BYTE*)k.d, ECC_BLOCK_LEN);/** tmp debug 固定了k值 **/
		SM2_BN_init(&k); 
		GenerateRandom1((BYTE*)k.d, ECC_BLOCK_LEN);
		if( (flag) && (table_id >= 0 )) /** 定义 MM_SM2_USE_ALG18_TABLE 时, 按ALG18调整随机数 **/
		{
			ec_trim_rand_a18(&k);/**  按ALG18调整随机数 **/
		} 
		else
		{
			ec_trim_rand(&k);	/**  按 SM2_EC_POINTs_mul 调整随机数  **/
		}		 
	}

	if( SM2_BN_is_zero(k.d, ECC_BLOCK_LEN_DWORD) )
	{
		fail_time++;
		goto again;
	}		 
 
	if ( SM2_BN_ucmp(k.d, ECC_BLOCK_LEN_DWORD, group->order.d, ECC_BLOCK_LEN_DWORD) > 0 )/** 防止k太大 **/
	{
		fail_time++;
		goto again;
	}	
		
	/** A2：计算点C1=[k]G=(x1,y1)，将C1转换为比特串； **/
 
 
//	if( ( flag ) ) 
	if( 0 ) 
	{/* 使用查表法加速验签，这里使用ALG18算法计算多倍点 */
		ec_GFp_pt_mul_a18(group, &R, &group->generator, &k, POINT_IS_GENERATOR); 
	} 
	else
	{
		SM2_EC_POINTs_mul(group, &R, &group->generator, &k, NULL, NULL); 
	}

	ret = ec_GFp_get_aff_coords(group, &R, &x1, &y1); 
	if(ret<0)
	{
		fail_time++;
		goto again;
		//error_log(&k, sizeof(BIGNUM), &R, sizeof(EC_POINT) ); 
	}


	PrintData(&x1, 32,		"x1:  ", 0);
	PrintData(&y1, 32,		"y1:  ", 0); 
	
	/** 将C1转换为比特串；C1=[k]G=(x1,y1)，  **/
	p = GET_C1_FRM_CIPHER(enc_data);
	SM2_BN_store_bn(&x1, p);
	SM2_BN_store_bn(&y1, p + ECC_BLOCK_LEN);

	/** A3：计算点S=[h]PB，若S是无穷远点，则报错并退出； **/
	/** 由于设置的参数中 h = 1,所以A3步骤可以忽略 **/

	/** A4：计算点[k]PB=(x2,y2)，将坐标x2、y2 转换为比特串； **/

	ret = 0;
	if( ( flag ) && (table_id >= 0 ) )
	{/* 使用查表法加速验签，这里使用ALG18算法计算多倍点 */
		ec_GFp_pt_mul_a18(group, &R, &Q, &k, POINT_IS_PUBLIC_KEY); 
		ret = 1;
	}
	if( !ret )
	{
		SM2_EC_POINTs_mul(group, &R, &Q, &k, NULL, NULL); 
	}  

	ret = ec_GFp_get_aff_coords(group, &R, &x2, &y2); 
	if(ret<0)
	{
		fail_time++;
		goto again;
		//error_log(&k, sizeof(BIGNUM), &R, sizeof(EC_POINT) ); 
	}
	PrintData(&x2, 32,		"x2:  ", 0);
	PrintData(&y2, 32,		"y2:  ", 0);  
	
	/** A5：计算t=KDF(x2 ∥ y2, klen)，若t为全0比特串，则返回A1； **/
	SM2_BN_store_bn(&x2, kdf_in + 0);
	SM2_BN_store_bn(&y2, kdf_in + ECC_BLOCK_LEN);  
	kdf(kdf_in, ECC_BLOCK_LEN*2, plain_len, kdf_out);	 
	if(  data_is_zero( kdf_out, plain_len)  )
	{
		fail_time++;
		goto again;
	}

	/** A6：计算C2 = M XOR t； **/
	p = GET_C2_FRM_CIPHER(enc_data); 
	data_xor(p, plain, kdf_out, plain_len);	

	/** A7：计算C3 = Hash(x2 || M || y2)； **/
	SM2_BN_store_bn(&x2, x2_byte);
	SM2_BN_store_bn(&y2, y2_byte);
	p = GET_C3_FRM_CIPHER(enc_data);
	

	sm3_init_core(   &x);
	sm3_process_core(&x, x2_byte,	ECC_BLOCK_LEN);
	sm3_process_core(&x, plain,		plain_len);	 
	sm3_process_core(&x, y2_byte,	ECC_BLOCK_LEN);	
	sm3_unit_core(   &x, p);  //p=&C3[0]



//	MM_FREE(kdf_out); //20150528 luoying del
	if( kdf_out != kdf_out0 )//20150528 luoying add
	{
		MM_FREE(kdf_out); 
	}

	/** A8：输出密文C = C1 || C3 || C2 **/
	/** 见 p_fmt **/
	return 1;
}

/**
//	函数功能:							   //
//      ECES解密运算(p域)                  //
//	函数参数:							   //
//      group:in,曲线参数                  //
//		BYTE *c1, BYTE *c2,BYTE *c3,加密值	           //
//         ECCParameter   eccpa 曲线参数，用于判断C1是否在曲线上。
//  ECC_ENCRYPTION *pEncryption,
//    BYTE *c1, 长度是32+32 ，
//     BYTE *c2, 和明文等长
//      c2_len C2的长度
//      BYTE *c3  和杂凑算法输出等长，此处选用32
//		pECCSK:in,ECC私钥                  //							
//		msg:out,明文				           //
//	函数返回:							   //
//		0 不成功；
//      1  成功     					   //
**/

/*
解密算法
输入：	C（密文，C=C1 ∥ C2 ∥ C3）
		klen（密文中C2的比特长度）
步骤：
B1：从C中取出比特串C1，将C1转换为点，验证C1是否满足曲线方程，若不满足则报错并退出；
B2：计算椭圆曲线点S=[h]C1，若S是无穷远点，则报错并退出；
B3：计算[dB]C1=(x2,y2)，将坐标x2、y2转换为比特串；
B4：计算t=KDF(x2 ∥ y2, klen)，若t为全0比特串，则报错并退出；
B5：从C中取出比特串C2，计算M′ = C2 ⊕ t；
B6：计算u = Hash(x2 ∥ M′ ∥ y2)，从C中取出比特串C3，若u .= C3，则报错并退出；
B7：输出明文M′。
*/

// enc_data_len	= ECC_BLOCK_LEN * 2 + 1 + SM3_HASH_VALUE_LEN + plain_len = plain_len + 97
// msg_len = enc_data_len - 97
int  ECES_decrypt(EC_GROUP *group, BYTE *enc_data, int enc_data_len,
					 ECC_PRIVATE_KEY *pECCSK, BYTE *msg, 
					 ECCParameter *pECCPara)
{ 
	const int pad_len = ECC_BLOCK_LEN * 2 + CIPHER_TAG_LEN + SM3_HASH_VALUE_LEN; 
	int c2_len = enc_data_len - pad_len,  ret = 0;
	EC_POINT pt_r, pt_q;
	BIGNUM sm2_bn_x2,  sm2_bn_y2, sm2_bn_sk; 
	BYTE  *p = NULL, *p_c2_kdf = NULL, x2_y2[ECC_BLOCK_LEN*2], u[ECC_BLOCK_LEN];
	ECC_PUBLIC_KEY pt_c1;   
	mm_sm3_ctx x; 
	BYTE c2_kdf0[256+16];//20150528 luoying add

	/** 0. 创建数据 **/
	//20150528 luoying change from
// 	if((p_c2_kdf =(BYTE*)MM_MALLOC(c2_len)) == NULL)
// 	{
// 		ret = -2;//_err_sm2_new_mem_failture; 
// 		goto _err_ECES_Decryption;
// 	}
	//20150528 luoying change to	
	p_c2_kdf =( c2_len < sizeof(c2_kdf0) ) ? c2_kdf0 : (BYTE*)MM_MALLOC(c2_len);
	if( p_c2_kdf == NULL)
	{
		ret = -2;//_err_sm2_new_mem_failture; 
		goto _err_ECES_Decryption;
	}
	//20150528 luoying change end


#ifdef MM_SM2_CIPHPER_HAS_TAG
	/** B1：从C中取出比特串C1，将C1转换为点，验证C1是否满足曲线方程，若不满足则报错并退出； **/
	p = GET_TAG_FRM_CIPHER(enc_data);
	if ( *p != 0x04 )/** 点的特殊标示 **/
	{
		ret = -3;//_err_sm2_c1_tag_error;
		goto _err_ECES_Decryption;
	}
#else /*#ifdef CIPHER_HAS_NOT_TAG*/
	/** 此时不检测tag  **/
#endif

	p = GET_C1_FRM_CIPHER(enc_data);
	MM_MEMCPY(pt_c1.Qx, p, ECC_BLOCK_LEN);	  
	MM_MEMCPY(pt_c1.Qy, p+ECC_BLOCK_LEN, ECC_BLOCK_LEN); 

	if(		( MM_VALID_PT(pECCPara) )/* 曲线参数有效的时候才检查 */
		&&	( !EC_point_is_on_curve(pECCPara, &pt_c1) ) )
	{
		ret = -4;//_err_sm2_point_not_on_curve;
		goto _err_ECES_Decryption;
	} 
 
	/** B2：计算椭圆曲线点S=[h]C1，若S是无穷远点，则报错并退出； 
	* 略,因为选取的h = 1
	**/
	 
	/** B3：计算[dB]C1=(x2,y2)，将坐标x2、y2转换为比特串； **/
	/**  3.1 初始化私钥 **/
	SM2_BN_load_bn(&sm2_bn_sk, pECCSK->Ka); 

	p = GET_C1_FRM_CIPHER(enc_data);
	EC_POINT_init(&pt_q); 
	SM2_BN_load_bn(&pt_q.X, p );
	SM2_BN_load_bn(&pt_q.Y, p + ECC_BLOCK_LEN ); 
	EcPointMapToMontgomery(&pt_q, group);
	pt_q.Z_is_one=1;	
	   
	/**  3.2 计算(x2,y2 )=[dB]C1 **/
	SM2_EC_POINTs_mul(group, &pt_r, &pt_q, &sm2_bn_sk, NULL,NULL); 
	ec_GFp_get_aff_coords(group, &pt_r, &sm2_bn_x2, &sm2_bn_y2);
	PrintData(&sm2_bn_x2, 32, "[dec] x2:", 0);
	PrintData(&sm2_bn_y2, 32, "[dec] y2:", 0);   
	
	/** B4：计算t=KDF(x2 ∥ y2, klen)，若t为全0比特串，则报错并退出； **/ 
	// 4.1	t = KDF(x2||y2, klen) 
	SM2_BN_store_bn(&sm2_bn_x2, x2_y2);
	SM2_BN_store_bn(&sm2_bn_y2, x2_y2+ECC_BLOCK_LEN);  
	kdf(x2_y2,ECC_BLOCK_LEN*2, c2_len, p_c2_kdf);
	PrintData(p_c2_kdf, c2_len, "[dec] kdf:", 0); 

	if ( data_is_zero(p_c2_kdf, c2_len) )/** 若t为全0比特串，则报错并退出； **/
	{
		ret = -5;//_err_sm2_kdf_output_is_zero;
		goto _err_ECES_Decryption;
	}
		
	/** B5：从C中取出比特串C2，计算M′ = C2 ⊕ t； **/
	p = GET_C2_FRM_CIPHER(enc_data);
	data_xor(msg, p, p_c2_kdf, c2_len);
	PrintData(msg, c2_len, "[dec] msg:", 0);   
			    
	/** B6：计算u = Hash(x2 ∥ M′ ∥ y2)，从C中取出比特串C3，若u != C3，则报错退出； **/
	sm3_init_core( &x );
	sm3_process_core(&x, x2_y2, ECC_BLOCK_LEN);
	sm3_process_core(&x, msg, c2_len); 
	sm3_process_core(&x, x2_y2+ECC_BLOCK_LEN, ECC_BLOCK_LEN);
	sm3_unit_core( &x, u); 
	PrintData(u, 32, "[dec] hash_out:", 0);   

	p = GET_C3_FRM_CIPHER(enc_data);
	if(MM_MEMCMP(u, p, ECC_BLOCK_LEN) != 0 )/** 若u != C3，则报错退出； **/
	{
		ret = -6;//_err_sm2_hash_output_not_match;
		goto _err_ECES_Decryption;
	}
		   
	ret = 1;

	/** B7：输出明文M′ ( B5步骤完成 ) **/
	
_err_ECES_Decryption:	
//	MM_FREE(p_c2_kdf);			//20150528 luoying del
	if( p_c2_kdf != c2_kdf0 )	//20150528 luoying add
	{
		MM_FREE(p_c2_kdf);
	}

	return ret;
} 


