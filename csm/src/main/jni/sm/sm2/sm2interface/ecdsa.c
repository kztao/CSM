//#include <stdio.h>
#include "ec.h"
#include "ec_lcl.h"
#include "ecdsa.h"
#include "ec_general.h"
#include "mm_basic_fun.h"
#include "mm_types.h"

 
/** Z值的计算见 CalcZValue(...) **/
/**   此接口加入了 SM2_ECDSA_sign() 没有进行A1,A2两个步骤 	**/
int SM2_ECDSA_sign_full(EC_GROUP *group, BYTE z[SM3_HASH_VALUE_LEN], 
					BYTE *p_msg, int msg_len, ECC_PRIVATE_KEY *p_sk,
					ECC_SIGNATURE *p_sign, BYTE rand_num[ECC_BLOCK_LEN] )	
{ 
	BYTE e[SM3_HASH_VALUE_LEN];
	
	ECDSA_CalcE(z, p_msg,msg_len, e ); 
	return SM2_ECDSA_sign( group, e, p_sk, p_sign, rand_num );
}

/* 
数字签名的生成算法
输入：M（待签名的消息）
输出：(r,s)（消息M的数字签名）
步骤：
A1：M`=ZA ∥ M；
A2：计算e = Hash(M`) 
A3：用随机数发生器产生随机数k ∈[1,n-1]；
A4：计算椭圆曲线点(x1,y1)=[k]G 
A5：计算r=(e+x1) modn，若r=0 或 r+k=n 则返回A3；
A6：计算s = ((1 + dA)exp{-1} · (k . r · dA)) modn，若s=0则返回A3；
A7：将r、s的数据类型转换为字节串，消息M 的签名为(r,s)。 
*/

/**  此接口没有进行A1,A2两个步骤，所以需要外面进行 **/
/**	Z值的计算见 CalcZValue(...) **/
int SM2_ECDSA_sign(EC_GROUP *group, BYTE e[ECC_BLOCK_LEN], ECC_PRIVATE_KEY *p_sk,
					ECC_SIGNATURE *p_sign, BYTE rand_num[ECC_BLOCK_LEN] )
{ 
	int top, top1, fail_time = 0;
	EC_POINT pt_r;
	BIGNUM sm2_bn_rand, sm2_bn_x, sm2_bn_y, sm2_bn_pt, sm2_bn_sk, sm2_bn_r, sm2_bn_s; 
	BIGNUM sm2_bn_r_add_k,sm2_bn_one,sm2_bn_one_add_da,sm2_bn_k_sub_rda;
	BIGNUM sm2_bn_temp, sm2_bn_tmp1, sm2_bn_tmp2; 
//	BYTE *p_tmp_rand = NULL;	    
/**
// 	// 产生随机数k  debug  standard use
// 	BYTE ecdsa_standard_rand_k[]= {
// 		0x6C,0xB2,0x8D,0x99,	0x38,0x5C,0x17,0x5C,	0x94,0xF9,0x4E,0x93,	0x48,0x17,0x66,0x3F, 
// 		0xC1,0x76,0xD9,0x25,	0xDD,0x72,0xB7,0x27,	0x26,0x0D,0xBA,0xAE,	0x1F,0xB2,0xF9,0x6F}; 
// 	rand_num = ecdsa_standard_rand_k;
// 	// debug  standard use end
**/

	SM2_BN_load_bn(&sm2_bn_pt, e);	/** 初始化明文  **/
	SM2_BN_load_bn(&sm2_bn_sk, p_sk->Ka); 	/** 初始化私钥 **/



	/** A1：M`=ZA ∥ M；
	* A2：计算e = Hash(M`) 
	* 此接口没有进行A1,A2两个步骤，所以需要外面进行
	**/

again:   
	if( (rand_num != NULL ) && (fail_time > 0 ) )
	{
		return -2; /** 外部输入随机数时，如果出现异常则直接退出 **/
	}

	/** A3：用随机数发生器产生随机数k ∈[1,n-1]； **/
	if( rand_num != NULL ) 
	{
		SM2_BN_load_bn(&sm2_bn_rand, rand_num); 	 
	}
	else
	{ 
		SM2_BN_init(&sm2_bn_rand); 
		GenerateRandom1((BYTE*)sm2_bn_rand.d, ECC_BLOCK_LEN); 
	}

	if( SM2_BN_is_zero(sm2_bn_rand.d, ECC_BLOCK_LEN_DWORD) )
	{
		fail_time++;
		goto again;
	}

	while(sm2_bn_rand.d[ECC_BLOCK_LEN_DWORD-1] >= group->order.d[ECC_BLOCK_LEN_DWORD-1])
	{
		sm2_bn_rand.d[ECC_BLOCK_LEN_DWORD-1] >>= 1;	
	}
 
	/** A4：计算椭圆曲线点(x1,y1)=[k]G  **/
 	SM2_EC_POINTs_mul(group, &pt_r, &group->generator, &sm2_bn_rand, NULL, NULL); 
    ec_GFp_get_aff_coords(group, &pt_r, &sm2_bn_x, &sm2_bn_y);  

	/** A5：计算r=(e+x1) modn，若r=0或r+k=n则返回A3；**/
	SM2_BN_mod_add(sm2_bn_temp.d, sm2_bn_pt.d, sm2_bn_x.d, group->order.d, group->order_top);	
    SM2_BN_div(NULL, NULL, sm2_bn_r.d, &top, sm2_bn_temp.d, group->order_top, group->order.d, group->order_top);		
	if(top == 0)
	{
		fail_time++;
		goto again;	/** r = 0  返回 **/
	}
 
	SM2_BN_mod_add(sm2_bn_r_add_k.d, sm2_bn_r.d, sm2_bn_rand.d, group->order.d, group->order_top);	
//	if(two_number_same(sm2_bn_r_add_k.d,ECC_BLOCK_LEN,group->order.d) == 0 ) 
	if(SM2_BN_ucmp(sm2_bn_r_add_k.d,ECC_BLOCK_LEN,group->order.d,ECC_BLOCK_LEN) == 0 ) 
	{
		fail_time++;
		goto again;	/**  r+k=n   返回 **/
	}

	/** A6：计算s = ((1 + dA)exp{-1} · (k - r · dA)) modn，若s=0则返回A3； **/
	//  1 + da
	SM2_BN_value_one(&sm2_bn_one);  
    SM2_BN_mod_add(sm2_bn_one_add_da.d, sm2_bn_one.d, sm2_bn_sk.d, group->order.d, group->order_top);

    /**   1+da 的逆 **/
	SM2_BN_mod_inverse(sm2_bn_tmp2.d, &top, sm2_bn_one_add_da.d, group->order_top, 
		group->order.d, group->order_top);

	//	r.da
	SM2_BN_mod_mul(sm2_bn_tmp1.d, &top, sm2_bn_sk.d, group->order_top, sm2_bn_r.d, group->order_top,
		group->order.d, group->order_top); 

	//	k - r.da 
    SM2_BN_mod_sub(sm2_bn_k_sub_rda.d, &top1, sm2_bn_rand.d, sm2_bn_tmp1.d, group->order.d, group->field_top);
	if( top1 == 0 )  
	{
		fail_time++;
		goto again;
	}

	//((1 + dA)exp{-1} · (k - r · dA)) modn
	SM2_BN_mod_mul(sm2_bn_s.d, &top,sm2_bn_k_sub_rda.d, group->order_top, sm2_bn_tmp2.d, group->order_top,
		group->order.d, group->order_top);  	
	if( top == 0 )
	{
		fail_time++;
		goto again;	//s = 0
	}

	/** A7：将r、s的数据类型转换为字节串，消息M 的签名为(r,s)。 **/
	SM2_BN_store_bn(&sm2_bn_r, p_sign->r);
	SM2_BN_store_bn(&sm2_bn_s, p_sign->s);

	return 1;
}

	 
/** 	Z值的计算见 CalcZValue(...) **/
/**   此接口加入了 SM2_ECDSA_verify() 没有进行B3,B4两个步骤 	**/
int SM2_ECDSA_verify_full(EC_GROUP *group, BYTE z[SM3_HASH_VALUE_LEN], 
					  BYTE *p_msg, int msg_len, ECC_PUBLIC_KEY *p_pk, 
					  ECC_SIGNATURE *p_sign)	
{ 
	BYTE e[SM3_HASH_VALUE_LEN];
	
	ECDSA_CalcE(z, p_msg,msg_len, e ); /** 进行B3,B4两个步骤 **/
	return SM2_ECDSA_verify( group, e, p_pk, p_sign, 0 );
}


/**
数字签名的验证算法  
输入：	M′			（收到的消息）
		(r′, s′)	（M′的数字签名）
输出：	1(检验通过) or <=0 (检验不通过)
步骤：
B1：检验r′ ∈[1,n-1]是否成立，若不成立则验证不通过；
B2：检验s′ ∈[1,n-1]是否成立，若不成立则验证不通过；
B3：置M′=ZA ∥ M′；
B4：计算e′ = Hv(M′)
B5：将r′、s′转换为整数，计算t = (r′ + s′) modn， 若t = 0，则验证不通过；
B6：计算椭圆曲线点(x1′, y1′)=[s′]G + [t]PA；
B7：将x1′转换为整数，计算R = (e′ + x1′) modn，
	检验R=r′是否成立，若成立则验证通过；否则验证不通过。 
**/
/**   此接口没有进行B3,B4两个步骤，所以需要外面进行 **/

/* B6步计算点(x1`, y1`)=[s`]G + [t]PA；采用以下方式：
	(1) 定义了 MM_SM2_USE_ALG18_TABLE, 则采用ALG18算法
	(2) 未定义 MM_SM2_USE_ALG18_TABLE, 则采用原来的算法，即两次WNAF，ALG16
	flag = 1表示使用ALG18算法，flag = 0表示不使用ALG18算法
	
	*/
int SM2_ECDSA_verify(EC_GROUP *group, BYTE e[SM3_HASH_VALUE_LEN], 
				 ECC_PUBLIC_KEY *p_pk, ECC_SIGNATURE *p_sign, int flag)
{ 
	int ret;
	BIGNUM sm2_bn_r, sm2_bn_s, sm2_bn_x, sm2_bn_y, sm2_bn_p, sm2_bn_t; 
	EC_POINT pt_r, pt_q, pt_t;


	SM2_BN_load_bn(&sm2_bn_p,	e);			/** 初始化明文  **/
	SM2_BN_load_bn(&pt_q.X, p_pk->Qx);	/** 初始化公钥 **/
	SM2_BN_load_bn(&pt_q.Y, p_pk->Qy);	/** 初始化公钥 	**/
	SM2_BN_load_bn(&sm2_bn_r,	p_sign->r); /** 初始化r **/
	SM2_BN_load_bn(&sm2_bn_s,	p_sign->s); /** 初始化s **/

	/** B1：检验r` ∈[1,n-1]是否成立，若不成立则验证不通过； **/
	if( ( ret = SM2_BN_CMP_256(&sm2_bn_r, &(group->order) ) ) >= 0 )
	{ 
		return -2; /** 验证未通过 **/
	} 					

	/** B2：检验s` ∈[1,n-1]是否成立，若不成立则验证不通过； **/
	if( ( ret = SM2_BN_CMP_256(&sm2_bn_s, &(group->order) ) ) >= 0 ) 
	{ 
		return -3; /** 验证未通过 **/
	}

	/**
	//B3：置M`=ZA || M`；	//此接口没有进行B3,B4两个步骤，所以需要外面进行
	//B4：计算e` = Hv(M`)	//此接口没有进行B3,B4两个步骤，所以需要外面进行
	**/

	/** B5：将r`、s`转换为整数，计算t = (r` + s`) modn， 若t = 0，则验证不通过； **/ 
	SM2_BN_mod_add(sm2_bn_t.d, sm2_bn_r.d, sm2_bn_s.d, group->order.d, group->order_top);
	if( ret = SM2_BN_is_zero(sm2_bn_t.d, group->order_top) )
	{
		return -4; /** 验证未通过 **/
	}

	/** B6：计算椭圆曲线点(x1`, y1`)=[s`]G + [t]PA；**/
	EcPointMapToMontgomery(&pt_q, group); 
	pt_q.Z_is_one = 0; 

	// do (x1`, y1`) = [s`]G + [t]PA；
	ret = 0;
	if( ( flag ) && ( ec_load_tables_a18(group, &pt_q) >= 0 ) )
	{/* 使用查表法加速验签，这里使用ALG18算法计算多倍点 */
		ec_GFp_pt_mul_a18(group, &pt_r, &group->generator, &sm2_bn_s, POINT_IS_GENERATOR);
		ec_GFp_pt_mul_a18(group, &pt_t, &pt_q, &sm2_bn_t, POINT_IS_PUBLIC_KEY);
		SM2_ec_GFp_simple_add(group, &pt_r, &pt_r, &pt_t); 	
		ret = 1;	 
	}
	if(!ret)
	{
		SM2_EC_POINTs_mul(group, &pt_r, &group->generator, &sm2_bn_s, &pt_q, &sm2_bn_t);  
	}

	ec_GFp_get_aff_coords(group, &pt_r, &sm2_bn_x, &sm2_bn_y); 

	/**B7：	将x1`转换为整数，计算R = (e` + x1`) modn，
	*		检验R=r`是否成立，若成立则验证通过；否则验证不通过。 
	**/
	SM2_BN_mod_add(sm2_bn_t.d, sm2_bn_p.d, sm2_bn_x.d, group->order.d, group->order_top);
	ret = SM2_BN_ucmp(sm2_bn_r.d, group->order_top, sm2_bn_t.d, group->order_top);

	return ( ret != 0 ) ? -4: 1; /** 结果不相等则验证不通过 **/
}

 

/** 如果定义了 MM_SM2_USE_ALG18_TABLE, 
*	则在调用 SM2_ECDSA_verify之前，执行本函数以完成表的制作或加载 
**/
int SM2_init_table_a18(EC_GROUP *group, ECC_PUBLIC_KEY *p_pk, int pos  )
{
	EC_POINT pt_q;

	ec_init_gp_table_a18(group);
 		
	SM2_BN_load_bn(&pt_q.X, p_pk->Qx);	/** 初始化公钥 **/
	SM2_BN_load_bn(&pt_q.Y, p_pk->Qy);	/** 初始化公钥 **/
	EcPointMapToMontgomery(&pt_q, group); 
	pt_q.Z_is_one = 0; 
	ec_init_pk_table_a18( group, &pt_q, pos); 
	return 1;
}

 
