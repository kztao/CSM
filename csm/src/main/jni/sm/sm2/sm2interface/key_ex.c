#include "mm_basic_fun.h"
#include "key_ex.h" 
#include "sm2.h" 
#include "kdf.h"   
//#include "mm_sm3.h"
#include "ec_general.h"

 

 


void CalcBnTrunc(BIGNUM  *p_sm2_bn_runc, BIGNUM  *p_bn)
{ 
	// x1_trunc = 2exp(w) + ( x1 & ( 2exp(w) - 1 ))； 
	MM_MEMSET(p_sm2_bn_runc, 0x00, sizeof(BIGNUM));
	MM_MEMCPY(p_sm2_bn_runc->d,p_bn->d,  16);/** w = 127, 所以 复制 128 bit **/
	p_sm2_bn_runc->d[3] |= 0x80000000;/** 第 127 bit 置 1 ; **/
}
/**
// 秘钥交换中任意一方的流程如下
//（在最后一步时会区分用户是发起方还是响应方）

//	准备阶段
// 0	计算 Z_self, Z_anti

//	第一次数据交换
// 1	产生随机数 r_self ∈ [1, n-1]；
// 2	计算点 R_self = [r_self]G=(x1;y1)； 
// 3	计算 x1_trunc = 2exp(w) + ( x1 & ( 2exp(w) - 1 ))；
// 4	计算 t_self = (d_self + x1_trunc · r_self) modn；// d_self为己方私钥
// 5	第一次数据交换：将 R_self 发送给对方，从对方获取 R_anti 

//	交换后计算协商秘钥
// 6	验证 R_anti 是否满足椭圆曲线方程，
//		若不满足则协商失败；
//		否则从 R_anti = (x2, y2) 中取出 x2 转换为整数，
//		计算 x2_trunc = 2exp(w) + ( x2 & ( 2exp(w) - 1 ))；
// 7	计算椭圆曲线点 U = [h · t_self ](PB + [ x2_trunc ] R_anti ) = (xU;yU) ，
//		若U是无穷远点，则A协商失败； 
//		否则将xU、yU为比特串；
// 8	计算K_share = KDF( xU || yU || Z_initiator || Z_responder, klen)；
//		若己方为发起者，则 Z_initiator 为Z_self
**/

int ECKA_set_ka_param(KaInnerPara *p_kainr, ECCParameter *p_ecprm, KaParameter *p_ka)
{  
//	p_kainr->reverse_cpy = 1;
	p_kainr->self_is_initiator = p_ka->self_is_initiator;
	SM2_BN_load_bn(&p_kainr->sm2_bn_self_sk,	p_ka->p_self_sk->Ka ); 
	EC_load_pt(&p_kainr->pt_self_pk,	p_ka->p_self_pk ); 
	EC_load_pt(&p_kainr->pt_anti_pk,	p_ka->p_anti_pk ); 
	MM_MEMSET(&p_kainr->sm2_bn_t_self,	0x00, sizeof(BIGNUM));/** CalcKaExData() 中计算 **/
	
	/**  0	计算 Z_self, Z_anti **/
	CalcZValue(p_ecprm, p_ka->p_anti_id, p_ka->anti_id_len, p_ka->p_anti_pk, p_kainr->anti_z_value );
	CalcZValue(p_ecprm, p_ka->p_self_id, p_ka->self_id_len, p_ka->p_self_pk, p_kainr->self_z_value );

	PrintData(p_kainr->anti_z_value, 32, "anti_z_value", 0);/** Z为HASH值，无需逆序打印 **/
	PrintData(p_kainr->self_z_value, 32, "self_z_value", 0);/** Z为HASH值，无需逆序打印 **/

	/** 标准中P256示例的ZA 和 ZB **/
	//ZA：E4D1D0C3 CA4C7F11 BC8FF8CB 3F4C02A7 8F108FA0 98E51A66 8487240F 75E20F31
	//ZB：6B4B6D0E 276691BD 4A11BF72 F4FB501A E309FDAC B72FA6CC 336E6656 119ABD67
	return 1;
}

 
int ECKA_calc_ka_ex_data(EC_GROUP *p_grp, KaInnerPara *p_kainr, 
						 ECC_PUBLIC_KEY *p_ex_data, BYTE rand[ECC_RAND_NUM_LEN])
{   
	EC_POINT pt_self; 
	BIGNUM sm2_bn_rand, sm2_bn_x1, sm2_bn_x1_trunc, sm2_bn_y1, sm2_bn_mod_res;  
	int /*reverse_cpy = p_kainr->reverse_cpy,*/ odr_top = p_grp->order_top, sm2_bn_top;

	SM2_BN_init(&sm2_bn_rand); 
	SM2_BN_init(&sm2_bn_x1); 
	SM2_BN_init(&sm2_bn_y1);  
	SM2_BN_init(&sm2_bn_mod_res); 
	SM2_BN_init(&sm2_bn_x1_trunc); 
	EC_POINT_init(&pt_self); 
		
	/**  1	产生随机数 r_self ∈ [1, n-1]； **/
	if( rand != NULL )
	{
		SM2_BN_load_bn(&sm2_bn_rand, rand);
	}
	else
	{
		GenerateRandom1(sm2_bn_rand.d, ECC_BLOCK_LEN);
	}
	/**  2	计算点 R_self = [r_self]G=(x1;y1)； **/
	SM2_EC_POINTs_mul(p_grp, &pt_self, &p_grp->generator, &sm2_bn_rand, NULL, NULL); 
	ec_GFp_get_aff_coords(p_grp, &pt_self, &sm2_bn_x1, &sm2_bn_y1); 

	/**  3	计算 x1_trunc = 2exp(w) + ( x1 & ( 2exp(w) - 1 ))； **/
	CalcBnTrunc(&sm2_bn_x1_trunc, &(sm2_bn_x1)); 

	/**  4	计算 t_self = (d_self + x1_trunc · r_self) modn；  d_self为己方私钥  **/

	SM2_BN_mod_mul(sm2_bn_mod_res.d, &sm2_bn_top, sm2_bn_rand.d, odr_top, sm2_bn_x1_trunc.d, odr_top, 
		p_grp->order.d, odr_top ); 
	SM2_BN_mod_add(p_kainr->sm2_bn_t_self.d, sm2_bn_mod_res.d, p_kainr->sm2_bn_self_sk.d, p_grp->order.d, odr_top);

	/**  5	第一次数据交换：将 R_self 发送给对方，从对方获取 R_anti  **/
	SM2_BN_store_bn(&sm2_bn_x1, p_ex_data->Qx );
	SM2_BN_store_bn(&sm2_bn_y1, p_ex_data->Qy ); 
	return 1; 
}


int ECKA_get_ka_key(EC_GROUP *p_grp, KaInnerPara *p_kainr, 	ECCParameter *p_ecprm, 
					ECC_PUBLIC_KEY *p_ex_data, int key_len, BYTE *p_share_key)
{  
	EC_POINT pt_anti_ex, pt_mul1, pt_mul2 ;
	BIGNUM sm2_bn_x_anti_trunc, sm2_bn_one, sm2_bn_x, sm2_bn_y; 
	int /*reverse_cpy = p_kainr->reverse_cpy,*/ kdf_input_len;
	int b_init = p_kainr->self_is_initiator;
	BYTE *p_initiator_z = b_init ? p_kainr->self_z_value : p_kainr->anti_z_value;
	BYTE *p_respondor_z = b_init ? p_kainr->anti_z_value : p_kainr->self_z_value;
	BYTE kdf_input[128];

	SM2_BN_init(&sm2_bn_x);
	SM2_BN_init(&sm2_bn_y);
	EC_POINT_init(&pt_anti_ex);
	EC_POINT_init(&pt_mul1);
	EC_POINT_init(&pt_mul2);
 
	SM2_BN_value_one(&sm2_bn_one); 
	
	/**
	// 6	验证 R_anti 是否满足椭圆曲线方程，
	//		若不满足则协商失败；@@@@@@@@@@@
	//		否则从 R_anti = (x2, y2) 中取出 x2 转换为整数，
	//			计算 x2_trunc = 2exp(w) + ( x2 & ( 2exp(w) - 1 ))；
	**/

	/** 6.1	验证 R_anti 是否满足椭圆曲线方程，若不满足则协商失败  **/
	if(!EC_point_is_on_curve(p_ecprm, p_ex_data))
	{
		return -1;//_err_sm2_infinity_point;
	}

	/**
	// 6.2 从 R_anti = (x2, y2) 中取出 x2 转换为整数，
	//		计算 x_trunc = 2exp(w) + ( x2 & ( 2exp(w) - 1 ))；
	**/
	EC_load_pt(&pt_anti_ex, p_ex_data); 
	CalcBnTrunc(&sm2_bn_x_anti_trunc, &pt_anti_ex.X); 
	PrintData(sm2_bn_x_anti_trunc.d, ECC_BLOCK_LEN, "x_trunc", 1);

	/**
	// 7	计算椭圆曲线点U = [h · t_self] ( P_anti + [ x_trunc] R_anti ) = (xU;yU) ，
	//		若U是无穷远点，则A协商失败； 
	//		否则将xU、yU为比特串；
	**/
	EcPointMapToMontgomery(&pt_anti_ex, p_grp);
	EcPointMapToMontgomery(&p_kainr->pt_anti_pk, p_grp);
	SM2_EC_POINTs_mul(p_grp, &pt_mul1, &pt_anti_ex, &sm2_bn_x_anti_trunc,&p_kainr->pt_anti_pk, &sm2_bn_one);   
	SM2_EC_POINTs_mul(p_grp, &pt_mul2, &pt_mul1, &p_kainr->sm2_bn_t_self, NULL, NULL); 
	if ( !ec_GFp_get_aff_coords(p_grp, &pt_mul2, &sm2_bn_x, &sm2_bn_y) )
	{
		return -2;//_err_sm2_infinity_point;;/** 若U是无穷远点，则A协商失败； **/
	}

	/**
	// 8	计算K_share = KDF( xU || yU || Z_initiator || Z_responder, klen)；
	//		若己方为发起者，则 Z_initiator 为Z_self
	// 8.1 kdf_input = xU || yU || Z_initiator || Z_respondor
	**/
	SM2_BN_store_bn(&sm2_bn_x, kdf_input);
	SM2_BN_store_bn(&sm2_bn_y, kdf_input+ECC_BLOCK_LEN);
	MM_MEMCPY(kdf_input+ECC_BLOCK_LEN*2, p_initiator_z, Z_VALUE_LEN);/**  Z 必须顺序复制 **/
	MM_MEMCPY(kdf_input+ECC_BLOCK_LEN*2+Z_VALUE_LEN, p_respondor_z, Z_VALUE_LEN);/**  Z 必须顺序复制 **/

	kdf_input_len = ECC_BLOCK_LEN*2+Z_VALUE_LEN*2;
	
	/** 8.2 协商密钥为 KDF( x1 || y1 || Z_initiator || Z_respondor, klen ) **/
	kdf(kdf_input, kdf_input_len, key_len, p_share_key); 
	
	return 1;
}



