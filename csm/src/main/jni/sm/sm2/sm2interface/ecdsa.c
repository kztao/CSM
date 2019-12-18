//#include <stdio.h>
#include "ec.h"
#include "ec_lcl.h"
#include "ecdsa.h"
#include "ec_general.h"
#include "mm_basic_fun.h"
#include "mm_types.h"

 
/** Zֵ�ļ���� CalcZValue(...) **/
/**   �˽ӿڼ����� SM2_ECDSA_sign() û�н���A1,A2�������� 	**/
int SM2_ECDSA_sign_full(EC_GROUP *group, BYTE z[SM3_HASH_VALUE_LEN], 
					BYTE *p_msg, int msg_len, ECC_PRIVATE_KEY *p_sk,
					ECC_SIGNATURE *p_sign, BYTE rand_num[ECC_BLOCK_LEN] )	
{ 
	BYTE e[SM3_HASH_VALUE_LEN];
	
	ECDSA_CalcE(z, p_msg,msg_len, e ); 
	return SM2_ECDSA_sign( group, e, p_sk, p_sign, rand_num );
}

/* 
����ǩ���������㷨
���룺M����ǩ������Ϣ��
�����(r,s)����ϢM������ǩ����
���裺
A1��M`=ZA �� M��
A2������e = Hash(M`) 
A3������������������������k ��[1,n-1]��
A4��������Բ���ߵ�(x1,y1)=[k]G 
A5������r=(e+x1) modn����r=0 �� r+k=n �򷵻�A3��
A6������s = ((1 + dA)exp{-1} �� (k . r �� dA)) modn����s=0�򷵻�A3��
A7����r��s����������ת��Ϊ�ֽڴ�����ϢM ��ǩ��Ϊ(r,s)�� 
*/

/**  �˽ӿ�û�н���A1,A2�������裬������Ҫ������� **/
/**	Zֵ�ļ���� CalcZValue(...) **/
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
// 	// ���������k  debug  standard use
// 	BYTE ecdsa_standard_rand_k[]= {
// 		0x6C,0xB2,0x8D,0x99,	0x38,0x5C,0x17,0x5C,	0x94,0xF9,0x4E,0x93,	0x48,0x17,0x66,0x3F, 
// 		0xC1,0x76,0xD9,0x25,	0xDD,0x72,0xB7,0x27,	0x26,0x0D,0xBA,0xAE,	0x1F,0xB2,0xF9,0x6F}; 
// 	rand_num = ecdsa_standard_rand_k;
// 	// debug  standard use end
**/

	SM2_BN_load_bn(&sm2_bn_pt, e);	/** ��ʼ������  **/
	SM2_BN_load_bn(&sm2_bn_sk, p_sk->Ka); 	/** ��ʼ��˽Կ **/



	/** A1��M`=ZA �� M��
	* A2������e = Hash(M`) 
	* �˽ӿ�û�н���A1,A2�������裬������Ҫ�������
	**/

again:   
	if( (rand_num != NULL ) && (fail_time > 0 ) )
	{
		return -2; /** �ⲿ���������ʱ����������쳣��ֱ���˳� **/
	}

	/** A3������������������������k ��[1,n-1]�� **/
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
 
	/** A4��������Բ���ߵ�(x1,y1)=[k]G  **/
 	SM2_EC_POINTs_mul(group, &pt_r, &group->generator, &sm2_bn_rand, NULL, NULL); 
    ec_GFp_get_aff_coords(group, &pt_r, &sm2_bn_x, &sm2_bn_y);  

	/** A5������r=(e+x1) modn����r=0��r+k=n�򷵻�A3��**/
	SM2_BN_mod_add(sm2_bn_temp.d, sm2_bn_pt.d, sm2_bn_x.d, group->order.d, group->order_top);	
    SM2_BN_div(NULL, NULL, sm2_bn_r.d, &top, sm2_bn_temp.d, group->order_top, group->order.d, group->order_top);		
	if(top == 0)
	{
		fail_time++;
		goto again;	/** r = 0  ���� **/
	}
 
	SM2_BN_mod_add(sm2_bn_r_add_k.d, sm2_bn_r.d, sm2_bn_rand.d, group->order.d, group->order_top);	
//	if(two_number_same(sm2_bn_r_add_k.d,ECC_BLOCK_LEN,group->order.d) == 0 ) 
	if(SM2_BN_ucmp(sm2_bn_r_add_k.d,ECC_BLOCK_LEN,group->order.d,ECC_BLOCK_LEN) == 0 ) 
	{
		fail_time++;
		goto again;	/**  r+k=n   ���� **/
	}

	/** A6������s = ((1 + dA)exp{-1} �� (k - r �� dA)) modn����s=0�򷵻�A3�� **/
	//  1 + da
	SM2_BN_value_one(&sm2_bn_one);  
    SM2_BN_mod_add(sm2_bn_one_add_da.d, sm2_bn_one.d, sm2_bn_sk.d, group->order.d, group->order_top);

    /**   1+da ���� **/
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

	//((1 + dA)exp{-1} �� (k - r �� dA)) modn
	SM2_BN_mod_mul(sm2_bn_s.d, &top,sm2_bn_k_sub_rda.d, group->order_top, sm2_bn_tmp2.d, group->order_top,
		group->order.d, group->order_top);  	
	if( top == 0 )
	{
		fail_time++;
		goto again;	//s = 0
	}

	/** A7����r��s����������ת��Ϊ�ֽڴ�����ϢM ��ǩ��Ϊ(r,s)�� **/
	SM2_BN_store_bn(&sm2_bn_r, p_sign->r);
	SM2_BN_store_bn(&sm2_bn_s, p_sign->s);

	return 1;
}

	 
/** 	Zֵ�ļ���� CalcZValue(...) **/
/**   �˽ӿڼ����� SM2_ECDSA_verify() û�н���B3,B4�������� 	**/
int SM2_ECDSA_verify_full(EC_GROUP *group, BYTE z[SM3_HASH_VALUE_LEN], 
					  BYTE *p_msg, int msg_len, ECC_PUBLIC_KEY *p_pk, 
					  ECC_SIGNATURE *p_sign)	
{ 
	BYTE e[SM3_HASH_VALUE_LEN];
	
	ECDSA_CalcE(z, p_msg,msg_len, e ); /** ����B3,B4�������� **/
	return SM2_ECDSA_verify( group, e, p_pk, p_sign, 0 );
}


/**
����ǩ������֤�㷨  
���룺	M��			���յ�����Ϣ��
		(r��, s��)	��M�������ǩ����
�����	1(����ͨ��) or <=0 (���鲻ͨ��)
���裺
B1������r�� ��[1,n-1]�Ƿ������������������֤��ͨ����
B2������s�� ��[1,n-1]�Ƿ������������������֤��ͨ����
B3����M��=ZA �� M�䣻
B4������e�� = Hv(M��)
B5����r�䡢s��ת��Ϊ����������t = (r�� + s��) modn�� ��t = 0������֤��ͨ����
B6��������Բ���ߵ�(x1��, y1��)=[s��]G + [t]PA��
B7����x1��ת��Ϊ����������R = (e�� + x1��) modn��
	����R=r���Ƿ����������������֤ͨ����������֤��ͨ���� 
**/
/**   �˽ӿ�û�н���B3,B4�������裬������Ҫ������� **/

/* B6�������(x1`, y1`)=[s`]G + [t]PA���������·�ʽ��
	(1) ������ MM_SM2_USE_ALG18_TABLE, �����ALG18�㷨
	(2) δ���� MM_SM2_USE_ALG18_TABLE, �����ԭ�����㷨��������WNAF��ALG16
	flag = 1��ʾʹ��ALG18�㷨��flag = 0��ʾ��ʹ��ALG18�㷨
	
	*/
int SM2_ECDSA_verify(EC_GROUP *group, BYTE e[SM3_HASH_VALUE_LEN], 
				 ECC_PUBLIC_KEY *p_pk, ECC_SIGNATURE *p_sign, int flag)
{ 
	int ret;
	BIGNUM sm2_bn_r, sm2_bn_s, sm2_bn_x, sm2_bn_y, sm2_bn_p, sm2_bn_t; 
	EC_POINT pt_r, pt_q, pt_t;


	SM2_BN_load_bn(&sm2_bn_p,	e);			/** ��ʼ������  **/
	SM2_BN_load_bn(&pt_q.X, p_pk->Qx);	/** ��ʼ����Կ **/
	SM2_BN_load_bn(&pt_q.Y, p_pk->Qy);	/** ��ʼ����Կ 	**/
	SM2_BN_load_bn(&sm2_bn_r,	p_sign->r); /** ��ʼ��r **/
	SM2_BN_load_bn(&sm2_bn_s,	p_sign->s); /** ��ʼ��s **/

	/** B1������r` ��[1,n-1]�Ƿ������������������֤��ͨ���� **/
	if( ( ret = SM2_BN_CMP_256(&sm2_bn_r, &(group->order) ) ) >= 0 )
	{ 
		return -2; /** ��֤δͨ�� **/
	} 					

	/** B2������s` ��[1,n-1]�Ƿ������������������֤��ͨ���� **/
	if( ( ret = SM2_BN_CMP_256(&sm2_bn_s, &(group->order) ) ) >= 0 ) 
	{ 
		return -3; /** ��֤δͨ�� **/
	}

	/**
	//B3����M`=ZA || M`��	//�˽ӿ�û�н���B3,B4�������裬������Ҫ�������
	//B4������e` = Hv(M`)	//�˽ӿ�û�н���B3,B4�������裬������Ҫ�������
	**/

	/** B5����r`��s`ת��Ϊ����������t = (r` + s`) modn�� ��t = 0������֤��ͨ���� **/ 
	SM2_BN_mod_add(sm2_bn_t.d, sm2_bn_r.d, sm2_bn_s.d, group->order.d, group->order_top);
	if( ret = SM2_BN_is_zero(sm2_bn_t.d, group->order_top) )
	{
		return -4; /** ��֤δͨ�� **/
	}

	/** B6��������Բ���ߵ�(x1`, y1`)=[s`]G + [t]PA��**/
	EcPointMapToMontgomery(&pt_q, group); 
	pt_q.Z_is_one = 0; 

	// do (x1`, y1`) = [s`]G + [t]PA��
	ret = 0;
	if( ( flag ) && ( ec_load_tables_a18(group, &pt_q) >= 0 ) )
	{/* ʹ�ò��������ǩ������ʹ��ALG18�㷨����౶�� */
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

	/**B7��	��x1`ת��Ϊ����������R = (e` + x1`) modn��
	*		����R=r`�Ƿ����������������֤ͨ����������֤��ͨ���� 
	**/
	SM2_BN_mod_add(sm2_bn_t.d, sm2_bn_p.d, sm2_bn_x.d, group->order.d, group->order_top);
	ret = SM2_BN_ucmp(sm2_bn_r.d, group->order_top, sm2_bn_t.d, group->order_top);

	return ( ret != 0 ) ? -4: 1; /** ������������֤��ͨ�� **/
}

 

/** ��������� MM_SM2_USE_ALG18_TABLE, 
*	���ڵ��� SM2_ECDSA_verify֮ǰ��ִ�б���������ɱ����������� 
**/
int SM2_init_table_a18(EC_GROUP *group, ECC_PUBLIC_KEY *p_pk, int pos  )
{
	EC_POINT pt_q;

	ec_init_gp_table_a18(group);
 		
	SM2_BN_load_bn(&pt_q.X, p_pk->Qx);	/** ��ʼ����Կ **/
	SM2_BN_load_bn(&pt_q.Y, p_pk->Qy);	/** ��ʼ����Կ **/
	EcPointMapToMontgomery(&pt_q, group); 
	pt_q.Z_is_one = 0; 
	ec_init_pk_table_a18( group, &pt_q, pos); 
	return 1;
}

 
