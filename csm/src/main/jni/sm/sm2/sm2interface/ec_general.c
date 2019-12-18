#include "mm_basic_fun.h"
#include "sm2_bn.h"
#include "ec_general.h"
#include "ec_lcl.h" 
#include "sm3_core.h"
#include "rc4.h"
#include "mm_sm_cfg.h"
#include "ec_fix_pt.h"
//#include "crypt_header.h"


#ifdef MM_SM2_PRNG_RC4
/** �������������ٶ�
*	����8�ֽ����ӣ����256�����������Խ������
* RC4��[debug] = 110 mbps   [release] = 235 mbps
* SM3: [debug] =  17 mbps   [release] =  31 mbps
**/
int GenerateRandom_sm2( BYTE *p_rand, u32_t rand_len, BYTE *p_seed, u32_t seed_len )
{
	RC4_KEY rc4_key;

	RC4_set_key(&rc4_key, seed_len, p_seed); 
	RC4(&rc4_key, rand_len, p_rand, p_rand); 
	return 1;
} 
#else 
int GenerateRandom_sm2( BYTE *p_rand, u32_t rand_len, BYTE *p_seed, u32_t seed_len )
{
	mm_handle hd = NULL;
	BYTE hash_value[SM3_HASH_VALUE_LEN], *p_data = p_seed;
	u32_t data_len = seed_len, copy_len, res_len = rand_len; 

	while( res_len > 0 )
	{ 
		hd = mm_sm3_new();
		mm_sm3_process(hd, p_data, data_len); 
		mm_sm3_delete(hd, hash_value);

		copy_len = MIN(res_len, SM3_HASH_VALUE_LEN);
		MM_MEMCPY(p_rand, hash_value, copy_len); 
		res_len -= copy_len; 
		p_data = hash_value;
		data_len = SM3_HASH_VALUE_LEN;
	}
	return 1;
}
#endif /* ʹ�ú������������㷨 RC4 ���� SM3 */

int GenerateRandom1( void *p_rand, u32_t rand_len )
{ 
	static u32_t stat = 0; 
	u32_t  ret, rd = get_time() + stat;
	ret = GenerateRandom_sm2(p_rand, rand_len, (BYTE*)(&rd), sizeof(int));
	stat++;
	return ret;
}

/**
//	������:							   //
//      ��ʼ�����߲���(p��)	               //
//	�������:							   //
//		ECCPara:in,���߲���				   //
//      p:out,���������߲���				//
//	�����:						       //
//		��								   //
**/


int EC_group_init(EC_GROUP *p, ECCParameter *pECCPara)
{
	int dwords;
	EC_GROUP *group;
	u32_t sm2_bn_ul_one[ECC_BLOCK_LEN_DWORD];		
	
	dwords = sizeof(EC_GROUP);
	MM_MEMSET(p,0,sizeof(EC_GROUP));
		
	SM2_BN_load_bn(&p->field,		pECCPara->p);	/** ���� p **/
	SM2_BN_load_bn(&p->a,			pECCPara->a);	/** ���� a **/
	SM2_BN_load_bn(&p->b,			pECCPara->b);	/** ���� b **/
	SM2_BN_load_bn(&p->generator.X,	pECCPara->Gx);	/** ���� Gx **/
	SM2_BN_load_bn(&p->generator.Y,	pECCPara->Gy);	/** ���� Gy **/
	SM2_BN_load_bn(&p->order,		pECCPara->Gn);	/** ���ؽ� **/

	/** ȷ��ģ�� **/
    dwords = ECC_BLOCK_LEN_DWORD;
    sm2_bn_fix_top(p->field.d,&dwords);
	p->field_top=dwords;

	/** ȷ���׳� **/
    dwords = ECC_BLOCK_LEN_DWORD;
    sm2_bn_fix_top(p->order.d, &dwords);
	p->order_top = dwords;

	SM2_BN_MONT_CTX_set(p->field.d, p->field_top, &p->n0, p->RR.d);
 
	MM_MEMSET(sm2_bn_ul_one,0,sizeof(sm2_bn_ul_one));
	sm2_bn_ul_one[0] = 1;	

	group = p;
	SM2_BN_mod_mul_montgomery(group->field_data2.d, sm2_bn_ul_one, group->RR.d, group->field.d, 
		group->field_top, group->n0);

	SM2_BN_TO_MONTGOMERY(group->a, group);
	SM2_BN_TO_MONTGOMERY(group->b, group);
	SM2_BN_TO_MONTGOMERY(group->generator.X, group);
	SM2_BN_TO_MONTGOMERY(group->generator.Y, group);

	SM2_BN_copy(&group->generator.Z, &group->field_data2); 
    group->generator.Z_is_one = 1;
 
//	Xsrand(  );
	return 1;
}

/**
//	������:							   //
//      ����ECC��Կ��					   //
//      1<=k<=n-1                          //
//	�������:							   //
//		group:in,����Ⱥ�ṹ 			   //
//      pECCPK:out,ECC��Կ                 //
//      pECCSK:out,ECC˽Կ                 //
//	�����:							   //
//      ��                                 //
**/

int EC_generate_key(EC_GROUP *group, ECC_PUBLIC_KEY *pECCPK, ECC_PRIVATE_KEY *pECCSK)
{ 
	BIGNUM k;
	BIGNUM x, y;
	EC_POINT R; 
  //  BYTE *p = NULL;
 
	SM2_BN_init(&x);
	SM2_BN_init(&y);
	
again:
	/** ����˽ԿSK,1<=SK<=n-1  **/
	SM2_BN_init(&k); 
	GenerateRandom1(k.d, ECC_BLOCK_LEN); 

	if(SM2_BN_is_zero(k.d, ECC_BLOCK_LEN_DWORD))
	{
		goto again;
	}

  	//1 <= k <= n-1 
	while(k.d[ECC_BLOCK_LEN_DWORD-1] >= group->order.d[ECC_BLOCK_LEN_DWORD-1])
	{
		k.d[ECC_BLOCK_LEN_DWORD-1] >>= 1;
	}

 	/** (x,y)=kG,���㹫Կ **/
 	SM2_EC_POINTs_mul(group, &R, &group->generator, &k, NULL, NULL);  
    if( ec_GFp_get_aff_coords(group, &R, &x, &y) <= 0 )
	{
		goto again;
	}

	SM2_BN_store_bn(&x, pECCPK->Qx);
	SM2_BN_store_bn(&y, pECCPK->Qy);
	SM2_BN_store_bn(&k, pECCSK->Ka);

	return 1;
}
					
/**
//	������:                                 //
//      1.��֤���߲���                        //
//      2.��֤���Ƿ���������                  //
//	�������:                                 //
//		pECCPara:in,ECC���߲���               //
//      pECCPoint:in,����֤�ĵ�               //
//	�����:                                 //
//      1:����������                          //
//      0:�㲻��������                        //
**/

int EC_point_is_on_curve(ECCParameter *p_para, ECC_PUBLIC_KEY *p_pk)
{ 
	BIGNUM sm2_bn_p, sm2_bn_a, sm2_bn_b, sm2_bn_x, sm2_bn_y;
    u32_t temp1[ECC_BLOCK_LEN_DWORD*2+1];
    u32_t temp2[ECC_BLOCK_LEN_DWORD*2+1];
	int p_top, a_top, b_top, x_top, y_top, temp1_top, temp2_top;

	/**   ��ʼ��p **/
	SM2_BN_load_bn(&sm2_bn_p, p_para->p);						
	p_top = ECC_BLOCK_LEN_DWORD;
    sm2_bn_fix_top(sm2_bn_p.d, &p_top);
	
	/**   ��ʼ��a **/
	SM2_BN_load_bn(&sm2_bn_a, p_para->a); 
    a_top = ECC_BLOCK_LEN_DWORD;
    sm2_bn_fix_top(sm2_bn_a.d, &a_top);

	/**   ��ʼ��b **/
	SM2_BN_load_bn(&sm2_bn_b, p_para->b);  
    b_top = ECC_BLOCK_LEN_DWORD;
    sm2_bn_fix_top(sm2_bn_b.d, &b_top);

	/** ��ʼ������֤�� **/
	SM2_BN_load_bn(&sm2_bn_x, p_pk->Qx);  
    x_top = ECC_BLOCK_LEN_DWORD;
    sm2_bn_fix_top(sm2_bn_x.d, &x_top);

	SM2_BN_load_bn(&sm2_bn_y, p_pk->Qy);  
    y_top = ECC_BLOCK_LEN_DWORD;
    sm2_bn_fix_top(sm2_bn_y.d, &y_top); 

	//y ^ 2 ==x ^ 3 + a * x + b mod p 
	//x ^ 3
	SM2_BN_mod_mul(temp1, &temp1_top, sm2_bn_x.d, x_top, sm2_bn_x.d, x_top, sm2_bn_p.d, p_top);
	SM2_BN_mod_mul(temp1, &temp1_top, temp1, temp1_top, sm2_bn_x.d, x_top, sm2_bn_p.d, p_top);

	//a * x
	SM2_BN_mod_mul(temp2, &temp2_top, sm2_bn_a.d, a_top, sm2_bn_x.d, x_top, sm2_bn_p.d, p_top);
	
	//x ^ 3 + a * x
	SM2_BN_mod_add(temp1, temp1, temp2, sm2_bn_p.d, p_top);

	//x ^ 3 + a * x +b
	SM2_BN_mod_add(temp1, temp1, sm2_bn_b.d, sm2_bn_p.d, p_top);
 
	//y ^ 2 
	SM2_BN_mod_mul(temp2, &temp2_top, sm2_bn_y.d, y_top, sm2_bn_y.d, y_top, sm2_bn_p.d, p_top); 

	//y ^ 2 ==x ^ 3 + a * x + b mod p 
	return SM2_BN_ucmp(temp1, temp1_top, temp2, temp2_top) == 0;  
}

/**
//����Zֵ 
// 1. ��Ϊǩ���ߵ��û�A���г���ΪentlenA���صĿɱ���ʶ��IDA����
// 2. �ǡ�ENTLA����������entlenAת����ɵ������ֽڣ�
// 3. �����߲���a��,��b��,G����꡾xG��,��yG����PA����꡾xA��,��yA��ת��Ϊ���ش�
// 4. ǩ���ߺ���֤�߶���Ҫ�������Ӵպ�������û�A���Ӵ�ֵZA��
// 5. ZA = H256( ENTLA �� IDA �� a �� b �� xG �� yG �� xA �� yA )�� 
// ��������ʹ�� SM3 �㷨��Ϊ�Ӵպ��� H256
**/
 
int CalcZValue(ECCParameter *p_ecprm, BYTE *p_id, u32_t id_len, ECC_PUBLIC_KEY *p_pk, 
			   BYTE out_z_value[32] )
{ 
	unsigned short int id_bit_len = (unsigned short int)(id_len * 8);  
	BYTE entl[2]; 
	mm_sm3_ctx x;  
	
	MM_STORE_U16H(id_bit_len, entl);  
	
	sm3_init_core(   &x);
	sm3_process_core(&x, entl,			2);
	sm3_process_core(&x, p_id,			id_len);
	sm3_process_core(&x, p_ecprm->a,	ECC_BLOCK_LEN);
	sm3_process_core(&x, p_ecprm->b,	ECC_BLOCK_LEN);
	sm3_process_core(&x, p_ecprm->Gx,	ECC_BLOCK_LEN);
	sm3_process_core(&x, p_ecprm->Gy,	ECC_BLOCK_LEN); 
	sm3_process_core(&x, p_pk->Qx,		ECC_BLOCK_LEN);
	sm3_process_core(&x, p_pk->Qy,		ECC_BLOCK_LEN); 
	sm3_unit_core(	 &x, out_z_value);
	
	return 1;
}

/** ZA=H256(ENTLA �� IDA �� a �� b �� xG �� yG �� xA �� yA)��
* A1��M`=ZA �� M��
* A2������e = Hash(M`) 
**/
int ECDSA_CalcE(BYTE z[SM3_HASH_VALUE_LEN], BYTE *p_msg , int msg_len, 
				BYTE e[SM3_HASH_VALUE_LEN] )
{  
	mm_sm3_ctx x; 
	sm3_init_core(   &x );
	sm3_process_core(&x,	z,		SM3_HASH_VALUE_LEN);
	sm3_process_core(&x,	p_msg,	msg_len);
	sm3_unit_core(	 &x,	e); 
	return 1;
}
