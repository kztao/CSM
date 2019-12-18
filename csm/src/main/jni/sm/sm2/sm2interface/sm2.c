#include "sm2.h" 
#include "sm3.h"
#include "ec_general.h"
#include "ecdsa.h"
#include "eces.h"
#include "key_ex.h"
#include "mm_basic_fun.h"
 
#ifndef USE_STD_LIB
SM2_EC_GROUP g_sm2_ec_grp;
#endif
 
mm_handle ECC_Init(	ECCParameter	* p_param)
{
#ifdef USE_STD_LIB
	SM2_EC_GROUP *p = (SM2_EC_GROUP*)MM_MALLOC(sizeof(SM2_EC_GROUP));
#else
	SM2_EC_GROUP *p = &g_sm2_ec_grp;
#endif

	if( MM_VALID_PT(p) )
	{
		MM_MEMSET(p, 0x00, sizeof(SM2_EC_GROUP));
		p->ecprm = MM_VALID_PT(p_param) ? *p_param : g_sgst_para; 
		EC_group_init(&p->ecgrp, &p->ecprm);
	}
	return p;
}


int ECC_Unit( mm_handle h)
{
	if( MM_VALID_PT(h) )
	{
		MM_MEMSET(h, 0x00, sizeof(SM2_EC_GROUP));
#ifdef USE_STD_LIB
		MM_FREE(h); 
#endif
		
		return 1;
	}
	return -1;
}

 
int ECC_GenerateKeyPair(mm_handle h, ECC_PUBLIC_KEY *p_pk, ECC_PRIVATE_KEY *p_sk) 
{
	SM2_EC_GROUP *p = (SM2_EC_GROUP*)h;
	if (	MM_VALID_PT(p)  
		&&	MM_VALID_PT(p_pk) 
		&&	MM_VALID_PT(p_sk) )
	{ 
		return EC_generate_key(&p->ecgrp, p_pk, p_sk);
	}
	return -1;
}
   

int ECDSA_Signature(mm_handle h, BYTE z[SM3_HASH_VALUE_LEN], 
					 ECC_PRIVATE_KEY * p_sk, ECC_SIGNATURE * p_sign, 
					 BYTE rand[ECC_BLOCK_LEN])
{
	SM2_EC_GROUP *p = (SM2_EC_GROUP*)h;
	if (	MM_VALID_PT(p)  
		&&	MM_VALID_PT(z) 
		&&	MM_VALID_PT(p_sk) 
		&&	MM_VALID_PT(p_sign) )
	{ 
		return SM2_ECDSA_sign(&p->ecgrp, z, p_sk, p_sign, rand);
	}
	return -1;
}


int ECDSA_SignatureFull(mm_handle h, BYTE z[SM3_HASH_VALUE_LEN], 
						BYTE *p_msg, u32_t msg_len, 
						ECC_PRIVATE_KEY *p_sk, ECC_SIGNATURE *p_sign, 
						BYTE rand[ECC_BLOCK_LEN] )
{
	SM2_EC_GROUP *p = (SM2_EC_GROUP*)h;
	if (	MM_VALID_PT(p)  
		&&	MM_VALID_PT(z) 
		&&	MM_VALID_PT(p_msg) 
		&&	MM_VALID_PT(p_sk) 
		&&	MM_VALID_PT(p_sign) )
	{ 
		return SM2_ECDSA_sign_full(&p->ecgrp, z, p_msg, msg_len, p_sk, p_sign, rand);
	}
	return -1;
}







int ECDSA_Verification(mm_handle h, BYTE p_msg[ECC_BLOCK_LEN], 
					   ECC_PUBLIC_KEY * p_pk, ECC_SIGNATURE * p_sign )
{ 
	SM2_EC_GROUP *p = (SM2_EC_GROUP*)h;
	if (	MM_VALID_PT(p)  
		&&	MM_VALID_PT(p_msg) 
		&&	MM_VALID_PT(p_pk) 
		&&	MM_VALID_PT(p_sign) )
	{ 
		return SM2_ECDSA_verify(&p->ecgrp, p_msg, p_pk, p_sign, 0); 
	}
	return -1; 
}
 

int ECDSA_VerificationFull(mm_handle h, BYTE z[SM3_HASH_VALUE_LEN], 
					  BYTE *p_msg, u32_t msg_len, ECC_PUBLIC_KEY *p_pk, 
					  ECC_SIGNATURE *p_sign)
{
	SM2_EC_GROUP *p = (SM2_EC_GROUP*)h;
	if (	MM_VALID_PT(p)  
		&&	MM_VALID_PT(p_msg) 
		&&	MM_VALID_PT(p_pk) 
		&&	MM_VALID_PT(p_sign) )
	{  
		return SM2_ECDSA_verify_full(&p->ecgrp, z, p_msg, msg_len, p_pk, p_sign );
	}
	return -1; 
}


int	ECES_Encryption(mm_handle h, BYTE *p_pt, u32_t pt_len, 
					 ECC_PUBLIC_KEY *p_pk, BYTE *p_ct, BYTE rand[ECC_BLOCK_LEN])
{
	SM2_EC_GROUP *p = (SM2_EC_GROUP*)h;
	if (	MM_VALID_PT(p)  
		&&	MM_VALID_PT(p_pt) 
		&&	MM_VALID_PT(p_pk) 
		&&	MM_VALID_PT(p_ct) 
		&&	( pt_len > 0 )  )
	{ 
		return ECES_encrypt(&p->ecgrp, p_pt, pt_len, p_pk, p_ct, rand, 0);
	}
	return -1; 
}



int ECES_Decryption(mm_handle h, BYTE *p_ct, u32_t ct_len, 
					 ECC_PRIVATE_KEY *p_sk, BYTE *p_pt )
{
	SM2_EC_GROUP *p = (SM2_EC_GROUP*)h;
	if (	MM_VALID_PT(p)  
		&&	MM_VALID_PT(p_pt) 
		&&	MM_VALID_PT(p_sk) 
		&&	MM_VALID_PT(p_ct) 
		&&	( ct_len > 0 )  )
	{ 
		return ECES_decrypt(&p->ecgrp, p_ct, ct_len, p_sk, p_pt, &p->ecprm);
	}  
	return -1;
}



 
int ECKA_SetKaParam(mm_handle h, KaParameter *p_ka)
{
	SM2_EC_GROUP *p = (SM2_EC_GROUP*)h;
	if (	MM_VALID_PT(p)  
		&&	MM_VALID_PT(p_ka)   )
	{  
		return ECKA_set_ka_param( &p->kainr, &p->ecprm, p_ka);
	} 
	return -1; 
}
 
int ECKA_CalcKaExData(mm_handle h, ECC_KA_EX_DATA *p_ex_data, BYTE rand[ECC_RAND_NUM_LEN])
{
	SM2_EC_GROUP *p = (SM2_EC_GROUP*)h;
	if (	MM_VALID_PT(p)  
		&&	MM_VALID_PT(p_ex_data)   )
	{  
		return ECKA_calc_ka_ex_data(&p->ecgrp, &p->kainr,p_ex_data, rand);
	} 
	return -1; 
}
 
int ECKA_GetKaKey(mm_handle h, ECC_KA_EX_DATA *p_ex_data, u32_t key_len, BYTE *p_key)
{
	SM2_EC_GROUP *p = (SM2_EC_GROUP*)h;
	if (	MM_VALID_PT(p)  
		&&	MM_VALID_PT(p_ex_data)  
		&&	MM_VALID_PT(p_key)  
		&&  ( key_len > 0 ) )
	{  
		return ECKA_get_ka_key(&p->ecgrp,&p->kainr, &p->ecprm, p_ex_data, key_len, p_key);
	} 
	return -1; 
}

 

int ECC_GetUserValueZ(ECCParameter *p_ecprm, BYTE *p_id, u32_t id_len, 
					   ECC_PUBLIC_KEY *p_pk, BYTE z[SM3_HASH_VALUE_LEN] )
{
	if ( MM_VALID_PT(p_id) 
		&&	MM_VALID_PT(p_pk)
		&&	MM_VALID_PT(z)	)
	{ 
		ECCParameter *p_para = MM_VALID_PT(p_ecprm) 
			? p_ecprm : (ECCParameter *)(&g_sgst_para);
		return CalcZValue( p_para, p_id, id_len, p_pk, z); 
	}
	return -1;
}


int ECC_GetValueE(ECCParameter *p_ecprm, 
				  BYTE *p_id,  u32_t id_len, 
				  BYTE *p_msg, u32_t msg_len, 
				  ECC_PUBLIC_KEY *p_pk, BYTE e[SM3_HASH_VALUE_LEN] )
{
	BYTE z[SM3_HASH_VALUE_LEN];
	int ret = 0;

	if (	MM_VALID_PT(p_id) 
		&&	MM_VALID_PT(p_msg) 
		&&	MM_VALID_PT(p_pk)
		&&	MM_VALID_PT(e)	)
	{   
		ECCParameter *p_para = MM_VALID_PT(p_ecprm) 
			? p_ecprm : (ECCParameter *)(&g_sgst_para); 

		ret = CalcZValue( p_para, p_id, id_len, p_pk, z);
		if( ret <= 0 )
		{
			return ret;
		} 
		return ECDSA_CalcE(z, p_msg , msg_len, e );
	}
	return -1;
} 


int ECC_GenerateRandNumber(BYTE *p_rand, u32_t rand_len,  
						   BYTE *p_seed, u32_t seed_len  )
{
	if (	MM_VALID_PT(p_rand) )
	{
		return (MM_VALID_PT(p_seed) && (seed_len>0) ) ?
				GenerateRandom_sm2(  p_rand, rand_len, p_seed, seed_len )
			:	GenerateRandom1( p_rand, rand_len ); 
	}
	return -1;
}

//  
// int SM3_Hash(BYTE *p_msg, unsigned int msg_len, BYTE hash[32] )
// {
// 	if (	VALID_PT(p_msg) 
// 		&&	VALID_PT(hash)  )
// 	{
// 		return 	SM3_HashMsg(p_msg, msg_len, hash);
// 	}
// 	return -1;
// }