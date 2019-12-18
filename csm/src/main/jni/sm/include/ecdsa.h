#ifndef ECDSA_H
#define ECDSA_H


#include "ec.h"
 

int SM2_ECDSA_sign(EC_GROUP *group, BYTE e[SM3_HASH_VALUE_LEN], ECC_PRIVATE_KEY *p_sk, 
			   ECC_SIGNATURE *p_sign, BYTE rand_num[ECC_BLOCK_LEN] ); 

int SM2_ECDSA_sign_full(EC_GROUP *group, BYTE z[SM3_HASH_VALUE_LEN], 
					BYTE *p_msg, int msg_len, ECC_PRIVATE_KEY *p_sk,
					ECC_SIGNATURE *p_sign, BYTE rand_num[ECC_BLOCK_LEN] );

int SM2_ECDSA_verify(EC_GROUP *group, BYTE e[SM3_HASH_VALUE_LEN], 
					   ECC_PUBLIC_KEY *p_pk, ECC_SIGNATURE *p_sign, int flag);

int SM2_ECDSA_verify_full(EC_GROUP *group, BYTE z[SM3_HASH_VALUE_LEN], 
					  BYTE *p_msg, int msg_len, ECC_PUBLIC_KEY *p_pk, 
					  ECC_SIGNATURE *p_sign);

int SM2_init_table_a18(EC_GROUP *group, ECC_PUBLIC_KEY *p_pk, int pos  );
#endif

