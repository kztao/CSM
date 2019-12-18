#ifndef ECES_H
#define ECES_H


#include "ec_lcl.h" 
 
 

int ECES_encrypt(EC_GROUP *group, BYTE *plain, int plain_len, ECC_PUBLIC_KEY *p_pk, 	
					BYTE *enc_data, BYTE rand[ECC_BLOCK_LEN], int flag );

int  ECES_decrypt(EC_GROUP *group, BYTE *enc_data, int enc_data_len,
					 ECC_PRIVATE_KEY *pECCSK, BYTE *msg, 
					 ECCParameter *pECCPara);

#endif

