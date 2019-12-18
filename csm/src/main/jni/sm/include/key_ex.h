#ifndef _KEY_EXCHANGE_H
#define _KEY_EXCHANGE_H
 
#include "ec_lcl.h" 
// #include "sm2.h"

int ECKA_set_ka_param(KaInnerPara *p_kainr, ECCParameter *p_ecprm, KaParameter *p_ka);

int ECKA_calc_ka_ex_data(EC_GROUP *p_grp, KaInnerPara *p_kainr, 
						 ECC_PUBLIC_KEY *p_ex_data, BYTE rand[ECC_RAND_NUM_LEN]);

int ECKA_get_ka_key(EC_GROUP *p_grp, KaInnerPara *p_kainr, 	ECCParameter *p_ecprm, 
					ECC_PUBLIC_KEY *p_ex_data, int key_len, BYTE *p_share_key); 
#endif