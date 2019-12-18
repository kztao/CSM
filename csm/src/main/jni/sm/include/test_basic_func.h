#ifndef _TEST_BASIC_FUNC_H
#define _TEST_BASIC_FUNC_H
  
#include "sm2.h" 


#ifndef NULL
#define NULL 0
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif 

#define MM_NEED_PRINT_DATA /*µ÷ÊÔ¿ª¹Ø*/


int     sm_data_xor(void* p_des, void* p_src1, void* p_src2, int len);
int     sm_data_and(void* p_des, void* p_src1, void* p_src2, int len);
void    sm_output_data(void * p_data, int byte_len, char *msg, int inv_prt);

int     str2bytes(BYTE *param, char *p_str, int len);
int     chk_data(BYTE *p_bytes,BYTE *p_str,int len, char *inf );
 
void    str2ecc_param(ECCParameter *p_ecprm, char *ec_p, char *ec_a, char *ec_b,
                  char *ec_gx, char *ec_gy, char *ec_gn );
void    str2key_pair(ECC_PUBLIC_KEY *p_pk, ECC_PRIVATE_KEY *p_sk, 
                  char *str_pkx, char *str_pky, char *str_sk );

#ifdef MM_NEED_PRINT_DATA 
#define OutputData( p_data, byte_len, msg, inv_prt)\
            sm_output_data( p_data, byte_len, msg, inv_prt)
#define print printf

#else
#define OutputData( p_data, byte_len, msg, inv_prt)
#define print
#endif 
                                
#endif