#ifndef SM2_BN_H
#define SM2_BN_H

#include "mm_types.h"
#include "mm_macro.h"
//#define u32_t unsigned int 

//typedef unsigned char BYTE;  


#define SM2_BN_BITS     64
#define SM2_BN_BYTES    4
#define SM2_BN_BITS2    32
#define SM2_BN_BITS4    16
#define SM2_BN_BITS8    8

#define SM2_BN_MASK2    (0xffffffffL)
#define SM2_BN_MASK2l   (0xffff)
#define SM2_BN_MASK2h   (0xffff0000L)
#define SM2_BN_TBIT     (0x80000000L)



//#define BIGNUM_SIZE   sizeof(BIGNUM)


#define ECC_BITS            256 /** ECC模长比特数  **/
#define ECC_BLOCK_LEN        32 /** ECC分组长度字节数  **/
#define ECC_BLOCK_LEN_DWORD   8 /** ECC分组长度双字数   **/

typedef struct bignum_st
{
    u32_t d[ECC_BLOCK_LEN_DWORD+2]; 
} BIGNUM;

static void SM2_BN_init(BIGNUM *a)
{
    MM_MEMSET(a,0,sizeof(BIGNUM)); 
} 


static void SM2_BN_copy(BIGNUM *a, const BIGNUM *b)
{
    MM_MEMCPY(a, b, sizeof(BIGNUM));
    //return(a);
}

static void SM2_BN_set_word(BIGNUM *a, u32_t w)
{
    MM_MEMSET(a, 0x00, sizeof(BIGNUM));
    a->d[0] = w;
}


#define SM2_BN_value_one(p_sm2_bn_one)  (SM2_BN_set_word(p_sm2_bn_one, 1) )
#define SM2_BN_zero(a)  (SM2_BN_set_word((a),0))

int SM2_BN_is_zero(u32_t *a, u32_t al);
int SM2_BN_is_one(u32_t *a, u32_t al);
void sm2_bn_fix_top(u32_t *a, int *al);
int SM2_BN_num_bits_word(u32_t l);
int SM2_BN_num_bits(u32_t *a, int al);
int SM2_BN_is_bit_set(const BIGNUM *a, int n);
int SM2_BN_set_bit(BIGNUM *a, int n);
int SM2_BN_clear_bit(BIGNUM *a, int n);
int SM2_BN_ucmp(u32_t *a, int al, u32_t *b, int bl);

#define SM2_BN_CMP_256(p_bn1, p_bn2)\
    SM2_BN_ucmp((p_bn1)->d, ECC_BLOCK_LEN_DWORD, (p_bn2)->d, ECC_BLOCK_LEN_DWORD)

void SM2_BN_rshift1(BIGNUM *r, int *r_top, BIGNUM *a, int a_top);
int SM2_BN_lshift(u32_t *r, int *rl, u32_t *a, int al, int n);
int SM2_BN_rshift(u32_t *r, int *rl, u32_t *a, int al, int n);

//int two_number_same(u32_t *a, int len, u32_t *b);//*




u32_t sm2_bn_mul_add_words(u32_t *rp, const u32_t *ap, int num, u32_t w);
u32_t sm2_bn_mul_words(u32_t *rp, const u32_t *ap, int num, u32_t w);
u32_t sm2_bn_div_words(u32_t h, u32_t l, u32_t d);
u32_t sm2_bn_add_words(u32_t *r, const u32_t *a, const u32_t *b, int n);
u32_t sm2_bn_sub_words(u32_t *r, const u32_t *a, const u32_t *b, int n);

int SM2_BN_uadd(u32_t *r, int *rl, u32_t *a, int al, u32_t *b, int bl);
int SM2_BN_usub(u32_t *r, int *rl, u32_t *a, int al, u32_t *b, int bl);

int SM2_BN_mul_mod_p_sm2(u32_t c[ECC_BLOCK_LEN_DWORD], u32_t a[ECC_BLOCK_LEN_DWORD], u32_t b[ECC_BLOCK_LEN_DWORD]);
void SM2_BN_mul_nomal(u32_t *r, u32_t *a, int na, u32_t *b, int nb);
void SM2_BN_mul(u32_t *r, int *rl, u32_t *a, int al, u32_t *b, int bl); 

void SM2_BN_div(u32_t *dv, int *dv_len, u32_t *rm, int *rm_len, 
            u32_t *num, int num_len, u32_t *divisor, int divisor_len);


void SM2_BN_mod_add(u32_t *r, u32_t *a, u32_t *b, u32_t *m, u32_t mLen);
void SM2_BN_mod_sub(u32_t *r, int *rl, u32_t *a, u32_t *b, u32_t *m, u32_t mLen);
void SM2_BN_mod_lshift1(u32_t *r, u32_t *a, u32_t *m, u32_t mLen); 
void SM2_BN_mod_mul(u32_t *r, int *rl, u32_t *a, int al, u32_t *b, int bl,
                u32_t *m, u32_t mLen);



void SM2_BN_mod_inverse(u32_t *in, int *in_len, u32_t *a, int a_len, u32_t *n, int n_len);


void SM2_BN_MONT_CTX_set(u32_t *Mod, int ModLen, u32_t *n0, u32_t *RR);
int  SM2_BN_mod_mul_montgomery(u32_t *r, u32_t *a, u32_t *b, u32_t *M, int M_Len, u32_t n0);
//void SM2_BN_mod_mul_montgomery_one(u32_t *r, u32_t *a, u32_t *M, int M_Len, u32_t n0);


/** 将BN自己转为MONT数 **/
#define SM2_BN_TO_MONTGOMERY(bn, p)\
SM2_BN_mod_mul_montgomery((bn).d, (bn).d, (p)->RR.d, (p)->field.d, (p)->field_top, (p)->n0)


void SM2_BN_store_bn(BIGNUM *p_bn, BYTE bytes[ECC_BLOCK_LEN]  );
void SM2_BN_load_bn( BIGNUM *p_bn, BYTE bytes[ECC_BLOCK_LEN]  );
 
//signed char *compute_wNAF(BIGNUM *scalar, int w, int order_top, int *ret_len);//20150528 luoying del
int compute_wNAF(BIGNUM *scalar, int w, int order_top, int *ret_len, char *r, int r_sz);//20150528 luoying add
#endif
