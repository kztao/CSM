#ifndef _EC_H
#define _EC_H
#include "mm_macro.h"
#include "sm2_type.h"
#include "ec_lcl.h"
#include "ec_fix_pt.h"



//MM_INLINE void EC_POINT_init(EC_POINT *dest ) 
static void EC_POINT_init(EC_POINT *dest)
{
	MM_MEMSET(dest, 0x00, sizeof(EC_POINT)); 
} 

static void EC_POINT_copy(EC_POINT *dest, const EC_POINT *src)
{
	MM_MEMCPY(dest, src, sizeof(EC_POINT));  
}


static void EC_store_pt(EC_POINT *ecpt, ECC_PUBLIC_KEY *pk )
{
	SM2_BN_store_bn(&ecpt->X, pk->Qx );
	SM2_BN_store_bn(&ecpt->Y, pk->Qy );
}

static void EC_load_pt(EC_POINT *ecpt, ECC_PUBLIC_KEY *pk )
{
	SM2_BN_load_bn(&ecpt->X, pk->Qx );
	SM2_BN_load_bn(&ecpt->Y, pk->Qy );
}

static void EcPointMapToMontgomery(EC_POINT *pt, EC_GROUP *group)
{ 
	SM2_BN_TO_MONTGOMERY(pt->X, group);
	SM2_BN_TO_MONTGOMERY(pt->Y, group);
	// 	SM2_BN_mod_mul_montgomery(pt->X.d, pt->X.d, group->RR.d, group->field.d, group->field_top, group->n0);
	// 	SM2_BN_mod_mul_montgomery(pt->Y.d, pt->Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
	MM_MEMCPY(pt->Z.d, group->field_data2.d, group->field_top*sizeof(u32_t));
}


static int ec_GFp_simple_is_at_infinity(EC_GROUP *group, EC_POINT *point)
{
	return SM2_BN_is_zero(point->Z.d, group->field_top);
}
 
#define ec_GFp_get_aff_coords ec_GFp_simple_point_get_affine_coordinates_GFp







void SM2_EC_POINTs_mul(EC_GROUP *group, EC_POINT *R, EC_POINT *P, BIGNUM *k, EC_POINT *Q, BIGNUM *l); 


int ec_GFp_simple_point_get_affine_coordinates_GFp(EC_GROUP *group, EC_POINT *point, BIGNUM *px, BIGNUM *py);
void SM2_ec_GFp_simple_add(EC_GROUP *group, EC_POINT *r, EC_POINT *a, EC_POINT *b);
void SM2_ec_GFp_simple_dbl(EC_GROUP *group, EC_POINT *r, EC_POINT *a); 

int ec_init_gp_table_a18(EC_GROUP *group);
int ec_init_pk_table_a18(EC_GROUP *group, EC_POINT *p_pt_p, int pos);
int ec_load_tables_a18(EC_GROUP *group, EC_POINT *p_pt_p);

int ec_GFp_precompute_a18(EC_GROUP *group, pt_table *p_tbl_1, pt_table *p_tbl_2e, EC_POINT *p_pt, int w);

#define POINT_IS_GENERATOR 1
#define POINT_IS_PUBLIC_KEY 0
int ec_GFp_pt_mul_a18(EC_GROUP *group, EC_POINT *p_pt_r, EC_POINT *p_pt_p, BIGNUM *k, int is_gp);
int ec_trim_rand_a18(BIGNUM *p);
int ec_trim_rand(BIGNUM *p);
#endif

