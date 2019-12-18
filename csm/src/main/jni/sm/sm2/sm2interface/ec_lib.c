#include "ec.h" 
//#include "mm_basic_fun.h"
// 
// int EC_POINT_init(EC_POINT *dest )
// {
// 	MM_MEMSET(dest, 0x00, sizeof(EC_POINT));
// 	return 1;
// }
// 
// int EC_POINT_copy(EC_POINT *dest, const EC_POINT *src)
// {
// 	MM_MEMCPY(dest, src, sizeof(EC_POINT)); 
// 	return 1;
// }
// 
// 
// void EC_store_pt(EC_POINT *ecpt, ECC_PUBLIC_KEY *pk )
// {
// 	SM2_BN_store_bn(&ecpt->X, pk->Qx );
// 	SM2_BN_store_bn(&ecpt->Y, pk->Qy );
// }
// 
// void EC_load_pt(EC_POINT *ecpt, ECC_PUBLIC_KEY *pk )
// {
// 	SM2_BN_load_bn(&ecpt->X, pk->Qx );
// 	SM2_BN_load_bn(&ecpt->Y, pk->Qy );
// }
// 
// void EcPointMapToMontgomery(EC_POINT *pt, EC_GROUP 	*group)
// { 
// 	SM2_BN_TO_MONTGOMERY(pt->X, group);
// 	SM2_BN_TO_MONTGOMERY(pt->Y, group);
// 	// 	SM2_BN_mod_mul_montgomery(pt->X.d, pt->X.d, group->RR.d, group->field.d, group->field_top, group->n0);
// 	// 	SM2_BN_mod_mul_montgomery(pt->Y.d, pt->Y.d, group->RR.d, group->field.d, group->field_top, group->n0);
// 	MM_MEMCPY(pt->Z.d, group->field_data2.d, group->field_top*sizeof(u32_t));
// }
