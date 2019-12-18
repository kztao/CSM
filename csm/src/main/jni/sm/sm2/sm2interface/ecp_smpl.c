//#include <stdio.h>//debug
//#include <stdlib.h>//debug
#include "ec.h" 
#include "ec_lcl.h"
#include "mm_basic_fun.h"
#include "ec_fix_pt.h"

/* A <- J */
int ec_GFp_simple_point_get_affine_coordinates_GFp(EC_GROUP *group, EC_POINT *point, BIGNUM *px, BIGNUM *py)
{
	BIGNUM sm2_bn_x, sm2_bn_y, sm2_bn_z, sm2_bn_one, sm2_bn_z1, sm2_bn_z2, sm2_bn_z3; 
	int xtop, ytop, z1top, z2top, z3top, fld_top = group->field_top;
	u32_t grpn0 = group->n0, *p_grp_d =group->field.d; 
	int pt_z_is_zero = 0; 
	
	pt_z_is_zero = SM2_BN_is_zero(point->Z.d, ECC_BLOCK_LEN_DWORD); 
	if( pt_z_is_zero )
	{
		return -1;
	} 

	SM2_BN_value_one(&sm2_bn_one);

	/* transform  (X, Y, Z)  into  (x, y) := (X/Z^2, Y/Z^3) */
//	SM2_BN_mod_mul_montgomery_one(sm2_bn_x.d, point->X.d, p_grp_d, fld_top, grpn0);
//	SM2_BN_mod_mul_montgomery_one(sm2_bn_y.d, point->Y.d, p_grp_d, fld_top, grpn0);
//	SM2_BN_mod_mul_montgomery_one(sm2_bn_z.d, point->Z.d, p_grp_d, fld_top, grpn0);
	SM2_BN_mod_mul_montgomery(sm2_bn_x.d, point->X.d, sm2_bn_one.d, p_grp_d, fld_top, grpn0);
    SM2_BN_mod_mul_montgomery(sm2_bn_y.d, point->Y.d, sm2_bn_one.d, p_grp_d, fld_top, grpn0);
    SM2_BN_mod_mul_montgomery(sm2_bn_z.d, point->Z.d, sm2_bn_one.d, p_grp_d, fld_top, grpn0);

	if(SM2_BN_is_zero(sm2_bn_z.d, fld_top))
	{
		return -2;
	}
	else if(SM2_BN_is_one(sm2_bn_z.d, fld_top))
	{
		SM2_BN_copy(px, &sm2_bn_x);
		SM2_BN_copy(py, &sm2_bn_y); 
	}
	else
	{
// 		SM2_BN_mod_inverse(sm2_bn_z1.d, &z1top, sm2_bn_z.d, group->field_top, group->field.d, group->field_top);
// 		SM2_BN_mul(temp, &temp_top, sm2_bn_z1.d, z1top, sm2_bn_z1.d, z1top);
// 		SM2_BN_div(NULL, NULL, sm2_bn_z2.d, &z2top, temp, temp_top, group->field.d, group->field_top);	
// 		SM2_BN_mul(temp, &temp_top, sm2_bn_x.d, group->field_top, sm2_bn_z2.d, z2top);
// 		SM2_BN_div(NULL, NULL, px->d, &xtop, temp, temp_top, group->field.d, group->field_top);		
// 		SM2_BN_mul(temp, &temp_top, sm2_bn_z2.d, z2top, sm2_bn_z1.d, z1top);
// 		SM2_BN_div(NULL, NULL, sm2_bn_z3.d, &z3top, temp, temp_top, group->field.d, group->field_top);		
// 		SM2_BN_mul(temp, &temp_top, sm2_bn_z3.d, z3top, sm2_bn_y.d, group->field_top);
// 		SM2_BN_div(NULL, NULL,py->d, &ytop, temp, temp_top, group->field.d, group->field_top);

		SM2_BN_mod_inverse(	sm2_bn_z1.d, &z1top, sm2_bn_z.d,  fld_top, p_grp_d, fld_top);		
		SM2_BN_mod_mul(	sm2_bn_z2.d, &z2top, sm2_bn_z1.d, z1top,   sm2_bn_z1.d,	z1top,	p_grp_d, fld_top);
		SM2_BN_mod_mul(	px->d,	 &xtop,	 sm2_bn_x.d,  fld_top, sm2_bn_z2.d,	z2top,	p_grp_d, fld_top);
		SM2_BN_mod_mul(	sm2_bn_z3.d, &z3top, sm2_bn_z2.d, z2top,   sm2_bn_z1.d,	z1top,	p_grp_d, fld_top);
		SM2_BN_mod_mul(	py->d,	 &ytop,	 sm2_bn_z3.d, z3top,   sm2_bn_y.d,  fld_top,p_grp_d, fld_top);
	}
	return 1;
}

/** J <- J + J . 也可做 J <- J + A **/
void SM2_ec_GFp_simple_add(EC_GROUP *group, EC_POINT *r, EC_POINT *a, EC_POINT *b)
{
	int top1, top2;
	BIGNUM n0, n1, n2, n3, n4, n5, n6;
	
	if(a == b)
	{
		SM2_ec_GFp_simple_dbl(group, r, a);
		return;
	}
	if(ec_GFp_simple_is_at_infinity(group, a))
	{
		EC_POINT_copy(r, b); 
		return;
	}
	if(ec_GFp_simple_is_at_infinity(group, b))
	{
		EC_POINT_copy(r, a);  
		return;
	} 

	/* n1, n2 */
	if (b->Z_is_one)
	{
		SM2_BN_copy(&n1, &a->X);	/* n1 = X_a */
		SM2_BN_copy(&n2, &a->Y);	/* n2 = Y_a */ 
	}
	else
	{ 
		/* n1 = X_a * Z_b^2 */
		SM2_BN_mod_mul_montgomery(n0.d, b->Z.d, b->Z.d, group->field.d, group->field_top, group->n0);
		SM2_BN_mod_mul_montgomery(n1.d, a->X.d, n0.d, group->field.d, group->field_top, group->n0);

		/* n2 = Y_a * Z_b^3 */
		SM2_BN_mod_mul_montgomery(n0.d, n0.d, b->Z.d, group->field.d, group->field_top, group->n0);
		SM2_BN_mod_mul_montgomery(n2.d, a->Y.d, n0.d, group->field.d, group->field_top, group->n0); 
	}

	/* n3, n4 */
	if (a->Z_is_one)
	{
		SM2_BN_copy(&n3, &b->X);	/* n3 = X_b */
		SM2_BN_copy(&n4, &b->Y);	/* n4 = Y_b */
	}
	else
	{
		/* n3 = X_b * Z_a^2 */
		SM2_BN_mod_mul_montgomery(n0.d, a->Z.d, a->Z.d, group->field.d, group->field_top, group->n0);
		SM2_BN_mod_mul_montgomery(n3.d, b->X.d, n0.d, group->field.d, group->field_top, group->n0); 

		/* n4 = Y_b * Z_a^3 */
		SM2_BN_mod_mul_montgomery(n0.d, n0.d, a->Z.d, group->field.d, group->field_top, group->n0);
		SM2_BN_mod_mul_montgomery(n4.d, b->Y.d, n0.d, group->field.d, group->field_top, group->n0); 
	}

	/* n5, n6 */ /* n5 = n1 - n3 */	/* n6 = n2 - n4 */
    SM2_BN_mod_sub(n5.d, &top1, n1.d, n3.d, group->field.d, group->field_top);
    SM2_BN_mod_sub(n6.d, &top2, n2.d, n4.d, group->field.d, group->field_top);

	if(!top1)
	{
		if(!top2)
		{
			SM2_ec_GFp_simple_dbl(group, r, a);
			return;
		}
		else
		{
			SM2_BN_zero(&r->Z); 
			r->Z_is_one = 0;
			return;
		}
	}

	/* 'n7', 'n8' */ /* 'n7' = n1 + n3 */	/* 'n8' = n2 + n4 */
    SM2_BN_mod_add(n1.d, n1.d, n3.d, group->field.d, group->field_top);
    SM2_BN_mod_add(n2.d, n2.d, n4.d, group->field.d, group->field_top); 

	/* Z_r */ /* Z_r = Z_a * Z_b * n5 */
	if (a->Z_is_one && b->Z_is_one)
	{
		SM2_BN_copy(&r->Z, &n5);
	}
	else
	{
		if (a->Z_is_one)
		{ 
			SM2_BN_copy(&n0, &b->Z); 
		}
		else if (b->Z_is_one)
		{ 
			SM2_BN_copy(&n0, &a->Z); 
		}
		else
		{ 
			SM2_BN_mod_mul_montgomery(n0.d, a->Z.d, b->Z.d, group->field.d, group->field_top, group->n0); 
		}
		SM2_BN_mod_mul_montgomery(r->Z.d, n0.d, n5.d, group->field.d, group->field_top, group->n0); 
	}
	r->Z_is_one = 0;

	/* X_r */ /* X_r = n6^2 - n5^2 * 'n7' */
	SM2_BN_mod_mul_montgomery(n0.d, n6.d, n6.d, group->field.d, group->field_top, group->n0);
	SM2_BN_mod_mul_montgomery(n4.d, n5.d, n5.d, group->field.d, group->field_top, group->n0);
	SM2_BN_mod_mul_montgomery(n3.d, n1.d, n4.d, group->field.d, group->field_top, group->n0);
    SM2_BN_mod_sub(r->X.d, &top1, n0.d, n3.d, group->field.d, group->field_top); 

	/* 'n9' */ /* n9 = n5^2 * 'n7' - 2 * X_r */
	SM2_BN_mod_lshift1(n0.d, r->X.d, group->field.d, group->field_top);
	SM2_BN_mod_sub(n0.d, &top1, n3.d, n0.d, group->field.d, group->field_top); 

	/* Y_r */ /* Y_r = (n6 * 'n9' - 'n8' * 'n5^3') / 2 */
	SM2_BN_mod_mul_montgomery(n0.d, n0.d, n6.d, group->field.d, group->field_top, group->n0);
	SM2_BN_mod_mul_montgomery(n5.d, n4.d, n5.d, group->field.d, group->field_top, group->n0);
	SM2_BN_mod_mul_montgomery(n1.d, n2.d, n5.d, group->field.d, group->field_top, group->n0);
	SM2_BN_mod_sub(n0.d, &top1, n0.d, n1.d, group->field.d, group->field_top);

	if(n0.d[0] & 1)
	{
		SM2_BN_uadd(n0.d, &top1, n0.d, group->field_top, group->field.d, group->field_top);
		SM2_BN_rshift(r->Y.d, &top1, n0.d, top1, 1);
	}
	else
	{
		SM2_BN_rshift(r->Y.d, &top1, n0.d, group->field_top, 1);
	}
}
/* J <- 2J */
void SM2_ec_GFp_simple_dbl(EC_GROUP *group, EC_POINT *r, EC_POINT *a)
{
	int top;
	BIGNUM n0, n1, n2, n3;
	
	if(ec_GFp_simple_is_at_infinity(group, a))
	{
		SM2_BN_zero(&r->Z); 
		r->Z_is_one = 0;
		return;
	} 
			
	/* n1 */
	if (a->Z_is_one)/* n1 = 3 * X_a^2 + a_curve */
	{
		SM2_BN_mod_mul_montgomery(n0.d, a->X.d, a->X.d, group->field.d, group->field_top, group->n0);
		SM2_BN_mod_lshift1(n1.d, n0.d, group->field.d, group->field_top);
		SM2_BN_mod_add(n0.d, n0.d, n1.d, group->field.d, group->field_top);
		SM2_BN_mod_add(n1.d, n0.d, group->a.d, group->field.d, group->field_top); 
	}
	else/* n1 = 3 * X_a^2 + a_curve * Z_a^4 */
	{
		SM2_BN_mod_mul_montgomery(n0.d, a->X.d, a->X.d, group->field.d, group->field_top, group->n0);
		SM2_BN_mod_lshift1(n1.d, n0.d, group->field.d, group->field_top);
		SM2_BN_mod_add(n0.d, n0.d, n1.d, group->field.d, group->field_top);
		SM2_BN_mod_mul_montgomery(n1.d, a->Z.d, a->Z.d, group->field.d, group->field_top, group->n0);
		SM2_BN_mod_mul_montgomery(n1.d, n1.d, n1.d, group->field.d, group->field_top, group->n0);
		SM2_BN_mod_mul_montgomery(n1.d, n1.d, group->a.d, group->field.d, group->field_top, group->n0);// 
		SM2_BN_mod_add(n1.d, n1.d, n0.d, group->field.d, group->field_top); 
	}

	/* Z_r */	/* Z_r = 2 * Y_a * Z_a */
	if (a->Z_is_one)
	{
		SM2_BN_copy(&n0, &a->Y);
	}
	else
	{
		SM2_BN_mod_mul_montgomery(n0.d, a->Y.d, a->Z.d, group->field.d, group->field_top, group->n0); 
	}
	SM2_BN_mod_lshift1(r->Z.d, n0.d, group->field.d, group->field_top); 
	r->Z_is_one = 0; 

	/* n2 */	/* n2 = 4 * X_a * Y_a^2 */
	SM2_BN_mod_mul_montgomery(n3.d, a->Y.d, a->Y.d, group->field.d, group->field_top, group->n0);
	SM2_BN_mod_mul_montgomery(n2.d, a->X.d, n3.d, group->field.d, group->field_top, group->n0);
	SM2_BN_mod_lshift1(n2.d, n2.d, group->field.d, group->field_top);
	SM2_BN_mod_lshift1(n2.d, n2.d, group->field.d, group->field_top); 

	/* X_r */	/* X_r = n1^2 - 2 * n2 */
	SM2_BN_mod_lshift1(n0.d, n2.d, group->field.d, group->field_top);
	SM2_BN_mod_mul_montgomery(r->X.d, n1.d, n1.d, group->field.d, group->field_top, group->n0);
    SM2_BN_mod_sub(r->X.d, &top, r->X.d, n0.d, group->field.d, group->field_top);  
	
	/* n3 */	/* n3 = 8 * Y_a^4 */
	SM2_BN_mod_mul_montgomery(n0.d, n3.d, n3.d, group->field.d, group->field_top, group->n0);
	SM2_BN_mod_lshift1(n3.d, n0.d, group->field.d, group->field_top);
	SM2_BN_mod_lshift1(n3.d, n3.d, group->field.d, group->field_top);
	SM2_BN_mod_lshift1(n3.d, n3.d, group->field.d, group->field_top);  

	/* Y_r */	/* Y_r = n1 * (n2 - X_r) - n3 */
	SM2_BN_mod_sub(n0.d, &top, n2.d, r->X.d, group->field.d, group->field_top);
	SM2_BN_mod_mul_montgomery(n0.d, n1.d, n0.d, group->field.d, group->field_top, group->n0);
	SM2_BN_mod_sub(r->Y.d, &top, n0.d, n3.d, group->field.d, group->field_top); 
}

// int ec_GFp_simple_is_at_infinity(EC_GROUP *group, EC_POINT *point)//luoying del 20150603
// {
// 	return SM2_BN_is_zero(point->Z.d, group->field_top);
// }
  
int ec_GFp_precompute_a18(EC_GROUP *group, pt_table *p_table_1, pt_table *p_table_2e, EC_POINT *p_pt, int w)
{
	int i, j, i_bound = 1<<w, d, e, r_is_infinity; 
	BIGNUM sm2_bn_x, sm2_bn_y, sm2_bn_2d, sm2_bn_2e; 
	EC_POINT pt_r, pt_1[8],pt_2[8];// w <= 8

	if( w <= 0 )
	{
		return 0;
	}

	d = (ECC_BITS+w-1)/w;  
	e = (d+1)/2;

	/**  0. 将 p_pt点保存到 p_tbl_1[0]，以便后续检查是哪个点 **/
	MM_MEMCPY(p_table_1[0].x, p_pt->X.d, ECC_BLOCK_LEN); 
	MM_MEMCPY(p_table_1[0].y, p_pt->Y.d, ECC_BLOCK_LEN); 

	/**  1. 计算2**(i*d) *  P 和 2**e * 2**(i*d) *  P , i=0,1,2,...,w-1 **/
	SM2_BN_value_one(&sm2_bn_2e);
	SM2_BN_lshift(sm2_bn_2e.d, &i, sm2_bn_2e.d, 1, e);//2**e
	SM2_BN_value_one(&sm2_bn_2d);
	SM2_BN_lshift(sm2_bn_2d.d,  &i, sm2_bn_2d.d,  1, d);//2**d 
	EC_POINT_copy(pt_1+0, p_pt);//1 * P  
	SM2_EC_POINTs_mul(group, pt_2+0, pt_1+0, &sm2_bn_2e, NULL, NULL); //2**e * P

	for ( i = 1; i < w; i++ )
	{
		SM2_EC_POINTs_mul(group, pt_1+i, pt_1+i-1, &sm2_bn_2d, NULL, NULL); 
		SM2_EC_POINTs_mul(group, pt_2+i, pt_1+i,   &sm2_bn_2e,NULL, NULL); 
	} 

	/**  2. 计算a_{w-1} * 2**((w-1)*d) *  P + a1 * 2**d *  P + a0 * P, ai = 0 or 1 **/
	for (i = 1;i < i_bound; i++)
	{
		r_is_infinity = 1;
		for (j = 0; j < w; j++ )
		{
			if( ( i >> j ) & 1 )
			{
				if( r_is_infinity ) EC_POINT_copy(&pt_r, pt_1+j);	//pt_1
				else SM2_ec_GFp_simple_add(group, &pt_r, &pt_r, pt_1+j);	//pt_1
				r_is_infinity = 0; 
			}
		}
		ec_GFp_get_aff_coords(group, &pt_r, &sm2_bn_x, &sm2_bn_y);
		SM2_BN_TO_MONTGOMERY(sm2_bn_x, group);/** 仿射点加载时有个XYZ转MONT的过程 **/
		SM2_BN_TO_MONTGOMERY(sm2_bn_y, group); 
		//SM2_BN_copy(&sm2_bn_y, &group->field_data2); 
		//this_pt.Z_is_one = 1;

		MM_MEMCPY(p_table_1[i].x, sm2_bn_x.d, ECC_BLOCK_LEN);//set table element
		MM_MEMCPY(p_table_1[i].y, sm2_bn_y.d, ECC_BLOCK_LEN); 
	}
	
	/**  2. 计算2**e * [a_{w-1} * 2**((w-1)*d) *  P + a1 * 2**d *  P + a0 * P ], ai = 0 or 1  **/
	for (i = 1;i < i_bound; i++)
	{
		r_is_infinity = 1;
		for (j = 0; j < w; j++ )
		{
			if( ( i >> j ) & 1 )
			{
				if( r_is_infinity ) EC_POINT_copy(&pt_r, pt_2+j);	//pt_2
				else SM2_ec_GFp_simple_add(group, &pt_r, &pt_r, pt_2+j);	//pt_2
				r_is_infinity = 0; 
			}
		}
		ec_GFp_get_aff_coords(group, &pt_r, &sm2_bn_x, &sm2_bn_y);
		SM2_BN_TO_MONTGOMERY(sm2_bn_x, group);/** 仿射点加载时有个XYZ转MONT的过程 **/
		SM2_BN_TO_MONTGOMERY(sm2_bn_y, group); 
		//SM2_BN_copy(&sm2_bn_y, &group->field_data2); 
		//this_pt.Z_is_one = 1;
		
		MM_MEMCPY(p_table_2e[i].x, sm2_bn_x.d, ECC_BLOCK_LEN);//set table element
		MM_MEMCPY(p_table_2e[i].y, sm2_bn_y.d, ECC_BLOCK_LEN); 
	}
	return 1;
}
 
#ifdef PRINT_PRECOMPUTE_TABLE
#define PRINT_PRE_TABLE print_table
#else 
#define PRINT_PRE_TABLE(table, sz, inf)
#endif

#ifdef PRINT_PRECOMPUTE_TABLE
#include <math.h>
void print_table( pt_table *p, int num, char *flags) 
{ 
	char name[256];
	int i, j, n = 0, mask = 1, sz = sizeof(p->x)/sizeof(p->x[0]);
	FILE *fp = NULL;

	sprintf(name, "d:\\table_%s_%d.txt", flags, SM2_ALG18_GP_W);
	fp = fopen(name, "wt");//debug
	fprintf(fp, "SM2_ALG18_GP_W = %d\n\n\n",  SM2_ALG18_GP_W);
	fprintf(fp, "static pt_table g_gp_table_%s[ 1<<SM2_ALG18_GP_W] = {\n", flags);

	for ( i = 0; i < num; i++ )
	{
		fprintf(fp, "/*%3d*/\t{\t{", i);
		for (j = 0;j < sz; j++) { fprintf(fp, "0x%08x,", p[i].x[j]); }
		fprintf(fp, "},\n/*   */\t\t{" );
		for (j = 0;j < sz; j++) { fprintf(fp, "0x%08x,", p[i].y[j]); }
		fprintf(fp, "}\t},\n" );
	}
			 
	fprintf(fp, "};\n");

	fclose(fp);
} 
#endif

/*加载公钥的表*/ 


int ec_init_gp_table_a18(EC_GROUP *group) 
{ 
	const u32_t tag = 0xaf456c78; 
 

	/*初始化基点的表*/  
	if (g_gp_table_1[0].y[0] != tag )
	{ 

		ec_GFp_precompute_a18(group, g_gp_table_1, g_gp_table_2e, 
			&(group->generator), SM2_ALG18_GP_W); 
		g_gp_table_1[0].y[0] = tag; 


		PRINT_PRE_TABLE(g_gp_table_1, 1<<SM2_ALG18_GP_W, "1");

		PRINT_PRE_TABLE(g_gp_table_2e, 1<<SM2_ALG18_GP_W, "2e"); 
	}  
	return 1;
}

int ec_init_pk_table_a18(EC_GROUP *group, EC_POINT *p_pt_p, int pos) 
{  
#if (SM2_ALG18_PK_W > 0)
	if (	(MM_MEMCMP(p_pt_p->X.d, g_pk_tables_1[pos][0].x, ECC_BLOCK_LEN) == 0 )
		&&	(MM_MEMCMP(p_pt_p->Y.d, g_pk_tables_1[pos][0].y, ECC_BLOCK_LEN) == 0 ) )
	{
		return 1;/** 已经存在此公钥的表，无需再初始化 **/
	}
	else
	{/*初始化公钥的表*/  
		ec_GFp_precompute_a18(  group, g_pk_tables_1[pos], g_pk_tables_2e[pos], 
			p_pt_p, SM2_ALG18_PK_W); 
	}
	return 1;
#else
	return 0;
#endif
}

int ec_load_tables_a18(EC_GROUP *group, EC_POINT *p_pt_p) 
{ 
	int i;  

	/*加载公钥的表*/ 
	for (i = 0; i<sizeof(g_pk_tables_1)/sizeof(g_pk_tables_1[0]);i++)
	{
		if (	(MM_MEMCMP(p_pt_p->X.d, g_pk_tables_1[i][0].x, ECC_BLOCK_LEN) == 0 )
			&&	(MM_MEMCMP(p_pt_p->Y.d, g_pk_tables_1[i][0].y, ECC_BLOCK_LEN) == 0 ) )
		{
			g_pk_table_1  = g_pk_tables_1[i];
			g_pk_table_2e = g_pk_tables_2e[i];
			return i;
		}
	}  
	return -1;
}

void SM2_BN_split_bn(BIGNUM ki[8], BIGNUM *k, int w)
{
	int i, j, d;
	d = (ECC_BITS+w-1)/w;

	// get ki 
	for (i = 0; i<w; i++ )
	{
		SM2_BN_rshift(ki[i].d, &j, k->d, ECC_BLOCK_LEN_DWORD, d*i ); 
		if( w < 8 )
		{
			j = (d+31) >> 5; 
			ki[i].d[j-1] &= 0xFFFFFFFF >> ( 32 - (d & 0x1F) );
			MM_MEMSET(ki[i].d+j, 0x00, sizeof(ki[i].d)-j*sizeof(u32_t)); 
		}
		else/** w == 8时需这样写 否则会导致ki全零 **/
		{ 
			MM_MEMSET(ki[i].d+1, 0x00, sizeof(ki[i].d)-sizeof(u32_t));  
		} 
	}   
}


/*	仿射点加载时有个XYZ转MONT的过程
	不过现在的存储信息中的XY坐标已经转为MONT	*/
#define TABLE_ELE_2_POINT(pt, ele)\
	MM_MEMCPY((pt).X.d, (ele).x, ECC_BLOCK_LEN);\
	MM_MEMCPY((pt).Y.d, (ele).y, ECC_BLOCK_LEN); 


/* R <- k * P ,按算法18实现 */ 
/**  调用前需保证 g_gp_table 正确 **/
int ec_GFp_pt_mul_a18(EC_GROUP *group, EC_POINT *p_pt_r, EC_POINT *p_pt_p, BIGNUM *k, int point_tag) 
{
	int d, e, w, i, j, c, q_is_infinity;
	int is_generator = (point_tag == POINT_IS_GENERATOR);
	pt_table *p_1  = is_generator ? g_gp_table_1  : g_pk_table_1;
	pt_table *p_2e = is_generator ? g_gp_table_2e : g_pk_table_2e;
	EC_POINT Q, Pi; 
	BIGNUM ki[8];

	if( is_generator )
	{
		ec_init_gp_table_a18( group );/** 初始化基点的表 **/
	}

	EC_POINT_init(&Q);
	EC_POINT_init(&Pi); 

	w = point_tag ? SM2_ALG18_GP_W : SM2_ALG18_PK_W;
	d = (ECC_BITS+w-1)/w;
	e = (d+1)/2;

	/** 仿射点加载是需将Z左标做如下设置,另外由于Z坐标只读，因此只在这里设置一次 **/
	SM2_BN_copy(&Pi.Z, &group->field_data2);
	Pi.Z_is_one = 1;  
  

	// get ki 
	for (i = 0; i<w; i++ )
	{
		SM2_BN_rshift(ki[i].d, &j, k->d, ECC_BLOCK_LEN_DWORD, d*i ); 
		if( w < 8 )
		{
			j = (d+31) >> 5; 
			c = 32 - (d & 0x1F);
			if(c==32) { c = 0;} /** 右移32比特的结果好像不统一 **/
			ki[i].d[j-1] &= ( 0xFFFFFFFF >> c );
			MM_MEMSET(ki[i].d+j, 0x00, sizeof(ki[i].d)-j*sizeof(u32_t));  
		}
		else/** w == 8时需这样写 否则会导致ki全零 **/
		{ 
			MM_MEMSET(ki[i].d+1, 0x00, sizeof(ki[i].d)-sizeof(u32_t));  
		} 
	}   
 
	q_is_infinity = 1; 
	for (i = e - 1; i >= 0; i--)
	{ 
		// Q <- 2 * Q
		if (!q_is_infinity)
		{ 
			SM2_ec_GFp_simple_dbl(group, &Q, &Q);
		}

		// Q <- Q + [k*, ... ,k*]P
		c = SM2_BN_is_bit_set(ki + w-1, i);
		for ( j = w-2; j >=0; j-- )
		{
			c <<= 1; 
			c  += SM2_BN_is_bit_set(ki + j, i); 
		} 

		if(c)
		{
			TABLE_ELE_2_POINT(Pi, p_1[c]);  
			q_is_infinity ? EC_POINT_copy(&Q, &Pi) : SM2_ec_GFp_simple_add(group, &Q, &Q, &Pi);   
			q_is_infinity = 0; 
		} 

		// Q <- Q + 2**e * [k*, ... ,k*]P
		c = SM2_BN_is_bit_set(ki + w-1, i+e);
		for ( j = w-2; j >= 0; j-- )
		{
			c <<= 1;
			c  += SM2_BN_is_bit_set(ki + j, i+e); 
		}

		if(c)
		{
			TABLE_ELE_2_POINT(Pi, p_2e[c]);  
			q_is_infinity ? EC_POINT_copy(&Q, &Pi) : SM2_ec_GFp_simple_add(group, &Q, &Q, &Pi);   
			q_is_infinity = 0; 
		}   
	} 

	EC_POINT_copy(p_pt_r, &Q);
	return 1;
}

/* 修剪后的随机数便于做Alg18中的运算 */
int ec_trim_rand_a18(BIGNUM *p)
{ 
	int i, j, d, e, w = SM2_ALG18_GP_W, pos;
	BIGNUM bn;
  
	d = (ECC_BITS+w-1)/w;
	e = (d+1)/2; 

	SM2_BN_zero(&bn);
	 
	for (i = SM2_RAND_TRIM_WIDTH - 1; i >= 0; i--)
	{   
		for ( j = w-1; j >=0; j-- )
		{ 
			pos = j*d+i;
			if( SM2_BN_is_bit_set(p, pos) )
			{
				SM2_BN_set_bit(&bn, pos);
			} 

			pos += e; 
			if( SM2_BN_is_bit_set(p, pos) )
			{
				SM2_BN_set_bit(&bn, j*d+i+e);
			} 
		}  
	} 

	SM2_BN_copy(p, &bn);
	return 1;
} 

/* 修剪后的随机数便于做普通的 SM2_EC_POINTs_mul 中的运算 */
int ec_trim_rand(BIGNUM *p)
{  
#if 1
	ec_trim_rand_a18(p);
	MM_MEMSET(p->d+2, 0x00, sizeof(p->d) - 2*sizeof(u32_t)); 
#else
	u32_t v = p->d[0];
	SM2_BN_set_word(p, v);
#endif
	return 1;
} 