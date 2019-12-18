#include "mm_basic_fun.h"
#include "ec.h"
#include "ec_lcl.h"


//luoying del
// #define EC_window_bits_for_scalar_size(b) \
// 		((b) >=  300 ? 4 : \
// 		 (b) >=   70 ? 3 : \
// 		 (b) >=   20 ? 2 : \
// 		  1)
//luoying add
/*返回值不得超过5，否则SM2_EC_POINTs_mul 内分配点空间不足 */
#define EC_window_bits_for_scalar_size(b) \
	((b) >=  300 ? 5 : \
	(b) >=   70 ? 5 : \
	(b) >=   20 ? 4 : \
	1)
/*	计算 R = kP 或 R = kP + lQ	*/

//#define LUOYING_DEBUG
#ifdef LUOYING_DEBUG//luoying add
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void FprintfPoint(FILE *fp, EC_POINT*pt, int k)//luoying add
{
	int counter, sz = ECC_BLOCK_LEN_DWORD;
	BYTE *p = NULL;
	if ( fp != NULL)
	{	
		p = (BYTE*)(&k);
		fprintf(fp, "%02X %02X %02X %02X ", p[0], p[1], p[2], p[3]);

		p = (BYTE*)pt;
		for (  counter = 0; counter<sizeof(EC_POINT); counter++)
		{
			fprintf(fp, "%02X ", p[counter]);  
		} 
	}

	//if ( fp != NULL)
	if(0)
	{	
		 fprintf(fp, "k = %4d, pt = (x, y, z) =\n", k);
		for (  counter = 0; counter<sz; counter++)
		{
			fprintf(fp, "%08x, ", pt->X.d[counter]);  
		}
		fprintf(fp, "\n");
		
		for (  counter = 0; counter<sz; counter++)
		{
			fprintf(fp, "%08x, ", pt->Y.d[counter]);  
		}
		fprintf(fp, "\n");
		
		for (  counter = 0; counter<sz; counter++)
		{
			fprintf(fp, "%08x, ", pt->Z.d[counter]);  
		}
		fprintf(fp, "\n\n\n"); 
	}
}
#endif

void SM2_EC_POINTs_mul(EC_GROUP *group, EC_POINT *R, EC_POINT *P, BIGNUM *k, EC_POINT *Q, BIGNUM *l) 
{
	EC_POINT tmp;
	int num;
	int totalnum; /** 最多为2 **/
	int i, j, flag;
	int kk;
	int r_is_inverted = 0;
	int r_is_at_infinity = 1;
	int top;
	int wsize[2]; /* individual window sizes */
	int wNAF_len[2];
	int max_len = 0;
	int num_val;
//	signed char **wNAF; /* individual wNAFs */	// 20150528 luoying del
	signed char *wNAF[3]={0};					// 20150528 luoying add
	EC_POINT val_sub[2][16]; /* pointers to sub-arrays of 'val' */
	signed char wNAF0[3][512+16]; /** 一般而言，NAF0[totalnum+1][256+1]比较合适，totalnum最多为2 **/
	
	
#ifdef LUOYING_DEBUG//luoying add
	int debug = 1;//(P->X.d[0] == 0x57194b3c);
	FILE *fp = NULL; 

	memset(val_sub, 0x00, sizeof(val_sub));
#endif //#ifdef LUOYING_DEBUG
#ifdef LUOYING_DEBUG//luoying add
	if(debug)
	{	
		fp = fopen("d:\\SM2_EC_POINTs_mul_wst.txt", "wt"); 
		memset(&tmp, 0x00, sizeof(tmp));
		FprintfPoint(fp, &tmp, 0); 
		FprintfPoint(fp, &tmp, 0); 
		FprintfPoint(fp, &tmp, 0); 
		FprintfPoint(fp, &tmp, 0); 
	}
#endif //#ifdef LUOYING_DEBUG
	if(l == NULL)
	{
		totalnum = 1;
		num = 0;
	}
	else
	{
		totalnum = 2;
		num = 1;
	}
			
//	wNAF = (signed char **)MM_MALLOC((totalnum + 1) * sizeof wNAF[0]);// 20150528 luoying del

	/* num_val := total number of points to precompute */
	num_val = 0;
	for (i = 0; i < totalnum; i++)
	{
		int bits;

		bits = i < num ? SM2_BN_num_bits(l->d,group->order_top) : SM2_BN_num_bits(k->d,group->order_top);
		wsize[i] = EC_window_bits_for_scalar_size(bits);
		num_val += 1 << (wsize[i] - 1);
	}

	/* prepare precomputed values:
	 *    val_sub[i][0] :=     points[i]
	 *    val_sub[i][1] := 3 * points[i]
	 *    val_sub[i][2] := 5 * points[i]
	 *    ...
	 */
	for (i = 0; i < totalnum; i++)
	{
		if (i < num)
		{
			MM_MEMCPY(&val_sub[i][0], Q, sizeof(EC_POINT));		
		}
		else
		{
			MM_MEMCPY(&val_sub[i][0], P, sizeof(EC_POINT));		
		}

		if (wsize[i] > 1)
		{
		    SM2_ec_GFp_simple_dbl(group, &tmp, &val_sub[i][0]);

			for (j = 1; j < (int)(1u << (wsize[i] - 1)); j++)
			{
				SM2_ec_GFp_simple_add(group, &val_sub[i][j], &val_sub[i][j - 1], &tmp);

#ifdef LUOYING_DEBUG//luoying add
				if(debug)
				{	
					FprintfPoint(fp, &val_sub[i][j], j); 
				}
#endif //#ifdef LUOYING_DEBUG
			}
		}
		wNAF[i + 1] = 0; 

		//20150528 luoying change from
		//wNAF[i] = compute_wNAF((i < num ? l : k), wsize[i], group->order_top, &wNAF_len[i]);
		//20150528 luoying change to
		flag = compute_wNAF((i < num ? l : k), wsize[i], group->order_top, 
			&wNAF_len[i], wNAF0[i], sizeof(wNAF0[i]));
		if( flag <= 0 )
		{
			MM_MEMSET(R, 0x00, sizeof(EC_POINT));//error
		}
		wNAF[i] = wNAF0[i];
		//20150528 luoying change end

		if (wNAF_len[i] > max_len)
			max_len = wNAF_len[i];
	}

	r_is_at_infinity = 1;



	for (kk = max_len - 1; kk >= 0; kk--)
	{
#ifdef LUOYING_DEBUG//luoying add
		if(debug && kk==0xf5)
		{
			debug+=0;
		}
#endif //#ifdef LUOYING_DEBUG

		if (!r_is_at_infinity)
		{
		  SM2_ec_GFp_simple_dbl(group, R, R);/** 两个点的double一起做 **/
		}
		
		for (i = 0; i < totalnum; i++)
		{
			if (wNAF_len[i] > kk)
			{
				//int digit = wNAF[i][kk];		//luoying change 20151011
				signed char digit = wNAF[i][kk];//luoying change 20151011
				int is_neg;

				if (digit) 
				{
					is_neg = digit < (signed char)0;

					if (is_neg)
						digit = -digit;

					if (is_neg != r_is_inverted)
					{
						if (!r_is_at_infinity)
						{
							if(ec_GFp_simple_is_at_infinity(group, R) || SM2_BN_is_zero(R->Y.d, group->field_top))
								goto next;

							SM2_BN_usub(R->Y.d, &top, group->field.d, group->field_top, R->Y.d, group->field_top);
						}
						next:
							r_is_inverted = !r_is_inverted;
					}

					/* digit > 0 */

					if (r_is_at_infinity)
					{
						MM_MEMCPY(R, &val_sub[i][digit >> 1], sizeof(EC_POINT));
						r_is_at_infinity = 0;
					}
					else
					{
						SM2_ec_GFp_simple_add(group, R, R, &val_sub[i][digit >> 1]);
					}
				}
			}
		} 
#ifdef LUOYING_DEBUG//luoying add
		if ( fp != NULL)
		{	
			FprintfPoint(fp, R, kk); 
		}
#endif //#ifdef LUOYING_DEBUG

	}

	if (r_is_inverted)
        SM2_BN_usub(R->Y.d, &top, group->field.d, group->field_top, R->Y.d, group->field_top);

#ifdef LUOYING_DEBUG//luoying add
	if ( fp != NULL)
	{	
		FprintfPoint(fp, R, kk); 
		fclose(fp);
	}
#endif //#ifdef LUOYING_DEBUG


// 	if (wNAF != 0)//20150528 luoying del
// 	{
// 		signed char **w;
// 		
// 		for (w = wNAF; *w != 0; w++)
// 			MM_FREE(*w);
// 		
// 		MM_FREE(wNAF);
// 	}
}
 

// /* R = k * P . P = fix point */
//void ec_GFp_fix_point_mul(EC_GROUP *group, EC_POINT *R, EC_POINT *P, BIGNUM *k) 
//{
//
//}