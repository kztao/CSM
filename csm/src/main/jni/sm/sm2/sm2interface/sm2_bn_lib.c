#include "sm2_bn.h"
#include "mm_basic_fun.h"


void SM2_BN_store_bn(BIGNUM *p_bn, BYTE *p_byte  )
{
// 	int i,j; 
// 	BYTE *p_u8 = p_byte;
// 	
// 	for ( i = 0, j = ECC_BLOCK_LEN_DWORD-1; i < ECC_BLOCK_LEN_DWORD; i++,j-- )
// 	{ 
// 		MM_STORE_U32H(p_bn->d[j], p_u8);
// 		p_u8 += 4;
// 	} 
	int j; 
	for ( j = ECC_BLOCK_LEN_DWORD-1; j >=0; j-- )
	{ 
		MM_STORE_U32H(p_bn->d[j], p_byte);
		p_byte += 4;
	} 
}

void SM2_BN_load_bn(BIGNUM *p_bn, BYTE *p_byte  )
{
// 	int i, j; 
// 	BYTE *p_u8 = p_byte;
// 	
// 	MM_MEMSET(p_bn, 0x00, sizeof(BIGNUM)); 
// 	for ( i = 0, j = ECC_BLOCK_LEN_DWORD-1; i < ECC_BLOCK_LEN_DWORD; i++,j-- )
// 	{ 
// 		MM_LOAD_U32H(p_bn->d[j], p_u8);
// 		p_u8 += 4;
// 	} 
	
	int j; 

	MM_MEMSET(p_bn->d + ECC_BLOCK_LEN_DWORD, 0x00, 
		sizeof(p_bn->d)-ECC_BLOCK_LEN_DWORD*sizeof(p_bn->d[0])); 
	for (  j = ECC_BLOCK_LEN_DWORD-1; j >=0; j-- )
	{ 
		MM_LOAD_U32H(p_bn->d[j], p_byte);
		p_byte += 4;
	} 
}

int SM2_BN_is_zero(u32_t *a, u32_t al)
{ 
	int i;
	for(i = (int)(al-1); i >= 0; i--)
		if( a[i] )
			return 0;
	return 1; 
}

int SM2_BN_is_one(u32_t *a, u32_t al)
{
	int i = 0;
	
	if( a[i++] != 1)
		return 0;
	for(; i < (int)(al-1); i++)
		if( a[i] )
			return 0;
	return 1;
}

void sm2_bn_fix_top(u32_t *a, int *al)
{
	if (*al > 0) 
	{ 
		for (; *al > 0; (*al)--) 
			if ( *(a+(*al)-1) ) break; 
	} 
}

int SM2_BN_num_bits_word(u32_t l)
{
	int i = SM2_BN_BITS2;
	
	while( !(l & (1 << (i-1))) )
		i--;
	
	return i;				
}



int SM2_BN_num_bits(u32_t *a, int al)
{
	u32_t l;
	int i, dwords;
	
    dwords = al;
	sm2_bn_fix_top(a, &dwords);
	
	if (dwords == 0) return(0);
	l = a[dwords-1];
	i = (dwords-1) * SM2_BN_BITS2;
	return(i + SM2_BN_num_bits_word(l));
}

int SM2_BN_ucmp(u32_t *a, int al, u32_t *b, int bl)
{
	int i;
	u32_t t1, t2;
	
	i = al - bl;
	if (i != 0) return(i);
	for (i = al - 1; i >= 0; i--)
	{
		t1 = a[i];
		t2 = b[i];
		if (t1 != t2)
			return(t1 > t2 ? 1 : -1);
	}
	return(0);
}


int SM2_BN_is_bit_set(const BIGNUM *a, int n)
{
	int i,j; 
	if (n < 0) 
		return 0;

	i=n/SM2_BN_BITS2;
	j=n%SM2_BN_BITS2; 

	if (i*sizeof(a->d[0]) >= sizeof(a->d)) 
		return 0;

	return (a->d[i] & (0x1<<j))? 1 : 0;
}

int SM2_BN_set_bit(BIGNUM *a, int n)
{
	int i,j;

	if (n < 0)
		return 0;

	i=n/SM2_BN_BITS2;
	j=n%SM2_BN_BITS2;

	a->d[i] |= 1 << j;
	return(1);
}

int SM2_BN_clear_bit(BIGNUM *a, int n)
{
	int i,j;
 
	if (n < 0) return 0;

	i=n/SM2_BN_BITS2;
	j=n%SM2_BN_BITS2; 

	a->d[i] &= ~( 1 << j );
	return(1);
}
// void SM2_BN_set_word(BIGNUM *a, u32_t w)
// {
// 	MM_MEMSET(a, 0x00, sizeof(BIGNUM));
// 	a->d[0] = w;
// }
//  
// 
// void SM2_BN_init(BIGNUM *a)
// {
// 	MM_MEMSET(a,0,sizeof(BIGNUM)); 
// } 
// 
// 
// BIGNUM *SM2_BN_copy(BIGNUM *a, const BIGNUM *b)
// {
// 	MM_MEMCPY(a, b, sizeof(BIGNUM));
// 	return(a);
// }



/* Determine the width-(w+1) Non-Adjacent Form (wNAF) of 'scalar'.
 * This is an array  r[]  of values that are either zero or odd with an
 * absolute value less than  2^w  satisfying
 *     scalar = \sum_j r[j]*2^j
 * where at most one of any  w+1  consecutive digits is non-zero.
 */
//signed char *compute_wNAF(BIGNUM *scalar, int w, int order_top, int *ret_len)//20150528 luoying del
int compute_wNAF(BIGNUM *scalar, int w, int order_top, int *ret_len, char *r, int r_sz)//20150528 luoying add
{
	int top;
	BIGNUM c;
	int bit, next_bit, mask;
	u32_t len = 0, j;
	//signed char *r; //20150528 luoying del
	bit = 1 << w; /* at most 128 */
	next_bit = bit << 1; /* at most 256 */
	mask = next_bit - 1; /* at most 255 */

	SM2_BN_copy(&c, scalar); 

	top = order_top;
	
	len = SM2_BN_num_bits(c.d, top) + 1; /* wNAF may be one digit longer than binary representation */

	//r = (signed char *)MM_MALLOC(len);// //20150528 luoying del
	if( (int)len > r_sz )
	{
		return -1;
	}

	j = 0;
	while (top)
	{
		int u = 0, u1;

		if (c.d[0] & 1) 
		{
			u = c.d[0] & mask;
			if (u & bit)
			{
				u -= next_bit;
				/* u < 0 */
				//c.d[0] -= u;
				u1 = -u;
                SM2_BN_uadd(c.d, &top, c.d, top, (u32_t *)&u1, 1);
			}
			else
			{
				/* u > 0 */
				//c.d[0] -= u;
				u1 = u;
                SM2_BN_usub(c.d, &top, c.d, top, (u32_t *)&u1, 1);
			}
		}

		r[j++] = (char)(u);
				
		SM2_BN_rshift1(&c, &top, &c, top);
	}

	*ret_len = j;

	//return r;//20150528 luoying del
	return 1;
}