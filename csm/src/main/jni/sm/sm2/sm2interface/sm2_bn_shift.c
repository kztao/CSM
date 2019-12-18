#include "mm_basic_fun.h"
#include "sm2_bn.h" 

void SM2_BN_rshift1(BIGNUM *r, int *r_top, BIGNUM *a, int a_top)
{
	u32_t *ap, *rp, t, c;
	int i;	
	if(a_top == 0)
	{
		SM2_BN_zero(r); 
		*r_top = 0;
		return ;
	}
	
	ap = a->d;
	rp = r->d;
	c = 0;
	for(i = a_top-1; i >= 0; i--)
	{
		t = ap[i];
		rp[i] = (t >> 1) | c;
		c = (t & 1) ? SM2_BN_TBIT : 0;
	}
	
	if(r->d[a_top-1])
		*r_top = a_top;
	else
		*r_top = a_top-1;
}

int SM2_BN_lshift(u32_t *r, int *rl, u32_t *a, int al, int n)
{
	int i, nw, lb, rb;
	u32_t l;
	
	nw = n/SM2_BN_BITS2;
	lb = n%SM2_BN_BITS2;
	rb = SM2_BN_BITS2 - lb;
	r[al+nw] = 0;
	if (lb == 0)
		for (i = al - 1; i >= 0; i--)
			r[nw+i] = a[i];
		else
			for (i = al - 1; i >= 0; i--)
			{
				l=a[i];
				r[nw+i+1] |= (l >> rb) & SM2_BN_MASK2;
				r[nw+i] = (l << lb) & SM2_BN_MASK2;
			}
			MM_MEMSET(r, 0, nw*sizeof(r[0]));
			/*	for (i=0; i<nw; i++)
			t[i]=0;*/
			*rl = al + nw + 1;
			sm2_bn_fix_top(r, rl);
			return(1);
}

int SM2_BN_rshift(u32_t *r, int *rl, u32_t *a, int al, int n)
{
	int i, j, nw, lb, rb;
	u32_t *t, *f;
	u32_t l, tmp;
	
	nw = n / SM2_BN_BITS2;
	rb = n % SM2_BN_BITS2;
	lb = SM2_BN_BITS2 - rb;
	if (nw > al || al == 0)
	{ 
		MM_MEMSET(r, 0, sizeof(BIGNUM));
		*rl = 0;
		return 0;
	}
	
	f = &a[nw];
	t = r;
	j = al - nw;
	*rl = j;
	
	if (rb == 0)
	{
		for (i = j + 1; i > 0; i--)
			*(t++) = *(f++);
	}
	else
	{
		l = *(f++);
		for (i = 1; i < j; i++)
		{
			tmp = (l >> rb) & SM2_BN_MASK2;
			l = *(f++);
			*(t++) = (tmp | (l << lb)) & SM2_BN_MASK2;
		}
		*(t++) = (l >> rb) & SM2_BN_MASK2;
	}
	*t = 0;
	sm2_bn_fix_top(r, rl);
	return(1);
}


/**   判断2个大数是否相等,0 相等，1 不等 **/
// 
// int two_number_same(u32_t *a, int len, u32_t *b)
// {
// 	int i;
// 	int sum =0;
// 	int hh;
// 	for(i=0;i<len;i++)
// 	{
// 		if( a[i] == b[i]) hh=0;
// 		else hh =1;
// 		sum  = sum +hh;
// 	}
// 	
// 	if(sum ==0) return 0;
// 	else return  1;
// }


