#include "sm2_bn.h"
//#include "sm2_bn_asm.h"
//#include "sm2_bn_lib.h"

int SM2_BN_uadd(u32_t *r, int *rl, u32_t *a, int al, u32_t *b, int bl)
{
	register int i;
	int max, min;
	u32_t *ap, *bp, *rp, carry, t1;
	u32_t *tmp;
	int tmp1;

	if (al < bl)
	{ 
		tmp = a; a = b; b = tmp; 
		tmp1 = al; al = bl; bl = tmp1; 
	}
	max = al;
	min = bl;
	*rl = max;
	ap = a;
	bp = b;
	rp = r;
	carry = 0;

	carry = sm2_bn_add_words(rp, ap, bp, min);
	rp += min;
	ap += min;
	bp += min;
	i = min;

	if (carry)
	{
		while (i < max)
		{	
			i++;
			t1 = *(ap++);
			if ((*(rp++) = (t1+1) & SM2_BN_MASK2) >= t1)
			{
				carry=0;
				break;
			}
		}
		if ((i >= max) && carry)
		{
			*(rp++) = 1;
			(*rl)++;
		}
	}
	if (rp != ap)
	{	
		for (; i < max; i++)
			*(rp++) = *(ap++);
	}
	return(1);
}

int SM2_BN_usub(u32_t *r, int *rl, u32_t *a, int al, u32_t *b, int bl)
{
	int max, min;
	register u32_t t1, t2, *ap, *bp, *rp;
	int i, carry;

	max = al;
	min = bl;

	ap = a;
	bp = b;
	rp = r;

	carry = 0;
	for (i = 0; i < min; i++)
	{
		t1= *(ap++);
		t2= *(bp++);
		if (carry)
		{
			carry = (t1 <= t2);
			t1 = (t1-t2-1) & SM2_BN_MASK2;
		}
		else
		{
			carry = (t1 < t2);
			t1 = (t1-t2) & SM2_BN_MASK2;
		}
		*(rp++) = t1 & SM2_BN_MASK2;
	}

	if (carry) /* subtracted */
	{
		while (i < max)
		{
			i++;
			t1 = *(ap++);
			t2 = (t1 - 1) & SM2_BN_MASK2;
			*(rp++) = t2;
			if (t1 > t2) break;
		}
	}

	if (rp != ap)
	{
		for (;;)
		{
			if (i++ >= max) break;
			rp[0]=ap[0];
			if (i++ >= max) break;
			rp[1]=ap[1];
			if (i++ >= max) break;
			rp[2]=ap[2];
			if (i++ >= max) break;
			rp[3]=ap[3];
			rp+=4;
			ap+=4;
		}
	}

	*rl=max;
	sm2_bn_fix_top(r, rl);
	return(1);
}

