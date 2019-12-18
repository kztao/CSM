#include "sm2_bn.h" 
#include "sm2_bn_lcl.h"

#define LUO_UNROLL_8
u32_t sm2_bn_mul_add_words(u32_t *rp, const u32_t *ap, int num, u32_t w)
{
	u32_t c = 0;
	u32_t bl, bh;

	if (num <= 0) return((u32_t)0);

	bl = LBITS(w);
	bh = HBITS(w);

	for (;;)
	{
		mul_add(rp[0], ap[0], bl, bh, c);
		if (--num == 0) break;
		mul_add(rp[1], ap[1], bl, bh, c);
		if (--num == 0) break;
		mul_add(rp[2], ap[2], bl, bh, c);
		if (--num == 0) break;
		mul_add(rp[3], ap[3], bl, bh, c);
		if (--num == 0) break;
		ap+=4;
		rp+=4;
	}
	return(c);
} 

u32_t sm2_bn_mul_words(u32_t *rp, const u32_t *ap, int num, u32_t w)
{
	u32_t carry=0;
	u32_t bl, bh;

	if (num <= 0) return((u32_t)0);

	bl = LBITS(w);
	bh = HBITS(w);
#ifndef LUO_UNROLL_8
	//20150528 luoying change from
	for (;;)
	{
		mul(rp[0], ap[0], bl, bh, carry);
		if (--num == 0) break;
		mul(rp[1], ap[1], bl, bh, carry);
		if (--num == 0) break;
		mul(rp[2], ap[2], bl, bh, carry);
		if (--num == 0) break;
		mul(rp[3], ap[3], bl, bh, carry);
		if (--num == 0) break;
		ap+=4;
		rp+=4;
	}
#else
	//20150528 luoying change to

	for (;num >= 8; num -= 8 )
	{
		mul(rp[0], ap[0], bl, bh, carry); 
		mul(rp[1], ap[1], bl, bh, carry); 
		mul(rp[2], ap[2], bl, bh, carry); 
		mul(rp[3], ap[3], bl, bh, carry); 
		mul(rp[4], ap[4], bl, bh, carry); 
		mul(rp[5], ap[5], bl, bh, carry); 
		mul(rp[6], ap[6], bl, bh, carry); 
		mul(rp[7], ap[7], bl, bh, carry); 
		ap += 8;
		rp += 8;
	}

	for (; num > 0; num-- )
	{
		mul(rp[0], ap[0], bl, bh, carry);
		ap++;
		rp++;
	}  
	//20150528 luoying change end
#endif
	return(carry);
} 

u32_t sm2_bn_div_words(u32_t h, u32_t l, u32_t d)
{
	u32_t dh, dl, q, ret = 0, th, tl, t;
	int i, count = 2;

	if (d == 0) return(SM2_BN_MASK2);

	i = SM2_BN_num_bits_word(d);

	i = SM2_BN_BITS2 - i;
	if (h >= d) h -= d;

	if (i)
	{
		d <<= i;
		h = (h << i) | (l >> (SM2_BN_BITS2 - i));
		l <<= i;
	}
	dh = (d & SM2_BN_MASK2h) >> SM2_BN_BITS4;
	dl = (d & SM2_BN_MASK2l);
	for (;;)
	{
		if ((h >> SM2_BN_BITS4) == dh)
			q = SM2_BN_MASK2l;
		else
			q = h / dh;

		th = q * dh;
		tl = dl * q;
		for (;;)
		{
			t = h - th;
			if ((t & SM2_BN_MASK2h) ||
				((tl) <= (
					(t << SM2_BN_BITS4)|
					((l & SM2_BN_MASK2h) >> SM2_BN_BITS4))))
				break;
			q--;
			th -= dh;
			tl -= dl;
		}
		t = (tl >> SM2_BN_BITS4);
		tl = (tl << SM2_BN_BITS4) & SM2_BN_MASK2h;
		th += t;

		if (l < tl) th++;
		l -= tl;
		if (h < th)
		{
			h += d;
			q--;
		}
		h -= th;

		if (--count == 0) break;

		ret = q << SM2_BN_BITS4;
		h = ((h << SM2_BN_BITS4)|(l >> SM2_BN_BITS4)) & SM2_BN_MASK2;
		l = (l & SM2_BN_MASK2l) << SM2_BN_BITS4;
	}
	ret |= q;
	return(ret);
}

u32_t sm2_bn_add_words(u32_t *r, const u32_t *a, const u32_t *b, int n)
{
	u32_t c, l, t;

	if (n <= 0) return((u32_t)0);

	c=0;

#define ADC_32(ri, ai, bi)\
{\
	t = ai;\
	t = (t + c)& SM2_BN_MASK2;\
	c = (t < c);\
	l = (t + bi)& SM2_BN_MASK2;\
	c += (l < t);\
	ri = l;\
}
#ifndef LUO_UNROLL_8

	//20150528 luoying change from
	for (;;)
	{
		t = a[0];
		t = (t + c) & SM2_BN_MASK2;
		c = (t < c);
		l = (t + b[0]) & SM2_BN_MASK2;
		c += (l < t);
		r[0] = l;
		if (--n <= 0) break;

		t = a[1];
		t = (t + c) & SM2_BN_MASK2;
		c =(t < c);
		l =(t + b[1]) & SM2_BN_MASK2;
		c += (l < t);
		r[1] = l;
		if (--n <= 0) break;

		t = a[2];
		t =(t + c) & SM2_BN_MASK2;
		c =(t < c);
		l =(t + b[2]) & SM2_BN_MASK2;
		c += (l < t);
		r[2] = l;
		if (--n <= 0) break;

		t = a[3];
		t =(t + c) & SM2_BN_MASK2;
		c =(t < c);
		l =(t + b[3]) & SM2_BN_MASK2;
		c += (l < t);
		r[3] = l;
		if (--n <= 0) break;

		a += 4;
		b += 4;
		r += 4;

	}
	//20150528 luoying change to
#else

	for (;n >= 8; n -= 8 )
	{ 
		ADC_32(r[0], a[0], b[0]);
		ADC_32(r[1], a[1], b[1]);
		ADC_32(r[2], a[2], b[2]);
		ADC_32(r[3], a[3], b[3]);
		ADC_32(r[4], a[4], b[4]);
		ADC_32(r[5], a[5], b[5]);
		ADC_32(r[6], a[6], b[6]);
		ADC_32(r[7], a[7], b[7]);

		a += 8;
		b += 8;
		r += 8;
	}

	for (; n > 0; n-- ) 
	{
		ADC_32(r[0], a[0], b[0]); 
		a++;
		b++;
		r++;
	}
	//20150528 luoying change end
#endif
	return((u32_t)c);
}

u32_t sm2_bn_sub_words(u32_t *r, const u32_t *a, const u32_t *b, int n)
{
	u32_t t1, t2;
	int c = 0;

	if (n <= 0) return((u32_t)0);

#define SBB_32(ri, ai, bi)\
{\
	t1 = ai;\
	t2 = bi;\
	ri = (t1 - t2 - c) & SM2_BN_MASK2;\
	if (t1 != t2) c = (t1 < t2);\
}
#ifndef LUO_UNROLL_8
	//luoying change from
	for (;;)
	{
		t1 = a[0]; t2 = b[0];
		r[0] = (t1 - t2 - c) & SM2_BN_MASK2;
		if (t1 != t2) c = (t1 < t2);
		if (--n <= 0) break;

		t1 = a[1]; t2 = b[1];
		r[1] = (t1 - t2 - c) & SM2_BN_MASK2;
		if (t1 != t2) c = (t1 < t2);
		if (--n <= 0) break;

		t1 = a[2]; t2 = b[2];
		r[2] = (t1 - t2 - c) & SM2_BN_MASK2;
		if (t1 != t2) c = (t1 < t2);
		if (--n <= 0) break;

		t1 = a[3]; t2 = b[3];
		r[3] = (t1 - t2 - c) & SM2_BN_MASK2;
		if (t1 != t2) c = (t1 < t2);
		if (--n <= 0) break;

		a += 4;
		b += 4;
		r += 4;
	} 
#else
	//20150528 luoying change to

	for (;n>=8;n-=8)
	{
		SBB_32(r[0], a[0], b[0]);
		SBB_32(r[1], a[1], b[1]);
		SBB_32(r[2], a[2], b[2]);
		SBB_32(r[3], a[3], b[3]);
		SBB_32(r[4], a[4], b[4]);
		SBB_32(r[5], a[5], b[5]);
		SBB_32(r[6], a[6], b[6]);
		SBB_32(r[7], a[7], b[7]);

		a += 8;
		b += 8;
		r += 8;
	}

	for ( ; n > 0; n-- )
	{
		SBB_32(r[0], a[0], b[0]);

		a++;
		b++;
		r++;
	}
	//20150528 luoying change end
#endif

	return(c);
}

