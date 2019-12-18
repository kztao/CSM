#ifndef SM2_BN_LCL_H
#define SM2_BN_LCL_H

#include "sm2_bn.h"

#define Lw(t)    (((u32_t)(t))&SM2_BN_MASK2)
#define Hw(t)    (((u32_t)((t)>>SM2_BN_BITS2))&SM2_BN_MASK2)

#define LBITS(a)	((a)&SM2_BN_MASK2l)
#define HBITS(a)	(((a)>>SM2_BN_BITS4)&SM2_BN_MASK2l)
#define	L2HBITS(a)	((u32_t)((a)&SM2_BN_MASK2l)<<SM2_BN_BITS4)

#define LLBITS(a)	((a)&SM2_BN_MASKl)
#define LHBITS(a)	(((a)>>SM2_BN_BITS2)&SM2_BN_MASKl)
#define	LL2HBITS(a)	((SM2_BN_ULLONG)((a)&SM2_BN_MASKl)<<SM2_BN_BITS2)

#define mul64(l,h,bl,bh) \
	{ \
	u32_t m,m1,lt,ht; \
	\
	lt=l; \
	ht=h; \
	m =(bh)*(lt); \
	lt=(bl)*(lt); \
	m1=(bl)*(ht); \
	ht =(bh)*(ht); \
	m=(m+m1)&SM2_BN_MASK2; if (m < m1) ht+=L2HBITS(1L); \
	ht+=HBITS(m); \
	m1=L2HBITS(m); \
	lt=(lt+m1)&SM2_BN_MASK2; if (lt < m1) ht++; \
	(l)=lt; \
	(h)=ht; \
	}

#define mul_add(r,a,bl,bh,c) { \
	u32_t l,h; \
	\
	h= (a); \
	l=LBITS(h); \
	h=HBITS(h); \
	mul64(l,h,(bl),(bh)); \
	\
	/* non-multiply part */ \
	l=(l+(c))&SM2_BN_MASK2; if (l < (c)) h++; \
	(c)=(r); \
	l=(l+(c))&SM2_BN_MASK2; if (l < (c)) h++; \
	(c)=h&SM2_BN_MASK2; \
	(r)=l; \
	}

#define mul(r,a,bl,bh,c) { \
	u32_t l,h; \
	\
	h= (a); \
	l=LBITS(h); \
	h=HBITS(h); \
	mul64(l,h,(bl),(bh)); \
	\
	/* non-multiply part */ \
	l+=(c); if ((l&SM2_BN_MASK2) < (c)) h++; \
	(c)=h&SM2_BN_MASK2; \
	(r)=l&SM2_BN_MASK2; \
	}


#endif
