
#include "sm2_bn.h"
 

void SM2_BN_mul_nomal(u32_t *r, u32_t *a, int na, u32_t *b, int nb)
{
	u32_t *rr;	
	if (na < nb)
	{
		int itmp;
		u32_t *ltmp;
		
		itmp = na; na = nb; nb = itmp;
		ltmp = a; a = b; b = ltmp;
		
	}
	rr = &(r[na]);
	rr[0] = sm2_bn_mul_words(r, a, na, b[0]);
	
	for (;;)
	{
		if (--nb <= 0) return;
		rr[1] = sm2_bn_mul_add_words(&(r[1]), a, na, b[1]);
		if (--nb <= 0) return;
		rr[2] = sm2_bn_mul_add_words(&(r[2]), a, na, b[2]);
		if (--nb <= 0) return;
		rr[3] = sm2_bn_mul_add_words(&(r[3]), a, na, b[3]);
		if (--nb <= 0) return;
		rr[4] = sm2_bn_mul_add_words(&(r[4]), a, na, b[4]);
		rr += 4;
		r += 4;
		b += 4;
	}
}

void SM2_BN_mul(u32_t *r, int *rl, u32_t *a, int al, u32_t *b, int bl)
{
	if ((al == 0) || (bl == 0))
	{
		*rl = 0;
		return;
	}
	
	*rl = al + bl;	
    SM2_BN_mul_nomal(r, a, al, b, bl);
	
	sm2_bn_fix_top(r, rl);
}


/* c = a * b mod p , p = B**8 - B**7 - B**3 + B**2 + 1, B = 2**32 */
int SM2_BN_mul_mod_p_sm2(u32_t c[ECC_BLOCK_LEN_DWORD], u32_t a[ECC_BLOCK_LEN_DWORD], u32_t b[ECC_BLOCK_LEN_DWORD])
{
	const int l_u32 =ECC_BLOCK_LEN_DWORD, l_u8 = ECC_BLOCK_LEN;
	int len;
	u32_t *p1, *p2, *pt, counter = 0;
	u32_t r[ECC_BLOCK_LEN_DWORD<<1], t[ECC_BLOCK_LEN_DWORD<<1], zero[ECC_BLOCK_LEN_DWORD]={0};
	
	p1 = r; 
	p2 = t;
	SM2_BN_mul_nomal(t, a, l_u32, b, l_u32);// p2 <- t 

	while( MM_MEMCMP(p2+l_u32, zero, l_u8) )/** p2 的高8字非零 **/
	{   
		MM_MEMSET(p1+l_u32, 0x00, l_u8);
		MM_MEMCPY(p1, p2, l_u8);//p1 <- (0,...,0) || (d7,...,d0)
		len = ECC_BLOCK_LEN_DWORD;

		MM_MEMSET(p2, 0x00, l_u8);// p2 <-  (d15,...,d8)||(0,...,0) 

		SM2_BN_uadd(p1, &len, p1, len, p2+l_u32-0, l_u32+0);//p1 <- p1 + (t15,...,t8)
		SM2_BN_uadd(p1, &len, p1, len, p2+l_u32-7, l_u32+7);//p1 <- p1 + (t15,...,t8) * B**7
		SM2_BN_uadd(p1, &len, p1, len, p2+l_u32-3, l_u32+3);//p1 <- p1 + (t15,...,t8) * B**3
		SM2_BN_usub(p1, &len, p1, len, p2+l_u32-2, l_u32+2);//p1 <- p1 + (t15,...,t8) * B**2 

		pt = p1;
		p1 = p2;
		p2 = pt;
		counter++;
	}

	//p2 = d mod p 
	MM_MEMCPY(c, p2, l_u8);
	return 1; 
}


/*p = B**8 - B**7 - B**3 + B**2 + 1, B = 2**32 */
int SM2_BN_mod_p_sm2(u32_t res[ECC_BLOCK_LEN_DWORD], u32_t d[ECC_BLOCK_LEN_DWORD*2] 	)
{
	const u32_t l_u32 =ECC_BLOCK_LEN_DWORD, l_u8 = ECC_BLOCK_LEN;
	int len;
	u32_t *p1, *p2, *pt;
	u32_t r[ECC_BLOCK_LEN_DWORD<<1], t[ECC_BLOCK_LEN_DWORD<<1], zero[ECC_BLOCK_LEN_DWORD]={0};

	p1 = r; 
	p2 = t;
	MM_MEMCPY(p2, d, l_u8<<1);// p2 <- d 

	while( MM_MEMCMP(p2+l_u32, zero, l_u8) )/** p2 的高8字非零 **/
	{   
		MM_MEMSET(p1+l_u8, 0x00, l_u8);
		MM_MEMCPY(p1, p2, l_u8);//p1 <- (0,...,0) || (d7,...,d0)
		len = l_u32;

		MM_MEMSET(p2, 0x00, l_u8);// p2 <-  (d15,...,d8)||(0,...,0) 

		SM2_BN_uadd(p1, &len, p1, len, p2+l_u32-0, l_u32+0);//p1 <- p1 + (t15,...,t8)
		SM2_BN_uadd(p1, &len, p1, len, p2+l_u32-7, l_u32+7);//p1 <- p1 + (t15,...,t8) * B**7
		SM2_BN_uadd(p1, &len, p1, len, p2+l_u32-3, l_u32+3);//p1 <- p1 + (t15,...,t8) * B**3
		SM2_BN_usub(p1, &len, p1, len, p2+l_u32-2, l_u32+2);//p1 <- p1 + (t15,...,t8) * B**2 

		pt = p1;
		p1 = p2;
		p2 = pt;
	}

	//p2 = d mod p 
	MM_MEMCPY(res, p2, l_u8);
	return 1; 
}