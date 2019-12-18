#include "mm_basic_fun.h"
#include "sm2_bn.h" 

void SM2_BN_mod_add(u32_t *r, u32_t *a, u32_t *b, u32_t *m, u32_t mLen)
{
   int rl;

   SM2_BN_uadd(r, &rl, a, mLen, b, mLen);
   if(SM2_BN_ucmp(r, rl, m, mLen) >= 0)	//r >= m
   {
       SM2_BN_usub(r, &rl, r, rl, m, mLen);
   }
}

void SM2_BN_mod_sub(u32_t *r, int *rl, u32_t *a, u32_t *b, u32_t *m, u32_t mLen)
{
    if(SM2_BN_ucmp(a, mLen, b, mLen) >= 0)	//a >= b
    {
	    SM2_BN_usub(r, rl, a, mLen, b, mLen);
	}
	else
	{
	    u32_t t[ECC_BLOCK_LEN_DWORD+2];
	    int tl;	    
	    SM2_BN_usub(t, &tl, m, mLen, b, mLen);
		SM2_BN_uadd(r, rl, a, mLen, t, tl);	
	}
}



void SM2_BN_mod_mul(u32_t *r, int *rl, u32_t *a, int al, u32_t *b, int bl,
				u32_t *m, u32_t mLen)
{
    u32_t muL_res[ECC_BLOCK_LEN_DWORD*2+1];
	int muL_res_top = 0;
	SM2_BN_mul(muL_res, &muL_res_top, a, al, b, bl); 
    SM2_BN_div(NULL, NULL, r, rl, muL_res, muL_res_top, m, mLen); 
}

void SM2_BN_mod_lshift1(u32_t *r, u32_t *a, u32_t *m, u32_t mLen)
{
	u32_t t0, t1, t2;
	u32_t c, carry;
	int i;
	
	if(a[mLen-1] & 0x80000000)	/** 大于模数 **/
		goto SM2_BN_mod_lshift1a;
		
	for(i = mLen - 1; i > 0; i--)
	{
		t0 = (a[i] << 1) + (a[i-1] >> 31);
		if(t0 > m[i])	/** 大于模数 **/
		{
SM2_BN_mod_lshift1a:
				c = 0;
				carry = 0;
				for(i = 0; i < (int)mLen; i++)
				{
						t0 = a[i];
						t1 = (t0 << 1) + c;
						t2 = m[i];
						r[i] = t1 - t2 - carry;
						if (t1 != t2) carry = (t1 < t2);
						c = t0 >> 31;
				}
				return;
		}	   
		if(t0 < m[i])	/** 小于模数 **/
		{
				c = 0;
				for(i = 0;i < (int)mLen; i++)
				{
						t0 = a[i];
						t1 = (t0 << 1) + c;
						r[i] = t1;
						c = t0 >> 31;
				}
				return;
		}
	}
	
	t0 = (a[i]<<1);
	if(t0 > m[i])	/** 大于模数 **/
	{
			c = 0;
			carry = 0;
			for(i = 0; i < (int)mLen; i++)
			{
					t0 = a[i];
					t1 = (t0 << 1) + c;
					t2 = m[i];
					r[i] = t1 - t2 - carry;
					if (t1 != t2) carry = (t1 < t2);
					c = t0 >> 31;
			}
			return;
	}	   
	if(t0 < m[i])	/** 小于模数 **/
	{
			c = 0;
			for(i = 0; i < (int)mLen; i++)
			{
					t0 = a[i];
					t1 = (t0<<1) + c;
					r[i] = t1;
					c = t0 >> 31;
			}
			return;
	}
	
	MM_MEMSET(r, 0, mLen);
}

