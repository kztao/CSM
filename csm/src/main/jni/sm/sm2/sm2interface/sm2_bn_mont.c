
#include "sm2_bn.h" 
#include "sm2_bn_lcl.h"
#include "mm_config.h"
#include "mm_basic_fun.h"

/** 20141027 luoying 修改了  SM2_BN_mod_mul_montgomery() 函数的代码 **/

//#define USE_OLD_MUL_MONT/* 使用原来的 SM2_BN_mod_mul_montgomery 代码 */

#ifdef USE_OLD_MUL_MONT
#include <assert.h>//debug
#define LUOYING_CHANGE
typedef mm_u64_t u64_t;			/* 64位无符号类型 */ 


#if (!(USE_ASM))
#ifdef WIN32
static u64_t MYMUL(u32_t m1, u32_t m2)
{
	u64_t res = (u64_t)m1 * (u64_t)m2;
	return res;
}
#else
static u64_t MYMUL(u32_t m1, u32_t m2)
{
	register union result 
	{
		u64_t r;
		struct 
		{
			u32_t high;
			u32_t low;
		} ul;
	} res;
	u32_t z0, zla, zlb, z1;
	if (m1 == 0 || m2 == 0)
		return 0;
	
	if (m1 == 1)
		return m2;
	
	if (m2 == 1)
		return m1;
	
	
	z0 = (m1 & 0xffff) * (m2 & 0xffff);
	zla = ((m1 & 0xffff)) * (m2 >> 16);
	zlb = (m1 >> 16) * (m2 & 0xffff);
	z1 = (m1 >> 16) * (m2 >> 16);
	
	res.r = z0;
	res.r += ((u64_t)zla + (u64_t)zlb) << 16;
	res.ul.high += z1;
	
	return res.r;
}
#endif//#ifdef WIN32

#else//#if (USE_ASM)
extern u64_t MYMUL(u32_t m1, u32_t m2);
#endif//#if (!(USE_ASM))



union BigNumber {
	u64_t r;
#if (MM_ENDIAN_TYPE == MM_BIG_ENDIAN )
	struct {
		u32_t n1;
		u32_t n0;
	} ul;
	struct {
		unsigned short n3;
		unsigned short n2;
		unsigned short n1;
		unsigned short n0;
	} us;
#else
	struct {
		u32_t n0;
		u32_t n1;
	} ul;
	struct {
		unsigned short n0;
		unsigned short n1;
		unsigned short n2;
		unsigned short n3;
	} us;
#endif
} res;


#define SM2_BN_HIGH(result, n) \
	do { \
	union BigNumber res; \
	res.r = n; \
	result = res.ul.n1; \
	} while(0)

#define SM2_BN_LOW(result, n) \
	do { \
	union BigNumber res; \
	res.r = n; \
	result = res.ul.n0; \
} while(0) 
#endif

/**
//	函数功能:								//
//		由模数计算出n0、RR					//
//	函数参数:								//
//		Mod:in,模数							//
//		ModLen:in,模长						//
//		n0:out								//							
//		RR:out								//
//	函数返回:								//
//		无									//
**/


void SM2_BN_MONT_CTX_set(u32_t *Mod, int ModLen, u32_t *n0, u32_t *RR)
{
	u32_t R[2];
	u32_t tmod;
	u32_t Ri[2];
	u32_t tmp[ECC_BLOCK_LEN_DWORD*2+1]={0x0};	
	int Ri_len;
	int RR_len;
	int i = 0;
	
	// Ri = R^-1 mod N
	
	R[0]=0;
	R[1]=1;
	tmod=Mod[0];
	
	SM2_BN_mod_inverse(&Ri[1], &Ri_len, R, 2, &tmod, 1);	

	// R*Ri-1  

	Ri[0] = 0xffffffff;Ri[1] -= 1;

	// Ni = (R*Ri-1)/N
	
	if(Ri[1])
		SM2_BN_div(Ri, &Ri_len, NULL, NULL, Ri, 2, &tmod, 1);
	else
		SM2_BN_div(Ri, &Ri_len, NULL, NULL, Ri, 1, &tmod, 1);
		
	*n0 = Ri[0];
	
	tmp[ModLen*2] = 1;	
	for(i = 0; i < ModLen*2; i++)
		tmp[i] = 0;

		
	SM2_BN_div(NULL, NULL, RR, &RR_len, tmp, ModLen*2+1, Mod, ModLen);
}


/**
//应用密码学手册 14.36 Algorithm Montgomery multiplication
// INPUT:	m = (m_{n-1} . . . m_1,m_0)_b, 
//			x = (x_{n-1} . . . x_1,x_0)_b, 
//			y = (y_{n-1} . . . y_1,y_0)_b
//			b = 2exp(32), 0 <= x,y < m, R = b exp(n), gcd(m, b) = 1, 
//			and m0 = -1 * inv(m) mod b 
// OUTPUT: x y (R exp(-1)) mod m.
//	1. A=0. (Notation: C = (c_{n}, c_{n-1}, . . . ,c_1, c_0)_b.)
//	2. For i from 0 to (n - 1) do the following:
//		2.1 ui <-- (c0 + xiy0)m0 mod b.
//		2.2 C <-- (C + xiy + uim) / b.
//	3. If C >= m then C = C - m
//	4. Return(C).
**/

#ifdef USE_OLD_MUL_MONT
int SM2_BN_mod_mul_montgomery1(u32_t *r, u32_t *x, u32_t *y, u32_t *m, int mlen, u32_t n0)
#else
int SM2_BN_mod_mul_montgomery(u32_t *r, u32_t *x, u32_t *y, u32_t *m, int mlen, u32_t n0)
#endif
{
	int i;
	u32_t lt, carry, bb,bl, bh, ui, n0l, n0h;
	int rl, cp_len;
//	u64_t carry1=0;
    u32_t c[ECC_BLOCK_LEN_DWORD*2+1], *cp;
	u32_t mulres[ECC_BLOCK_LEN_DWORD*2];

	
	cp = c;
	
	MM_MEMSET(c, 0, sizeof(c));
	MM_MEMSET(mulres, 0x00,sizeof(mulres));
	
	n0l=LBITS(n0);//no = -1 * inv(m) mod b, b=2^32
	n0h=HBITS(n0);
	
	for(i = 0; i < mlen; i++)
	{ 
		bb = y[i];
		bl=LBITS(bb);
		bh=HBITS(bb); 
		
		carry = 0;
		mul(lt, x[0], bl, bh, carry );
		
		lt += cp[0];
		
		carry = 0;
		mul(ui, lt, n0l, n0h, carry ); 
		
// 		cp[mlen+1] = sm2_bn_mul_add_words(cp, x, mlen, bb);
// 		cp[mlen+1] = sm2_bn_mul_add_words(cp, m, mlen, ui); 
		mulres[mlen] = sm2_bn_mul_words(mulres, x, mlen, bb);
		SM2_BN_uadd(cp, &cp_len, cp, mlen+1, mulres, mlen+1);
		mulres[mlen] = sm2_bn_mul_words(mulres, m, mlen, ui);
		SM2_BN_uadd(cp, &cp_len, cp, mlen+1, mulres, mlen+1);

		cp++;
	}
	
	rl = ECC_BLOCK_LEN_DWORD*2+1-mlen;
	sm2_bn_fix_top(cp, &rl);
	if(SM2_BN_ucmp(cp, rl, m, mlen) >= 0)
	{
		SM2_BN_usub(cp, &rl, cp, rl, m, mlen); 
	} 
	MM_MEMCPY(r, cp, sizeof(u32_t)*mlen);
	return rl;
}

#ifdef USE_OLD_MUL_MONT
int SM2_BN_mod_mul_montgomery(u32_t *r, u32_t *a, u32_t *b, u32_t *M, int M_Len, u32_t n0)
{
	int i, j, k;
	u32_t ht, lt, ht1, lt1, carry, bb,m, u;
	int rl;
	u64_t tmp, tmp1, carry1=0;
    u32_t c[ECC_BLOCK_LEN_DWORD*2+1], *cp;
	u32_t debug_r[ECC_BLOCK_LEN_DWORD*2+1];
	u32_t debug_a[ECC_BLOCK_LEN_DWORD];
	u32_t debug_b[ECC_BLOCK_LEN_DWORD];
	int rl_debug;

	cp = c;

	MM_MEMSET(c, 0, sizeof(c));
	MM_MEMCPY(debug_a, a, sizeof(debug_a));
	MM_MEMCPY(debug_b, b, sizeof(debug_b));

	for(i = 0; i < M_Len; i++)
	{
		u = *cp;
		
		carry = 0;
		carry1 = 0;
		bb = b[i]; 

		tmp = MYMUL(a[0], bb);
		SM2_BN_LOW(lt, tmp);
		tmp = MYMUL(lt+u, n0);
		SM2_BN_LOW(m, tmp); 

		for(j = 0; j < M_Len; j++)
		{
			//ai*bi
			tmp = MYMUL(a[j], bb);
			SM2_BN_HIGH(ht, tmp);
			SM2_BN_LOW(lt, tmp);
			
			//n0*M
			tmp1 = MYMUL(m, M[j]);
			SM2_BN_HIGH(ht1, tmp1);
			SM2_BN_LOW(lt1, tmp1);
			//ci=ci+ai*bi+n0*M+carry
			
			tmp = (u64_t)lt + (u64_t)lt1;
			tmp += (u64_t)cp[j];
			tmp += (u64_t)carry;
			cp[j] = (u32_t)tmp;
			
			carry1 += (u64_t)ht;
			carry1 += (u64_t)ht1;
			SM2_BN_HIGH(tmp, tmp);
			carry1 += tmp;
			SM2_BN_LOW(carry, carry1);
			SM2_BN_HIGH(carry1, carry1);
		}
		cp[j] += carry;
		k = j+1;
	
		if(cp[j] < carry)
		{
			cp[k] += 1;
			cp[k] += (u32_t)carry1;
		}
		else
		{
			cp[k] += (u32_t)carry1;
		}
	
		cp++;
	}
/**
	//判断乘积位数是否超过模数位数
	
// 20140327 luoying del
// 修改原因： 
// 可能存在c[M_Len*2 ] = 1的情况，此时的carry1可能判断失误；因为c[M_Len*2 ] = 1是执行如下代码得到的
// 		if(cp[j] < carry)
// 		{
// 			cp[k] += 1; 
// 			cp[k] += (u32_t)carry1; 
// 		}
// 此时for(i = 0; i < M_Len; i++)r[i] = c[M_Len + i];将导致最高的UL没有被复制
// 最后，本来 r > m 的就会被误认为 r < m，导致处理出错。
**/
#ifndef LUOYING_CHANGE
	/** 这部分是原来的代码 **/
	if(!carry1)
	{
		for(i = 0; i < M_Len; i++)
			r[i] = c[M_Len + i];

		if(SM2_BN_ucmp(r, M_Len, M, M_Len) >= 0)
		{
			SM2_BN_usub(r, &rl, r, M_Len, M, M_Len);
		}
	}
	else
		SM2_BN_usub(r, &rl, &c[M_Len], M_Len+1, M, M_Len);
#else	// luoying  add
	/** 这部分是修改后的代码 **/
	if(!carry1)
	{
		for(i = 0; i < M_Len+1; i++)
			r[i] = c[M_Len + i];

		if( r[M_Len] || SM2_BN_ucmp(r, M_Len, M, M_Len) >= 0)
		{
			SM2_BN_usub(r, &rl, r, M_Len+1, M, M_Len);
		}
	}
	else
	{
		SM2_BN_usub(r, &rl, &c[M_Len], M_Len+1, M, M_Len);
	}
#endif	//luoying done


	rl_debug = SM2_BN_mod_mul_montgomery1(debug_r, debug_a, debug_b, M, M_Len, n0);

//	assert(rl==rl_debug);

	k = MM_MEMCMP(r,debug_r, sizeof(u32_t)*M_Len);
	if(k!=0)
	{
		k+=0;
	}
	assert(k==0);
	return M_Len;
}
#endif

/*
//准备不再使用此函数
void SM2_BN_mod_mul_montgomery_one(u32_t *r, u32_t *a, u32_t *M, int M_Len, u32_t n0)
{
	int i, j, k;
	u32_t ht1, lt1, carry, m, u;
	int rl;
	u64_t tmp, tmp1, carry1 = 0;
    	u32_t c[ECC_BLOCK_LEN_DWORD*2+1], *cp;
    	int first = 1;

	cp = c;

	MM_MEMSET(c, 0, sizeof(c));

	for(i = 0; i < M_Len; i++)
	{
		u = *cp;
		
		carry = 0;
		carry1 = 0;


// 		if(first)
// 			m = (u32_t)((u64_t)(a[0]+u) * (u64_t)n0);
// 		else
// 			m = (u32_t)(u * n0);

		if(first)
			tmp1 = MYMUL(a[0]+u ,n0);
		else
			tmp1 = MYMUL(u , n0);
		SM2_BN_LOW(m, tmp1); 

		for(j = 0; j < M_Len; j++)
		{
			
			//n0*M
			tmp1 = MYMUL(m, M[j]);
// 			ht1 = (u32_t)(tmp1>>32);
// 			lt1 = (u32_t)tmp1;
			SM2_BN_HIGH(ht1, tmp1);
			SM2_BN_LOW(lt1, tmp1);

			//ci=ci+ai*bi+n0*M+carry
			
			if(first)
				tmp = (u64_t)a[j] + (u64_t)lt1;
			else
				tmp = (u64_t)lt1;
			tmp += (u64_t)cp[j];
			tmp += (u64_t)carry;
			cp[j] = (u32_t)tmp;
			
			carry1 += (u64_t)ht1;
			SM2_BN_HIGH(tmp, tmp);
			carry1 += tmp;
			SM2_BN_LOW(carry, carry1);
			SM2_BN_HIGH(carry1, carry1);
		}
		cp[j] += carry;
		k = j+1;
	
		if(cp[j] < carry)
		{
			cp[k] += 1;
			cp[k] += (u32_t)carry1;
		}
		else
			cp[k] += (u32_t)carry1;
	
		cp++;

		if(first)
			first = 0;
	}

	//判断乘积位数是否超过模数位数
	
	// 20140327 luoying del
// 修改原因： 
// 可能存在c[M_Len*2 ] = 1的情况，此时的carry1可能判断失误；因为c[M_Len*2 ] = 1是执行如下代码得到的
// 		if(cp[j] < carry)
// 		{
// 			cp[k] += 1; 
// 			cp[k] += (u32_t)carry1; 
// 		}
// 此时for(i = 0; i < M_Len; i++)r[i] = c[M_Len + i];将导致最高的UL没有被复制
// 最后，本来 r > m 的就会被误认为 r < m，导致处理出错。
#ifndef LUOYING_CHANGE
	if(!carry1)
	{
		for(i = 0; i < M_Len; i++)
			r[i] = c[M_Len + i];

		if(SM2_BN_ucmp(r, M_Len, M, M_Len) >= 0)
		{
			SM2_BN_usub(r, &rl, r, M_Len, M, M_Len);
		}
	}
	else
		SM2_BN_usub(r, &rl, &c[M_Len], M_Len+1, M, M_Len);
#else
	if(!carry1)
	{
		for(i = 0; i < M_Len+1; i++)
			r[i] = c[M_Len + i];

		if( r[M_Len] || SM2_BN_ucmp(r, M_Len, M, M_Len) >= 0)
		{
			SM2_BN_usub(r, &rl, r, M_Len+1, M, M_Len);
		}
	}
	else
		SM2_BN_usub(r, &rl, &c[M_Len], M_Len+1, M, M_Len);
#endif	//luoying done
}
*/