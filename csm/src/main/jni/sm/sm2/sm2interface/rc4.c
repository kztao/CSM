#include "rc4.h" 
#include "mm_sm_cfg.h"

/** 参见 应用密码学教程,胡向东魏琴芳编著,电子工业出版社,2005.pdf 第10.4节 **/
#ifdef MM_SM2_PRNG_RC4

void RC4_set_key(RC4_KEY *key, int len, const BYTE *data)
{
	register u32_t tmp;
	register int id1,id2;
	register u32_t *d;
	u32_t i;
	
	d= &(key->data[0]);
	key->x = 0;     
	key->y = 0;     
	id1=id2=0;     
	
#define SK_LOOP(d,n) { \
	tmp=d[(n)]; \
	id2 = (data[id1] + tmp + id2) & 0xff; \
	if (++id1 == len) id1=0; \
	d[(n)]=d[id2]; \
	d[id2]=tmp; }
	
	for (i=0; i < 256; i++) 
	{
		d[i]=i;
	}

	for (i=0; i < 256; i+=4)
	{
		SK_LOOP(d,i+0);
		SK_LOOP(d,i+1);
		SK_LOOP(d,i+2);
		SK_LOOP(d,i+3);
	}
}


void RC4(RC4_KEY *key, u32_t len, const BYTE *indata, BYTE *outdata)
{
	register u32_t *d;
	register u32_t x,y,tx,ty;
	int i;
	
	x=key->x;     
	y=key->y;     
	d=key->data; 
	
#define LOOP(in,out) \
	x=((x+1)&0xff); \
	tx=d[x]; \
	y=(tx+y)&0xff; \
	d[x]=ty=d[y]; \
	d[y]=tx; \
	(out) = (BYTE)d[(tx+ty)&0xff]^ (in);
	
#define RC4_LOOP(a,b,i)	LOOP(*((a)++),*((b)++))
	 
	i=(int)(len>>3L);
	if (i)
	{
		for (;;)
		{
			RC4_LOOP(indata,outdata,0);
			RC4_LOOP(indata,outdata,1);
			RC4_LOOP(indata,outdata,2);
			RC4_LOOP(indata,outdata,3);
			RC4_LOOP(indata,outdata,4);
			RC4_LOOP(indata,outdata,5);
			RC4_LOOP(indata,outdata,6);
			RC4_LOOP(indata,outdata,7);
			
			if (--i == 0) 
			{
				break;
			}
		}
	}

	i=(int)len&0x07;
	if (i)
	{
		for (;;)
		{
			RC4_LOOP(indata,outdata,0); if (--i == 0) break;
			RC4_LOOP(indata,outdata,1); if (--i == 0) break;
			RC4_LOOP(indata,outdata,2); if (--i == 0) break;
			RC4_LOOP(indata,outdata,3); if (--i == 0) break;
			RC4_LOOP(indata,outdata,4); if (--i == 0) break;
			RC4_LOOP(indata,outdata,5); if (--i == 0) break;
			RC4_LOOP(indata,outdata,6); if (--i == 0) break;
		}
	}               
	key->x=x;     
	key->y=y;
}
#endif //ifdef MM_SM2_PRNG_RC4