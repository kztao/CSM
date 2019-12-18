#include <string.h>
#include <malloc.h>
#include "types.h"
#include "sm3.h"

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))
#define P0(x)	x^rol(x,9)^rol(x,17)
#define P1(x)	x^rol(x,15)^rol(x,23)

#define FF1(a,b,c)	(a^b^c)	
#define FF2(a,b,c)	((a&b)|(a&c)|(b&c))
#define GG1(e,f,g)	(e^f^g)
#define GG2(e,f,g)  ((e&f)|((~e)&g))

/* Hash a single 512-bit block. This is the core of the algorithm. */
void SM3Transform(unsigned long state[8], unsigned char buffer[64])
{
	unsigned long a = 0;
	unsigned long b = 0;
	unsigned long c = 0;
	unsigned long d = 0;
	unsigned long e = 0;
	unsigned long f = 0;
	unsigned long g = 0;
	unsigned long h = 0;
	unsigned long ss1 = 0;
	unsigned long ss2 = 0;
	unsigned long tt1 = 0;
	unsigned long tt2 = 0;
	unsigned long tmp = 0;
	unsigned long tmp1 = 0;
	unsigned long tmp2 = 0;
	unsigned long tmp3 = 0;
	unsigned long tmp4 = 0;
	unsigned long tmp5 = 0;
	unsigned long tmp6 = 0;
	unsigned long tmp7 = 0;
	unsigned long W[68] = {0};
	unsigned long W1[64] = {0};
	int j = 0;
	int i = 0;
	
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];
	
	/* get W0~W67  */
	for (j = 0; j < 16; j++)
	{
		W[j] = (buffer[j*4] << 24) | (buffer[j*4+1] << 16) | (buffer[j*4+2] << 8) | buffer[j*4+3];
	}
	
	for (j = 16; j < 68; j++)
	{
		tmp = rol(W[j-3], 15) ^ W[j-9] ^ W[j-16];
		W[j] = P1(tmp) ^ rol(W[j-13], 7) ^ W[j-6];
		
		tmp1 = rol(W[j-3], 15);
		tmp2 = rol(W[j-3], 15) ^ W[j-9];
		tmp3 = rol(W[j-3], 15) ^ W[j-9] ^ W[j-16];
		tmp4 = P1(tmp3);
		tmp5 = rol(W[j-13], 7);
		tmp6 = tmp4 ^ rol(W[j-13], 7);
		tmp7 = tmp4 ^ rol(W[j-13], 7) ^ W[j-6];
	}
	
	for (j = 0; j < 64; j++)
	{
		W1[j] = W[j] ^ W[j+4];
	}
	
	/* 63 rounds of operations each. Loop unrolled. */
	j = 0;
	
	do
	{
		if (j == 0)
		{
			tmp = rol(a, 12) + e + 0x79cc4519;
		}
		else
		{
			tmp = rol(a, 12) + e + rol(0x79cc4519, j);
		}
		
		ss1 = rol(tmp, 7);
		ss2 = ss1 ^ rol(a, 12);
		tt1 = FF1(a, b, c) + d + ss2 + W1[j];
		tt2 = GG1(e, f, g) + h + ss1 + W[j];
		
		d = c;
		c = rol(b, 9);
		b = a;
		a = tt1;
		h = g;
		g = rol(f, 19);
		f = e;
		e = P0(tt2);		
		
		j++;
		
	} while (j < 16);
	
	i = 0;
	
	do
	{
		i = j % 32;
		
		if (i == 0)
		{
			tmp = rol(a, 12) + e + 0x7a879d8a;
		}
		else
		{
			tmp = rol(a, 12) + e + rol(0x7a879d8a, i);
		}
		
		ss1 = rol(tmp, 7);
		ss2 = ss1 ^ rol(a, 12);
		tt1 = FF2(a, b, c) + d + ss2 + W1[j];
		tt2 = GG2(e, f, g) + h + ss1 + W[j];
		
		d = c;
		c = rol(b, 9);
		b = a;
		a = tt1;
		h = g;
		g = rol(f, 19);
		f = e;
		e = P0(tt2);
		
		j++;
		
	} while (j < 64);
	
    /* Add the working vars back into context.state[] */
    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
	state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
	
    /* Wipe variables */
    a = b = c = d = e = f = g = h =0;
}

/* SHA1Init - Initialize new context */
void SM3_Init(SM3_CTX* context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x7380166f;
    context->state[1] = 0x4914b2b9;
    context->state[2] = 0x172442d7;
    context->state[3] = 0xda8a0600;
    context->state[4] = 0xa96f30bc;
	context->state[5] = 0x163138aa;
    context->state[6] = 0xe38dee4d;
    context->state[7] = 0xb0fb0e4e;
    context->count[0] = context->count[1] = 0;
}

/* Run your data through this. */
void SM3Update(SM3_CTX* context, unsigned char* data, unsigned int len)
{
	unsigned int i = 0;
	unsigned int j = 0;
	
    j = (context->count[0] >> 3) & 63;
	
    if ((context->count[0] += len << 3) < (len << 3)) 
	{
		context->count[1]++;
	}
	
    context->count[1] += (len >> 29);
    
	if ((j + len) > 63) 
	{
		i = 64 - j;
		
        memcpy(&context->buffer[j], data, i);
        
		SM3Transform(context->state, context->buffer);
        
		for (; i + 63 < len; i += 64) 
		{
            SM3Transform(context->state, &data[i]);
        }
		
        j = 0;
    }
    else
	{
		i = 0;
	}
	
    memcpy(&context->buffer[j], &data[i], len - i);
}

/* Add padding and return the message digest. */
void SM3Final(unsigned char *pbDigest, SM3_CTX* context, int outlen)
{
	unsigned long i = 0;
	unsigned long j = 0;
	unsigned long a = 0;
	unsigned long b = 0;
	unsigned long c = 0; 
	unsigned long d = 0;
	unsigned long e = 0;
	unsigned long f = 0;
	unsigned long g = 0;
	unsigned long h = 0;
	unsigned char finalcount[8] = {0};
	
    for (i = 0; i < 8; i++) 
	{
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)] >> ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
    }
	
    SM3Update(context, (unsigned char *)"\200", 1);
	
    while ((context->count[0] & 504) != 448) 
	{
        SM3Update(context, (unsigned char *)"\0", 1);
    }
	
    SM3Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */
	
	if (outlen == 32)
    {
		for (i = 0; i < 32; i++)
		{
			pbDigest[i] = (unsigned char)((context->state[i>>2] >> ((3-(i & 3)) * 8)) & 255);
		}
	}
	
	if (outlen == 24)
	{
		a = context->state[0];
		b = context->state[1];
		c = context->state[2];
		d = context->state[3];
		e = context->state[4];
		f = context->state[5];
		g = context->state[6];
		h = context->state[7];
		
		context->state[0] = a ^ b ^ e;
		context->state[1] = b ^ f;
		context->state[2] = c ^ g;
		context->state[3] = d ^ h;
		context->state[4] = f ^ c;
		context->state[5] = d ^ g;
		
		for (i = 0; i < 24; i++)
		{
			pbDigest[i] = (unsigned char)((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
		}
	}
	
	if (outlen == 20)
	{
		a = context->state[0];
		b = context->state[1];
		c = context->state[2];
		d = context->state[3];
		e = context->state[4];
		f = context->state[5];
		g = context->state[6];
		h = context->state[7];
		
		context->state[0] = a ^ b ^ e;
		context->state[1] = b ^ f ^ c;
		context->state[2] = c ^ g;
		context->state[3] = d ^ h;
		context->state[4] = d ^ g;
		
		for (i = 0; i < 20; i++)
		{
			pbDigest[i] = (unsigned char)((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
		}
	}
	
    /* Wipe variables */
    i = 0;
	j = 0;
	
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 32);
    memset(context->count, 0, 8);
    memset(&finalcount, 0, 8);
}

void SM3_Data( unsigned char* data, unsigned int charlen, unsigned char *digest, unsigned int outlen)
{
	SM3_CTX context;
	
	SM3_Init(&context);
	SM3Update(&context, data, charlen);
	SM3Final(digest, &context, outlen);
}

void GBCombine(BYTE *X, unsigned long bytelen1, BYTE *Y, unsigned long bytelen2, BYTE *XY, unsigned long *bytelen3)
{
	unsigned int len = 0;
	unsigned long j = 0;
	unsigned long i = 0;
	
	len = bytelen1 + bytelen2;
	*bytelen3 = len;
	
	for (j = 0; j < bytelen1; j++)
	{
		XY[j] = X[j];
	}
	
	for (i = 0; i < bytelen2; i++)
	{
		XY[bytelen1+i] = Y[i];
	}
}

int GBKDF(BYTE *Z, unsigned long bytelen, unsigned long klen, BYTE *ZOut, int Hashlen)
{
	unsigned long ct = 0;
	int bitlen = 0;
	int sl = 0;
    unsigned long Zctlen = 0;
	unsigned char *Zctbyte = NULL;
	unsigned char Hashbyte[32] = {0};
	unsigned char ctstr[4] = {0};
	unsigned long glen = 0;
	unsigned long hashblen = 0;
	int i = 0;
	int j = 0;
	int k = 0;
	int len = 0;
	
	if (klen % 8 != 0)
	{
		return 0;
	}
	
	ct = 0x1;
	hashblen = Hashlen * 8;
	sl = (klen % hashblen == 0) ? (klen / hashblen) : ((klen / hashblen) + 1);
	
	Zctbyte = (unsigned char *)malloc(bytelen + 4);
	
	ctstr[0] = (unsigned char)((ct & 0xff000000) >> 24);
	ctstr[1] = (unsigned char)((ct & 0x00ff0000) >> 16); 
	ctstr[2] = (unsigned char)((ct & 0x0000ff00) >> 8);  
	ctstr[3] = (unsigned char)((ct & 0x000000ff));
	
	glen = 0;
	k = 0;
	
	for (i = 1; i <= sl; i++)
	{
		memset(Zctbyte, 0, bytelen + 4);
		
		GBCombine(Z, bytelen, ctstr, 4, Zctbyte, &Zctlen);
		
		SM3_Data(Zctbyte, Zctlen, Hashbyte, Hashlen);
		
		ct++;
		
		ctstr[0] = (unsigned char)((ct & 0xff000000) >> 24);
		ctstr[1] = (unsigned char)((ct & 0x00ff0000) >> 16); 
		ctstr[2] = (unsigned char)((ct & 0x0000ff00) >> 8);  
		ctstr[3] = (unsigned char)((ct & 0x000000ff));
		
		glen = Hashlen * 8 * i;
		
		if (glen > klen)
		{
			bitlen = klen - (glen - Hashlen * 8);
			len = bitlen / 8;
			
			for (j = 0; j < len; j++)
			{
				ZOut[k] = Hashbyte[j];
				
				k++;
			}	
			
			break;
		}
		else
		{
			for (j = 0; j < Hashlen; j++)
			{
				ZOut[k] = Hashbyte[j];
				
				k++;
			}	
		}
	}
	
	free(Zctbyte);
	
	return 1;
}