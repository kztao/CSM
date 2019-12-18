#include "types.h"
#include "bn.h"
#include "ecp.h"
#include "ecc.h"
#include "sm2.h"
#include "curve.h"
#include "stdio.h"
#include "stdlib.h"
#include "time.h"
#include "config.h"


typedef unsigned char  U8;                    /* Unsigned  8 bit quantity                           */
typedef unsigned int   U16;                   /* Unsigned 16 bit quantity                           */
typedef unsigned long  U32;                   /* Unsigned 32 bit quantity                           */

#define DIRECT_INITIATOR	0
#define DIRECT_RECIPIENT	1

#define SM2_DEBUG		0

struct FPECC{
char *p;
char *a;
char *b;
char *n;
char *x;
char *y;
};

#if SM2_DEBUG

void PrintBuf(unsigned char *buf, int	buflen) 
{
	int i;
	printf("\n");
	printf("len = %d\n", buflen);
	for(i=0; i<buflen; i++) {
  	if (i % 32 != 31)
  	  printf("%02x", buf[i]);
  	  else
  	  printf("%02x\n", buf[i]);
  }
  printf("\n");
  return;
}
void PrintBig(big data) 
{
 int len=0;
 unsigned char buf[10240];
    
 len=big_to_bytes(0,data,(char *)buf,0);
 PrintBuf(buf,len);
}

unsigned char radom[]  = {0x6C,0xB2,0x8D,0x99,0x38,0x5C,0x17,0x5C,0x94,0xF9,0x4E,0x93,0x48,0x17,0x66,0x3F,0xC1,0x76,0xD9,0x25,0xDD,0x72,0xB7,0x27,0x26,0x0D,0xBA,0xAE,0x1F,0xB2,0xF9,0x6F};
unsigned char radom1[] = {0x4C,0x62,0xEE,0xFD,0x6E,0xCF,0xC2,0xB9,0x5B,0x92,0xFD,0x6C,0x3D,0x95,0x75,0x14,0x8A,0xFA,0x17,0x42,0x55,0x46,0xD4,0x90,0x18,0xE5,0x38,0x8D,0x49,0xDD,0x7B,0x4F};
unsigned char randkey[] = {0x83,0xA2,0xC9,0xC8,0xB9,0x6E,0x5A,0xF7,0x0B,0xD4,0x80,0xB4,0x72,0x40,0x9A,0x9A,0x32,0x72,0x57,0xF1,0xEB,0xB7,0x3F,0x5B,0x07,0x33,0x54,0xB2,0x48,0x66,0x85,0x63};
unsigned char randkeyb[]= {0x33,0xFE,0x21,0x94,0x03,0x42,0x16,0x1C,0x55,0x61,0x9C,0x4A,0x0C,0x06,0x02,0x93,0xD5,0x43,0xC8,0x0A,0xF1,0x97,0x48,0xCE,0x17,0x6D,0x83,0x47,0x7D,0xE7,0x1C,0x80};

struct FPECC Ecc256={
"8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
"787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
"63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
"8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
"421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
"0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
};
unsigned char sm2_par_dig[128] = {
0x78,0x79,0x68,0xB4,0xFA,0x32,0xC3,0xFD,0x24,0x17,0x84,0x2E,0x73,0xBB,0xFE,0xFF,
0x2F,0x3C,0x84,0x8B,0x68,0x31,0xD7,0xE0,0xEC,0x65,0x22,0x8B,0x39,0x37,0xE4,0x98,
0x63,0xE4,0xC6,0xD3,0xB2,0x3B,0x0C,0x84,0x9C,0xF8,0x42,0x41,0x48,0x4B,0xFE,0x48,
0xF6,0x1D,0x59,0xA5,0xB1,0x6B,0xA0,0x6E,0x6E,0x12,0xD1,0xDA,0x27,0xC5,0x24,0x9A,
0x42,0x1D,0xEB,0xD6,0x1B,0x62,0xEA,0xB6,0x74,0x64,0x34,0xEB,0xC3,0xCC,0x31,0x5E,
0x32,0x22,0x0B,0x3B,0xAD,0xD5,0x0B,0xDC,0x4C,0x4E,0x6C,0x14,0x7F,0xED,0xD4,0x3D,
0x06,0x80,0x51,0x2B,0xCB,0xB4,0x2C,0x07,0xD4,0x73,0x49,0xD2,0x15,0x3B,0x70,0xC4,
0xE5,0xD7,0xFD,0xFC,0xBF,0xA3,0x6E,0xA1,0xA8,0x58,0x41,0xB9,0xE4,0x6E,0x09,0xA2,
};

#else
/*SM2*/
struct FPECC Ecc256={
"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
};

unsigned char sm2_par_dig[128] = {
0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93,
0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7,
0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0,
};

unsigned char enkey[32] = {
0xB1,0x6B,0xA0,0xDA,0x27,0xC5,0x24,0x9A,0xF6,0x1D,0x6E,0x6E,0x12,0xD1,0x59,0xA5,
0xB6,0x74,0x64,0x34,0xEB,0xD6,0x1B,0x62,0xEA,0xEB,0xC3,0xCC,0x31,0x5E,0x42,0x1D,
};
#endif


#define SEED_CONST 0x1BD8C95A


extern unsigned char *sm3(const unsigned char *d, unsigned int n, unsigned char *md);

void random_xid()
{
	static int initialized = 0;

	if(!initialized)
	{
	    unsigned long seed = 0;

        seed = time(0);

	    srand((unsigned)seed);
		initialized++;
	}
 
}


void BNRandom(Word *bn)
{
	int i = 0;
	
	for(i = 0; i < BNWORDLEN; i++)
	{
		bn[i]=(rand()<<16)|rand();
	}
}

int SM2Init()
{
	/*double dtime = 0;
	
	ECPInitByParameter(SM2_SystemParameter);
	
#ifdef WIN32
	dtime = (double)time(NULL);
#else
	struct timeval time;
	gettimeofday(&time,NULL);
	dtime = (time.tv_sec)*1000000+(time.tv_usec);
#endif
	

	//srand((unsigned)dtime);*/

	ECPInitByParameter(SM2_SystemParameter);

	random_xid();
	
	return SM2_OK;
}

int SM2GenKey(BYTE *pbPriKey, int *piPriKeyLen, BYTE *pbPubKey, int *piPubKeyLen)
{
	Word K[MAXBNWordLen] = {0};
	Word PubKeyX[MAXBNWordLen] = {0};
	Word PubKeyY[MAXBNWordLen] = {0};
	
	if (pbPriKey == 0 || pbPubKey == 0 || *piPriKeyLen < WordByteLen*BNWORDLEN || *piPubKeyLen < 2*WordByteLen*BNWORDLEN)
	{
		*piPriKeyLen = WordByteLen * BNWORDLEN;
		*piPubKeyLen = 2 * WordByteLen * BNWORDLEN;
	}
	else
	{
		BNRandom(K);
		
		ECCGenkey(K, PubKeyX, PubKeyY);
		
		BN2Byte(K, pbPriKey, 0);
		
		BN2Byte(PubKeyX, pbPubKey, 0);
		BN2Byte(PubKeyY, pbPubKey, WordByteLen * BNWORDLEN);
		
		*piPriKeyLen = WordByteLen * BNWORDLEN;
		*piPubKeyLen = 2 * WordByteLen * BNWORDLEN;
	}
	
	return SM2_OK;
}

/*
功能:公钥与私钥点乘
参数:
1. BYTE *pbPriKey:私钥，32字节
2. BYTE *pbPubKey:公钥，64字节
3. BYTE *pbMul:存储公钥与私钥点乘之后的结果，即工作密钥，64字节
返回值:无
*/
void SM2PointMul(BYTE *pbPriKey, BYTE *pbPubKey, BYTE *pbMul)
{
	A_Point KP;
	A_Point Q;
	Word K[MAXBNWordLen] = {0};
	Word wPriKeyX[MAXBNWordLen] = {0};
	Word wPubKeyX[MAXBNWordLen] = {0};
	Word wPubKeyY[MAXBNWordLen] = {0};
	
	//私钥转换为BN 格式(32字节)
	Byte2BN(pbPriKey, 0, MAXBNByteLen, wPriKeyX);
	
	//公钥转换为BN 格式(64字节)
	Byte2BN(pbPubKey, 0, MAXBNByteLen, wPubKeyX);
	Byte2BN(pbPubKey, MAXBNByteLen, MAXBNByteLen, wPubKeyY);
	
	//BN 格式的私钥转存至K
	BNAssign(K,wPriKeyX);
	
	//BN 格式的公钥转存至Q
	BNAssign(Q.X, wPubKeyX);
	BNAssign(Q.Y, wPubKeyY);//Q=Pub
	
	//调用点乘函数完成BN 格式下的点乘, BN 格式下的结果存KP
	ECPKP(K, &Q, &KP);
	
	//BN 格式转换为64 字节后存pbMul
	BN2Byte(KP.X,pbMul, 0);
	BN2Byte(KP.Y,pbMul + 32, 0);
}

int SM2SignHash(BYTE *pbHash, int iHashLen, BYTE *pbPriKey, int iPriKeyLen, BYTE *pbSign, int *piSignLen)
{
	int Ret = SM2_OK;
	Word wRandom[MAXBNWordLen] = {0};
	Word wHash[MAXBNWordLen] = {0};
	Word wPriKey[MAXBNWordLen] = {0};
	Word wR[MAXBNWordLen] = {0};
	Word wS[MAXBNWordLen] = {0};
	
	if (pbSign != 0 && *piSignLen >= 2*WordByteLen*BNWORDLEN)
	{
		Byte2BN(pbHash, 0, iHashLen, wHash);	
		Byte2BN(pbPriKey, 0, iPriKeyLen, wPriKey);
		
		BNRandom(wRandom);
		
		Ret = ECCSM2SignHash(wRandom, wHash, wPriKey, wR, wS);
		
		BN2Byte(wR, pbSign, 0);
		BN2Byte(wS, pbSign, WordByteLen*BNWORDLEN);
	}
	
	*piSignLen = 2 * WordByteLen * BNWORDLEN;
	
	return Ret;
}

int SM2VerifyHash(BYTE *pbHash, int iHashLen, BYTE *pbPubKey, int iPubKeyLen, BYTE *pbSign, int iSignLen)
{
	Word wHash[MAXBNWordLen] = {0};
	Word wPubKeyX[MAXBNWordLen] = {0};
	Word wPubKeyY[MAXBNWordLen] = {0};
	Word wR[MAXBNWordLen] = {0};
	Word wS[MAXBNWordLen] = {0};

	
	Byte2BN(pbHash, 0, iHashLen, wHash);
	Byte2BN(pbPubKey, 0, WordByteLen*BNWORDLEN, wPubKeyX);
	Byte2BN(pbPubKey, WordByteLen*BNWORDLEN, WordByteLen*BNWORDLEN, wPubKeyY);
	Byte2BN(pbSign, 0, WordByteLen*BNWORDLEN, wR);
	Byte2BN(pbSign, WordByteLen*BNWORDLEN, WordByteLen*BNWORDLEN, wS);
	
	return ECCSM2VerifyHash(wHash, wPubKeyX, wPubKeyY, wR, wS);
}

int SM2Encrypt(BYTE *pbPlainText, int iPlainTextLen, BYTE *pbPubKey, int iPubKeyLen, BYTE *pbCipherText, int *piCipherTextLen)
{
	int i = 0;
	int j = 0;
	int Ret = SM2_OK;
	Word wRandom[MAXBNWordLen] = {0};
	Word wPubKeyX[MAXBNWordLen] = {0};
	Word wPubKeyY[MAXBNWordLen] = {0};
	BYTE pbC1[2*MAXBNByteLen] = {0};
	BYTE pbC2[MAXPLAINTEXTLEN] = {0};
	BYTE C3[HASHLEN] = {0};

	if (iPlainTextLen > 1024)
	{
		return SM2_Encrypt_Error;
	}
	
	if (pbCipherText==0)
	{
		*piCipherTextLen = iPlainTextLen + 2*MAXBNWordLen*WordByteLen + HASHLEN;
		
		return SM2_OK;
	}
	
	Byte2BN(pbPubKey, 0, MAXBNByteLen, wPubKeyX);
	Byte2BN(pbPubKey, MAXBNByteLen, MAXBNByteLen, wPubKeyY);
	
	BNRandom(wRandom);		

	Ret = ECCSM2Encrypt(wRandom, pbPlainText, iPlainTextLen, wPubKeyX, wPubKeyY, pbC1, pbC2, C3);
	
	if (Ret != 1)
	{	
		return SM2_Encrypt_Error;
	}	
	
	i = 0;

	for (j = 0; j < 2*MAXBNWordLen*WordByteLen; i++, j++)
	{
		pbCipherText[i] = pbC1[j];
	}

	for (j = 0; j < iPlainTextLen; i++, j++)
	{
		pbCipherText[i] = pbC2[j];
	}

	for (j = 0; j < MAXBNByteLen; j++, i++)
	{
		pbCipherText[i] = C3[j];
	}
	
	*piCipherTextLen = iPlainTextLen + 2*MAXBNWordLen*WordByteLen + HASHLEN;

	//printf("End of SM2Encrypt. i = %d, piCipherTextLen = %d (0x%0x)\n", i, *piCipherTextLen,*piCipherTextLen);
	
	return SM2_OK;
}

int SM2Decrypt(BYTE *pbCipherText, int iCipherTextLen, BYTE *pbPriKey, int iPriKeyLen, BYTE *pbPlainText, int *piPlainTextLen)
{
	int i = 0;
	int j = 0;
	int ret = SM2_OK;
	Word wPriKey[MAXBNWordLen] = {0};
	BYTE pbC1[2*MAXBNByteLen] = {0};
	BYTE pbC2[MAXPLAINTEXTLEN] = {0};
	BYTE C3[HASHLEN] = {0};
	
	if (iCipherTextLen > 1120)
	{
		return SM2_Decrypt_Error;
	}

	if (pbPlainText == 0)
	{
		*piPlainTextLen = iCipherTextLen - HASHLEN - 2*MAXBNWordLen*WordByteLen;
		
		return SM2_OK;
	}
	
	Byte2BN(pbPriKey, 0, MAXBNByteLen, wPriKey);
	
	*piPlainTextLen = iCipherTextLen - HASHLEN - 2*MAXBNWordLen*WordByteLen;
	
	i = 0;	
	for (j = 0; j < 2*MAXBNWordLen*WordByteLen; i++, j++)
	{
		pbC1[j] = pbCipherText[i];
	}
	
	for (j = 0; j < (*piPlainTextLen); j++, i++)
	{
		pbC2[j] = pbCipherText[i];
	}
	
	for (j = 0; j < HASHLEN; j++, i++)
	{
		C3[j] = pbCipherText[i];	
	}
	
	ret = ECCSM2Decrypt (pbC1,pbC2,C3,wPriKey,pbPlainText,*piPlainTextLen);
	
	if (ret != 1)
	{	
		printf("ret = %d\n", ret);
		return SM2_Decrypt_Error;
	}
	
	return SM2_OK;
}