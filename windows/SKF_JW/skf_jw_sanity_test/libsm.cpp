/******************************************************************************************
*zhouzhe
*2013.5.3
*******************************************************************************************/
//#include "stdafx.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "libsm.h"

#ifndef USE_MALLOC
#define USE_MALLOC

#define ECC256_BNWLEN				8


#define Rot1(_x,_y) (((_x)<<(_y)) | ((_x)>>(32-(_y))))
#define ByteSub(_A) ((Sbox[((_A)>>24)&0xFF]<<24)^ \
	(Sbox[((_A)>>16)&0xFF]<<16)^ \
	(Sbox[((_A)>>8)&0xFF]<<8)^ \
	 Sbox[(_A)&0xFF])

#define L1(_B) ((_B)^Rot1(_B,2)^Rot1(_B,10)^Rot1(_B,18)^Rot1(_B,24))
#define L2(_B) ((_B)^Rot1(_B,13)^Rot1(_B,23))

unsigned int m_rk[32];

unsigned char StandECC_P[32]={0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
unsigned char StandECC_A[32]={0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC};
unsigned char StandECC_B[32]={0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93};
unsigned char StandECC_Gx[32]={0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7};
unsigned char StandECC_Gy[32]={0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0};
unsigned char StandECC_N[32]={0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x72,0x03,0xDF,0x6B,0x21,0xC6,0x05,0x2B,0x53,0xBB,0xF4,0x09,0x39,0xD5,0x41,0x23};


static int Compare(char* str1,char* str2);
static int CompareEx(char* str1,char* str2,char* strMessage);
static int CompareEx_Not(char* str1,char* str2,char* strMessage);
static char* AsHexString(int Len,int Value);



int ByteToBN(unsigned char *pByteBuf, int bytelen, unsigned int  *pwBN, int iBNWordLen);
int BNToByte(unsigned int *pwBN,int iBNWordLen,unsigned char *pByteBuf,int *bytelen);
void BN_Print(unsigned int *pwBN,int iBNWordLen);
void BN_Reset(unsigned int *pwBN,int iBNWordLen);
void BN_Assign(unsigned int *pwDest, unsigned int *pwSource, int  iBNWordLen);
int BN_IsZero(unsigned int *pwBN,int iBNWordLen);
int BN_IsOne(unsigned int *pwBN,int iBNWordLen);
int BN_IsEven(unsigned int *pwBN);
int BN_IsOdd(unsigned int *pwBN);
int BN_JE(unsigned int *pwX, unsigned int *pwY, int iBNWordLen);
int BN_JA(unsigned int *pwX, unsigned int *pwY, int iBNWordLen);
int BN_GetBitLen(unsigned int *pwBN, int iBNWordLen);
int BN_GetWordLen(unsigned int *pwBN, int iBNWordLen);
void BN_GetLen(int *pBitLen, int *pWordLen, unsigned int *pwBN, int iBNWordLen);
void BN_ShiftRightOneBit(unsigned int *pwBN, int iBNWordLen);
unsigned int BN_ShiftLeftOneBit(unsigned int *pwBN, int iBNWordLen);

unsigned int BN_Add( unsigned int *pwSum, unsigned int *pwX, unsigned int *pwY,int  iBNWordLen);
unsigned int BN_Sub(unsigned int *pwDiff, unsigned int *pwX, unsigned int *pwY, int  iBNWordLen);
void BN_Mul(unsigned int *pwPro, unsigned int *pwX, unsigned int *pwY, int  iBNWordLen);

void BN_ModAdd(unsigned int *pwResult, unsigned int *pwX, unsigned int *pwY, unsigned int *pwModule, int  iBNWordLen);
void BN_ModSub(unsigned int *pwResult, unsigned int *pwX, unsigned int *pwY, unsigned int *pwModule, int  iBNWordLen);

unsigned int BN_SAdd(unsigned int* pwSum, int* Flag_Sum, unsigned int* pwX, int Flag_X, unsigned int* pwY, int Flag_Y, int iBNWordLen);
unsigned int BN_SSub(unsigned int* pwDiff, int* Flag_Diff, unsigned int* pwX, int Flag_X, unsigned int* pwY, int Flag_Y, int iBNWordLen);
int BN_GetInv_Even(unsigned int* pwResult, unsigned int* pwa, unsigned int *pwm, int iBNWordLen);
int BN_GetInv_Odd(unsigned int *pwResult, unsigned int *pwa, unsigned int *pwm, int iBNWordLen);
int BN_GetInv(unsigned int *pwResult, unsigned int *pwa, unsigned int *pwm, int iBNWordLen);

int BN_Mod_Basic(unsigned int *rem, int iBNWordLen_r, unsigned int *pwBNX, int iBNWordLen_X, unsigned int *pwBNM, int iBNWordLen_M);
int BN_Mod(unsigned int *pwResult,  int iBNWordLen_r, unsigned int *pwBNX, int iBNWordLen_X, unsigned int *pwBNM,  int iBNWordLen_M);
void BN_ModWord(unsigned int *pResult, unsigned int *pwBN, int iBNWordLen, unsigned int n);

int BN_IsCoprime(unsigned int pwX, unsigned int *pwY, int iBNWordLen);

void BN_ModMul_Stand(unsigned int *pwPro, unsigned int *pwX, unsigned int *pwY, unsigned int *pwM, int iBNWordLen);
void BN_ModExp_Stand(unsigned int *pwResult, unsigned int *pwX, unsigned int *pwE, unsigned int *pwM, int iBNWordLen);

void BN_SetM(unsigned int *pwM, int iBNBitLen, int iBNWordLen);
void BN_SetE(unsigned int *pwE, int iBNBitLen, int iBNWordLen);
void BN_ModMul(unsigned int *pwPro, unsigned int *pwX, unsigned int *pwY, int iBNWordLen);
void BN_ModExp(unsigned int *pwResult, unsigned int *pwX, int iBNWordLen);

void BN_Random(unsigned int *pwBN, int iBNWordLen);

void BN_To_W_NAF(NAF *pnaf, unsigned int *pwBN, int iBNWordLen);
int BN_Compare(unsigned int *pwX, unsigned int *pwY,int iBNWordLen);


void ECP_Init(pEC pEc, int iBNWordLen, unsigned char *pbSystemParameter);
void ECP_AToJ(pJ_Point pJp, pA_Point pAp, pEC pEc);
void ECP_AToJm(pJm_Point pJmp, pA_Point pAp, pEC pEc);
void ECP_JToA(pA_Point pAp, pJ_Point pJp, pEC pEc);
void ECP_JmToA(pA_Point pAp, pJm_Point pJmp, pEC pEc);
int ECP_IsOnCurve(pA_Point pAp_A, pEC pEc);

void ECP_AAddAToA(pA_Point pAp_Sum, pA_Point pAp_A, pA_Point pAp_B, pEC pEc);
void ECP_JAddAToJm(pJm_Point pJm_Sum, pJ_Point pJp, pA_Point pAp, pEC pEc);
void ECP_JAddAToJ(pJ_Point pJ_Sum, pJ_Point pJp, pA_Point pAp, pEC pEc);
void ECP_JSubAToJm(pJm_Point pJm_Sum, pJ_Point pJp, pA_Point pAp, pEC pEc);
void ECP_JSubAToJ(pJ_Point pJ_Sum, pJ_Point pJp, pA_Point pAp, pEC pEc);

void ECP_DoubleJmToJ(pJ_Point pJp, pJm_Point pJm, pEC pEc);
void ECP_DoubleJToJ(pJ_Point pJp_Result, pJ_Point pJp, pEC pEc);
void ECP_DoubleJmToJm(pJm_Point pJmp_Result, pJm_Point pJmp, pEC pEc);

void ECP_KP_PreCom(pA_Point  np, pA_Point pAp,  pEC pEc);
void ECP_KP(pA_Point KP, pA_Point pAp, unsigned int *K,  pA_Point np,  pEC pEc);
void ECP_KPLQ(pA_Point KPLQ, pA_Point pAp_P, unsigned int *K, pA_Point np, pA_Point pAp_Q, unsigned int *L, pA_Point nq, pEC pEc);


#ifdef _WIN32
//#include <time.h>
//static __inline void Rand_Init(void)
//{
//	srand((int)clock());
//}
//static __inline int Rand_Get(void)
//{
//	return rand();
	//return 0x12345678;
//}

// Move following Function declare to project include header file.


#ifndef WIN32_API
void DumpData(const char * str, unsigned char * pBuf, unsigned int len)
{
	unsigned int i;
	char tmp[17];
	char *p;
	char *add = (char *)pBuf;
	return;
	if(str)
	{
		//Uart_Printf("\r\n%s: length = %d [0x%X]\r\n", str, len, len);
		//Uart_Printf("\r\n%s=", str);
	}
	if(len == 0)
	{
		return;
	}
	p = tmp;
		//Uart_Printf("%p  ", add);
	//Uart_Printf("\t");
	for(i=0;i<len;i++)
	{
		
		//Uart_Printf("%02X",pBuf[i]);
		if((pBuf[i]>=0x20) && (pBuf[i]<0x7F))
		{
			*p++ = pBuf[i];
		}
		else
		{
			*p++ = '.';
		}
		if((i+1)%16==0)
		{
			*p++ = 0;//string end
			//Uart_Printf("        | %s", tmp);
			p = tmp;
			
			//Uart_Printf("\r\n");
			
			if((i+1) < len)
			{
				add += 16;
				//Uart_Printf("%p  ", add);
				//Uart_Printf("\t");
			}
		}
		else if((i+1)%8==0)
		{
			//Uart_Printf("- ");
		}
	}
	if(len%16!=0)
	{
		for(i=len%16;i<16;i++)
		{
			//Uart_Printf("   ");
			if(((i+1)%8==0) && ((i+1)%16!=0))
			{
				//Uart_Printf("- ");
			}
		}
		*p++ = 0;//string end
		//Uart_Printf("        | %s", tmp);
		//Uart_Printf("\r\n");
	}
	
	return;
}
#endif
//#error "should define Rand function First."
// suggest

//static __inline void Rand_Init(void)
static  void Rand_Init(void)
{
	srand((int)123);
}
int Rand_Get(void)
{
	//return rand();
        return 123456;
}
#else

#endif

const unsigned char Sbox[256] =
{
	0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
	0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
	0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
	0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
	0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
	0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
	0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
	0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
	0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
	0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
	0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
	0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
	0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
	0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
	0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
	0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};
const unsigned int CK[32] =
{
	0x00070E15,0x1C232A31,0x383F464D,0x545B6269,
	0x70777E85,0x8C939AA1,0xA8AFB6BD,0xC4CBD2D9,
	0xE0E7EEF5,0xFC030A11,0x181F262D,0x343B4249,
	0x50575E65,0x6C737A81,0x888F969D,0xA4ABB2B9,
	0xC0C7CED5,0xDCE3EAF1,0xF8FF060D,0x141B2229,
	0x30373E45,0x4C535A61,0x686F767D,0x848B9299,
	0xA0A7AEB5,0xBCC3CAD1,0xD8DFE6ED,0xF4FB0209,
	0x10171E25,0x2C333A41,0x484F565D,0x646B7279
};


void U8ToU32_L(unsigned int *pDataOut,unsigned char* pDataIn,int wordlen)
{
	int i = 0;	
	while(i < wordlen)
	{
		pDataOut[i] =((unsigned int)pDataIn[i*4  ] << 24)|
			((unsigned int)pDataIn[i * 4 + 1] << 16) |
			((unsigned int)pDataIn[i * 4 + 2] << 8) |
			((unsigned int)pDataIn[i * 4 + 3]);
		i++;
	}

}
void U32ToU8_L(unsigned char *pDataOut,unsigned int *pDataIn,int wordlen)
{
	int i = 0;
	while(i < wordlen)
	{
		pDataOut[i * 4    ] =  (unsigned char)(pDataIn[i] >> 24);    
		pDataOut[i * 4 + 1] =  (unsigned char)(pDataIn[i] >> 16);
		pDataOut[i * 4 + 2] =  (unsigned char)(pDataIn[i] >> 8);
		pDataOut[i * 4 + 3] =  (unsigned char)(pDataIn[i]); 
		i++;
	} 
}

static void *Conv_HexAsc(unsigned char *pucDest,unsigned char *pucSrc,unsigned int uiLen)
{
	unsigned int uiI;
	unsigned char *pucPtr;

    pucPtr = pucDest ;
    if ( uiLen % 2 )
        *pucDest++ = (*pucSrc++ & 0x0F) + 0x30 ;
    for ( uiI = 0 ; uiI < (uiLen / 2) ; uiI++)
    {
        *pucDest++ = ( (*pucSrc & 0xF0) >> 4 ) + 0x30 ;
        *pucDest++ = (*pucSrc++ & 0x0F) + 0x30 ;
    }
    while (pucPtr != pucDest)
    {
        if (*pucPtr >= 0x3A)
            *pucPtr += 7 ;
        pucPtr++;
    }
	return((unsigned char*)pucDest);
}

/***********************************************************************
	����:��U8��������ת���ɴ�����
	����:
		pByteBuf:U8��������
		bytelen:U8�������鳤��
	���:
		pwBN:unsigned int��������,���bytelenΪ4�ı�����iBNWordLen����Ϊbytelen/4,����Ϊbytelen/4 + 1
		iBNWordLen:������pwBN������
	 * ����ֵ:
		0:ת�����̴���
		1:ת���ɹ�
***********************************************************************/
int ByteToBN(unsigned char *pByteBuf, int bytelen, unsigned int  *pwBN, int iBNWordLen)
{
	/*******************/
	int ExpLen = 0;
	int Rem = 0;
	int i = 0;
	int j = 0;
	/*******************/

	ExpLen = bytelen >> 2;
	Rem = bytelen & 0x00000003;
	if (Rem != 0)//���bytelen����4��������
	{
		ExpLen += 1; 
	}

	if (ExpLen > iBNWordLen)
	{
		return 0;
	}

	i = bytelen - 1;
	j = 0;
	while (i >= Rem)
	{
		pwBN[j] = ((unsigned int)pByteBuf[i]) | ((unsigned int)pByteBuf[i - 1] << 8) | ((unsigned int)pByteBuf[i - 2] << 16) | ((unsigned int)pByteBuf[i - 3] << 24);
		i -= 4;
		j++;
	}

	i = 0;
	while (i < Rem)
	{
		pwBN[j] = (pwBN[j] << 8) | ((unsigned int)pByteBuf[i]);
		i++;
	}

	return 1;
}
/***********************************************************************
	����:��U8��������ת���ɴ�����
	����:
	pwBN:unsigned int��������
	iBNWordLen:������pwBN������

	���:
	pByteBuf:U8��������
	bytelen:U8��������

	 * ����ֵ:
	0:ת�����̴���
	1:ת���ɹ�
***********************************************************************/
int BNToByte(unsigned int *pwBN,int iBNWordLen,unsigned char *pByteBuf,int *bytelen)
{
	//==============================//
	int i ;
	unsigned char *P;
	unsigned int  W;
	//=================================//
	P=pByteBuf;

	for(i=iBNWordLen-1;i>=0;i--)	
	{
		W=pwBN[i];
		*P++=(unsigned char) ((W & 0xFF000000) >> 24);
		*P++=(unsigned char) ((W & 0x00FF0000) >> 16);
		*P++=(unsigned char) ((W & 0x0000FF00) >> 8);
		*P++=(unsigned char) (W &  0x000000FF) ;
	}
	*bytelen = iBNWordLen * 4;
	return 1;

}
/***********************************************************************
	����:����Ļ����ʾ������
	����:
		pwBN:�����������
		iBNWordLen:����������			
***********************************************************************/
void BN_Print(unsigned int *pwBN, int iBNWordLen)
{
	/*****************/
	int i = 0;
	int wordlen = 0;
	/*****************/

	wordlen = BN_GetWordLen(pwBN, iBNWordLen);
	if (wordlen == 0)
	{
		printf("%08X", pwBN[0]);
		printf("\n");
	}
	else
	{
		for (i = wordlen - 1; i >= 0; i--)
		{
			printf("%08X", pwBN[i]);
			printf("\n");
		}
		printf("\n");
	}
}

/***********************************************************************
	����:��������0
	����:pwBN:�����������
		 iBNWordLen:����������			
***********************************************************************/
void BN_Reset(unsigned int *pwBN,int iBNWordLen)
{
	/*************/
	int i = 0;
	/*************/
	
	for (i = 0; i < iBNWordLen; i++)
		pwBN[i] = 0x0;
}

/***********************************************************************
	����:��������ֵ,pwDest=pwSource
	����:pwDest:����ֵ����
		 pwSource:Դ����
		 iBNWordLen:����������			
***********************************************************************/

void BN_Assign(unsigned int *pwDest, unsigned int *pwSource, int  iBNWordLen)
{
	/**********/
	int i;
	/**********/
	
	for (i = 0; i < iBNWordLen; i++)
		pwDest[i] = pwSource[i];
}

/***********************************************************************
	����:�жϴ������Ƿ�Ϊ��
	����:pwBN:���жϴ�����	
	 * ����ֵ:0:pwBN��Ϊ��
		   1:pwBNΪ��
***********************************************************************/
int BN_IsZero(unsigned int *pwBN,int iBNWordLen)
{
	/********/
	int i;
	/********/

	for (i = 0; i < iBNWordLen; i++)		
		if ( pwBN[i] != 0)		
			return 0;
		return 1;
}

/***********************************************************************
	����:�жϴ������Ƿ�Ϊ1
	����:pwBN:���жϴ�����	
	 * ����ֵ:0:pwBN��Ϊ1
		   1:pwBNΪ1
***********************************************************************/
int BN_IsOne(unsigned int *pwBN,int iBNWordLen)
{
	/********/
	int i = 0;
	/********/

	if (pwBN[0] != LSBOfWord)
	{
		return 0;
	}
	for (i = 1; i < iBNWordLen; i++)	
	{
		if ( pwBN[i] != 0)		
			return 0;
	}
	return 1;
}
/***********************************************************************
	����:�жϴ������Ƿ�ż��
	����:pwBN:���жϴ�����	
	 * ����ֵ:0:pwBN������
		   1:pwBNΪż��
***********************************************************************/
int BN_IsEven(unsigned int *pwBN)
{
	if (pwBN[0] & LSBOfWord)		
		return 0;
	return 1;
}

/***********************************************************************
	����:�жϴ������Ƿ�Ϊ����
	����:pwBN:���жϴ�����	
	 * ����ֵ:0:pwBN������
		   1:pwBNΪż��
***********************************************************************/
int BN_IsOdd(unsigned int *pwBN)
{
	return	(pwBN[0] & LSBOfWord);
}

/***********************************************************************
	����:�жϴ������Ƿ����
	����:
		pwX:���жϴ�����1
		pwY:���жϴ�����1
	 * ����ֵ:0:X��Y�����
		   1:X��Y���
***********************************************************************/
int BN_JE(unsigned int *pwX, unsigned int *pwY, int iBNWordLen)
{
	/*******************/
	int i =0;
	/*******************/

	for (i = 0; i < iBNWordLen; i++)
	{
		if (pwX[i] != pwY[i])
		{
			return 0;
		}
	}
	return 1;
}

/***********************************************************************
	����:�жϴ�����X�Ƿ����Y
	����:
		pwX:���жϴ�����1
		pwY:���жϴ�����1
		iBNWordLen:
	 * ����ֵ:1:X>Y
		   0:X<Y��X=Y
***********************************************************************/
int BN_JA(unsigned int *pwX, unsigned int *pwY, int iBNWordLen)
{
	/*******************/
	int i =0;
	/*******************/

	for (i = iBNWordLen - 1; i >= 0; i--)
	{
		if (pwX[i] > pwY[i])
		{
			return 1;
		}
		else
		{
			if (pwX[i] < pwY[i])
			{
				return 0;
			}
		}
	}
	return 0;
}

/***********************************************************************
	����:�õ��������ı�����
	����:
		pwBN:������
		iBNWordLen:������������
***********************************************************************/
int BN_GetBitLen(unsigned int *pwBN, int iBNWordLen)
{
	/***********************/
	int i = 0;
	int k = 0;
	unsigned int tmp = 0;
	/***********************/

	for (i = iBNWordLen - 1; i >= 0; i--)
	{
		if (pwBN[i] != 0)
		{
			break;
		}
	}
	if (i == -1)
	{		
		return 0;
	}
	tmp = pwBN[i];
	k = 0;
	while((tmp & MSBOfWord) == 0)	
	{
		tmp = tmp << 1;
		k++;
	}
	return (i  << 5) + (WordLen - k);

}

/***********************************************************************
	����:�õ��������ı�����
	����:
		pwBN:������
		iBNWordLen:������������
***********************************************************************/
int BN_GetWordLen(unsigned int *pwBN, int iBNWordLen)
{
	/***********************/
	int i = 0;
	/***********************/

	for (i = iBNWordLen - 1; i >= 0; i--)
	{
		if (pwBN[i] != 0)
		{
			return i + 1;
		}
	}
	return 0;

}
/***********************************************************************
	����:�õ�����������Ч��������Чλ��
	����:
		pwBN:������
		iBNWordLen:������������
	���:
		pBitLen:��Ч������
		pWordLen:��Ч����
***********************************************************************/
void BN_GetLen(int *pBitLen, int *pWordLen, unsigned int *pwBN, int iBNWordLen)
{
	/***********************/
	int i = 0;
	int j = 0;
	unsigned int tmp = 0;
	/***********************/

	*pWordLen = 0;
	for (i = iBNWordLen - 1; i >= 0; i--)
	{
		if (pwBN[i] != 0)
		{
			break;
		}
	}
	if (i == -1)
	{
		*pBitLen = 0;
		*pWordLen = 0;
	}
	else
	{
		j = 0;
		tmp = pwBN[i];
		while ((tmp & MSBOfWord) == 0)
		{
			tmp = tmp << 1;
			j++;
		}
		*pWordLen = i + 1;
		*pBitLen = (i << 5) + (WordLen - j);
	}
}

/***********************************************************************
	����:�����������ƶ�1����
	����:pwBN:��Ҫ�ƶ������� & �ƶ�֮�����Ĵ洢λ��
		 iBNWordLen:������������
***********************************************************************/
void BN_ShiftRightOneBit(unsigned int *pwBN, int iBNWordLen)
{
	/**********/
	int i;
	/**********/

	for(i = 0; i < iBNWordLen - 1; i++)
	{
		pwBN[i] = (pwBN[i] >> 1) | (pwBN[i + 1] << 31);
		//pwBN[i] = pwBN[i] >> 1;
		//pwBN[i] = (pwBN[i + 1] & LSBOfWord) ? (pwBN[i] | MSBOfWord) : pwBN[i];
	}
	pwBN[i] = pwBN[i] >> 1;
}

/***********************************************************************
	����:�������������ƶ�1����
	����:pwBN:��Ҫ�ƶ������� & �ƶ�֮�����Ĵ洢λ��
		 iBNWordLen:������������
	 * ����ֵ:����������߱���λ
***********************************************************************/	
unsigned int BN_ShiftLeftOneBit(unsigned int *pwBN, int iBNWordLen)
{
	/**************/
	int i;
	unsigned int Carry;
	/**************/
	
	Carry = pwBN[iBNWordLen - 1] & MSBOfWord;
	
	for (i=iBNWordLen-1; i>0; i--)
	{
		pwBN[i] = (pwBN[i] << 1) | (pwBN[i - 1] >> 31);
		//pwBN[i] = pwBN[i] << 1;
		//pwBN[i] = (pwBN[i-1] & MSBOfU32) ? (pwBN[i] | LSBOfU32) : pwBN[i];
	}
	
	pwBN[0] = pwBN[0] << 1;
	
	return Carry;
}

/***********************************************************************
	����:���������,pwSum=pwX+pwY
	����:pwSum:��
		 pwX:������
		 pwY:����
		 iBNWordLen:�������ֳ�
	 * ����ֵ:��λ
***********************************************************************/	
unsigned int BN_Add( unsigned int *pwSum, unsigned int *pwX, unsigned int *pwY,int  iBNWordLen)
{
	/*********************/
    int i;
    unsigned long long carry = 0;
	/*********************/
	
	for (i = 0; i < iBNWordLen; i++)
    {
        carry = (unsigned long long)pwX[i] + (unsigned long long)pwY[i] + carry;
        pwSum[i] = (unsigned int)carry;
        carry = carry >> 32;
    }	
    return (unsigned int)carry;
}

/***********************************************************************
	����:���������,pwDif=pwX-pwY
	����:pwDiff:��
		 pwX:������
		 pwY:����
		 iBNWordLen:�������ֳ�
	 * ����ֵ:��λ
***********************************************************************/
unsigned int BN_Sub(unsigned int *pwDiff, unsigned int *pwX, unsigned int *pwY, int  iBNWordLen)
{
	/**********************/
    int i = 0;
    unsigned long long borrow = 0;
	/**********************/
	
    for (i = 0; i < iBNWordLen; i++)
    {
        borrow = (unsigned long long)pwX[i] - (unsigned long long)pwY[i] + borrow;
        pwDiff[i] = (unsigned int)borrow;
        borrow = (unsigned long long)(((long long)borrow) >> 32);
    }	
    return (unsigned int)borrow;
}

/***********************************************************************
	����:���������,pwPro=pwX*pwY
	����:
		pwPro:�˻�
		pwX:����
		pwY:������
		iBNWordLen:������X����Y���ֳ�
	 * ����ֵ:��
	Pro���ֳ�����Ϊ2*iBNWordLen
***********************************************************************/
void BN_Mul(unsigned int *pwPro, unsigned int *pwX, unsigned int *pwY, int  iBNWordLen)
{
	/*****************/
	int i = 0;
	int j = 0;
	unsigned long long carry = 0;
	/*****************/

	i = iBNWordLen << 1;
	BN_Reset(pwPro, i);
	for (i = 0; i < iBNWordLen; i++)
	{
		carry = 0;
		for (j = 0; j < iBNWordLen; j++)
		{
			carry = (unsigned long long)pwPro[i + j] + (unsigned long long)pwX[j] * (unsigned long long)pwY[i] + carry;
			pwPro[i + j] = (unsigned int)carry;
			carry >>= WordLen;;
		}
		pwPro[i + iBNWordLen] = (unsigned int)(carry);
	}
}
/***********************************************************************
	����:������ģ��,pwResult=(pwX+pwY) mod pwModule
	����:pwResult:���
		 pwX:����1
		 pwY:����2
		 pwModule:ģ
		 iBNWordLen:�������ֳ�
	ע:T=2^(iBNWordLen*32)  X<T,Y<T,R<T,Result<T
***********************************************************************/
void BN_ModAdd(unsigned int *pwResult, unsigned int *pwX, unsigned int *pwY, unsigned int *pwModule, int  iBNWordLen)
{
	/**********************/
    unsigned int c = 0;
	/**********************/
	
    c = BN_Add(pwResult, pwX, pwY,iBNWordLen);
	
    if (c == 0)
        return;
    do
    {
        c = BN_Sub(pwResult, pwResult, pwModule,iBNWordLen);
    } while (c==0);	
}

/***********************************************************************
	����:������ģ��,pwResult=(pwX-pwY) mod pwModule
	����:pwResult:���
		 pwX:������
		 pwY:����
		 pwModule:ģ
		 iBNWordLen:�������ֳ�
	ע:T=2^(iBNWordLen*32)  X<T,Y<T,R<T,Result<T
***********************************************************************/
void BN_ModSub(unsigned int *pwResult, unsigned int *pwX, unsigned int *pwY, unsigned int *pwModule, int  iBNWordLen)
{
	/**********************/
    unsigned int c = 0;
	/**********************/
	
    c = BN_Sub(pwResult, pwX, pwY,iBNWordLen);
	
    if (c == 0)
        return;
    do
    {
        c = BN_Add(pwResult, pwResult, pwModule,iBNWordLen);
    } while (c == 0);	
}

/**********************************************************************************************************
	������ʵ���з��Ŵ������ӷ�����������������,Result = x+Y,����X,Y����Ч����ֻ��32*(iBNWordLen-1)+1����.
	���룺
		pwX:����
		Flag_X:X�ķ���,0��ʾ����,1��ʾ����
		pwY:������
		Flag_Y:Y�ķ���,0��ʾ����,1��ʾ����
		iBNWordLen:���������ֳ�
	�����
		pwSum:��
		Flag_Sum:Sum�ķ���,0��ʾ����,1��ʾ����
**********************************************************************************************************/
unsigned int BN_SAdd(unsigned int* pwSum, int* Flag_Sum, unsigned int* pwX, int Flag_X, unsigned int* pwY, int Flag_Y, int iBNWordLen)
{
	/********************/
	int carry = 0;
	/********************/

	if (Flag_X == Flag_Y)
	{/*���X,Y�ķ�����ͬ*/
		carry = BN_Add(pwSum, pwX, pwY, iBNWordLen);
		*Flag_Sum = Flag_X;
	}
	else
	{/*X,Y�ķ����෴*/
		if (BN_JA(pwX, pwY, iBNWordLen))
		{/*���|X| > |Y|*/
			carry = BN_Sub(pwSum, pwX, pwY, iBNWordLen);
			*Flag_Sum = Flag_X;
		}
		else
		{/*���|X| <= |Y|*/
			carry = BN_Sub(pwSum, pwY, pwX, iBNWordLen);
			*Flag_Sum = Flag_Y;
		}
	}
	return carry;
}

/**********************************************************************************************************
	������ʵ���з��Ŵ�������������������������,����X,Y�ķ�����ͬ,����X,Y����Ч����ֻ��32*(iBNWordLen-1)+1����.
	���룺
		pwX:����
		Flag_X:X�ķ���,0��ʾ����,1��ʾ����
		pwY:������
		Flag_Y:Y�ķ���,0��ʾ����,1��ʾ����
		iBNWordLen:���������ֳ�
	�����
		pwDiff:��
		Flag_Sum:Sum�ķ���,0��ʾ����,1��ʾ����
**********************************************************************************************************/
unsigned int BN_SSub(unsigned int* pwDiff, int* Flag_Diff, unsigned int* pwX, int Flag_X, unsigned int* pwY, int Flag_Y, int iBNWordLen)
{
	/************************/
	unsigned int carry = 0;
	/************************/

	if (Flag_X != Flag_Y)
	{/*���X,Y�ķ����෴*/
		carry = BN_Add(pwDiff, pwX, pwY, iBNWordLen);
		*Flag_Diff = Flag_X;
	}
	else
	{/*���X,Y�ķ�����ͬ*/
		if (BN_JA(pwX, pwY, iBNWordLen))
		{/*���|X| > |Y|*/
			carry = BN_Sub(pwDiff, pwX, pwY, iBNWordLen);
			*Flag_Diff = Flag_X;
		}
		else
		{/*���|X| <= |Y|*/
			carry = BN_Sub(pwDiff, pwY, pwX, iBNWordLen);
			if (Flag_X == Minus)
			{
				*Flag_Diff = Plus;
			}
			else
			{
				*Flag_Diff = Minus;
			}
		}
	}
	return carry;
}

/***********************************************************************
	����:����������,	pwR=pwa^-1 mod pwm
	����:
		pwa:������
		pwm:������,ģ
		iBNWordLen:���������ֳ�
	���:
		pwR:������pwa^-1 mod pwm
***********************************************************************/
int BN_GetInv_Even(unsigned int* pwResult, unsigned int* pwa, unsigned int *pwm, int iBNWordLen)
{
	/************************/
	unsigned int U[Ext_RSABNWordLen];
	unsigned int V[Ext_RSABNWordLen];
	unsigned int R[Ext_RSABNWordLen];
	unsigned int S[Ext_RSABNWordLen ];
	unsigned int EXP_2_u[Ext_RSABNWordLen];
	unsigned int EXP_2_v[Ext_RSABNWordLen];
	unsigned int m_tmp[Ext_RSABNWordLen];
	int u = 0;
	int v = 0;
	int carry = 0;
	int Flag_U = 0;
	int Flag_V = 0;
	int Flag_R = 0;
	int Flag_S = 0;
	int bitlen_m = 0;
	int quo = 0;
	int rem = 0;
	unsigned int flag = LSBOfWord;
	unsigned int RealWordLen = 0;
	/************************/

	bitlen_m = BN_GetBitLen(pwm, iBNWordLen);
	quo= bitlen_m >> 5;
	RealWordLen = quo;
	rem = bitlen_m & 0x1f;
	flag <<= (rem - 1); 
	if (rem != 0)
	{
		RealWordLen++;//��չλ���������з��Ŵ���������
	}
	if (RealWordLen > RSABNWordLen)//ֻ֧��λ��������32*RSAWordLen����������
	{
		return 2;
	}
	if (rem == 0)
	{
		RealWordLen++;//��չλ���������з��Ŵ���������
		quo--;
	}
	
	BN_Reset(U, Ext_RSABNWordLen);
	BN_Reset(V, Ext_RSABNWordLen);
	BN_Reset(R, Ext_RSABNWordLen);
	BN_Reset(S, Ext_RSABNWordLen);
	BN_Reset(EXP_2_u, Ext_RSABNWordLen);
	BN_Reset(EXP_2_v, Ext_RSABNWordLen);
	BN_Reset(m_tmp, Ext_RSABNWordLen);

	BN_Assign(U, pwm, iBNWordLen);//U=m
	BN_Assign(V, pwa, iBNWordLen);//V=a, R=0
	S[0] = LSBOfWord;//S=1
	EXP_2_u[0] = LSBOfWord;//2^u = 1
	EXP_2_v[0] = LSBOfWord;//2^v = 1
	BN_Assign(m_tmp, pwm, iBNWordLen);//m_tmp = m

	RealWordLen++;//��չλ����ʹ�ü�����̲�������λ
	while ( (!BN_JE(U, EXP_2_u, RealWordLen)) && (!BN_JE(V, EXP_2_v, RealWordLen)))
	{
		if ( !(U[quo] & flag))//���|U|<2^(n-1)
		{
			carry = BN_ShiftLeftOneBit(U, RealWordLen);//U=2U
			u = u + 1;
			carry = BN_ShiftLeftOneBit(EXP_2_u, RealWordLen);//����2^u
			if (u > v)
			{
				carry = BN_ShiftLeftOneBit(R, RealWordLen);//R=2R
			}
			else
			{
				BN_ShiftRightOneBit(S, RealWordLen);//S=S/2
			}
		}
		else
		{
			if ( !(V[quo] & flag))//���|V|<2^(n-1)
			{
				carry = BN_ShiftLeftOneBit(V, RealWordLen);//V=2V
				v = v + 1;
				carry = BN_ShiftLeftOneBit(EXP_2_v, RealWordLen);
				if (v > u)
				{
					carry = BN_ShiftLeftOneBit(S, RealWordLen);//S=2S
				}
				else
				{
					BN_ShiftRightOneBit(R, RealWordLen);//R=R/2
				}
			}
			else
			{
				if (Flag_U == Flag_V)
				{
					if ( u <= v)
					{
						carry = BN_SSub(U, &Flag_U, U, Flag_U, V, Flag_V, RealWordLen);//U=U-V
						carry = BN_SSub(R, &Flag_R, R, Flag_R, S, Flag_S, RealWordLen);//R=R-S
					}
					else
					{
						carry = BN_SSub(V, &Flag_V, V, Flag_V, U, Flag_U, RealWordLen);//V=V-U
						carry = BN_SSub(S, &Flag_S, S, Flag_S, R, Flag_R, RealWordLen);//S=S-R
					}
				}
				else
				{
					if ( u <= v)
					{
						carry = BN_SAdd(U, &Flag_U, U, Flag_U, V, Flag_V, RealWordLen);//U=U+V
						carry = BN_SAdd(R, &Flag_R, R, Flag_R, S, Flag_S, RealWordLen);//R=R+S
					}
					else
					{
						carry = BN_SAdd(V, &Flag_V, V, Flag_V, U, Flag_U, RealWordLen);//V=V+U
						carry = BN_SAdd(S, &Flag_S, S, Flag_S, R, Flag_R, RealWordLen);//S=S+R
					}
				}
			}
		}

		if ( BN_IsZero(U, RealWordLen) || BN_IsZero(V, RealWordLen))//���U=0����V=0
		{
			return 0;
		}		
	}

	if (BN_JE(V, EXP_2_v, RealWordLen))//���|V|=2^v
	{
		BN_Assign(R, S, RealWordLen);//R=S
		Flag_R = Flag_S;

		BN_Assign(U, V, RealWordLen);//U=V
		Flag_U = Flag_V;
	}

	if (Flag_U == Minus)//���U<0
	{
		if (Flag_R == Minus)//���R<0
		{
			Flag_R = Plus;//R=-R
		}
		else
		{
			carry = BN_SSub(R, &Flag_R, m_tmp, Plus, R, Flag_R, RealWordLen);//R=m-R
		}
	}
	if (Flag_R == Minus)
	{
		carry = BN_SAdd(R, &Flag_R, m_tmp, Plus, R, Flag_R, RealWordLen);//R=m+R
	}
	BN_Assign(pwResult, R, RealWordLen);//����R
	return 1;
}

/***********************************************************************
	����:����������,	pwR=pwa^-1 mod pwm
	����:
		pwa:������
		pwm:������,ģ
		iBNWordLen:���������ֳ�
	���:
		pwResult:������pwa^-1 mod pwm
	ע��:����pwm����Ϊ����,pwa < pwm
***********************************************************************/
int BN_GetInv_Odd(unsigned int *pwResult, unsigned int *pwa, unsigned int *pwm, int iBNWordLen)
{
	/*********************************/
	unsigned int u[RSABNWordLen];
	unsigned int v[RSABNWordLen];
	unsigned int A[RSABNWordLen];
	unsigned int C[RSABNWordLen];
	unsigned int carry = 0;
	/*********************************/

	/* A=1, C=0, u=a, v=p */
	BN_Reset(A, RSABNWordLen);
	BN_Reset(C, RSABNWordLen);
	BN_Reset(u, RSABNWordLen);
	BN_Reset(v, RSABNWordLen);
	A[0]=1;
	BN_Assign(u, pwa, iBNWordLen);
	BN_Assign(v, pwm, iBNWordLen);

	while(!BN_IsZero(u, iBNWordLen))
	{
		while(!BN_IsOdd(u))
		{
			carry = 0;
			BN_ShiftRightOneBit(u, iBNWordLen);
			if(BN_IsOdd(A))
			{
				carry = BN_Add(A, A, pwm, iBNWordLen);
			}
			BN_ShiftRightOneBit(A, iBNWordLen);			
			if (carry == 1)
			{
				A[iBNWordLen - 1] |= MSBOfWord;
			}			
		}

		while(!BN_IsOdd(v))
		{
			carry = 0;
			BN_ShiftRightOneBit(v, iBNWordLen);
			if(BN_IsOdd(C))
			{
				carry = BN_Add(C, C, pwm, iBNWordLen);
			}
			BN_ShiftRightOneBit(C, iBNWordLen);			
			if (carry == 1)
			{
				C[iBNWordLen - 1] |= MSBOfWord;
			}			
		}
		
		if (BN_JA(v, u, iBNWordLen))
		{
			BN_Sub(v, v, u, iBNWordLen);
			BN_ModSub(C, C, A, pwm, iBNWordLen);
		}
		else
		{
			BN_Sub(u, u, v, iBNWordLen);
			BN_ModSub(A, A, C, pwm, iBNWordLen);
		}

	}
	if (BN_IsOne(v, iBNWordLen) == 0)
	{
		return 0;
	}
	BN_Assign(pwResult, C, iBNWordLen);
	return 1;
}

/***********************************************************************
	����:����������,�ú�����Ҫ����pwm����ż���������Ӻ��������������㣬pwR=pwa^-1 mod pwm
	����:
		pwa:������
		pwm:������,ģ
		iBNWordLen:���������ֳ�
	���:
		pwResult:������pwa^-1 mod pwm
***********************************************************************/
int BN_GetInv(unsigned int *pwResult, unsigned int *pwa, unsigned int *pwm, int iBNWordLen)
{
	/********************/
	int result = 0;
	/********************/

	if (BN_IsOdd(pwm))
	{
		result = BN_GetInv_Odd(pwResult, pwa, pwm, iBNWordLen);
	}
	else
	{
		result = BN_GetInv_Even(pwResult, pwa, pwm, iBNWordLen);
	}
	return result;
}

/***********************************************************************
	����:������ȡģ����pwBNX = quo * pwBNM + rem, 0<= rem < pwBNM,����Ҫ��pwBNM[l-1]>=2^(w-1),����lΪpwBNM������
	����:
		pwBNX:������������ֳ�λiBNWordLen_X
		iBNWordLen_X:pwBNX���ֳ�,���ܳ���MAXBNWordLen-2
		pwBNM:������,ģ,�ֳ�ΪiBNWordLen_M
		iBNWordLen_M:pwBNM���ֳ�
		iBWordLen_q:quo���ֳ�,����ΪiBNWordLen_X��iBNWordLen_M+1
	���:
		quo:��,�ֳ��ֳ�����ΪiBNWordLen_q		
		rem:����,�ֳ�����ΪiBNWordLen_r,
***********************************************************************/
int BN_Mod_Basic(unsigned int *rem, int iBNWordLen_r, unsigned int *pwBNX, int iBNWordLen_X, unsigned int *pwBNM, int iBNWordLen_M)
{	
	/******************************/
	int i = 0;
	int j = 0;
	unsigned long long q = 0;
	unsigned long long carry = 0;
	unsigned long long tmp = 0;
	int k = 0;
	int l = 0;
	int ll = 0;
	int len_rem = 0;
	unsigned int temp[BNMAXWordLen];
	unsigned int quo_tmp[BNMAXWordLen];
	/******************************/

	BN_Reset(temp, BNMAXWordLen);
	BN_Reset(quo_tmp, BNMAXWordLen);
	k = iBNWordLen_X;
	l = iBNWordLen_M;
	ll = l - 1;
	for (i = k - l; i >= 0; i--)
	{
		q = ((((unsigned long long)(pwBNX[i + l]) << WordLen) + (unsigned long long)pwBNX[i + l - 1]))/(unsigned long long)pwBNM[ll];//q[i] = (r[i+l]B+R[i+l-1])/b[l-1]
		if(q & 0xffffffff00000000)//���q[i]>=B-1
			quo_tmp[i] = 0xffffffff;
		else
			quo_tmp[i] = (unsigned int)q;
		carry = 0;
		for(j = 0; j < l; j++)//temp = q[i] * pwBNM
		{
			carry = (unsigned long long)quo_tmp[i] * ( unsigned long long)pwBNM[j] + carry;
			temp[j] = (unsigned int)carry;
			carry >>= WordLen;
		}
		temp[j] = (unsigned int)carry;
		carry = 0;
		for(j = 0; j < l; j++)//pwBNX = pwBNX - (temp << ( 32 * i))
		{
			carry = (unsigned long long)pwBNX[i+j] - (unsigned long long)temp[j] + carry;
			pwBNX[i+j] = (unsigned int) carry;
			carry = ((long long)carry) >> WordLen;
		}
		carry = (unsigned long long)pwBNX[i+j] - (unsigned long long)temp[j] + carry;
		while(carry & 0x1000000000000000)//while r[i+l] < 0
		{
			tmp = 0;
			for(j = 0; j < l; j++)//pwBNX = pwBNX + (pwBNM << ( 32 * i))
			{
				tmp = (unsigned long long)pwBNX[i+j] + (unsigned long long)pwBNM[j]+tmp;
				pwBNX[i + j] = (unsigned int)tmp;
				tmp = (unsigned long long)(tmp >> WordLen);
			}
			carry = carry + tmp;
			quo_tmp[i] -= 1;
		}
		pwBNX[i + l] = (unsigned int)carry;
	}
	len_rem = BN_GetWordLen(pwBNX, iBNWordLen_M);
	if (len_rem > iBNWordLen_r)//�ж�rem��λ���Ƿ�����
		return 0;
	BN_Assign(rem, pwBNX, len_rem);
	return 1;
}

/***********************************************************************
	����:������ȡģ����pwBNX = quo * pwBNM + rem, 0<= rem < pwBNM,��Ҫ�Ƕ����ݽ�������ʹ֮����BN_Mod_Basic���������
		 ����,��������BN_Div_Basic�����ݽ��д���,���Եõ��Ľ������У�����Ӷ��õ����ս��.
	����:
		pwBNX:������������ֳ�λiBNWordLen_X
		iBNWordLen_X:pwBNX���ֳ�,���ܳ���RSAWordLen
		pwBNM:������,ģ,�ֳ�ΪiBNWordLen
		iBNWordLen:pwBNM,quo,rem���ֳ�
	���:
		quo:��,�ֳ��ֳ�ΪiBNWordLen
		rem:����,�ֳ��ֳ�ΪiBNWordLen
***********************************************************************/
int BN_Mod(unsigned int *pwResult,  int iBNWordLen_r, unsigned int *pwBNX, int iBNWordLen_X, unsigned int *pwBNM,  int iBNWordLen_M)
{
	/*~~~~~~~~~~~~~~~~~~~*/
	int wordlen_x = 0;
	int wordlen_m = 0;
	unsigned int temp = 0;
	int i = 0;
	int shiftbit = 0;
	unsigned int temp_pwx[BNMAXWordLen];
	unsigned int temp_pwm[BNMAXWordLen];
	int result = 0;
	/*~~~~~~~~~~~~~~~~~~~*/

	wordlen_x = BN_GetWordLen(pwBNX, iBNWordLen_X);
	if (wordlen_x > 64)//ֻ֧��λ��������2048���ص�ȡģ����
	{
		return 0;
	}
	wordlen_m = BN_GetWordLen(pwBNM, iBNWordLen_M);
	if (wordlen_m > 64)
	{		
		return 0;
	}
	BN_Reset(temp_pwx, BNMAXWordLen);
	BN_Reset(temp_pwm, BNMAXWordLen);
	BN_Assign(temp_pwx, pwBNX, wordlen_x);
	BN_Assign(temp_pwm, pwBNM, wordlen_m);
	temp = temp_pwm[wordlen_m - 1];
	
	while (temp < MSBOfWord)//������Ҫ���ƶ���λ������ʹ������ִ���2^(w-1)
	{
		temp <<= 1;
		shiftbit++;
	}
	for (i = 0; i < shiftbit; i++)//ʹtemp_pwm��������������2^(w-1)
	{
		BN_ShiftLeftOneBit(temp_pwx, wordlen_x + 1);
		BN_ShiftLeftOneBit(temp_pwm, wordlen_m);
	}
	if (temp_pwx[wordlen_x] != 0)//�õ�temp_pwx������
		wordlen_x += + 1;
	BN_Reset(pwResult, iBNWordLen_r);
	result = BN_Mod_Basic(pwResult, iBNWordLen_r, temp_pwx, wordlen_x, temp_pwm, wordlen_m);//����BN_Mod_Basic����
	if (result == 0)
		return 0;
	for (i = 0; i < shiftbit; i++)
	{
		BN_ShiftRightOneBit(pwResult, wordlen_m);
	}
	return 1;
}

/***********************************************************************
	����:������ȡģ����
	����:
		pwBN:���������ֳ�λiBNWordLen
		iBNWordLen:pwBNX���ֳ�,���ܳ���RSABNWordLen
		n:ģ,32��������
	���:
		pResult:���
***********************************************************************/
void BN_ModWord(unsigned int *pResult, unsigned int *pwBN, int iBNWordLen, unsigned int n)
{
	/********************************/
	int shiftbit = 0;
	int shiftbit2 = 0;
	int wordlen = 0;
	int k = 0;
	unsigned int rem[Ext_RSABNWordLen];//֧��1024���صĴ���������
	unsigned int quo[Ext_RSABNWordLen];
	unsigned int temp[2];
	int i = 0;
	unsigned int n_tmp = 0;
	unsigned long long carry = 0;
	unsigned long long tmp = 0;
	unsigned long long q = 0;
	/********************************/

	for (i = 0; i < Ext_RSABNWordLen; i++)
	{
		rem[i] = 0;
		quo[i] = 0;
	}
	temp[0] = 0;
	temp[1] = 0;
	wordlen = BN_GetWordLen(pwBN, iBNWordLen);
	BN_Assign(rem, pwBN, wordlen);

	n_tmp = n;
	while (n_tmp != 0)
	{
		n_tmp >>= 1;
		shiftbit++;
	}
	shiftbit2 = shiftbit;
	shiftbit = WordLen - shiftbit;

	n_tmp = (n << shiftbit);
	for (i = wordlen; i > 0; i--)//����rem
	{
		rem[i] = (rem[i] << shiftbit) | (rem[i - 1] >> shiftbit2);
	}
	rem[0] <<= shiftbit;

	if (rem[wordlen] != 0)
	{
		k = wordlen + 1;
	}
	else
	{
		k = wordlen;
	}

	for (i = k - 1; i >= 0; i--)
	{
		q = ((((unsigned long long)(rem[i + 1]) << WordLen) + (unsigned long long)rem[i]))/(unsigned long long)n_tmp;//q[i] = (r[i+l]B+R[i+l-1])/b[l-1]
		if(q & 0xffffffff00000000)//���q[i]>=B-1
			quo[i] = 0xffffffff;
		else
			quo[i] = (unsigned int)q;

		carry = (unsigned long long)quo[i] * ( unsigned long long)n_tmp;
		temp[0] = (unsigned int)carry;
		carry >>= WordLen;
		temp[1] = (unsigned int)carry;

		carry = (unsigned long long)rem[i] - (unsigned long long)temp[0];
		rem[i] = (unsigned int)carry;
		carry = ((long long)carry) >> WordLen;

		carry = (unsigned long long)rem[i + 1] - (unsigned long long)temp[1] + carry;
		while (carry & 0x1000000000000000)//while r[i+l] < 0
		{
			tmp = (unsigned long long)rem[i] + (unsigned long long)n_tmp;
			rem[i] = (unsigned int)tmp;
			tmp = (unsigned long long)(tmp >> WordLen);
			carry = carry + tmp;
			quo[i] -= 1;
		}
		rem[i + 1] = (unsigned int)carry;
	}
	*pResult = rem[0] >> shiftbit;
}

/***********************************************************************
	����:�ж�һ��32���ص�����һ���������Ƿ���
	����:
		pwX:32���ص�����
		pwY:������,ģ,�ֳ�ΪiBNWordLen
		iBNWordLen:pwBNM,quo,rem���ֳ�
	 * ����ֵ:
		0:������
		1:����
***********************************************************************/
int BN_IsCoprime(unsigned int pwX, unsigned int *pwY, int iBNWordLen)
{
	/*********************************/
	unsigned int a = 0;
	unsigned int b = 0;
	unsigned int t = 0;
	unsigned int wordlen = 0;
	int Flag_t = 0;
	/*********************************/

	a = pwX;
	BN_Mod(&b, 1, pwY, iBNWordLen, &a, 1);
	if ( b == 0)
		return 0;
	
	while (b != 0)
	{
		t = a % b;
		a = b;
		b =t;
	}
	if (a == 1)
		return 1;
	else
		return 0;
}

/***********************************************************************
	����:������ģ������pwPro = pwX * pxY mod pwM
	����:
		pwX:������X,�ֳ�λiBNWordLen
		pwY:������Y,�ֳ�ΪiBNWordLen
		pwM:������M,ģ,�ֳ�ΪiBNWordLen
		iBNWordLen:���������ֳ���λ��������1024
	���:
		pwPro:ģ�˽��,�ֳ��ֳ�ΪiBNWordLen
***********************************************************************/
void BN_ModMul_Stand(unsigned int *pwPro, unsigned int *pwX, unsigned int *pwY, unsigned int *pwM, int iBNWordLen)
{
	/***********************************/
	unsigned int Pro_tmp[2 * RSABNWordLen];
	/***********************************/

	BN_Reset(Pro_tmp, 2 * RSABNWordLen);
	BN_Mul(Pro_tmp, pwX, pwY, iBNWordLen); //Pro_tmp = pwX * pwY
	BN_Mod(pwPro, iBNWordLen, Pro_tmp, 2 * RSABNWordLen, pwM, iBNWordLen);//pwPro = Pro_tmp mod pxM
}

/***********************************************************************
	����:������ģ������pwResult = pwX ^ pxE mod pwM
	����:
		pwX:������X,�ֳ�λiBNWordLen
		pwE:������Y,�ֳ�ΪiBNWordLen
		pwM:������M,ģ,�ֳ�ΪiBNWordLen
		iBNWordLen:���������ֳ���λ��������1024
	���:
		pwResult:ģ�ݽ��,�ֳ��ֳ�ΪiBNWordLen
***********************************************************************/
void BN_ModExp_Stand(unsigned int *pwResult, unsigned int *pwX, unsigned int *pwE, unsigned int *pwM, int iBNWordLen)
{
	/***********************************/
	int bitlen = 0;
	int i = 0;
	unsigned int flag[32] = {0x00000001,0x00000002,0x00000004,0x00000008,
				   0x00000010,0x00000020,0x00000040,0x00000080,
				   0x00000100,0x00000200,0x00000400,0x00000800,
				   0x00001000,0x00002000,0x00004000,0x00008000,
				   0x00010000,0x00020000,0x00040000,0x00080000,
				   0x00100000,0x00200000,0x00400000,0x00800000,
				   0x01000000,0x02000000,0x04000000,0x08000000,
				   0x10000000,0x20000000,0x40000000,0x80000000};
	/***********************************/

	bitlen = BN_GetBitLen(pwE, iBNWordLen);
	if (bitlen == 0)
	{
		BN_Reset(pwResult, iBNWordLen);
		pwResult[0] = LSBOfWord;
	}
	else
	{		
		BN_Reset(pwResult, iBNWordLen);
		BN_Assign(pwResult, pwX, iBNWordLen);		
		for (i = bitlen - 2; i >= 0; i--)
		{
			BN_ModMul_Stand(pwResult, pwResult, pwResult, pwM, iBNWordLen);
			if (pwE[i / WordLen] & flag[i % WordLen])
				BN_ModMul_Stand(pwResult, pwResult, pwX, pwM, iBNWordLen);
		}
	}
}

/***********************************************************************
	����:��ģ��ģ��λ�����õ���Ӧ�ļĴ�����
	����:
		pwM:������M,ģ,λ��ΪiBNBitLen
		iBNBitLen:��������λ����λ��������1024
		iBNWordLen:����������Ч����
***********************************************************************/
void BN_SetM(unsigned int *pwM, int iBNBitLen, int iBNWordLen)
{
	/***********************/
	int i = 0;
	/***********************/

	//REG32(RSANLENADD) = iBNBitLen;//����M�ĳ��ȼĴ���
	for (i = 0; i < iBNWordLen; i++)
	{
		//REG32(RSANBASE + i * 4) = pwM[i];//����M
	}
}

/***********************************************************************
	����:��ָ����ָ����λ�����õ���Ӧ�ļĴ�����
	����:
		pwE:������E,ָ��,λ��ΪiBNBitLen
		iBNBitLen:��������λ����λ��������1024
***********************************************************************/
void BN_SetE(unsigned int *pwE, int iBNBitLen, int iBNWordLen)
{
	/***********************/
	int i = 0;
	/***********************/

	//REG32(RSAELENADD) = iBNBitLen;//����E�ĳ��ȼĴ���
	for (i = 0; i < iBNWordLen; i++)
	{
		//REG32(RSAEBASE + i * 4) = pwE[i];//����E
	}
}

/***********************************************************************
	����:������ģ������pwPro = pwX * pxY mod pwM,�ڵ��øú���ǰ�������Ѿ�ִ����BN_SetM
	����:
		pwX:������X,�ֳ�λiBNWordLen
		pwY:������Y,�ֳ�ΪiBNWordLen
		iBNWordLen:����������Ч�ֳ�
	���:
		pwPro:ģ�˽��,�ֳ��ֳ�ΪiBNWordLen
***********************************************************************/
void BN_ModMul(unsigned int *pwPro, unsigned int *pwX, unsigned int *pwY, int iBNWordLen)
{
	/************************/
	int i = 0;
	unsigned int flag = 0;
	/************************/

	for (i = 0; i < iBNWordLen; i++)
	{
		//REG32(RSAABASE + i * 4) = pwX[i];
		//REG32(RSABBASE + i * 4) = pwY[i];
	}

	//REG32(RSACOMADD) = RSAHABCOM;
  	//REG32(RSACTLADD) = 0x1;

	do
 	{
		//flag = REG32(RSACTLADD);	  
 	}while (flag & 1);

 	for (i = 0; i < iBNWordLen; i++)
 	{
		//pwPro[i] = REG32(RSAABASE + i * 4); 
	}	
}

/***********************************************************************
	����:������ģ������pwPro = pwX * pxE mod pwM,�ڵ��øú���ǰ�������Ѿ�ִ����BN_SetM��BN_SetE
	����:
		pwX:������X,�ֳ�λiBNWordLen
		iBNWordLen:����������Ч�ֳ�
	���:
		pwResult:ģ�ݽ��,�ֳ��ֳ�ΪiBNWordLen
***********************************************************************/
void BN_ModExp(unsigned int *pwResult, unsigned int *pwX, int iBNWordLen)
{
	/************************/
	int i = 0;
	unsigned int flag = 0;
	/************************/

	for (i = 0; i < iBNWordLen; i++)		
	{
		//REG32(RSAABASE + i * 4) = pwX[i];	// set a data
	}

	//REG32(RSACOMADD) = RSAHAECOM;
  	//REG32(RSACTLADD) = 0x1;
	do
 	{
		//flag = REG32(RSACTLADD);
 	}while (flag & 1);
		
 	for (i = 0; i < iBNWordLen; i++)
 	{
		//pwResult[i] = REG32(RSABBASE + i * 4);
 	}
}

/***********************************************************************
	����:�����������
	����:
		pwBN:������X,�ֳ�λiBNWordLen
		iBNWordLen:����������Ч�ֳ�
***********************************************************************/
void BN_Random(unsigned int *pwBN, int iBNWordLen)
{
	/*******************/
	int i = 0;
	/*******************/

	for (i = 0; i < iBNWordLen; i++)
	{
		//pwBN[i] = Get_Rand();
		pwBN[i] = (rand() <<16 ) | (rand());
	}
}

void BN_To_W_NAF(NAF *pnaf, unsigned int *pwBN,  int iBNWordLen)
{
	/**************************************/
	int temp1 = 0;
	int temp2 = 0;
	int temp3 = 0;
	unsigned int flag=0;
	unsigned int i = 0;
	unsigned int bn_k[ECCBNWordLen];
	unsigned int temp[ECCBNWordLen];
	/**************************************/

	temp1 = 1 << NAF_W;         //temp1=2^w
	temp2=1 << (NAF_W - 1);     //temp2=2^(w-1)
	BN_Reset(bn_k, ECCBNWordLen);
	BN_Reset(temp, ECCBNWordLen);
	BN_Assign(bn_k, pwBN, iBNWordLen);
	
	//loop while k is not 0 
	while (!BN_IsZero(bn_k, iBNWordLen))
	{
		if ( BN_IsOdd(bn_k) )
		{
			//pnaf->k[i] =  bn_k[0] % temp1;
			pnaf->k[i] =  bn_k[0] & NAF_Flag;
			if (pnaf->k[i] > temp2)
			{
				pnaf->k[i] = pnaf->k[i] - temp1;
			}
			if ( pnaf->k[i] < 0 )     
			{
				temp3 =  pnaf->k[i] - 1;
				temp[0] = ~temp3;
				flag = BN_Add(bn_k, bn_k, temp, iBNWordLen);
			}
			else
			{
				temp[0] = pnaf->k[i];
				BN_Sub(bn_k, bn_k, temp, iBNWordLen);
			}   
		}
		else
		{
			pnaf->k[i] = 0;
		}
		BN_ShiftRightOneBit(bn_k, iBNWordLen);
		if(flag == 1)
		{
			bn_k[iBNWordLen - 1] = bn_k[iBNWordLen - 1] | MSBOfWord;
			flag=0;
		}
		i++;
	}
	pnaf->count = i;
}
/***********************************************************************
����:�Ƚ����������Ĵ�С
����:
pwX:������X,�ֳ�λiBNWordLen
pwY:������Y,�ֳ�λiBNWordLen
iBNWordLen:����������Ч�ֳ�
���أ� X= Y������0
	   X >Y,����1
	   X<Y������-1
***********************************************************************/
int BN_Compare(unsigned int *pwX, unsigned int *pwY,int iBNWordLen)
{
	int i;
	for(i = iBNWordLen-1; i >= 0; i--)
		if(pwX[i] != pwY[i]) 
			return((pwX[i] > pwY[i]) << 1) - 1;
	return 0;
}

/***********************************************************************
	����:��ʼ����Բ�������ݽṹ
	����:
		pbSystemParameter:��Բ���� * �������������Բ���� * ��������p��a��b��Gx��Gy��N
		iBNWordLen:ECC����������Ч�ֳ�
	���:
		pEc:��Բ���� * �������ݽṹ
	 * ����ֵ:
		��
***********************************************************************/
void ECP_Init(pEC pEc, int iBNWordLen, unsigned char *pbSystemParameter)
{
	/***************************/
	int ibytelen = 0;
	unsigned char *start = pbSystemParameter;
	/***************************/

	ibytelen = iBNWordLen << 2;

	pEc->BNWordLen = iBNWordLen;//������Ч�ֳ�

	ByteToBN(start, ibytelen, pEc->EC_P, iBNWordLen);//����p
	start += ibytelen;

	ByteToBN(start, ibytelen, pEc->EC_a, iBNWordLen);//����a
	start += ibytelen;

	ByteToBN(start, ibytelen, pEc->EC_b, iBNWordLen);//����b
	start += ibytelen;

	ByteToBN(start, ibytelen, pEc->EC_G.X, iBNWordLen);//����G���X����
	start += ibytelen;

	ByteToBN(start, ibytelen, pEc->EC_G.Y, iBNWordLen);//����G���Y����
	start += ibytelen;

	ByteToBN(start, ibytelen, pEc->EC_N, iBNWordLen);//����N
	

	//Ԥ����
	ECP_KP_PreCom(pEc->GArray, &pEc->EC_G, pEc);
}

/***********************************************************************
	����:�ѷ����ת������Ӱ�����
	����:
		pAp:��Բ��������Affine�����ʾ�ĵ�
		pEc:��Բ���� * �������ݽṹ
	���:
		pJp::��Բ��������Jacobian�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/
void ECP_AToJ(pJ_Point pJp, pA_Point pAp, pEC pEc)
{
	BN_Assign(pJp->X, pAp->X, pEc->BNWordLen);
	BN_Assign(pJp->Y, pAp->Y, pEc->BNWordLen);
	BN_Reset(pJp->Z, ECCBNWordLen);
	pJp->Z[0] = LSBOfWord;
}

/***********************************************************************
	����:�ѷ����ת������Ӱ�����
	����:
		pAp:��Բ��������Affine�����ʾ�ĵ�
		pEc:��Բ���� * �������ݽṹ
	���:
		pJmp::��Բ��������JacobianM�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/
void ECP_AToJm(pJm_Point pJmp, pA_Point pAp, pEC pEc)
{
	BN_Assign(pJmp->X, pAp->X, pEc->BNWordLen);
	BN_Assign(pJmp->Y, pAp->Y, pEc->BNWordLen);
	BN_Reset(pJmp->Z, pEc->BNWordLen);
	pJmp->Z[0] = LSBOfWord;
	BN_Assign(pJmp->aZ4, pEc->EC_a, pEc->BNWordLen);
}

/***********************************************************************
	����:��Jacobian�����ת����Affine��
	����:
		pJp::��Բ��������Jacobian�����ʾ�ĵ�
		pEc:��Բ���� * �������ݽṹ
	���:
		pAp:��Բ��������Affine�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/
void ECP_JToA(pA_Point pAp, pJ_Point pJp, pEC pEc)
{
	/***************************/
	unsigned int bn_tmp[ECCBNWordLen];
	/***************************/

	BN_Reset(bn_tmp, ECCBNWordLen);
	BN_ModMul_Stand(bn_tmp, pJp->Z, pJp->Z, pEc->EC_P, pEc->BNWordLen);//tmp = Z ^ 2
	BN_ModMul_Stand(bn_tmp, bn_tmp, pJp->Z, pEc->EC_P, pEc->BNWordLen);//tmp = Z ^ 3
	BN_GetInv(bn_tmp, bn_tmp, pEc->EC_P, pEc->BNWordLen);//tmp = Z ^ -3	
	BN_ModMul_Stand(pAp->Y, pJp->Y, bn_tmp, pEc->EC_P, pEc->BNWordLen);//Y1 = Y * Z^-3
	BN_ModMul_Stand(bn_tmp, bn_tmp, pJp->Z, pEc->EC_P, pEc->BNWordLen);//tmp = Z^-2
	BN_ModMul_Stand(pAp->X, pJp->X, bn_tmp, pEc->EC_P, pEc->BNWordLen);//X1 = X * Z ^ -2
}

/***********************************************************************
	����:��JacobianM�����ת����Affine��
	����:
		pJmp::��Բ��������JacobianM�����ʾ�ĵ�
		pEc:��Բ���� * �������ݽṹ
	���:
		pAp:��Բ��������Affine�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/
void ECP_JmToA(pA_Point pAp, pJm_Point pJmp, pEC pEc)
{
	/***************************/
	unsigned int bn_tmp[ECCBNWordLen];
	/***************************/

	BN_Reset(bn_tmp, ECCBNWordLen);
	BN_ModMul_Stand(bn_tmp, pJmp->Z, pJmp->Z, pEc->EC_P, pEc->BNWordLen);//tmp = Z ^ 2
	BN_ModMul_Stand(bn_tmp, bn_tmp, pJmp->Z, pEc->EC_P, pEc->BNWordLen);//tmp = Z ^ 3
	BN_GetInv(bn_tmp, bn_tmp, pEc->EC_P, pEc->BNWordLen);//tmp = Z ^ -3	
	BN_ModMul_Stand(pAp->Y, pJmp->Y, bn_tmp, pEc->EC_P, pEc->BNWordLen);//Y1 = Y * Z^-3
	BN_ModMul_Stand(bn_tmp, bn_tmp, pJmp->Z, pEc->EC_P, pEc->BNWordLen);//tmp = Z^-2
	BN_ModMul_Stand(pAp->X, pJmp->X, bn_tmp, pEc->EC_P, pEc->BNWordLen);//X1 = X * Z ^ -2
}

/***********************************************************************
	����:�жϵ�A�Ƿ���������
	����:
		pAp_A:��Բ��������Affine�����ʾ�ĵ�A
		pEc:��Բ���� * �������ݽṹ
	���:
		��
	 * ����ֵ:
		0:����������
		1:��������
***********************************************************************/
int ECP_IsOnCurve(pA_Point pAp_A, pEC pEc)
{
	/************************/
	int iBNWordLen = 0;
	unsigned int bn_tmp1[ECCBNWordLen];
	unsigned int bn_tmp2[ECCBNWordLen];
	/************************/

	memset(bn_tmp1, 0 ,sizeof(bn_tmp1));
	memset(bn_tmp2, 0 ,sizeof(bn_tmp2));
	iBNWordLen = pEc->BNWordLen;
	iBNWordLen = BN_GetWordLen(pEc->EC_P, iBNWordLen);
	BN_ModMul_Stand(bn_tmp1, pAp_A->X, pAp_A->X, pEc->EC_P, iBNWordLen);//tmp1 = X ^ 2 mod p
	BN_ModMul_Stand(bn_tmp1, bn_tmp1, pAp_A->X, pEc->EC_P, iBNWordLen);//tmp1 = X ^ 3 mod p
	BN_ModMul_Stand(bn_tmp2, pAp_A->X, pEc->EC_a, pEc->EC_P, iBNWordLen);//tmp2 = a * X mod p
	BN_ModAdd(bn_tmp1, bn_tmp1, bn_tmp2, pEc->EC_P, iBNWordLen);//tmp1 = X ^ 3 + a * X mod p
	BN_ModAdd(bn_tmp1, bn_tmp1, pEc->EC_b, pEc->EC_P, iBNWordLen);//tmp1 = X ^ 3 + a * X  + b mod p 
	BN_ModMul_Stand(bn_tmp2, pAp_A->Y, pAp_A->Y, pEc->EC_P, iBNWordLen);//tmp2 = Y ^ 2 mod p
	if (BN_JE(bn_tmp1, bn_tmp2, iBNWordLen) == 0)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}
/***********************************************************************
	����:��Բ���ߵĵ������,Ap_Sum = Ap_A + Ap_B
	����:
		pAp_A::��Բ��������Affine�����ʾ�ĵ�A
		pAp_B::��Բ��������Affine�����ʾ�ĵ�B
		pEc:��Բ���� * �������ݽṹ
	���:
		pAp_Sum:��ӽ��,��Affine�����ʾ�ĵ�
	 * ����ֵ:
		��
	ע:pAp_Sum������pAp_A��ͬ����������pAp_B��ͬ
***********************************************************************/
/*
void ECP_AAddAToA(pA_Point pAp_Sum, pA_Point pAp_A, pA_Point pAp_B, pEC pEc)
{
	unsigned int bn_tmp1[ECCBNWordLen];
	unsigned int bn_tmp2[ECCBNWordLen];
	unsigned int bn_tmp3[ECCBNWordLen];
	int iBNWordLen = 0;

	BN_Reset(bn_tmp1, ECCBNWordLen);
	BN_Reset(bn_tmp2, ECCBNWordLen);
	BN_Reset(bn_tmp3, ECCBNWordLen);

	iBNWordLen = pEc->BNWordLen;
	BN_ModSub(bn_tmp1, pAp_A->X, pAp_B->X, pEc->EC_P, iBNWordLen);//tmp1 = X1 - X2
	BN_GetInv(bn_tmp1, bn_tmp1, pEc->EC_P, iBNWordLen);//tmp1 = (X1-X2)^-1
	BN_ModSub(bn_tmp2, pAp_A->Y, pAp_B->Y, pEc->EC_P, iBNWordLen);//tmp2 = Y1 - Y2
	BN_ModMul_Stand(bn_tmp3, bn_tmp2, bn_tmp1, pEc->EC_P, iBNWordLen);//tmp3 =(Y1 - Y2)*(X1-X2)^-1
	BN_ModMul_Stand(bn_tmp1, bn_tmp3, bn_tmp3, pEc->EC_P, iBNWordLen);//tmp1 = S^2
	BN_ModSub(pAp_Sum->X, bn_tmp1, pAp_A->X, pEc->EC_P, iBNWordLen);//X3 = S^2 - X1
	BN_ModSub(pAp_Sum->X, pAp_Sum->X, pAp_B->X, pEc->EC_P, iBNWordLen);//X3 = S^2 -X1 - X2
	BN_ModSub(bn_tmp1, pAp_B->X, pAp_Sum->X, pEc->EC_P, iBNWordLen);//tmp1 = X2 - X3
	BN_ModMul_Stand(bn_tmp1, bn_tmp1, bn_tmp3, pEc->EC_P, iBNWordLen);//tmp1 = S*(X2 - X3)
	BN_ModSub(pAp_Sum->Y, bn_tmp1, pAp_B->Y, pEc->EC_P, iBNWordLen);//Y3 = S*(X2 - X3) - Y2
}
*/

/***********************************************************************
	����:��Բ���ߵĵ������,Jm_Sum = Jp + Ap
	����:
		pJp:��Բ��������Jacobian�����ʾ�ĵ�A
		pAp:��Բ��������Affine�����ʾ�ĵ�B
		pEc:��Բ���� * �������ݽṹ
	���:
		pJm_Sum:��ӽ��,��JacobianM�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/

void ECP_JAddAToJm(pJm_Point pJm_Sum, pJ_Point pJp, pA_Point pAp, pEC pEc)
{
	unsigned int bn_tmp1[ECCBNWordLen];
	unsigned int bn_tmp2[ECCBNWordLen];
	unsigned int bn_tmp3[ECCBNWordLen];
	int iBNWordLen = 0;

	BN_Reset(bn_tmp1, ECCBNWordLen);
	BN_Reset(bn_tmp2, ECCBNWordLen);
	BN_Reset(bn_tmp3, ECCBNWordLen);

	iBNWordLen = pEc->BNWordLen;
	BN_ModMul_Stand(bn_tmp3, pJp->Z, pJp->Z, pEc->EC_P, iBNWordLen);//tmp3 = Z1^2
	BN_ModMul_Stand(bn_tmp2, bn_tmp3, pJp->Z, pEc->EC_P, iBNWordLen);//tmp2 = Z1^3
	BN_ModMul_Stand(bn_tmp3, bn_tmp3, pAp->X, pEc->EC_P, iBNWordLen);//tmp3 = X2 * Z1^2 = A
	BN_ModSub(bn_tmp3, bn_tmp3, pJp->X, pEc->EC_P, iBNWordLen);//tmp3 = A - X1 = C
	BN_ModMul_Stand(pJm_Sum->Z, pJp->Z, bn_tmp3, pEc->EC_P, iBNWordLen);//Z3 = Z1 * C
	BN_ModMul_Stand(bn_tmp2, bn_tmp2, pAp->Y, pEc->EC_P, iBNWordLen);//tmp2 = Y2 * Z1 ^ 3 = B
	BN_ModSub(bn_tmp2, bn_tmp2, pJp->Y, pEc->EC_P, iBNWordLen);//tmp2 = B - Y1 = D
	BN_ModMul_Stand(bn_tmp1, bn_tmp3, bn_tmp3, pEc->EC_P, iBNWordLen);//tmp1 = C ^ 2
	BN_ModMul_Stand(bn_tmp3, bn_tmp3, bn_tmp1, pEc->EC_P, iBNWordLen);//tmp3 = C ^ 3
	BN_ModMul_Stand(bn_tmp1, bn_tmp1, pJp->X, pEc->EC_P, iBNWordLen);//tmp1 = X1 * C^2
	BN_ModAdd(pJm_Sum->X, bn_tmp1, bn_tmp1, pEc->EC_P, iBNWordLen);//X3 = 2 X1 * C^2
	BN_ModAdd(pJm_Sum->X, pJm_Sum->X, bn_tmp3, pEc->EC_P, iBNWordLen);//X3 = C ^ 3 + 2 X1 * C^2
	BN_ModMul_Stand(pJm_Sum->Y, pJp->Y, bn_tmp3, pEc->EC_P, iBNWordLen);//Y3 = Y1 * C^3
	BN_ModMul_Stand(bn_tmp3, bn_tmp2, bn_tmp2, pEc->EC_P, iBNWordLen);//tmp3 = D^2
	BN_ModSub(pJm_Sum->X, bn_tmp3, pJm_Sum->X, pEc->EC_P, iBNWordLen);//X3 = D ^ 2 - ( C ^ 3 + 2 X1 * C^2)
	BN_ModSub(bn_tmp1, bn_tmp1, pJm_Sum->X, pEc->EC_P, iBNWordLen);//tmp1 = X1 * C ^ 2 - X3
	BN_ModMul_Stand(bn_tmp1, bn_tmp1, bn_tmp2, pEc->EC_P, iBNWordLen);//tmp1 = D * (X1 * C ^ 2 - X3)
	BN_ModSub(pJm_Sum->Y, bn_tmp1, pJm_Sum->Y, pEc->EC_P, iBNWordLen);//Y3 = D * (X1 * C ^ 2 - X3) - Y1 * C ^ 3
	BN_ModMul_Stand(bn_tmp1, pJm_Sum->Z, pJm_Sum->Z, pEc->EC_P, iBNWordLen);//tmp1 = Z3 ^ 2
	BN_ModMul_Stand(bn_tmp1, bn_tmp1, bn_tmp1, pEc->EC_P, iBNWordLen);//tmp1 = Z3 ^ 4
	BN_ModMul_Stand(pJm_Sum->aZ4, bn_tmp1, pEc->EC_a, pEc->EC_P, iBNWordLen);//aZ4 = a Z3 ^ 4
}


/***********************************************************************
	����:��Բ���ߵĵ������,J_Sum = Jp + Ap
	����:
		pJp:��Բ��������Jacobian�����ʾ�ĵ�A
		pAp:��Բ��������Affine�����ʾ�ĵ�B
		pEc:��Բ���� * �������ݽṹ
	���:
		pJ_Sum:��ӽ��,��Jacobian�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/
void ECP_JAddAToJ(pJ_Point pJ_Sum, pJ_Point pJp, pA_Point pAp, pEC pEc)
{
	/************************/
	unsigned int bn_tmp1[ECCBNWordLen];
	unsigned int bn_tmp2[ECCBNWordLen];
	unsigned int bn_tmp3[ECCBNWordLen];
	int iBNWordLen = 0;
	/************************/

	BN_Reset(bn_tmp1, ECCBNWordLen);
	BN_Reset(bn_tmp2, ECCBNWordLen);
	BN_Reset(bn_tmp3, ECCBNWordLen);

	iBNWordLen = pEc->BNWordLen;
	BN_ModMul_Stand(bn_tmp3, pJp->Z, pJp->Z, pEc->EC_P, iBNWordLen);//tmp3 = Z1^2
	BN_ModMul_Stand(bn_tmp2, bn_tmp3, pJp->Z, pEc->EC_P, iBNWordLen);//tmp2 = Z1^3
	BN_ModMul_Stand(bn_tmp3, bn_tmp3, pAp->X, pEc->EC_P, iBNWordLen);//tmp3 = X2 * Z1^2 = A
	BN_ModSub(bn_tmp3, bn_tmp3, pJp->X, pEc->EC_P, iBNWordLen);//tmp3 = A - X1 = C
	BN_ModMul_Stand(pJ_Sum->Z, pJp->Z, bn_tmp3, pEc->EC_P, iBNWordLen);//Z3 = Z1 * C
	BN_ModMul_Stand(bn_tmp2, bn_tmp2, pAp->Y, pEc->EC_P, iBNWordLen);//tmp2 = Y2 * Z1 ^ 3 = B
	BN_ModSub(bn_tmp2, bn_tmp2, pJp->Y, pEc->EC_P, iBNWordLen);//tmp2 = B - Y1 = D
	BN_ModMul_Stand(bn_tmp1, bn_tmp3, bn_tmp3, pEc->EC_P, iBNWordLen);//tmp1 = C ^ 2
	BN_ModMul_Stand(bn_tmp3, bn_tmp3, bn_tmp1, pEc->EC_P, iBNWordLen);//tmp3 = C ^ 3
	BN_ModMul_Stand(bn_tmp1, bn_tmp1, pJp->X, pEc->EC_P, iBNWordLen);//tmp1 = X1 * C^2
	BN_ModAdd(pJ_Sum->X, bn_tmp1, bn_tmp1, pEc->EC_P, iBNWordLen);//X3 = 2 X1 * C^2
	BN_ModAdd(pJ_Sum->X, pJ_Sum->X, bn_tmp3, pEc->EC_P, iBNWordLen);//X3 = C ^ 3 + 2 X1 * C^2
	BN_ModMul_Stand(pJ_Sum->Y, pJp->Y, bn_tmp3, pEc->EC_P, iBNWordLen);//Y3 = Y1 * C^3
	BN_ModMul_Stand(bn_tmp3, bn_tmp2, bn_tmp2, pEc->EC_P, iBNWordLen);//tmp3 = D^2
	BN_ModSub(pJ_Sum->X, bn_tmp3, pJ_Sum->X, pEc->EC_P, iBNWordLen);//X3 = D ^ 2 - ( C ^ 3 + 2 X1 * C^2)
	BN_ModSub(bn_tmp1, bn_tmp1, pJ_Sum->X, pEc->EC_P, iBNWordLen);//tmp1 = X1 * C ^ 2 - X3
	BN_ModMul_Stand(bn_tmp1, bn_tmp1, bn_tmp2, pEc->EC_P, iBNWordLen);//tmp1 = D * (X1 * C ^ 2 - X3)
	BN_ModSub(pJ_Sum->Y, bn_tmp1, pJ_Sum->Y, pEc->EC_P, iBNWordLen);//Y3 = D * (X1 * C ^ 2 - X3) - Y1 * C ^ 3
}

/***********************************************************************
	����:��Բ���ߵĵ������,Jm_Sum = Jp - Ap
	����:
		pJp:��Բ��������Jacobian�����ʾ�ĵ�A
		pAp:��Բ��������Affine�����ʾ�ĵ�B
		pEc:��Բ���� * �������ݽṹ
	���:
		pJm_Sum:��ӽ��,��JacobianM�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/
void ECP_JSubAToJm(pJm_Point pJm_Sum, pJ_Point pJp, pA_Point pAp, pEC pEc)
{
	/************************/
	A_Point A_Point_tmp;
	int iBNWordLen = 0;
	/************************/

	iBNWordLen = pEc->BNWordLen;
	BN_Reset(A_Point_tmp.X, ECCBNWordLen);
	BN_Reset(A_Point_tmp.Y, ECCBNWordLen);
	BN_Assign(A_Point_tmp.X, pAp->X, iBNWordLen);
	BN_ModSub(A_Point_tmp.Y, pEc->EC_P, pAp->Y, pEc->EC_P, iBNWordLen);
	ECP_JAddAToJm(pJm_Sum, pJp, &A_Point_tmp, pEc);
}

/***********************************************************************
	����:��Բ���ߵĵ������,J_Sum = Jp - Ap
	����:
		pJp:��Բ��������Jacobian�����ʾ�ĵ�A
		pAp:��Բ��������Affine�����ʾ�ĵ�B
		pEc:��Բ���� * �������ݽṹ
	���:
		pJ_Sum:��ӽ��,��Jacobian�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/
/*
void ECP_JSubAToJ(pJ_Point pJ_Sum, pJ_Point pJp, pA_Point pAp, pEC pEc)
{
	A_Point A_Point_tmp;
	int iBNWordLen = 0;

	iBNWordLen = pEc->BNWordLen;
	BN_Reset(A_Point_tmp.X, ECCBNWordLen);
	BN_Reset(A_Point_tmp.Y, ECCBNWordLen);
	BN_Assign(A_Point_tmp.X, pAp->X, iBNWordLen);
	BN_ModSub(A_Point_tmp.Y, pEc->EC_P, pAp->Y, pEc->EC_P, iBNWordLen);
	ECP_JAddAToJ(pJ_Sum, pJp, &A_Point_tmp, pEc);
}
*/

/***********************************************************************
	����:��Բ���ߵĵ㱶����,Jp = 2Jm
	����:
		pJm:��Բ��������JacobianM�����ʾ�ĵ�
		pEc:��Բ���� * �������ݽṹ
	���:
		pJp:�㱶���,��Jacobian�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/
void ECP_DoubleJmToJ(pJ_Point pJp, pJm_Point pJm, pEC pEc)
{
	/************************/
	unsigned int bn_tmp1[ECCBNWordLen];
	unsigned int bn_tmp2[ECCBNWordLen];
	unsigned int bn_tmp3[ECCBNWordLen];
	unsigned int bn_tmp4[ECCBNWordLen];
	unsigned int bn_tmp5[ECCBNWordLen];
	int iBNWordLen = 0;
	/************************/

	BN_Reset(bn_tmp1, ECCBNWordLen);
	BN_Reset(bn_tmp2, ECCBNWordLen);
	BN_Reset(bn_tmp3, ECCBNWordLen);
	BN_Reset(bn_tmp4, ECCBNWordLen);
	BN_Reset(bn_tmp5, ECCBNWordLen);

	iBNWordLen = pEc->BNWordLen;
	BN_ModMul_Stand(bn_tmp1, pJm->Y, pJm->Y, pEc->EC_P, iBNWordLen);//tmp1 = Y1 ^ 2
	BN_ModMul_Stand(bn_tmp2, pJm->X, bn_tmp1, pEc->EC_P, iBNWordLen);//tmp2 = X1 * Y1 ^ 2
	BN_ModAdd(bn_tmp2, bn_tmp2, bn_tmp2, pEc->EC_P, iBNWordLen);//tmp2 = 2 X1 * Y1 ^ 2
	BN_ModAdd(bn_tmp2, bn_tmp2, bn_tmp2, pEc->EC_P, iBNWordLen);//tmp2 = 4 X1 * Y1 ^ 2 = S
	BN_ModMul_Stand(bn_tmp3, bn_tmp1, bn_tmp1, pEc->EC_P, iBNWordLen);//tmp3 = Y1 ^ 4
	BN_ModAdd(bn_tmp3, bn_tmp3, bn_tmp3, pEc->EC_P, iBNWordLen);//tmp3 = 2 Y1 ^ 4
	BN_ModAdd(bn_tmp3, bn_tmp3, bn_tmp3, pEc->EC_P, iBNWordLen);//tmp3 = 4 Y1 ^ 4
	BN_ModAdd(bn_tmp3, bn_tmp3, bn_tmp3, pEc->EC_P, iBNWordLen);//tmp3 = 8 Y1 ^ 4 = U
	BN_ModMul_Stand(bn_tmp4, pJm->X, pJm->X, pEc->EC_P, iBNWordLen);//tmp4 = X1 ^ 2
	BN_ModAdd(bn_tmp5, bn_tmp4, bn_tmp4, pEc->EC_P, iBNWordLen);//tmp 5 = 2 X1 ^ 2
	BN_ModAdd(bn_tmp5, bn_tmp5, bn_tmp4, pEc->EC_P, iBNWordLen);//tmp5 = 3 X1 ^ 2
	BN_ModAdd(bn_tmp5, bn_tmp5, pJm->aZ4, pEc->EC_P, iBNWordLen);//tmp5 = 3 X1 ^ 2 + aZ1 ^ 4 = M
	BN_ModMul_Stand(bn_tmp1, bn_tmp5, bn_tmp5, pEc->EC_P, iBNWordLen);//tmp1 = M ^ 2
	BN_ModSub(pJp->X, bn_tmp1, bn_tmp2, pEc->EC_P, iBNWordLen);//X3 = M ^ 2 - S
	BN_ModSub(pJp->X, pJp->X, bn_tmp2, pEc->EC_P, iBNWordLen);//X3 = M ^ 2 - 2 S = T
	BN_ModSub(bn_tmp1, bn_tmp2, pJp->X, pEc->EC_P, iBNWordLen);//tmp1 = S - T
	BN_ModMul_Stand(bn_tmp1, bn_tmp1, bn_tmp5, pEc->EC_P, iBNWordLen);//tmp1 = M * (S  - T)
	BN_ModSub(pJp->Y, bn_tmp1, bn_tmp3, pEc->EC_P, iBNWordLen);//Y3 = M * (S - T) - U
	BN_ModMul_Stand(bn_tmp4, pJm->Y, pJm->Z, pEc->EC_P, iBNWordLen);//tmp4 = Y1 * Z1
	BN_ModAdd(pJp->Z, bn_tmp4, bn_tmp4, pEc->EC_P, iBNWordLen);//Z3 = 2 Y1 * Z1
}

/***********************************************************************
	����:��Բ���ߵĵ㱶����,Jp_Result = 2Jp
	����:
		pJp:��Բ��������Jacobian�����ʾ�ĵ�
		pEc:��Բ���� * �������ݽṹ
	���:
		pJp_Result:�㱶���,��Jacobian�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/
void ECP_DoubleJToJ(pJ_Point pJp_Result, pJ_Point pJp, pEC pEc)
{
	/************************/
	unsigned int bn_tmp1[ECCBNWordLen];
	unsigned int bn_tmp2[ECCBNWordLen];
	unsigned int bn_tmp3[ECCBNWordLen];
	unsigned int bn_tmp4[ECCBNWordLen];
	unsigned int bn_tmp5[ECCBNWordLen];
	int iBNWordLen = 0;
	/************************/

	BN_Reset(bn_tmp1, ECCBNWordLen);
	BN_Reset(bn_tmp2, ECCBNWordLen);
	BN_Reset(bn_tmp3, ECCBNWordLen);
	BN_Reset(bn_tmp4, ECCBNWordLen);
	BN_Reset(bn_tmp5, ECCBNWordLen);

	iBNWordLen = pEc->BNWordLen;
	BN_ModMul_Stand(bn_tmp4, pJp->Y, pJp->Y, pEc->EC_P, iBNWordLen);//tmp4 = Y1 ^ 2
	BN_ModMul_Stand(bn_tmp1, bn_tmp4, pJp->X, pEc->EC_P, iBNWordLen);//tmp1 = X1 * Y1 ^ 2
	BN_ModAdd(bn_tmp1, bn_tmp1, bn_tmp1, pEc->EC_P, iBNWordLen);//tmp1 = 2 X1 * Y1 ^ 2
	BN_ModAdd(bn_tmp1, bn_tmp1, bn_tmp1, pEc->EC_P, iBNWordLen);//tmp1 = 4 X1 * Y1 ^ 2 = A
	BN_ModMul_Stand(bn_tmp2, bn_tmp4, bn_tmp4, pEc->EC_P, iBNWordLen);//tmp2 = Y1 ^ 4
	BN_ModAdd(bn_tmp2, bn_tmp2, bn_tmp2, pEc->EC_P, iBNWordLen);//tmp2 = 2 Y1 ^ 4
	BN_ModAdd(bn_tmp2, bn_tmp2, bn_tmp2, pEc->EC_P, iBNWordLen);//tmp2 = 4 Y1 ^ 4
	BN_ModAdd(bn_tmp2, bn_tmp2, bn_tmp2, pEc->EC_P, iBNWordLen);//tmp2 = 8 Y1 ^ 4 = B
	BN_ModMul_Stand(bn_tmp4, pJp->Z, pJp->Z, pEc->EC_P, iBNWordLen);//tmp4 = Z1 ^ 2
	BN_ModMul_Stand(bn_tmp4, bn_tmp4, bn_tmp4, pEc->EC_P, iBNWordLen);//tmp4 = Z1 ^ 4
	BN_ModMul_Stand(bn_tmp4, bn_tmp4, pEc->EC_a, pEc->EC_P, iBNWordLen);//tmp4 = a Z1 ^ 4
	BN_ModMul_Stand(bn_tmp3, pJp->X, pJp->X, pEc->EC_P, iBNWordLen);//tmp3 = X1 ^ 2
	BN_ModAdd(bn_tmp5, bn_tmp3, bn_tmp3, pEc->EC_P, iBNWordLen);//tmp5 = 2 X1 ^ 2
	BN_ModAdd(bn_tmp3, bn_tmp3, bn_tmp5, pEc->EC_P, iBNWordLen);//tmp3 = 3 X1 ^ 2
	BN_ModAdd(bn_tmp3, bn_tmp3, bn_tmp4, pEc->EC_P, iBNWordLen);//tmp3 = 3 X1 ^ 2 + aZ1 ^ 4 = C
	BN_ModMul_Stand(pJp_Result->X, bn_tmp3, bn_tmp3, pEc->EC_P, iBNWordLen);//X3 = C ^ 2
	BN_ModSub(pJp_Result->X, pJp_Result->X, bn_tmp1, pEc->EC_P, iBNWordLen);//X3 = C ^ 2 - A
	BN_ModSub(pJp_Result->X, pJp_Result->X, bn_tmp1, pEc->EC_P, iBNWordLen);//X3 = C ^ 2 - 2A
	BN_ModSub(bn_tmp1, bn_tmp1, pJp_Result->X, pEc->EC_P, iBNWordLen);//tmp1 = A - X3
	BN_ModMul_Stand(bn_tmp1, bn_tmp1, bn_tmp3, pEc->EC_P, iBNWordLen);//tmp1 = C * (A - X3)
	BN_ModMul_Stand(pJp_Result->Z, pJp->Y, pJp->Z, pEc->EC_P, iBNWordLen);//Z3 = Y1 * Z1
	BN_ModAdd(pJp_Result->Z, pJp_Result->Z, pJp_Result->Z, pEc->EC_P, iBNWordLen);//Z3 = 2 Y1 * Z1
	BN_ModSub(pJp_Result->Y, bn_tmp1, bn_tmp2, pEc->EC_P, iBNWordLen);//Y3 = C * (A - X3) - B
}

/***********************************************************************
	����:��Բ���ߵĵ㱶����,Jmp_Result = 2Jmp
	����:
		pJmp:��Բ��������JacobianM�����ʾ�ĵ�
		pEc:��Բ���� * �������ݽṹ
	���:
		pJmp_Result:�㱶���,��JacobianM�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/
void ECP_DoubleJmToJm(pJm_Point pJmp_Result, pJm_Point pJmp, pEC pEc)
{
	/************************/
	unsigned int bn_tmp1[ECCBNWordLen];
	unsigned int bn_tmp2[ECCBNWordLen];
	unsigned int bn_tmp3[ECCBNWordLen];
	unsigned int bn_tmp4[ECCBNWordLen];
	unsigned int bn_tmp5[ECCBNWordLen];
	int iBNWordLen = 0;
	/************************/

	BN_Reset(bn_tmp1, ECCBNWordLen);
	BN_Reset(bn_tmp2, ECCBNWordLen);
	BN_Reset(bn_tmp3, ECCBNWordLen);
	BN_Reset(bn_tmp4, ECCBNWordLen);
	BN_Reset(bn_tmp5, ECCBNWordLen);

	iBNWordLen = pEc->BNWordLen;
	BN_ModMul_Stand(bn_tmp1, pJmp->Y, pJmp->Y, pEc->EC_P, iBNWordLen);//tmp1 = Y1 ^ 2
	BN_ModMul_Stand(bn_tmp2, bn_tmp1, pJmp->X, pEc->EC_P, iBNWordLen);//tmp2 = X1 * Y1 ^ 2
	BN_ModAdd(bn_tmp2, bn_tmp2, bn_tmp2, pEc->EC_P, iBNWordLen);//tmp2 = 2  X1 * Y1 ^ 2
	BN_ModAdd(bn_tmp2, bn_tmp2, bn_tmp2, pEc->EC_P, iBNWordLen);//tmp2 = 4  X1 * Y1 ^ 2
	BN_ModMul_Stand(bn_tmp3, bn_tmp1, bn_tmp1, pEc->EC_P, iBNWordLen);//tmp3 = Y1 ^ 4
	BN_ModAdd(bn_tmp3, bn_tmp3, bn_tmp3, pEc->EC_P, iBNWordLen);//tmp3 = 2 Y1 ^ 4
	BN_ModAdd(bn_tmp3, bn_tmp3, bn_tmp3, pEc->EC_P, iBNWordLen);//tmp3 = 4 Y1 ^ 4
	BN_ModAdd(bn_tmp3, bn_tmp3, bn_tmp3, pEc->EC_P, iBNWordLen);//tmp3 = 8 Y1 ^ 4
	BN_ModMul_Stand(bn_tmp4, pJmp->X, pJmp->X, pEc->EC_P, iBNWordLen);//tmp4 = X1 ^ 2
	BN_ModAdd(bn_tmp5, bn_tmp4, bn_tmp4, pEc->EC_P, iBNWordLen);//tmp5 = 2 X1 ^ 2
	BN_ModAdd(bn_tmp5, bn_tmp5, bn_tmp4, pEc->EC_P, iBNWordLen);//tmp5 = 3 X1 ^ 2
	BN_ModAdd(bn_tmp5, bn_tmp5, pJmp->aZ4, pEc->EC_P, iBNWordLen);//tmp5 = 3 X1 ^ 2 + a Z1 ^ 4 = M
	BN_ModMul_Stand(bn_tmp1, bn_tmp5, bn_tmp5, pEc->EC_P, iBNWordLen);//tmp1 = (3 X1 ^ 2 + a Z1 ^ 4) ^ 2 = M ^ 2
	BN_ModSub(pJmp_Result->X, bn_tmp1, bn_tmp2, pEc->EC_P, iBNWordLen);//X3 = M ^ 2 - S
	BN_ModSub(pJmp_Result->X, pJmp_Result->X, bn_tmp2, pEc->EC_P, iBNWordLen);//X3 = M ^ 2 - 2S = T
	BN_ModSub(bn_tmp1, bn_tmp2, pJmp_Result->X, pEc->EC_P, iBNWordLen);//tmp1 = S - T
	BN_ModMul_Stand(bn_tmp1, bn_tmp1, bn_tmp5, pEc->EC_P, iBNWordLen);//tmp1 = M * (S - T)
	BN_ModMul_Stand(bn_tmp4, pJmp->Y, pJmp->Z, pEc->EC_P, iBNWordLen);//tmp4 = Y1 * Z1
	BN_ModAdd(pJmp_Result->Z, bn_tmp4, bn_tmp4, pEc->EC_P, iBNWordLen);//Z3 = 2 Y1 * Z1
	BN_ModSub(pJmp_Result->Y, bn_tmp1, bn_tmp3, pEc->EC_P, iBNWordLen);//Y3 = M * (S -T ) - U
	BN_ModMul_Stand(bn_tmp1, bn_tmp3, pJmp->aZ4, pEc->EC_P, iBNWordLen);//tmp1 = U * (a * Z1 ^ 4)
	BN_ModAdd(pJmp_Result->aZ4, bn_tmp1, bn_tmp1, pEc->EC_P, iBNWordLen);//aZ3 ^ 4 = 2 U * (a * Z1 ^ 4)
}

/***********************************************************************
	����:Ϊ����KP���е�Ԥ���㣬����P, 3P��5P��������2^(w-1) - 1
	����:
		pAp:��Բ��������Affine�����ʾ�ĵ�
		w:NAF�㷨���ڵĿ��
		pEc:��Բ���� * �������ݽṹ
	���:
		pJmp_Result:Ԥ����������Բ������Affine�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/
void ECP_KP_PreCom(pA_Point  np, pA_Point pAp,  pEC pEc)
{
	/**************************/
	int i = 0;
	int j = 0;
	J_Point Jp_tmp1;
	J_Point Jp_tmp2;
	/**************************/

	BN_Reset(Jp_tmp1.X, ECCBNWordLen);
	BN_Reset(Jp_tmp1.Y, ECCBNWordLen);
	BN_Reset(Jp_tmp1.Z, ECCBNWordLen);
	BN_Reset(Jp_tmp2.X, ECCBNWordLen);
	BN_Reset(Jp_tmp2.Y, ECCBNWordLen);
	BN_Reset(Jp_tmp2.Z, ECCBNWordLen);

	j = (1 << (NAF_W - 2)) - 1;
	BN_Assign(np[0].X, pAp->X, pEc->BNWordLen);
	BN_Assign(np[0].Y, pAp->Y, pEc->BNWordLen);
	ECP_AToJ(&Jp_tmp1, pAp, pEc);
	ECP_DoubleJToJ(&Jp_tmp1, &Jp_tmp1, pEc);
	for (i = 1; i <= j; i++)
	{
		ECP_JAddAToJ(&Jp_tmp2, &Jp_tmp1, &np[i - 1], pEc);
		ECP_JToA(&np[i], &Jp_tmp2, pEc);
	}
}

/***********************************************************************
	����:������Բ�����ϵĵ��KP = K * Ap
	����:
		pAp:��Բ��������Affine�����ʾ�ĵ�
		np:Ԥ������
		pEc:��Բ���� * �������ݽṹ
		K:������
	���:
		KP:�����������Բ������Affine�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/
void ECP_KP(pA_Point KP, pA_Point pAp, unsigned int *K,  pA_Point np,  pEC pEc)
{
	/******************************/
	NAF nafk;
	int iBNWordLen = 0;
	int index = 0;
	int i = 0;
	int flag = 0;
	Jm_Point tempKP;
	J_Point Jp_tmp;
	/******************************/

	memset(&nafk, 0, sizeof(nafk));
	memset(&tempKP, 0, sizeof(tempKP));
	memset(&Jp_tmp, 0, sizeof(Jp_tmp));
	iBNWordLen = pEc->BNWordLen;
	BN_To_W_NAF(&nafk, K, iBNWordLen);//ת��ΪNAF����

	index = (nafk.k[nafk.count - 1] - 1) >> 1;
	BN_Assign(tempKP.X, np[index].X, iBNWordLen);//tempKP = k[highest] * P, ����ΪJm
	BN_Assign(tempKP.Y, np[index].Y, iBNWordLen);
	tempKP.Z[0] = LSBOfWord;
	BN_Assign(tempKP.aZ4, pEc->EC_a, iBNWordLen);

	for (i = nafk.count - 2; i > 0; i--)
	{
		if (flag == 0)
		{
			if (nafk.k[i - 1] == 0)
			{
				ECP_DoubleJmToJm(&tempKP, &tempKP, pEc);
			}
			else
			{
				ECP_DoubleJmToJ(&Jp_tmp, &tempKP, pEc);
				flag = 1;
			}
		}
		else
		{
			ECP_DoubleJToJ(&Jp_tmp, &Jp_tmp, pEc);
		}

		if (nafk.k[i] != 0)
		{
			if (nafk.k[i] > 0)
			{
				index = (nafk.k[i] - 1) >> 1;
				ECP_JAddAToJm(&tempKP, &Jp_tmp, &np[index], pEc);
			}
			else
			{
				index = ((0 - nafk.k[i]) - 1) >> 1;
				ECP_JSubAToJm(&tempKP, &Jp_tmp, &np[index], pEc);
			}
			flag = 0;
		}
	}

	if (flag == 0)//nafk.k[0] == 0
	{
		ECP_DoubleJmToJ(&Jp_tmp, &tempKP, pEc);
		ECP_JToA(KP, &Jp_tmp, pEc);
	}
	else//nafk.k[0] != 0
	{
		ECP_DoubleJToJ(&Jp_tmp, &Jp_tmp, pEc);
		if (nafk.k[i] > 0)
		{
			index = (nafk.k[i] - 1) >> 1;
			ECP_JAddAToJm(&tempKP, &Jp_tmp, &np[index], pEc);
		}
		else
		{
			index = ((0 - nafk.k[i]) - 1) >> 1;
			ECP_JSubAToJm(&tempKP, &Jp_tmp, &np[index], pEc);
		}
		ECP_JmToA(KP, &tempKP, pEc);
	}
}

/***********************************************************************
 *	����:������Բ�����ϵĵ��KP = K * Ap_P + L * Ap_Q 
	����:
		pAp_P:��Բ��������Affine�����ʾ�ĵ�P
		K:������
		np:P���Ԥ������
		pAp_Q:��Բ��������Affine�����ʾ�ĵ�Q
		L:������
		np:Q���Ԥ������
		pEc:��Բ���� * �������ݽṹ
	���:
		KPLQ:�����������Բ������Affine�����ʾ�ĵ�
	 * ����ֵ:
		��
***********************************************************************/
void ECP_KPLQ(pA_Point KPLQ, pA_Point pAp_P, unsigned int *K, pA_Point np, pA_Point pAp_Q, unsigned int *L, pA_Point nq, pEC pEc)
{
	/******************************/
	NAF nafk;
	NAF nafl;
	int iBNWordLen = 0;
	int index = 0;
	int i = 0;
	int flag = 0;
	Jm_Point tempKPLQ;
	J_Point Jp_tmp;
	/******************************/

	memset(&nafk, 0, sizeof(nafk));
	memset(&nafl, 0, sizeof(nafl));
	memset(&tempKPLQ, 0, sizeof(tempKPLQ));
	memset(&Jp_tmp, 0, sizeof(Jp_tmp));
	iBNWordLen = pEc->BNWordLen;
	BN_To_W_NAF(&nafk, K, iBNWordLen);//ת��ΪNAF����
	BN_To_W_NAF(&nafl, L, iBNWordLen);//ת��ΪNAF����

	
	if (nafk.count > nafl.count)//k��NAF�����l��NAF���볤
	{
		index = (nafk.k[nafk.count - 1] - 1) >> 1;
		BN_Assign(tempKPLQ.X, np[index].X, iBNWordLen);//tempKPLQ = k[highest] * P, ����ΪJm
		BN_Assign(tempKPLQ.Y, np[index].Y, iBNWordLen);
		tempKPLQ.Z[0] = LSBOfWord;
		BN_Assign(tempKPLQ.aZ4, pEc->EC_a, iBNWordLen);
		i = nafk.count - 2;
	}
	else
	{
		if (nafk.count < nafl.count)//k��NAF�����l��NAF�����
		{
			index = (nafl.k[nafl.count - 1] - 1) >> 1;
			BN_Assign(tempKPLQ.X, nq[index].X, iBNWordLen);//tempKPLQ = L[highest] * Q, ����ΪJm
			BN_Assign(tempKPLQ.Y, nq[index].Y, iBNWordLen);
			tempKPLQ.Z[0] = LSBOfWord;
			BN_Assign(tempKPLQ.aZ4, pEc->EC_a, iBNWordLen);
			i = nafl.count - 2;
		}
		else//k��NAF������l��NAF������ͬ
		{
			index = (nafk.k[nafk.count - 1] - 1) >> 1;
			BN_Assign(Jp_tmp.X, np[index].X, iBNWordLen);
			BN_Assign(Jp_tmp.Y, np[index].Y, iBNWordLen);
			Jp_tmp.Z[0] = LSBOfWord;
			index = (nafl.k[nafl.count - 1] - 1) >> 1;
			ECP_JAddAToJm(&tempKPLQ, &Jp_tmp, &nq[index], pEc);//tempKPLQ = k[highest] * P + L[highest] * Q, ����ΪJm
			i = nafk.count - 2;
		}
	}

	for (; i >= 0; i--)
	{
		ECP_DoubleJmToJm(&tempKPLQ, &tempKPLQ, pEc);

		if (nafk.k[i] != 0)
		{
			BN_Assign(Jp_tmp.X, tempKPLQ.X, iBNWordLen);
			BN_Assign(Jp_tmp.Y, tempKPLQ.Y, iBNWordLen);
			BN_Assign(Jp_tmp.Z, tempKPLQ.Z, iBNWordLen);
			if (nafk.k[i] > 0)
			{
				index = (nafk.k[i] - 1) >> 1;
				ECP_JAddAToJm(&tempKPLQ, &Jp_tmp, &np[index], pEc);
			}
			else
			{
				index = ((0 - nafk.k[i]) - 1) >> 1;
				ECP_JSubAToJm(&tempKPLQ, &Jp_tmp, &np[index], pEc);
			}
		}

		if (nafl.k[i] != 0)
		{
			BN_Assign(Jp_tmp.X, tempKPLQ.X, iBNWordLen);
			BN_Assign(Jp_tmp.Y, tempKPLQ.Y, iBNWordLen);
			BN_Assign(Jp_tmp.Z, tempKPLQ.Z, iBNWordLen);
			if (nafl.k[i] > 0)
			{
				index = (nafl.k[i] - 1) >> 1;
				ECP_JAddAToJm(&tempKPLQ, &Jp_tmp, &nq[index], pEc);
			}
			else
			{
				index = ((0 - nafl.k[i]) - 1) >> 1;
				ECP_JSubAToJm(&tempKPLQ, &Jp_tmp, &nq[index], pEc);
			}
		}
	}
	ECP_JmToA(KPLQ, &tempKPLQ, pEc);
}


//SMS4?????
//????:Input???????,output???????,rk????
void SM4Operation(unsigned int *Input,unsigned int *Output,unsigned int *rk)
{
	unsigned int r,mid,x0,x1,x2,x3;
	x0 = Input[0];
	x1 = Input[1];
	x2 = Input[2];
	x3 = Input[3];

	for(r = 0;r < 32;r += 4)
	{
		mid = x1 ^ x2 ^ x3 ^ rk[r + 0];
		mid = ByteSub(mid);
		x0 ^= L1(mid);

		mid = x2^ x3^ x0^rk[r + 1];
		mid = ByteSub(mid);
		x1 ^= L1(mid);

		mid = x3^ x0^ x1^rk[r + 2];
		mid = ByteSub(mid);
		x2 ^= L1(mid);

		mid = x0 ^ x1 ^ x2 ^ rk[r + 3];
		mid = ByteSub(mid);
		x3 ^= L1(mid);

		
	}

	Output[0] = x3;
	Output[1] = x2;
	Output[2] = x1;
	Output[3] = x0;
}
//SMS4???????
//????:Key?????,rk????,CryptFlag??????
void SM4KeyExt(unsigned int *Key,unsigned int *rk,unsigned char CryptFlag)
{
	unsigned int r,mid,x0,x1,x2,x3;

	x0 = Key[0];
	x1 = Key[1];
	x2 = Key[2];
	x3 = Key[3];

	x0 ^= 0xa3b1bac6;
	x1 ^= 0x56aa3350;
	x2 ^= 0x677d9197;
	x3 ^= 0xb27022dc;
	for(r = 0;r < 32;r += 4)
	{
		mid = x1 ^ x2 ^ x3 ^ CK[r + 0];
		mid = ByteSub(mid);
		rk[r+0] = x0 ^= L2(mid);

		mid = x2^ x3^ x0^CK[r + 1];
		mid = ByteSub(mid);
		rk[r+1] = x1^=L2(mid);

		mid = x3^ x0^ x1^CK[r + 2];
		mid = ByteSub(mid);
		rk[r + 2] = x2 ^= L2(mid);

		mid = x0^ x1^ x2 ^ CK[r + 3];
		mid = ByteSub(mid);
		rk[r + 3] = x3 ^= L2(mid);
	}
	if(CryptFlag == 1)
	{
		for(r = 0;r < 16;r++)
			mid = rk[r],rk[r] = rk[31 - r],rk[31 - r] = mid;
	}
}

void SM4_Encrypt(unsigned char *pKey, unsigned char *pDataIn, unsigned char *pDataOut)
{
	unsigned int m_Key[4];
	unsigned int m_DataIn[4];
	unsigned int m_DataOut[4];

	U8ToU32_L(m_Key, pKey, 4);
	U8ToU32_L(m_DataIn, pDataIn, 4);

	SM4KeyExt(m_Key,m_rk,0);
	SM4Operation(m_DataIn, m_DataOut, m_rk);

	U32ToU8_L(pDataOut, m_DataOut, 4);
}

void SM4_Decrypt(unsigned char *pKey, unsigned char *pDataIn, unsigned char *pDataOut)
{
	unsigned int m_Key[4];
	unsigned int m_DataIn[4];
	unsigned int m_DataOut[4];

	U8ToU32_L(m_Key, pKey, 4);
	U8ToU32_L(m_DataIn, pDataIn, 4);

	SM4KeyExt(m_Key,m_rk,1);
	SM4Operation(m_DataIn, m_DataOut, m_rk);

	U32ToU8_L(pDataOut, m_DataOut, 4);
}


/************************************************************************
 *  ConvertHexChar
 * ��������
 *	���ַ���ת��Ϊ16���Ƶ����ݣ���Byte�洢
 * ����
 *	ch
 *	[IN] ��������ַ�
 *	ch_byte
 *	[OUT] ����������, Byte����
 *
 * ����ֵ��
 *	���ת���ɹ��򷵻�0��
 *	���򷵻�-1
 ************************************************************************/
int ConvertHexChar(char ch, unsigned char *ch_byte)
{
	if ((ch >= '0') && (ch <= '9'))
	{

		*ch_byte = (unsigned char)(ch - 0x30);
		return 0;

	}
	else
	{
		if ((ch >= 'A') && (ch <= 'F'))
		{
			*ch_byte = (unsigned char)(ch - 'A' + 0x0a);
			return 0;
		}
		else
		{
			if ((ch >= 'a') && (ch <= 'f'))
			{
				*ch_byte = (unsigned char)(ch - 'a' + 0x0a);
				return 0;
			}
		}
	}

	return -1;
}

/************************************************************************
 *	Compare
 *	��������
 *		�ַ����ȽϺ���,��ͬ����0
 *	����
 *		str1
 *			[IN] ��������ַ�1
 *		str2
 *			[IN] ��������ַ�2
 * ����ֵ
 *	��ͬ�򷵻�0
 *	���򷵻�����ֵ
 ************************************************************************/
int Compare(char* str1,char* str2)
{
	return strcmp(str1,str2);
}
/************************************************************************
CompareEx
 * ��������
 *	�ַ������ִ�Сд�Ƚ�
 *
 * ����
 *	str1
 *	[IN] ��������ַ�1
 *	str2
 *	[IN]��������ַ�2
 *
 * ����ֵ��
 *		����ַ�����һ�����򷵻�0��
 *		���str1����С��str2�� * ����ֵС��0��
 *		���str1����С��str2�� * ����ֵ����0��
 ************************************************************************/
int CompareEx(char* str1,char* str2,char* strMessage)
{
	int Ret = -1;
	Ret = strcmp(str1,str2);
	if(Ret==0)
	{
		printf("%s\n",strMessage);
	}
	else
	{
		printf("�ַ����Ƚϲ�һ��\n");
	}
	return Ret;
}
/************************************************************************
 *	CompareEx_Not
 *	��������
 *		�ַ������ִ�Сд�Ƚ�
 *
 *	����
 *		str1
 *			[IN] ��������ַ�1
 *		str2
 *			[IN]��������ַ�2
 *
 *	����ֵ��
 *		����ַ�����һ�����򷵻�0��
 *		���str1����С��str2�� * ����ֵС��0��
 *		���str1����С��str2�� * ����ֵ����0��
 ************************************************************************/
int CompareEx_Not(char* str1,char* str2,char* strMessage)
{
	int Ret = 0;
	Ret = strcmp(str1,str2);
	if(Ret == 0)
	{
		printf("�ַ����Ƚ�,���һ��\n");
	}
	else
	{
		printf("%s\n",strMessage);
	}
	return Ret;
}

/************************************************************************
AsHexString
 * ��������
	��int����תΪ�ַ�����ʾ
 * ����
	Len
	[IN] �̶�Ϊ1��2
	Value
	[IN] int��ֵ
 * ����ֵ
	�ַ������
************************************************************************/
char* AsHexString(int Len,int Value)
{
	char* ret;
	unsigned char buffer[1];
	int j;
	char finalhash[20];
	char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    //if(Value==0)
	//	return "";
	buffer[0]=(unsigned char)Value;

	for(j = 0; j < 1; j++)
	{
		finalhash[j*2] = hexval[((buffer[j] >> 4) & 0xF)];
		finalhash[(j*2) + 1] = hexval[(buffer[j]) & 0x0F];
	}
	finalhash[j*2]=0;

	
	ret = finalhash;
	if(Len == 1)
	{
		ret = &finalhash[1];
	}
	return ret;

}


#define SignR_Is_Zero		0x02
#define N_EQUEL_SignRAddK	0x03
#define SignS_Is_Zero       0x04
#define T_Is_Zero           0x05
#define SCESign_Succeed     0x01
#define SCEVerify_Error     0x00
#define SCEVerify_Succeed   0x01
#define ZOut_Is_Zero		0x06
#define SCEEnc_Succeed      0x01
#define Point_Invalid       0x07
#define SCEDec_Succeed      0x01
#define SCEDec_Error        0x00

/************************************************************************/
/*SCE????                                                           */
/************************************************************************/
int	SCESignHash (unsigned int *pwRandom,unsigned int *pwHash,unsigned int *pwPriKey,unsigned int *pwSignR,unsigned int *pwSignS,pEC pEc)
{
	int i;
	A_Point KG;
	unsigned int r[ECCBNWordLen],s[ECCBNWordLen];
	unsigned int bn1[ECCBNWordLen],bn2[ECCBNWordLen],bn3[ECCBNWordLen];
	int iBNWordLen;
	
	
	iBNWordLen=pEc->BNWordLen;
	//K=pwRandom,d=pwPriKey,e=pwHash
	ECP_KP(&KG, &pEc->EC_G, pwRandom, pEc->GArray, pEc);//??KG=kG
	BN_ModAdd(r,KG.X,pwHash,pEc->EC_N,iBNWordLen);//r=(e+x)modN
	BN_ModSub(r,r,pEc->EC_N,pEc->EC_N,iBNWordLen);	//check r
	
	//?r=0?r+k=n ?????,?????????Random
	if (BN_IsZero(r,iBNWordLen))
		return SignR_Is_Zero;
	BN_Add(bn1,r,pwRandom,iBNWordLen);	//bn1=r+k;
	if (BN_Compare(bn1,pEc->EC_N,iBNWordLen)==0)
		return N_EQUEL_SignRAddK;
	//
	bn1[0]=0x1;
	for (i=1;i<iBNWordLen;i++)
	{
		bn1[i]=0x0;
	}
	
	BN_Add(bn2,bn1,pwPriKey,iBNWordLen);						//bn2=1+dA
	BN_GetInv(bn1, bn2, pEc->EC_N,iBNWordLen);				//bn1=(1+dA)^-1
	BN_ModMul_Stand(bn3,r,pwPriKey,pEc->EC_N,iBNWordLen);			//bn3=r*dA
	BN_ModSub(bn3,pwRandom,bn3,pEc->EC_N,iBNWordLen);				//bn3=K-r*dA
	BN_ModMul_Stand(bn2,bn1,bn3,pEc->EC_N,iBNWordLen);		//bn2=(1+dA)^-1*(K-r*dA)
	BN_ModSub(s,bn2,pEc->EC_N,pEc->EC_N,iBNWordLen);				//check s

	//?s=0,?????,?????????Random
	if (BN_IsZero(s,iBNWordLen))
		return SignS_Is_Zero;
	else
	{	
		BN_Assign(pwSignR,r,iBNWordLen);
		BN_Assign(pwSignS,s,iBNWordLen);
		return SCESign_Succeed;
	}
}
/************************************************************************/
/*SCE????                                                           */
/************************************************************************/
int SCEVerifyHash (unsigned int *pwHash,unsigned int *pwPubKeyX,unsigned int *pwPubKeyY,unsigned int *pwSignR,unsigned int *pwSignS,pEC pEc)
{
	unsigned int t[ECCBNWordLen],R[ECCBNWordLen];
	A_Point Q,sGtP;
	A_Point nq[ECCPreTableSize];
	int iBNWordLen;

	iBNWordLen=pEc->BNWordLen;
	//e=pwHash,r=pwSignR,s=pwSignS
	BN_Assign(Q.X, pwPubKeyX,iBNWordLen);
	BN_Assign(Q.Y, pwPubKeyY,iBNWordLen);

	BN_ModAdd(t,pwSignR,pwSignS,pEc->EC_N,iBNWordLen);//(r+s)modN
	BN_ModSub(t,t,pEc->EC_N,pEc->EC_N,iBNWordLen);//check t
	if (BN_IsZero(t,iBNWordLen))
		return T_Is_Zero;

	ECP_KP_PreCom(nq, &Q, pEc);//???
	ECP_KPLQ(&sGtP, &pEc->EC_G, pwSignS, pEc->GArray, &Q, t, nq, pEc);//sGtP = sG+tP
	BN_ModAdd(R,sGtP.X,pwHash,pEc->EC_N,iBNWordLen); //R=(e+Q.x)modN
	BN_ModSub(R,R,pEc->EC_N,pEc->EC_N,iBNWordLen);   //check R

	if(BN_Compare(R,pwSignR,iBNWordLen)==0)
		return SCEVerify_Succeed;
	else
		return SCEVerify_Error;
}

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))
#define P0(x)	x^rol(x,9)^rol(x,17)
#define P1(x)	x^rol(x,15)^rol(x,23)
#define FF1(a,b,c)	(a^b^c)	
#define FF2(a,b,c)	((a&b)|(a&c)|(b&c))
#define GG1(e,f,g)	(e^f^g)
#define GG2(e,f,g)  ((e&f)|((~e)&g))

/* Hash a single 512-bit block. This is the core of the algorithm. */
void SCHTransform(unsigned int state[8], unsigned char buffer[64])
{
	unsigned int a, b, c, d, e, f, g, h;
	unsigned int tmp,ss1,ss2,tt1,tt2;
	unsigned int W[68],W1[64];
	unsigned int tmp1,tmp2,tmp3,tmp4,tmp5,tmp6,tmp7;
	int j,i;
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
	for(j=0;j<16;j++)
		W[j]=(buffer[j*4]<<24)|(buffer[j*4+1]<<16)|(buffer[j*4+2]<<8)|buffer[j*4+3];
	for(j=16;j<68;j++)
	{
		tmp=rol(W[j-3],15)^W[j-9]^W[j-16];
		W[j]=P1(tmp)^rol(W[j-13],7)^W[j-6];
		//
		tmp1=rol(W[j-3],15);
		tmp2=rol(W[j-3],15)^W[j-9];
		tmp3=rol(W[j-3],15)^W[j-9]^W[j-16];
		tmp4=P1(tmp3);
		tmp5=rol(W[j-13],7);
		tmp6=tmp4^rol(W[j-13],7);
		tmp7=tmp4^rol(W[j-13],7)^W[j-6];
		//
	}
	for(j=0;j<64;j++)
		W1[j]=W[j]^W[j+4];
	/* 63 rounds of operations each. Loop unrolled. */
	j=0;
	do
	{
		if (j==0)
			tmp = rol(a,12)+e+0x79cc4519;
		else
			tmp = rol(a,12)+e+rol(0x79cc4519,j);
		ss1 = rol(tmp,7);
		ss2 = ss1^rol(a,12);
		tt1 = FF1(a,b,c)+d+ss2+W1[j];
		tt2 = GG1(e,f,g)+h+ss1+W[j];
		d = c;
		c = rol(b,9);
		b = a;
		a = tt1;
		h = g;
		g = rol(f,19);
		f = e;
		e = P0(tt2);		
		j++;
	} while(j < 16);
	i=0;
	do
	{
		i=j%32;
		if(i==0)
			tmp = rol(a,12)+e+0x7a879d8a;
		else
			tmp = rol(a,12)+e+rol(0x7a879d8a,i);
		ss1 = rol(tmp,7);
		ss2 = ss1^rol(a,12);
		tt1 = FF2(a,b,c)+d+ss2+W1[j];
		tt2 = GG2(e,f,g)+h+ss1+W[j];
		d = c;
		c = rol(b,9);
		b = a;
		a = tt1;
		h = g;
		g = rol(f,19);
		f = e;
		e = P0(tt2);		
		j++;
	} while(j < 64);
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

void SCH_Init(SCH_CTX* context)
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

void SCHUpdate(SCH_CTX* context, unsigned char* data, unsigned int len)
{
	unsigned int i, j;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) 
		context->count[1]++;
    context->count[1] += (len >> 29);
    if ((j + len) > 63) 
	{
        memcpy(&context->buffer[j], data, (i = 64-j));
        SCHTransform(context->state, context->buffer);
        for ( ; i + 63 < len; i += 64) 
		{
            SCHTransform(context->state, &data[i]);
        }
        j = 0;
    }
    else 
		i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

void SCHFinal(unsigned char *pbDigest, SCH_CTX* context,int outlen)
{
	unsigned int i, j;
	unsigned char finalcount[8];
	unsigned int a,b,c,d,e,f,g,h;

    for (i = 0; i < 8; i++) 
	{
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)] >> ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
    }
    SCHUpdate(context, (unsigned char *)"\200", 1);
    while ((context->count[0] & 504) != 448) 
	{
        SCHUpdate(context, (unsigned char *)"\0", 1);
    }
    SCHUpdate(context, finalcount, 8);  /* Should cause a SHA1Transform() */
	if(outlen==32)
    {
		for (i = 0; i < 32; i++)
		{
			pbDigest[i] = (unsigned char)((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
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
	if (outlen==20)
	{
		a=context->state[0];
		b=context->state[1];
		c=context->state[2];
		d=context->state[3];
		e=context->state[4];
		f=context->state[5];
		g=context->state[6];
		h=context->state[7];
		context->state[0]=a^b^e;
		context->state[1]=b^f^c;
		context->state[2]=c^g;
		context->state[3]=d^h;
		context->state[4]=d^g;
		for (i = 0; i < 20; i++)
		{
			pbDigest[i] = (unsigned char)((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
		}
	}
    /* Wipe variables */
    i = j = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 32);
    memset(context->count, 0, 8);
    memset(&finalcount, 0, 8);
}

void  SCH_Data( unsigned char* data, unsigned int charlen,unsigned char *digest,unsigned int outlen)
{
	/*~~~~~~~~~~~~~~~~*/
	SCH_CTX context;
	/*~~~~~~~~~~~~~~~~*/
	
	SCH_Init(&context);
	SCHUpdate(&context,data,charlen);
	SCHFinal(digest,&context,outlen);
}

void GBCombine(unsigned char *X,unsigned int bytelen1,unsigned char *Y,unsigned int bytelen2,unsigned char *XY,unsigned int *bytelen3)
{
	unsigned int len;
	unsigned int j,i;
	
	len = bytelen1 + bytelen2;
	*bytelen3 = len;
	
	for(j = 0;j < bytelen1;j++)
		XY[j] = X[j];
	
	for(i = 0;i < bytelen2;i++)
		XY[bytelen1 + i] = Y[i];
}

int GBKDF(unsigned char *Z,unsigned int bytelen,unsigned int klen,unsigned char *ZOut,int Hashlen)
{
	unsigned int ct;
	int Zctlen,bitlen,sl;

	unsigned char Zctbyte[300];
	unsigned char Hashbyte[32];
	unsigned char ctstr[4];
	unsigned int glen,hashblen;
	int i,j,k,len;

	if(klen%8!=0)
		return 0;
	ct=0x1;
	hashblen=Hashlen*8;
	sl=(klen%hashblen==0)?(klen/hashblen):((klen/hashblen)+1);
	
	//Zctbyte=(unsigned char *)malloc(bytelen+4);
	memset(Zctbyte,0,sizeof(Zctbyte));
	ctstr[0]=(unsigned char)((ct&0xff000000)>>24);
	ctstr[1]=(unsigned char)((ct&0x00ff0000)>>16); 
	ctstr[2]=(unsigned char)((ct&0x0000ff00)>>8);  
	ctstr[3]=(unsigned char)((ct&0x000000ff));
	glen=0;
	k=0;
	for(i=1;i<=sl;i++)
	{
			memset(Zctbyte,0,bytelen+4);
			GBCombine(Z,bytelen,ctstr,4,Zctbyte,(unsigned int *)&Zctlen);
			SCH_Data(Zctbyte,Zctlen,Hashbyte,Hashlen);

			ct++;
			ctstr[0]=(unsigned char)((ct&0xff000000)>>24);
			ctstr[1]=(unsigned char)((ct&0x00ff0000)>>16); 
			ctstr[2]=(unsigned char)((ct&0x0000ff00)>>8);  
			ctstr[3]=(unsigned char)((ct&0x000000ff));
			glen=Hashlen*8*i;
			if (glen>klen)
			{
				bitlen=klen-(glen-Hashlen*8);
				len=bitlen/8;
				for (j=0;j<len;j++)
				{
					ZOut[k]=Hashbyte[j];
					k++;
				}	
				break;
			}
			else
			{
				for (j=0;j<Hashlen;j++)
				{
					ZOut[k]=Hashbyte[j];
					k++;
				}	
			}
	
	}
	
	return 1;
}

//***********************************************************************//
// SCE????                                                          //
//***********************************************************************//
int	SCEEncrypt (unsigned int *pwRandom,
				unsigned char *pbPlainText,
				int iPlainTextLen,
				unsigned int *pwPubKeyX,
				unsigned int *pwPubKeyY,
				int HashLen,
				unsigned char *pbC1,
				unsigned char *pbC2,
				unsigned char *pbC3,
				pEC pEc)
{
	int i;
	A_Point KG,KP,Q;
	unsigned char XYbyte[64];
	unsigned char ZOut[250];
	unsigned char Xbyte[32];
	unsigned char Ybyte[32];
	unsigned char XMbyte[290];
	unsigned char XMYbyte[320];

	int iBNWordLen;
	unsigned int bytelen1,bytelen2;
	A_Point nq[ECCPreTableSize];

	iBNWordLen=pEc->BNWordLen;
	//K = pwRandom
	BN_Assign(Q.X, pwPubKeyX,iBNWordLen);
	BN_Assign(Q.Y, pwPubKeyY,iBNWordLen);					//Q=Pub
	ECP_KP(&KG,&pEc->EC_G,pwRandom,pEc->GArray,pEc);		//C1=KG=(x1,y1)
	BNToByte(KG.X,iBNWordLen,pbC1,(int*)&bytelen1);
	BNToByte(KG.Y,iBNWordLen,&pbC1[bytelen1],(int*)&bytelen2);

	ECP_KP_PreCom(nq, &Q, pEc);//???
	ECP_KP(&KP,&Q,pwRandom,nq,pEc);		//KP=KPub(x2,y2)
	for(i=0;i<iBNWordLen;i++)		//??Q???????
	{
		if((KP.X[i]!=0 )||(KP.Y[i]!=0))
			break;		
	}
	memset(XYbyte,0,sizeof(XYbyte));//XYbyte=(unsigned char *)malloc(2*iBNWordLen*WordByteLen);
	BNToByte(KP.X,iBNWordLen,XYbyte,(int*)&bytelen1);
	BNToByte(KP.Y,iBNWordLen,&XYbyte[bytelen1],(int*)&bytelen2); //XYbyte = x||y


	memset(ZOut,0,sizeof(ZOut));//ZOut=(unsigned char *)malloc(iPlainTextLen);
	GBKDF(XYbyte,2*iBNWordLen*WordByteLen,iPlainTextLen*8,ZOut,HashLen);   //ZOut=KDF(x2||y2,klen)

	for(i=0;i<iPlainTextLen;i++)			//??ZOut???0
	{
		if(ZOut[i]!=0 )
			break;		
	}
	if(i==iPlainTextLen)
		return ZOut_Is_Zero;

	for(i=0;i<iPlainTextLen;i++)			//C2==Message^ZOut
		pbC2[i]=pbPlainText[i]^ZOut[i];

	BNToByte(KP.X,iBNWordLen,Xbyte,(int*)&bytelen1);
	BNToByte(KP.Y,iBNWordLen,Ybyte,(int*)&bytelen2);

	memset(XMbyte,0,sizeof(XMbyte));
	GBCombine(Xbyte,iBNWordLen*WordByteLen,pbPlainText,iPlainTextLen,XMbyte,&bytelen1);  //XMbyte = x2||Message

	memset(XMYbyte,0,sizeof(XMYbyte));
	GBCombine(XMbyte,bytelen1,Ybyte,iBNWordLen*WordByteLen,XMYbyte,&bytelen2);  //XMYbyte = x2||Message||y2

	SCH_Data(XMYbyte,bytelen2,pbC3,HashLen);  //C3=Hash(x2||Message||y2)


	return SCEEnc_Succeed;
}
//**********************************************************************//
// SCE????                                                          //
//**********************************************************************//
int	SCEDecrypt	(unsigned char *pbC1,
				   unsigned char *pbC2,
				   unsigned char *pbC3,
				   unsigned int *pwPriKey,
				   int HashLen,
				   unsigned char *pbPlainText,
				   int iPlainTextLen,
				   pEC pEc)
{
	int i;
	A_Point Q,PriQ;
	unsigned char Ubyte[MAXBNByteLen];
	int iBNWordLen;
	unsigned char XYbyte[64];
	unsigned char ZOut[250];
	unsigned char Xbyte[32];
	unsigned char Ybyte[32];
	unsigned char XMbyte[290];
	unsigned char XMYbyte[320];

	unsigned int bytelen1,bytelen2;
	A_Point nq[ECCPreTableSize];

	iBNWordLen=pEc->BNWordLen;
	//d=pwPriKey
	ByteToBN(pbC1,iBNWordLen*WordByteLen,Q.X,iBNWordLen);
	ByteToBN(&pbC1[iBNWordLen*WordByteLen],iBNWordLen*WordByteLen,Q.Y,iBNWordLen);

	ECP_KP_PreCom(nq, &Q, pEc);//???
	ECP_KP(&PriQ,&Q,pwPriKey,nq,pEc);		//PriQ=Pri*C1=(x,y)
	for(i=0;i<iBNWordLen;i++)		//??PriQ???????
	{
		if((PriQ.X[i]!=0 )||(PriQ.Y[i]!=0))
			break;		
	}
	if(i==iBNWordLen)
		return Point_Invalid;

	
	memset(Xbyte,0,sizeof(Xbyte));
	memset(Ybyte,0,sizeof(Ybyte));
	memset(XYbyte,0,sizeof(XYbyte));
	
	BNToByte(PriQ.X,iBNWordLen,XYbyte,(int*)&bytelen1);
	BNToByte(PriQ.Y,iBNWordLen,&XYbyte[bytelen1],(int*)&bytelen2);			//XYbyte = x||y

	memset(ZOut,0,sizeof(ZOut));
	GBKDF(XYbyte,2*iBNWordLen*WordByteLen,iPlainTextLen*8,ZOut,HashLen);   //ZOut=KDF(x2||y2,klen)

	for(i=0;i<iPlainTextLen;i++)		    //??ZOut???0
	{
		if(ZOut[i]!=0 )
			break;		
	}
	if(i==iPlainTextLen)
		return ZOut_Is_Zero;

	for(i=0;i<iPlainTextLen;i++)			//M'=C2^ZOut
		pbPlainText[i]=pbC2[i]^ZOut[i];	
	memset(Xbyte,0,sizeof(Xbyte));
	memset(Ybyte,0,sizeof(Ybyte));

	BNToByte(PriQ.X,iBNWordLen,Xbyte,(int*)&bytelen1);
	BNToByte(PriQ.Y,iBNWordLen,Ybyte,(int*)&bytelen2);
	
	memset(XMbyte,0,sizeof(XMbyte));
	GBCombine(Xbyte,iBNWordLen*WordByteLen,pbPlainText,iPlainTextLen,XMbyte,&bytelen1);  //XMbyte = x||M'
	
	memset(XMYbyte,0,sizeof(XMYbyte));
	GBCombine(XMbyte,bytelen1,Ybyte,iBNWordLen*WordByteLen,XMYbyte,&bytelen2);  //XMYbyte = x||M'||y

	SCH_Data(XMYbyte,bytelen2,Ubyte,HashLen);  //C3=Hash(x2||Message||y2)
	for(i = 0;i < MAXBNByteLen;i++)
	{
		if(Ubyte[i] != pbC3[i])
			return SCEDec_Error;
	}
	return SCEDec_Succeed;
}

unsigned char SM4_EncrptBlock(char* pucSrc,unsigned int uiSrcLen,char* pucKey,unsigned char *pucDst)
{
	int length = 0;
	unsigned int i = 0;
	unsigned char *pIn = (unsigned char *)pucSrc;
	unsigned char *pOut =(unsigned char *) pucDst;

	for ( i = 0; i < uiSrcLen / 16; i++ )
	{
		SM4_Encrypt((unsigned char *)pucKey, pIn, pOut);
		pIn += 16;
		pOut += 16;
	}

	return 0x00;

}

unsigned char SM4_DecrptBlock(char* pucSrc,unsigned int pucSrcLen,char* pucKey,char *pucDst)
{
	int length = 0;

	int INPUT_Len = 0;
	int OUTPUT_Len = 0;
	int Key_Len = 0;
	int i = 0;
	unsigned char *pIn = (unsigned char *)pucSrc;
	unsigned char *pOut = (unsigned char *)pucDst;

	for ( i = 0; i < INPUT_Len / 16; i++ )
	{
		SM4_Decrypt((unsigned char *)pucKey, pIn,(unsigned char *) pOut);
		pIn += 16;
		pOut += 16;
	}

	return 0x00;
}


int SM3_Compute(unsigned char* InMessage,unsigned int uiInLen,unsigned char*strDigest)
{
	DumpData("strInData",InMessage,uiInLen);
	SCH_Data( InMessage, uiInLen,strDigest,32);
	DumpData("strDigest",strDigest,32);
	return 0x00;
}

void SM3_Hash(unsigned char *pucInMessage,unsigned int uiInMessageLen,unsigned char *pucDigest)
{
	SCH_Data( pucInMessage, uiInMessageLen,pucDigest,32);
}


/************************************************************************
* ECCData_Generate
* 
*  * ����:�������ECC��������
*  * ����:
*		iRSAKeyBitLen
*		[IN] 512/ 1024/2048
*		iGetRandomLen
*		[IN] ÿ�λ�ȡ������ĳ���
*  * ����ֵ:�ַ������
************************************************************************/
char* ECCData_Generate(int ECCKeyBitLen ,int iGetRandomLen,unsigned char *pucRand)
{
	int i = 0;
	
	Rand_Init();
	for (i = 0;i < ECCKeyBitLen/8;i++)
	{
		pucRand[i] = (char)Rand_Get();
	}

	return 0x00;
}

unsigned char SM2_ENC(unsigned char* pucPlainHex,unsigned int uiPlainLen,unsigned char* strPub,unsigned char*pucEncipher)
{
	char aucRand[32];
	int Ret = 0;
	A_Point Pub;
	unsigned char C1[255];
	unsigned char C2[255];
	unsigned char C3[255];
	unsigned int Random[ECCBNWordLen];
	EC Ec_tmp;
	unsigned char SysBuf[192];

	memcpy(SysBuf,StandECC_P,32);
	memcpy(&SysBuf[1*32],StandECC_A,32);
	memcpy(&SysBuf[2*32],StandECC_B,32);
	memcpy(&SysBuf[3*32],StandECC_Gx,32);
	memcpy(&SysBuf[4*32],StandECC_Gy,32);
	memcpy(&SysBuf[5*32],StandECC_N,32);
	ECP_Init(&Ec_tmp,ECC256_BNWLEN,SysBuf);


	ByteToBN(&strPub[0],32,Pub.X,Ec_tmp.BNWordLen);
	ByteToBN(&strPub[32],32,Pub.Y,Ec_tmp.BNWordLen);

	ECCData_Generate(256,16,(unsigned char *)aucRand);

	ByteToBN((unsigned char *)aucRand,16,Random,Ec_tmp.BNWordLen);

	Ret = SCEEncrypt(Random,pucPlainHex,uiPlainLen,Pub.X,Pub.Y,32,C1,C2,C3,&Ec_tmp);
	DumpData("aucRand",(unsigned char *)aucRand,16);
	DumpData("InBuf",pucPlainHex,uiPlainLen);
	DumpData("Pub.X",(unsigned char*)Pub.X,32);
	DumpData("Pub.Y",(unsigned char*)Pub.Y,32);
	DumpData("C1",C1,64);
	DumpData("C2",C2,uiPlainLen);
	DumpData("C3",C3,32);


	if(Ret != SCEEnc_Succeed)
	{
		printf("PC SCE_256 Encrypt Error!\n");	
		return 0x01;
	}
	else
	{	
		memcpy((char*)&pucEncipher[0],C1,64);
		//memcpy((char*)&pucEncipher[64],C2,uiPlainLen);
		//memcpy((char*)&pucEncipher[uiPlainLen + 64],C3,32);
		memcpy((char*)&pucEncipher[64], C3, 32);
		memcpy((char*)&pucEncipher[96], C2, uiPlainLen);

	}
	return 0x00;
}

unsigned char SM2_DEC(unsigned char* cipher, unsigned int cipherLen, unsigned char* strPri,unsigned char *pucPlainHex)
{
	int PlainTextLen =0;
	//int cipherlen;
	int Ret = 0;
	unsigned char C1[255];
	unsigned char C2[255];
	unsigned char C3[255];
	unsigned int Pri[ECCBNWordLen];
	EC Ec_tmp;
	unsigned char SysBuf[192];
	int InLen = 0;
	if (cipherLen <= 96) {
		return 1;
	}
	memcpy(SysBuf,StandECC_P,32);
	memcpy(&SysBuf[1*32],StandECC_A,32);
	memcpy(&SysBuf[2*32],StandECC_B,32);
	memcpy(&SysBuf[3*32],StandECC_Gx,32);
	memcpy(&SysBuf[4*32],StandECC_Gy,32);
	memcpy(&SysBuf[5*32],StandECC_N,32);
	ECP_Init(&Ec_tmp,ECC256_BNWLEN,SysBuf);
	PlainTextLen = cipherLen - 96; 
	memcpy((char*)C1, (char*)&cipher[0], 64);
	//memcpy((char*)C2, (char*)&cipher[64], PlainTextLen);
	//memcpy((char*)C3, (char*)&cipher[cipherLen - 32], 32);

	memcpy((char*)C3, (char*)&cipher[64], 32);
	memcpy((char*)C2, (char*)&cipher[96], PlainTextLen);

	ByteToBN(strPri,32,Pri,Ec_tmp.BNWordLen);

	Ret = SCEDecrypt(C1,C2,C3,Pri,32,pucPlainHex,PlainTextLen,&Ec_tmp);
	if(Ret != SCEDec_Succeed)
	{
		printf("PC SCE_256 Decrypt Error!\n");	
		return 1;
	}

	return 0x00;
}

int SM2_Sign(unsigned char* pucData,unsigned int uiDataLen,unsigned char* strPri,unsigned char *strSign)
{
	int Ret;
	char aucRand[32];
	
	unsigned int Pri[ECCBNWordLen],ECCSignR[ECCBNWordLen],ECCSignS[ECCBNWordLen];
	unsigned int Random[ECCBNWordLen],Hash[ECCBNWordLen];
	EC Ec_tmp;
	unsigned char SysBuf[192];
	unsigned char InBuf[300];
	int InLenR = 0,InLenS = 0;
	memcpy(SysBuf,StandECC_P,32);
	memcpy(&SysBuf[1*32],StandECC_A,32);
	memcpy(&SysBuf[2*32],StandECC_B,32);
	memcpy(&SysBuf[3*32],StandECC_Gx,32);
	memcpy(&SysBuf[4*32],StandECC_Gy,32);
	memcpy(&SysBuf[5*32],StandECC_N,32);
	ECP_Init(&Ec_tmp,ECC256_BNWLEN,SysBuf); 
	ByteToBN(pucData,uiDataLen,Hash,Ec_tmp.BNWordLen);

	ByteToBN(strPri,32,Pri,Ec_tmp.BNWordLen);

	ECCData_Generate(256,16,(unsigned char *)aucRand);
	ByteToBN((unsigned char *)aucRand,32,Random,Ec_tmp.BNWordLen);

	Ret = SCESignHash (Random,Hash,Pri,ECCSignR,ECCSignS,&Ec_tmp);
	if(Ret !=1)
	{
		printf("PC SCE_256 Sign ERROR!\n");	
		return 1;
	}
	else
	{
		BNToByte(ECCSignR,Ec_tmp.BNWordLen,InBuf,&InLenR);
		memcpy((char*)&strSign[0],InBuf,InLenR);

		BNToByte(ECCSignS,Ec_tmp.BNWordLen,InBuf,&InLenS);
		memcpy((char*)&strSign[InLenR],InBuf,InLenS);
	}
	return 0x00;
}

int  SM2_Verify(unsigned char* pucData,unsigned int uiInLen,unsigned char* Signature,unsigned char* strPub)
{
	int Ret  = 0;
	unsigned int ECCSignR[ECCBNWordLen],ECCSignS[ECCBNWordLen];
	unsigned int Hash[ECCBNWordLen];
	A_Point Pub;
	EC Ec_tmp;
	unsigned char SysBuf[192];

	memcpy(SysBuf,StandECC_P,32);
	memcpy(&SysBuf[1*32],StandECC_A,32);
	memcpy(&SysBuf[2*32],StandECC_B,32);
	memcpy(&SysBuf[3*32],StandECC_Gx,32);
	memcpy(&SysBuf[4*32],StandECC_Gy,32);
	memcpy(&SysBuf[5*32],StandECC_N,32);
	ECP_Init(&Ec_tmp,ECC256_BNWLEN,SysBuf);


	ByteToBN(strPub,32,Pub.X,Ec_tmp.BNWordLen);


	ByteToBN(&strPub[32],32,Pub.Y,Ec_tmp.BNWordLen);
	
	DumpData("pubx",strPub,32);
	DumpData("puby",&strPub[32],32);

	ByteToBN(pucData,uiInLen,Hash,Ec_tmp.BNWordLen);


	ByteToBN(Signature,32,ECCSignR,Ec_tmp.BNWordLen);
	ByteToBN(&Signature[32],32,ECCSignS,Ec_tmp.BNWordLen);

	Ret = SCEVerifyHash (Hash,Pub.X,Pub.Y,ECCSignR,ECCSignS,&Ec_tmp);
	if(Ret !=1)
	{
		printf("PC SCE_256 Verify ERROR!\n");
		Ret = 1;
	}
	else
		Ret = 0;

	return Ret;
}

int PBOC_SMHash(unsigned char *pucPub,unsigned int uiPubicKeyLen,unsigned char *pucInData,unsigned int uiInLen,unsigned char *pucDigest)
{
#define SMHEAD_LEN 0x92
	const unsigned char strSMHead[SMHEAD_LEN + 1]=	{
		"\x00\x80"
		"\x31\x32\x33\x34\x35\x36\x37\x38\x31\x32\x33\x34\x35\x36\x37\x38"
		"\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC"
		"\x28\xE9\xFA\x9E\x9D\x9F\x5E\x34\x4D\x5A\x9E\x4B\xCF\x65\x09\xA7\xF3\x97\x89\xF5\x15\xAB\x8F\x92\xDD\xBC\xBD\x41\x4D\x94\x0E\x93"
		"\x32\xC4\xAE\x2C\x1F\x19\x81\x19\x5F\x99\x04\x46\x6A\x39\xC9\x94\x8F\xE3\x0B\xBF\xF2\x66\x0B\xE1\x71\x5A\x45\x89\x33\x4C\x74\xC7"
		"\xBC\x37\x36\xA2\xF4\xF6\x77\x9C\x59\xBD\xCE\xE3\x6B\x69\x21\x53\xD0\xA9\x87\x7C\xC6\x2A\x47\x40\x02\xDF\x32\xE5\x21\x39\xF0\xA0"
	};
	char strPub[256],strDigest[256],strHash[256];
	int ret;
	char strInData[2048];

	memset(strInData,0,sizeof(strInData));
	memset(strPub,0,sizeof(strPub));
	memset(strInData,0,uiInLen + 512);
	memset(strDigest,0,sizeof(strDigest));
	memset(strHash,0,sizeof(strHash));
	Conv_HexAsc((unsigned char*)strPub,pucPub,uiPubicKeyLen*2);
	Conv_HexAsc((unsigned char*)strHash,pucDigest,64*2);
	
	memcpy(strInData,strSMHead,SMHEAD_LEN);
	ret = sizeof(strSMHead);

	memcpy(&strInData[SMHEAD_LEN],pucPub,uiPubicKeyLen);	
	SM3_Compute((unsigned char*)strInData,SMHEAD_LEN + uiPubicKeyLen,(unsigned char*)strDigest);

	memset(strInData,0,sizeof(strInData));
	memcpy(strInData,strDigest,uiPubicKeyLen/2);

	memcpy((char*)&strInData[uiPubicKeyLen/2],pucInData,uiInLen);
	
	SM3_Compute((unsigned char*)strInData,uiPubicKeyLen/2+uiInLen,(unsigned char*)strDigest);

	ret = SM2_Verify((unsigned char*)strDigest,32,pucDigest,pucPub);

	return ret;
}

#endif