/*
*********************************************************************************************************
*                                               SM4 FUNCTIONS                                          
*
*                                (c) Copyright 2014, R.Kolidat min.bo@30raycom.com
*                                           All Rights Reserved
*
* File : SM4.C
* By   : R.Kolidat
*********************************************************************************************************
*/

#include <string.h>
#include <stdlib.h>
#include "types.h"
#include "sm4ofb.h"
#include "time.h"

#define RC_EXPORT __attribute__((visibility("default")))

/*
*********************************************************************************************************
*                                                 MACRO
*********************************************************************************************************
*/
#define SMS4_ROUND     32                                                    
#define ROL(x, y)      (((x) << (y)) | (((x) & 0xFFFFFFFFul) >> (32 - (y))))   

/*
*********************************************************************************************************
*                                               CONSTANTS
*********************************************************************************************************
*/ 
static u32 FK[4] = 
{
    0xA3B1BAC6ul, 0x56AA3350ul, 0x677D9197ul, 0xB27022DCul
};

static u32 CK[SMS4_ROUND] = 
{
    0x00070e15ul, 0x1c232a31ul, 0x383f464dul, 0x545b6269ul,
	0x70777e85ul, 0x8c939aa1ul, 0xa8afb6bdul, 0xc4cbd2d9ul,
	0xe0e7eef5ul, 0xfc030a11ul, 0x181f262dul, 0x343b4249ul,
	0x50575e65ul, 0x6c737a81ul, 0x888f969dul, 0xa4abb2b9ul,
	0xc0c7ced5ul, 0xdce3eaf1ul, 0xf8ff060dul, 0x141b2229ul,
	0x30373e45ul, 0x4c535a61ul, 0x686f767dul, 0x848b9299ul,
	0xa0a7aeb5ul, 0xbcc3cad1ul, 0xd8dfe6edul, 0xf4fb0209ul,
	0x10171e25ul, 0x2c333a41ul, 0x484f565dul, 0x646b7279ul
};

static u8 Sbox[256] =
{
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

/*
*********************************************************************************************************
*                                         Non-linear Transform
*
* Description : None
*
* Arguments   : A          input
*
*
* Returns     : B          output
*********************************************************************************************************
*/
static u32 t(u32 A) 
{
    u8  a[4] = {0};
    u8  b[4] = {0};
    u32 B = 0;
    u8  i = 0;
	
    for (i = 0; i < 4; i++) 
    {
        a[i] = (u8)((A >> (i*8)) & 0x00ff);
        b[i] = Sbox[(a[i])];
        
		B |= ((u32)(b[i]) << (i*8));
    }
	
    return B;
}

/*
*********************************************************************************************************
*                               Compose Transform for Encryption / Decryption
*
* Description : 
*
* Arguments   : A          input
*
*
* Returns     : C          output
*********************************************************************************************************
*/
static u32 T1(u32 A) 
{
    u32 B = 0;
    u32 C = 0;
	
    B = t(A);
    C = B ^ ROL(B, 2) ^ ROL(B, 10) ^ ROL(B, 18) ^ ROL(B, 24);
	
    return C;
}


/*
*********************************************************************************************************
*                                   Compose Transform for Key Expansion
*
* Description : 
*
* Arguments   : A          input
*
*
* Returns     : C          output
*********************************************************************************************************
*/
static u32 T2(u32 A) 
{
    u32 B = 0;
    u32 C = 0;
	
    B = t(A);
    C = B ^ ROL(B, 13) ^ ROL(B, 23);
	
    return C;
}


/*
*********************************************************************************************************
*                                             Key Expansion
*
* Description : None
*
* Arguments   : MK[]       Seed Key
*
*               rk[]       Round Key
* 
*
* Returns     : None
*********************************************************************************************************
*/
void SMS4_KeyExpansion(u32 MK[], u32 rk[]) 
{
    u32 K[4] = {0};
    u8  i = 0;
    
    for (i = 0; i < 4; i++)
    {
        K[i] = MK[i] ^ FK[i];
    }
    
    for (i = 0; i < SMS4_ROUND; i++)
    {
        K[i%4] ^= T2(K[(i+1)%4] ^ K[(i+2)%4] ^ K[(i+3)%4] ^ CK[i]);
        rk[i] = K[i % 4];
    }    
}

/*
*********************************************************************************************************
*                                             SMS4 Encryption
*
* Description : None
*
* Arguments   : X[]        PlainText 
*
*               rk[]       Round Key
*
*               Y[]        CypherText
* 
*
* Returns     : None
*********************************************************************************************************
*/
void SMS4_Encryption(u32 X[], u32 rk[], u32 Y[])
{
    u32 tempX[4] = {0};
    u8 i = 0;
    
    for (i = 0; i < 4; i++)
	{
		tempX[i] = X[i];
	}
	
    for (i = 0; i < SMS4_ROUND; i++)
	{
		tempX[i%4] ^= T1(tempX[(i+1)%4] ^ tempX[(i+2)%4] ^ tempX[(i+3)%4] ^ rk[i]);
	}
	
    for (i = 0; i < 4; i++)
	{
		Y[i] = tempX[3-i];
	}
}


/*
*********************************************************************************************************
*                                             SMS4 Decryption
*
* Description : None
*`
* Arguments   : X[]        CypherText
*
*               rk[]       Round Key
*
*               Y[]        PlainText
* 
*
* Returns     : None
*********************************************************************************************************
*/
void SMS4_Decryption(u32 X[], u32 rk[], u32 Y[])
{
    u32 tempX[4] = {0};
    u8  i = 0;
    
    for (i = 0; i < 4; i++)
	{
		tempX[i] = X[i];
	}
	
    for (i = 0; i < SMS4_ROUND; i++)
	{
		tempX[i%4] ^= T1(tempX[(i+1)%4] ^ tempX[(i+2)%4] ^ tempX[(i+3)%4] ^ rk[(31-i)]);
	}
	
    for (i = 0; i < 4; i++)
	{
		Y[i] = tempX[3-i];
	}
}

int SEA_Encrypt(u8 *wk, u32 wk_len, u8 *mk, u32 mk_len, u8 *input, u32 input_len, u8 *output, u32 *output_len)
{
    u32 outputData[4] = {0};
	u32 sea_iv[4] = {0};
    u32 tmp_mk[4] = {0};
	u32 rk[32] = {0};	
    u16 k = 0;
	u16 j = 0;
	u16 leavenum = 0;
    u8 tmp[16] = {0};
    u8 outdata[16] = {0};
	int i = 0;
	
	//printf("enter SEA_Encrypt.\n");
    if (input == NULL || input_len == 0)
	{
    	printf("SEA_Encrypt input data is null");
		*output_len = 0;

		return 0;
	}

	if (wk == NULL || wk_len != 16)
	{
		printf("SEA_Encrypt key is invalid");
		return 1;
	}

	if (output == NULL || *output_len < input_len)
	{
		if(output == NULL)
		{
			printf("output  is null. \n");
		}

		printf("output_len = %d, input_len = %d\n", *output_len, input_len);
		
		printf("SEA_Encrypt output buffer too small");

		*output_len = input_len;

		return 2;
	}

    k = input_len / 16;
    leavenum = input_len - 16 * k;
    
	for (i = 0; i < 4; i++) 
    {
        tmp_mk[i] = ((u32)wk[4*i] << 24) | ((u32)wk[4*i+1] << 16) | ((u32)wk[4*i+2] << 8) | ((u32)wk[4*i+3]);
    }
	
    SMS4_KeyExpansion(tmp_mk, rk);
	
    for (j = 0; j < 4; j++)
    {
        sea_iv[j] = ((u32)mk[4*j] << 24) | ((u32)mk[4*j+1] << 16) | ((u32)mk[4*j+2] << 8) | ((u32)mk[4*j+3]); 
    }
	
    for (i = 0; i < k; i++)
    {  
        memcpy(&tmp[0], &input[i*16], 16);
        SMS4_Encryption(sea_iv, rk, outputData); 
        memcpy(sea_iv, outputData, 16);        
        
		for (j = 0; j < 4; j++)
        { 
            output[16*i+4*j] = (u8)(outputData[j] >> 24);
            output[16*i+4*j+1] = (u8)(outputData[j] >> 16);
            output[16*i+4*j+2] = (u8)(outputData[j] >> 8);
            output[16*i+4*j+3] = (u8)outputData[j];
        }

//		memcpy(mk, &output[16*i], 16);
		
        for (j = 0; j < 16; j++)
        {
            output[16*i+j] ^= tmp[j];
        }
    }
	
    if(leavenum)
    {    
        memcpy(&tmp[0], &input[k*16], leavenum);
        SMS4_Encryption(sea_iv, rk, outputData); 
		
		for (j = 0; j < 4; j++)
		{ 
			outdata[4*j] = (u8)(outputData[j] >> 24);
			outdata[4*j+1] = (u8)(outputData[j] >> 16);
			outdata[4*j+2] = (u8)(outputData[j] >> 8);
			outdata[4*j+3] = (u8)outputData[j];
		}
		
        for (j = 0; j < leavenum; j++)
		{
			outdata[j]^=tmp[j]; 
		}
		
		for(j = 0; j < leavenum; j++)
		{
			output[16*k+j] = outdata[j]; 
		}
	}    

	*output_len = input_len;

	//printf("leave SEA_Encrypt.\n");
	return 0;
}

int SEA_Decrypt(u8 *wk, u32 wk_len, u8 *mk, u32 mk_len, u8 *input, u32 input_len, u8 *output, u32 *output_len)
{
	printf("SEA_Decrypt in... \n");
    u32 i = 0;
    u32 outputData[4] = {0};
	u32 sea_iv[4] = {0};
    u32 tmp_mk[4] = {0};
	u32 rk[32] = {0};	
    u16 k = 0;
	u16 j = 0;
	u16 leavenum = 0;
    u8 tmp[16] = {0};
    u8 outdata[16] = {0};
	
    if (input == NULL || input_len == 0)
	{
    	printf("SEA_Decrypt input data is null");

		*output_len = 0;

		return 0;
	}

	if (wk == NULL || wk_len != 16)
	{
		printf("SEA_Decrypt key is invalid");

		return -1;
	}

	printf("output_len = %d, input_len = %d\n", *output_len, input_len);
	
	if (output == NULL || *output_len < input_len)
	{
		printf("SEA_Decrypt output buffer too small");

		*output_len = input_len;

		return -2;
	}

    k = input_len / 16;
    leavenum = input_len - 16 * k;
    
	for (i = 0; i < 4; i++) 
    {
        tmp_mk[i] = ((u32)wk[4*i] << 24) | ((u32)wk[4*i+1] << 16) | ((u32)wk[4*i+2] << 8) | ((u32)wk[4*i+3]);
    }
	
    SMS4_KeyExpansion(tmp_mk, rk);
	
    for (j = 0; j < 4; j++)
    {
        sea_iv[j] = ((u32)mk[4*j] << 24) | ((u32)mk[4*j+1] << 16) | ((u32)mk[4*j+2] << 8) | ((u32)mk[4*j+3]); 
    }
	
    for (i = 0; i < k; i++)
    {  
        memcpy(&tmp[0], &input[i*16], 16);
        SMS4_Encryption(sea_iv, rk, outputData); 
        memcpy(sea_iv, outputData, 16);        
		
		for (j = 0; j < 4; j++)
        { 
            output[16*i+4*j] = (u8)(outputData[j] >> 24);
            output[16*i+4*j+1] = (u8)(outputData[j] >> 16);
            output[16*i+4*j+2] = (u8)(outputData[j] >> 8);
            output[16*i+4*j+3] = (u8)outputData[j];
        }

//		memcpy(mk, &output[16*i], 16);
		
        for (j = 0; j < 16; j++)
        {
            output[16*i+j] ^= tmp[j];
        }
    }
	
    if (leavenum)
    {    
        memcpy(&tmp[0], &input[k*16], leavenum);
        SMS4_Encryption(sea_iv, rk, outputData); 
		
		for (j = 0; j < 4; j++)
		{ 
			outdata[4*j] = (u8)(outputData[j] >> 24);
			outdata[4*j+1] = (u8)(outputData[j] >> 16);
			outdata[4*j+2] = (u8)(outputData[j] >> 8);
			outdata[4*j+3] = (u8)outputData[j];
		}
		
        for (j = 0; j < leavenum; j++)
		{
			outdata[j] ^= tmp[j]; 
		}
		
		for (j = 0; j < leavenum; j++)
		{
			output[16*k+j] = outdata[j]; 
		}
	}    

	*output_len = input_len;

	printf("SEA_Decrypt output len: %d\n", *output_len);

	return 0;
}

void SEA_Random(u8 *seedData, u32 seedLength, u8 *outputData, u32 dataLength)
{
	u16 i = 0;
	double dseed = 0;
	int dseed_len = seedLength > sizeof(double) ? sizeof(double) : seedLength;
	
	if (seedData != NULL && seedLength != 0)
	{
		memcpy(&dseed, seedData, dseed_len);
	}
	else
	{
#ifdef WIN32
		dseed = (double)time(NULL);
#else
		struct timeval time;
		gettimeofday(&time,NULL);
		dseed = (time.tv_sec)*1000000+(time.tv_usec);
#endif
	}
	
	srand((unsigned)dseed);
	
	for(i = 0; i < dataLength; i++)
	{
		outputData[i] = (u8)((rand() % 0xFF) & 0xFF);
	}
}
