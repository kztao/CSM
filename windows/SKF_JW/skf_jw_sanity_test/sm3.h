#ifndef __HEADER_SM3_H
#define __HEADER_SM3_H

#include <stdio.h>
#include <string.h>
#include "types.h"

typedef struct _SM3_CTX
{
    unsigned long state[8];
    unsigned long count[2];
    unsigned char buffer[64];
} SM3_CTX;

#define SM3160				20	  //中国商用杂凑算法160的输出字节长度
#define SM3192				24	  //中国商用杂凑算法192的输出字节长度
#define SM3256				32    //中国商用杂凑算法256的输出字节长度

#ifdef __cplusplus
extern "C"
{
#endif
	
void SM3Transform(unsigned long state[8], unsigned char buffer[64]);
void SM3_Init(SM3_CTX* context);
void SM3Update(SM3_CTX* context, unsigned char* data, unsigned int len);
void SM3Final(unsigned char *pbDigest, SM3_CTX* context,int outlen);
void SM3_Data( unsigned char* data, unsigned int charlen,unsigned char *digest,unsigned int outlen);

void GBCombine(BYTE *X,					//X
			   unsigned long bytelen1,  //X的字节长
			   BYTE *Y,					//Y
			   unsigned long bytelen2,	//Y的字节长
		       BYTE *XY,				//X||Y
		       unsigned long *bytelen3);//X||Y的字节长
	
int GBKDF(BYTE *Z,						//KDF 的输入
		  unsigned long bytelen,		//Z 的字节数
		  unsigned long klen,			//Klen 比特数
		  BYTE *ZOut,					//KDF输出结果
		  int Hashlen);					//KDF中Hash的输出结果的字节长度

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SHA1_H_INCLUDED__ */