#ifndef __HEADER_SM3_H
#define __HEADER_SM3_H

#include <stdio.h>
#include <string.h>
#include "types.h"

typedef struct _SM3_CTX
{
    unsigned int state[8];
    unsigned int count[2];
    unsigned char buffer[64];
} SM3_CTX;

#define SM3160				20	  //�й������Ӵ��㷨160������ֽڳ���
#define SM3192				24	  //�й������Ӵ��㷨192������ֽڳ���
#define SM3256				32    //�й������Ӵ��㷨256������ֽڳ���

#ifdef __cplusplus
extern "C"
{
#endif
	
void SM3Transform(unsigned int state[8], unsigned char buffer[64]);
void SM3_Init(SM3_CTX* context);
void SM3Update(SM3_CTX* context, unsigned char* data, unsigned int len);
void SM3Final(unsigned char *pbDigest, SM3_CTX* context,int outlen);
void SM3_Data( unsigned char* data, unsigned int charlen,unsigned char *digest,unsigned int outlen);

void GBCombine(BYTE *X,					//X
			   unsigned int bytelen1,  //X���ֽڳ�
			   BYTE *Y,					//Y
			   unsigned int bytelen2,	//Y���ֽڳ�
		       BYTE *XY,				//X||Y
		       unsigned int *bytelen3);//X||Y���ֽڳ�
	
int GBKDF(BYTE *Z,						//KDF ������
		  unsigned int bytelen,		//Z ���ֽ���
		  unsigned int klen,			//Klen ������
		  BYTE *ZOut,					//KDF������
		  int Hashlen);					//KDF��Hash�����������ֽڳ���

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SHA1_H_INCLUDED__ */