/* *Copyright (c) 2012, �人��ѧ�����о�����* 
   *All rights reserved.* 
   *
   *�ļ����ƣ�Config.h
   *ժ    Ҫ������ͷ�ļ�
   *��    ��: �����
   *ʱ    ��: 2012.3.14 11:06
   *���°汾: v1.0.0
*/
#ifndef __HEADER_CONFIG_H
#define __HEADER_CONFIG_H

#ifdef  __cplusplus
extern "C" {
#endif


#define BNWORDLEN			8
#define MAXBNWordLen		8
#define WordByteLen			4
#define WordBitLen			32
#define MAXBNByteLen		MAXBNWordLen*WordByteLen
#define MAXBNBitLen			MAXBNByteLen*8
#define MAXPLAINTEXTLEN		1024
#define MAX2BNByteLen       2*MAXBNByteLen
#define HASHLEN             32


#ifdef  __cplusplus
}
#endif

#endif
