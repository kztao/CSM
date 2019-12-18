#ifndef __HEADER_SM2_H
#define __HEADER_SM2_H

#include "types.h"

//��������б�
#define  SM2_OK									  0   //������������
#define  SM2_Signature_Illeage                    -1  //ǩ��δͨ��
#define  SM2_Encrypt_Error                        -2 //���ܴ���
#define  SM2_Decrypt_Error                        -3 //���ܴ���

#ifdef  __cplusplus
extern "C" {
#endif
void BNRandom(Word *bn);

int SM2Init();

int SM2GenKey(BYTE *pbPriKey, int *piPriKeyLen, BYTE *pbPubKey, int *piPubKeyLen);

void SM2PointMul(BYTE *pbPriKey, BYTE *pbPubKey, BYTE *pbMul);

int SM2SignHash(BYTE *pbHash, int iHashLen, BYTE *pbPriKey, int iPriKeyLen, BYTE *pbSign, int *piSignLen);

int SM2VerifyHash(BYTE *pbHash, int iHashLen, BYTE *pbPubKey, int iPubKeyLen, BYTE *pbSign, int iSignLen);

int SM2Encrypt(BYTE *pbPlainText, int iPlainTextLen, BYTE *pbPubKey, int iPubKeyLen, BYTE *pbCipherText, int *piCipherTextLen);

int SM2Decrypt(BYTE *pbCipherText, int iCipherTextLen, BYTE *pbPriKey, int iPriKeyLen, BYTE *pbPlainText, int *piPlainTextLen);

#ifdef  __cplusplus
}
#endif

#endif