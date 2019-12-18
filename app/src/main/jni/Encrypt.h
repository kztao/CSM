#ifndef ENCRYPT_H_
#define ENCRYPT_H_
#include <stdbool.h>
/*
#ifdef __cplusplus
extern "C" {
#endif
*/
CK_ULONG Show_Result(char* func_name, int i, const char* run_type, CK_RV rtn);
CK_ULONG Free_Memory(unsigned int _free_nums, ...);
CK_ULONG Result_Compare(unsigned char* outdata, int outdatalen, unsigned char* srcdata, int srcdatalen);
CK_RV Rv_False_Free_Memory(unsigned int _rv, unsigned int _free_nums, ...) ;

void RandomGenerate(unsigned char* dataaddress, unsigned int cnt);
CK_ULONG xtest_SM2_keytest();
CK_ULONG xtest_SM3Encrypt();
CK_ULONG xtest_SM3Performance(int looptime,int datalen);
CK_ULONG xtest_FindKeyObjectAndDestroy();
CK_ULONG xtest_SM4ECB_Encrypt();
CK_ULONG xtest_SM2calcimportkey(int looptime, int datalen);
CK_ULONG xtest_SM4_KEY(CK_MECHANISM_TYPE mAlgType);
CK_ULONG xtest_ZUC_KEY();
CK_ULONG xtest_ZUCPerformance(int looptime,int datalen);
CK_ULONG xtest_ZUCPerformance_two(int looptime,int datalen);
CK_ULONG xtest_ZUCHashPerformance_withkey(int looptime,int datalen);
CK_ULONG xtest_ZUCHashPerformance_withkey(int looptime,int datalen);
CK_ULONG xtest_SM4ECB_Speed_GenV5(int looptime, int datalen);
CK_ULONG xtest_SM4CBC_Speed(int looptime,int datalen);
CK_ULONG xtest_SM4OFB_Speed_GenV5(int looptime, int datalen);
CK_ULONG xtest_SM2KeyCoordinate_Performace();
CK_ULONG TestUnwrapAll();
CK_ULONG test_WrapKeyOut_Gen();
CK_ULONG xtest_ZUC_MultiSession(int looptime,int datalen);
CK_ULONG xtest_SM3Encrypt_MultiSession();
CK_ULONG xtest_SM4ECB_MultiSession();
CK_ULONG xtest_GenerateKeyPairAndOperateDate();
CK_ULONG xtest_CleanFlags();
CK_ULONG xtest_ZUCPerformance_Extend(int looptime,int datalen);
CK_ULONG xtest_SM4ECB_SM2();
CK_ULONG xtest_ZUC_Extend_MultiSession(int looptime,int datalen);
CK_ULONG xtest_Poweroff();
CK_OBJECT_HANDLE xtest_KeyExchange();
CK_ULONG TT();
CK_ULONG xtest_generatekeytest();
CK_ULONG TTupdate();
CK_ULONG p11_mode_crypt_sm2();
CK_ULONG setcokek();
CK_ULONG BKupdate();
CK_ULONG checkOTP();
CK_ULONG OTPupdate();
CK_ULONG SCdestroyKey();
CK_ULONG setDestroyRND();
CK_ULONG xtest_SM2_signtest();
CK_ULONG xtest_wrapkeybyBKtest();
CK_ULONG xtest_symkey_test();


/*
#ifdef __cplusplus
}
#endif
*/
#endif
