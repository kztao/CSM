#include "skf.h"
#include "devAndAppTest.h"
#include "generaldefine.h"
#include <android/log.h>
#include <string.h>
#include <string>
#include "sm4.h"
#include "../jni/sm2.h"

static DEVHANDLE	hdev = NULL;
static char pszdev[32]  = {0};
static CHAR pApp[1024] = {0};
static HAPPLICATION appHandle = 0;
static HCONTAINER hcont;

///////创建容器(未登录/登录)
string test_createcontainer(){
    ULONG ulRslt = 0;
    string info = "";
    char		*szDevName = NULL;
    ULONG		ulNameLen = 0;
    ULONG  appSize = 0;
    ULONG contSize = 0;
    CHAR contName[1024] = { 0 };
    ULONG contSize2 = 0;
    CHAR contName2[1024] = { 0 };
    ULONG  remainC = 0;

    ulRslt = SKF_EnumDev(1, NULL, &ulNameLen);
    OUT_INFO("SKF_EnumDev(null）,ulNameLen = %lu, ulRslt = %d",ulNameLen,ulRslt);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取设备失败","SKF_EnumDev(null)",info);
    ASSERT_VALUE_NOT("ulNameLen",ulNameLen,0,"No card","SKF_EnumDev",info);

    szDevName = new char[ulNameLen];
    ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
    strncpy(pszdev,szDevName,sizeof(pszdev));
    delete [] szDevName;
    szDevName = NULL;
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"获取设备失败","SKF_EnumDev",info);

    ulRslt = SKF_ConnectDev(pszdev, &hdev);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"连接设备失败","SKF_ConnectDev",info);
    ASSERT_VALUE_NOT("hdev",hdev,NULL,"连接设备失败","SKF_ConnectDev",info);

    ulRslt = SKF_EnumApplication(hdev, pApp, &appSize);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"枚举应用失败","SKF_EnumApplication",info);

    ulRslt = SKF_OpenApplication(hdev, pApp, &appHandle);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"打开应用失败","SKF_OpenApplication",info);
    ASSERT_VALUE("appHandle",NULL,SAR_OK,"打开应用失败","SKF_OpenApplication",info);

    ulRslt = SKF_ClearSecureState(appHandle);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"清除应用安全状态失败","SKF_ClearSecureState",info);

    ulRslt = SKF_EnumContainer(appHandle, NULL, &contSize);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"枚举容器失败","SKF_EnumContainer(null)",info);

    contSize = sizeof(contName);
    memset(contName, 0, sizeof(contName));
    ulRslt = SKF_EnumContainer(appHandle, contName, &contSize);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"枚举容器失败","SKF_EnumContainer",info);

    ulRslt = SKF_CreateContainer(appHandle, TEST_CONTAINER_NAME, &hcont);
    ASSERT_VALUE("ret",ulRslt,SAR_USER_NOT_LOGGED_IN,"无权限创建容器应失败","SKF_CreateContainer",info);

    contSize = sizeof(contName2);
    memset(contName2, 0, sizeof(contName2));
    ulRslt = SKF_EnumContainer(appHandle, contName2, &contSize2);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"枚举容器失败","SKF_EnumContainer",info);
    ASSERT_VALUE("contSize",contSize2,contSize,"枚举容器错误","SKF_EnumContainer",info);
    if(memcmp(contName,contName2,sizeof(contName))){
        info.append("枚举容器错误，结果变化");
        return info;
    }

    ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, USER_PIN, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"验证用户PIN失败","SKF_VerifyPIN",info);

    ulRslt = SKF_CreateContainer(appHandle, TEST_CONTAINER_NAME, &hcont);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"创建容器失败","SKF_CreateContainer",info);

    ulRslt = SKF_ClearSecureState(appHandle);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"清除应用安全状态失败","SKF_ClearSecureState",info);

    contSize = sizeof(contName2);
    memset(contName2, 0, sizeof(contName2));
    ulRslt = SKF_EnumContainer(appHandle, contName2, &contSize2);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"新建后枚举容器失败","SKF_EnumContainer",info);

    if(contSize2<=contSize){
        info.append("新建后枚举容器错误");
        return info;
    }

    ulRslt = SKF_OpenContainer(appHandle, TEST_CONTAINER_NAME, &hcont);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"打开容器失败","SKF_CreateContainer",info);

    return info;
}

/////////生成SM2签名密钥并签名验签以验证正确性
string test_genSignKey(){
    ULONG ulRslt = 0;
    string info = "";
    ECCPUBLICKEYBLOB	eccPubSign = { 0 };
    ULONG  remainC = 0;
    ECCSIGNATUREBLOB	ecc_sign = { 0 };
    ECCSIGNATUREBLOB	ecc_sign2 = { 0 };
    BYTE	pHashData[32] = { 0 };
    ULONG	ulHashDataLen = 32;
    unsigned char pub_key[64] = {0};
    unsigned char signdata[64] = {0};

    ulRslt = SKF_ClearSecureState(appHandle);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"清除应用安全状态失败","SKF_ClearSecureState",info);

    memset(&eccPubSign, 0, sizeof(eccPubSign));
    ulRslt = SKF_GenECCKeyPair(hcont, SGD_SM2_1, &eccPubSign);
    ASSERT_VALUE("ret",ulRslt,SAR_USER_NOT_LOGGED_IN,"无权限生成签名密钥应失败","SKF_GenECCKeyPair",info);

    ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, USER_PIN, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"验证用户PIN失败","SKF_VerifyPIN",info);

    memset(&eccPubSign, 0, sizeof(eccPubSign));
    ulRslt = SKF_GenECCKeyPair(hcont, SGD_SM2_1, &eccPubSign);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"生成签名密钥失败","SKF_GenECCKeyPair",info);
    ASSERT_VALUE("bitlen",eccPubSign.BitLen,256,"生成签名密钥bitlen","SKF_GenECCKeyPair",info);

    //生成随机数作为SM2签名输入
    ulRslt = SKF_GenRandom(hdev, pHashData, ulHashDataLen);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"随机数产生失败","SKF_GenRandom",info);

    memset(&ecc_sign, 0, sizeof(ecc_sign));
    ulRslt = SKF_ECCSignData(hcont, pHashData, ulHashDataLen, &ecc_sign);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"SM2签名失败","SKF_ECCSignData",info);

    //软算法验签
    memcpy(pub_key,eccPubSign.XCoordinate+32,32);
    memcpy(pub_key+32,eccPubSign.YCoordinate+32,32);
    memcpy(signdata,ecc_sign.r+32,32);
    memcpy(signdata+32,ecc_sign.s+32,32);

    SM2Init();
    int soft_verfiy = SM2VerifyHash(pHashData,ulHashDataLen,pub_key,64,signdata,64);
    ASSERT_VALUE("ret",soft_verfiy,0,"软算法验签失败","SKF_ECCSignData",info);

    ulRslt = SKF_ECCVerify(hdev, &eccPubSign, pHashData, ulHashDataLen, &ecc_sign);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"SM2验签失败","SKF_ECCVerify",info);

    ulRslt = SKF_ClearSecureState(appHandle);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"清除应用安全状态失败","SKF_ClearSecureState",info);

    memset(&ecc_sign2, 0, sizeof(ecc_sign2));
    ulRslt = SKF_ECCSignData(hcont, pHashData, ulHashDataLen, &ecc_sign2);
    ASSERT_VALUE_NOT("ret",ulRslt,SAR_OK,"未登录时SM2签名应失败","SKF_ECCSignData",info);

    ulRslt = SKF_ECCVerify(hdev, &eccPubSign, pHashData, ulHashDataLen, &ecc_sign);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"未登录时SM2验签失败","SKF_ECCVerify",info);

    return info;
}

string test_importEncKeypair(){
    ULONG ulRslt = 0;
    string info = "";
    ULONG  remainC = 0;
    ECCPUBLICKEYBLOB	eccSignPub = { 0 };
    ECCPUBLICKEYBLOB	eccEncPub = { 0 };
    ULONG	ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
    unsigned char pub_key[64] = {0};

    BYTE	sesskey[16] = { 0 };
    ULONG	sesskeyLen = sizeof(sesskey);
    sm4_context ctx_sm4;
    BYTE	cipher_sesskey[128] = { 0 };
    int   cipher_sesskeylen = sizeof(cipher_sesskey);
    HANDLE tempKeyHandle = 0;

    ENVELOPEDKEYBLOB cryptKeyEnv = {0};
    unsigned char privKeyExternal[32] = { 0x12, 0xaf, 0x0e, 0x78, 0x13, 0x24, 0x38, 0x1b, 0x12, 0x3a, 0x70, 0x38, 0x7c, 0x55, 0x7a, 0xdb,
		0x2e, 0x7c, 0x03, 0xc2, 0x72, 0xee, 0x20, 0x0b, 0x5a, 0x34, 0x5e, 0x88, 0x21, 0x25, 0x35, 0x39 };
    unsigned char pubKeyExternal[64] = { 0xc1, 0x1d, 0xe2, 0x42, 0x0e, 0xb3, 0xd3, 0xed, 0x02, 0x33, 0xca, 0x1b, 0xba, 0xa4, 0x53, 0x40,
		0xcd, 0xda, 0x2e, 0x8c, 0x95, 0xfb, 0x43, 0xb6, 0x84, 0x3d, 0x91, 0x3b, 0x79, 0x99, 0xdd, 0xea,
		0x6a, 0x55, 0x9a, 0xe8, 0x88, 0x0e, 0xec, 0x92, 0x06, 0x31, 0x98, 0x92, 0xbd, 0xf2, 0xa6, 0xcf,
		0x55, 0xb3, 0x4a, 0x0b, 0x88, 0x80, 0x6d, 0xff, 0x12, 0x45, 0x70, 0x5e, 0x10, 0x16, 0x63, 0x95 };
    unsigned char cipherPrivateKey[32] = { 0 };
    ULONG cipherPrivateKeyLen = 32;

    BLOCKCIPHERPARAM bp = { 0 };

    unsigned char testRandomPlain[32] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, \
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
    unsigned long testRandomLength = 32;
    unsigned char testRandomEncOut[32] = { 0 };
    unsigned long testRandomEncOutLen = 32;
    unsigned char testRandomDecOut[32] = { 0 };
    unsigned long testRandomDecOutLen = 32;
    unsigned char testRandomEncOut2[32] = { 0 };
    unsigned long testRandomEncOutLen2 = 32;


    PECCCIPHERBLOB  cryptSessKey = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB)+128);
    cryptSessKey->CipherLen = 128;

    ulRslt = SKF_ClearSecureState(appHandle);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"清除应用安全状态失败","SKF_ClearSecureState",info);

    //生成随机数作为加密私钥的symkey,并用于打包加密私钥
    ulRslt = SKF_GenRandom(hdev, sesskey, sesskeyLen);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"随机数产生失败","SKF_GenRandom",info);

    sm4_setkey_enc(&ctx_sm4, sesskey);
    sm4_crypt_ecb(&ctx_sm4, SM4_ENCRYPT, sizeof(privKeyExternal), privKeyExternal, cipherPrivateKey);

    //打包会话密钥symkey
    ulRslt = SKF_ExportPublicKey(hcont, TRUE, (BYTE *)&eccSignPub, &ulEccpubLen);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"导出签名公钥失败","SKF_ExportPublicKey",info);

    memcpy(pub_key,eccSignPub.XCoordinate+32,32);
    memcpy(pub_key+32,eccSignPub.YCoordinate+32,32);

    memset(cryptSessKey, 0, sizeof(ECCCIPHERBLOB)+128);
    cryptSessKey->CipherLen = 128;
    ulRslt = SKF_ExtECCEncrypt(hdev, &eccSignPub, sesskey, sesskeyLen, cryptSessKey);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"SM2外部公钥加密失败","SKF_ExtECCEncrypt",info);

    cryptKeyEnv.Version = 1;
    cryptKeyEnv.ulSymmAlgID = SGD_SMS4_ECB;
    cryptKeyEnv.ulBits = 256;
    memset(cryptKeyEnv.cbEncryptedPriKey, 0, 64);
    memcpy(cryptKeyEnv.cbEncryptedPriKey, cipherPrivateKey, cipherPrivateKeyLen);
    cryptKeyEnv.PubKey.BitLen = 256;
    memcpy(cryptKeyEnv.PubKey.XCoordinate + 32, pubKeyExternal, 32);
    memcpy(cryptKeyEnv.PubKey.YCoordinate + 32, pubKeyExternal + 32, 32);
    memcpy(&(cryptKeyEnv.ECCCipherBlob), &cryptSessKey, sizeof(ECCCIPHERBLOB)+128);

    delete[] cryptSessKey;
    cryptSessKey = NULL;

    ulRslt = SKF_ImportECCKeyPair(hcont, &cryptKeyEnv);
    ASSERT_VALUE_NOT("ret",ulRslt,SAR_OK,"导入加密密钥对应失败","SKF_ImportECCKeyPair",info);

    ulRslt = SKF_VerifyPIN(appHandle, USER_TYPE, USER_PIN, &remainC);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"验证用户PIN失败","SKF_VerifyPIN",info);

    ulRslt = SKF_ImportECCKeyPair(hcont, &cryptKeyEnv);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"导入加密密钥对失败","SKF_ImportECCKeyPair",info);

    ulRslt = SKF_ExportPublicKey(hcont, FALSE, (BYTE *)&eccEncPub, &ulEccpubLen);
    int m1 = memcmp(eccEncPub.XCoordinate+32,pubKeyExternal,32);
    int m2 = memcmp(eccEncPub.YCoordinate+32,pubKeyExternal+32,32);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"导出加密公钥失败","SKF_ExportPublicKey",info);
    ASSERT_VALUE("m1",m1,0,"导出加密公钥失败","SKF_ExportPublicKey",info);
    ASSERT_VALUE("m2",m2,0,"导出加密公钥失败","SKF_ExportPublicKey",info);

    SM2Init();
    SM2Encrypt(sesskey, sesskeyLen, pubKeyExternal, sizeof(pubKeyExternal), cipher_sesskey, &cipher_sesskeylen);

    ulRslt = SKF_ImportSessionKey(hcont, SGD_SMS4_ECB, cipher_sesskey, cipher_sesskeylen, &tempKeyHandle);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"导入会话密钥失败","SKF_ImportSessionKey",info);

    ulRslt = SKF_EncryptInit(tempKeyHandle, bp);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"SM4-ECB加密初始化失败","SKF_EncryptInit",info);

    ulRslt = SKF_Encrypt(tempKeyHandle, testRandomPlain, sizeof(testRandomPlain), testRandomEncOut, &testRandomEncOutLen);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"SM4-ECB加密失败","SKF_Encrypt",info);

    sm4_setkey_enc(&ctx_sm4, sesskey);
    sm4_crypt_ecb(&ctx_sm4, SM4_ENCRYPT, sizeof(testRandomPlain),testRandomPlain, testRandomEncOut2);
    int m3 = memcmp(testRandomEncOut,testRandomEncOut2,32);
    ASSERT_VALUE("m3",m3,0,"SM4-ECB加密错误","SKF_Encrypt",info);

    ulRslt = SKF_DecryptInit(tempKeyHandle, bp);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"SM4-ECB解密初始化失败","SKF_DecryptInit",info);

    ulRslt = SKF_Decrypt(tempKeyHandle, testRandomEncOut, testRandomEncOutLen, testRandomDecOut, &testRandomDecOutLen);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"SM4-ECB解密失败","SKF_Decrypt",info);
    int m4 = memcmp(testRandomDecOut,testRandomPlain,32);
    ASSERT_VALUE("m4",m4,0,"SM4-ECB解密错误","SKF_Decrypt",info);

    ulRslt = SKF_ClearSecureState(appHandle);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"清除应用安全状态失败","SKF_ClearSecureState",info);

    ulRslt = SKF_ImportSessionKey(hcont, SGD_SMS4_ECB, cipher_sesskey, cipher_sesskeylen, &tempKeyHandle);
    ASSERT_VALUE_NOT("ret",ulRslt,SAR_OK,"无权限导入会话密钥应失败","SKF_ImportSessionKey",info);

    memset(testRandomEncOut,0,sizeof(testRandomEncOutLen));
    memset(testRandomEncOut2,0,sizeof(testRandomEncOutLen2));
    memset(testRandomDecOut,0,sizeof(testRandomDecOut));

    ulRslt = SKF_EncryptInit(tempKeyHandle, bp);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"未登录时SM4-ECB加密初始化失败","SKF_EncryptInit",info);

    ulRslt = SKF_Encrypt(tempKeyHandle, testRandomPlain, sizeof(testRandomPlain), testRandomEncOut, &testRandomEncOutLen);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"未登录时SM4-ECB加密失败","SKF_Encrypt",info);

    sm4_setkey_enc(&ctx_sm4, sesskey);
    sm4_crypt_ecb(&ctx_sm4, SM4_ENCRYPT, sizeof(testRandomPlain),testRandomPlain, testRandomEncOut2);
    m3 = memcmp(testRandomEncOut,testRandomEncOut2,32);
    ASSERT_VALUE("m3",m3,0,"未登录时SM4-ECB加密错误","SKF_Encrypt",info);

    ulRslt = SKF_DecryptInit(tempKeyHandle, bp);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"未登录时SM4-ECB解密初始化失败","SKF_DecryptInit",info);

    ulRslt = SKF_Decrypt(tempKeyHandle, testRandomEncOut, testRandomEncOutLen, testRandomDecOut, &testRandomDecOutLen);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"未登录时SM4-ECB解密失败","SKF_Decrypt",info);
    m4 = memcmp(testRandomDecOut,testRandomPlain,32);
    ASSERT_VALUE("m4",m4,0,"未登录时SM4-ECB解密错误","SKF_Decrypt",info);

    ulRslt = SKF_CloseHandle(tempKeyHandle);
    ASSERT_VALUE("ret",ulRslt,SAR_OK,"关闭句柄失败","SKF_CloseHandle",info);

    return info;
}


string skf_certTest(){
    string info = "";

    info.append(test_createcontainer());
    if(info!=""){
        info.append("test_createcontainer fail!");
        return info;
    }

    info.append(test_genSignKey());
    if(info!=""){
        info.append("test_genSignKey fail!");
        return info;
    }

    info.append(test_importEncKeypair());
    if(info!=""){
        info.append("test_importEncKeypair fail!");
        return info;
    }

    return info;
}
