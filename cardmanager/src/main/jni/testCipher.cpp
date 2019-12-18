#include "skf.h"
#include <iostream>
#ifdef _WIN32
#include <Windows.h>
#else
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>
#include <stdio.h>

//#define ENABLE_TEST_CALL_P11

using namespace std;

#define JWPIN "123456"

#define ERROR_THROW(r) {if((r) != SAR_OK) {std::cout<<__FILE__<<"["<<dec<<__LINE__<<"] ------------------->>>>>> ERROR_THROW ret = 0x"<<hex<<r<<endl;return 0;}}

#define PRINT_LOG(...)													\
do																		\
{																		\
	printf(__VA_ARGS__);												\
	printf("\n");														\
} while (0)


static void logData(unsigned char * pData, unsigned long ulDataLen)
{
	char buffer0[256] = { 0 };
	int printfRet = 0;
	int currentIdx = 0;
	unsigned int writeIdx = 0;

	for (writeIdx = 0, currentIdx = 0; writeIdx < ulDataLen; writeIdx++)
	{
#ifdef _WIN32
		printfRet = sprintf_s(buffer0 + currentIdx, 256 - currentIdx, "%02x", pData[writeIdx]);
#else
		printfRet = sprintf(buffer0 + currentIdx, "%02x", pData[writeIdx]);
#endif
		if (printfRet <= 0) {return;} // unexpected error
		currentIdx = currentIdx + printfRet;
		if (currentIdx >= 63)
		{
			//__android_log_print(ANDROID_LOG_ERROR, "RCUserObjectDataMgr", "%s", buffer0);
			PRINT_LOG("%s", buffer0);
			currentIdx = 0;
			memset(buffer0, 0, sizeof(buffer0));
		}
	}
	//printf("%s\n", buffer0);
	if (buffer0[0])
	{
		PRINT_LOG("%s", buffer0);
	}

	return;
}



ULONG test2Padding(HANDLE hdev)
{
	ULONG		ulRslt;
	HANDLE		hkey = NULL;
	BLOCKCIPHERPARAM bp = { 0 };
	char *dev_auth_key = "8765432112345678";
	unsigned char inputRaw03[3] = { 31, 32, 33 };
	unsigned char inputRaw04[4] = { 31, 32, 33, 34 };
	unsigned char inputRaw16[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
	unsigned char inputRaw17[17] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
	unsigned char inputRaw20[20] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };
	unsigned char outputCipher[256] = { 0 };
	ULONG outCipherLen = sizeof(outputCipher);
	unsigned char outputPlain[256] = { 0 };
	ULONG outPlainLen = sizeof(outputPlain);

	printf("\n================================== function %s start ===============================\n", __FUNCTION__);

	//char *dev_auth_key = "1234567812345678";
	ULONG padding = 1;
	ulRslt = SKF_SetSymmKey(hdev, (unsigned char*)dev_auth_key, SGD_SMS4_ECB, &hkey);
	ERROR_THROW(ulRslt)

	printf("====== input plain data length 3 test start\n");
	bp.PaddingType = padding;
	ulRslt = SKF_EncryptInit(hkey, bp);
	ERROR_THROW(ulRslt)
	outCipherLen = sizeof(outputCipher);
	memset(outputCipher, 0, sizeof(outputCipher));
	ulRslt = SKF_Encrypt(hkey, inputRaw03, sizeof(inputRaw03), outputCipher, &outCipherLen);
	ERROR_THROW(ulRslt)
	printf("SKF_Encrypt get output length %d for length 3 input plain\n", outCipherLen);
	ulRslt = SKF_DecryptInit(hkey, bp);
	ERROR_THROW(ulRslt)
	outPlainLen = sizeof(outputPlain);
	memset(outputPlain, 0, sizeof(outputPlain));
	ulRslt = SKF_Decrypt(hkey, outputCipher, outCipherLen, outputPlain, &outPlainLen);
	//ulRslt = SKF_Decrypt(hkey, outputCipher, 14, outputPlain, &outPlainLen);
	ERROR_THROW(ulRslt)
	printf("SKF_Decrypt get output length %d for length %d input cipher\n", outPlainLen, outCipherLen);
	logData(outputPlain, outPlainLen);
	printf("====== input plain data length 3 test end\n");

	printf("====== input plain data length 4 test start\n");
	bp.PaddingType = padding;
	ulRslt = SKF_EncryptInit(hkey, bp);
	ERROR_THROW(ulRslt)
	outCipherLen = sizeof(outputCipher);
	memset(outputCipher, 0, sizeof(outputCipher));
	ulRslt = SKF_Encrypt(hkey, inputRaw04, sizeof(inputRaw04), outputCipher, &outCipherLen);
	ERROR_THROW(ulRslt)
	printf("SKF_Encrypt get output length %d for length 4 input plain\n", outCipherLen);
	ulRslt = SKF_DecryptInit(hkey, bp);
	ERROR_THROW(ulRslt)
	outPlainLen = sizeof(outputPlain);
	memset(outputPlain, 0, sizeof(outputPlain));
	ulRslt = SKF_Decrypt(hkey, outputCipher, outCipherLen, outputPlain, &outPlainLen);
	ERROR_THROW(ulRslt)
	printf("SKF_Decrypt get output length %d for length %d input cipher\n", outPlainLen, outCipherLen);
	logData(outputPlain, outPlainLen);
	printf("====== input plain data length 4 test end\n");

	printf("====== input plain data length 16 test start\n");
	bp.PaddingType = padding;
	ulRslt = SKF_EncryptInit(hkey, bp);
	ERROR_THROW(ulRslt)
	outCipherLen = sizeof(outputCipher);
	memset(outputCipher, 0, sizeof(outputCipher));
	ulRslt = SKF_Encrypt(hkey, inputRaw16, sizeof(inputRaw16), outputCipher, &outCipherLen);
	ERROR_THROW(ulRslt)
	printf("SKF_Encrypt get output length %d for length 16 input plain\n", outCipherLen);
	ulRslt = SKF_DecryptInit(hkey, bp);
	ERROR_THROW(ulRslt)
	outPlainLen = sizeof(outputPlain);
	memset(outputPlain, 0, sizeof(outputPlain));
	ulRslt = SKF_Decrypt(hkey, outputCipher, outCipherLen, outputPlain, &outPlainLen);
	ERROR_THROW(ulRslt)
	printf("SKF_Decrypt get output length %d for length %d input cipher\n", outPlainLen, outCipherLen);
	logData(outputPlain, outPlainLen);
	printf("====== input plain data length 16 test end\n");

	printf("====== input plain data length 17 test start\n");
	bp.PaddingType = padding;
	ulRslt = SKF_EncryptInit(hkey, bp);
	ERROR_THROW(ulRslt)
	outCipherLen = sizeof(outputCipher);
	memset(outputCipher, 0, sizeof(outputCipher));
	ulRslt = SKF_Encrypt(hkey, inputRaw17, sizeof(inputRaw17), outputCipher, &outCipherLen);
	ERROR_THROW(ulRslt)
	printf("SKF_Encrypt get output length %d for length 17 input plain\n", outCipherLen);
	ulRslt = SKF_DecryptInit(hkey, bp);
	ERROR_THROW(ulRslt)
	outPlainLen = sizeof(outputPlain);
	memset(outputPlain, 0, sizeof(outputPlain));
	ulRslt = SKF_Decrypt(hkey, outputCipher, outCipherLen, outputPlain, &outPlainLen);
	ERROR_THROW(ulRslt)
	printf("SKF_Decrypt get output length %d for length %d input cipher\n", outPlainLen, outCipherLen);
	logData(outputPlain, outPlainLen);
	printf("====== input plain data length 17 test end\n");

	printf("====== input plain data length 20 test start\n");
	bp.PaddingType = padding;
	ulRslt = SKF_EncryptInit(hkey, bp);
	ERROR_THROW(ulRslt)
	outCipherLen = sizeof(outputCipher);
	memset(outputCipher, 0, sizeof(outputCipher));
	ulRslt = SKF_Encrypt(hkey, inputRaw20, sizeof(inputRaw20), outputCipher, &outCipherLen);
	ERROR_THROW(ulRslt)
	printf("SKF_Encrypt get output length %d for length 20 input plain\n", outCipherLen);
	ulRslt = SKF_DecryptInit(hkey, bp);
	ERROR_THROW(ulRslt)
	outPlainLen = sizeof(outputPlain);
	memset(outputPlain, 0, sizeof(outputPlain));
	ulRslt = SKF_Decrypt(hkey, outputCipher, outCipherLen, outputPlain, &outPlainLen);
	ERROR_THROW(ulRslt)
	printf("SKF_Decrypt get output length %d for length %d input cipher\n", outPlainLen, outCipherLen);
	logData(outputPlain, outPlainLen);
	printf("====== input plain data length 20 test end\n");

	printf("==================================  function %s end  ===============================\n", __FUNCTION__);

	return SAR_OK;
}

ULONG externalSignatureVerification(HANDLE hdev)
{
	ULONG ulRslt = SAR_OK;

	// test if signature by opposite card JW/LongMai can be verified by current card LongMai/JW
	// for JW, raw data from LongMai log2
	ECCPUBLICKEYBLOB pubKeyVerify;
	memset(&pubKeyVerify, 0, sizeof(pubKeyVerify));
	// 0001000000000000000000000000000000000000000000000000000000000000
	// 0000000026c5509187b467264c2912472e1055535cee60ef0414d418fab2cf5c
	// a1e6fc0100000000000000000000000000000000000000000000000000000000
	// 00000000b5fa190b0492422bc6272151224f28515bfe73bc42a8ab5a8fc01958
	// c161a885
	unsigned char pubKeyVerifyValue[] = {
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x26, 0xc5, 0x50, 0x91, 0x87, 0xb4, 0x67, 0x26, 0x4c, 0x29, 0x12, 0x47,
		0x2e, 0x10, 0x55, 0x53, 0x5c, 0xee, 0x60, 0xef, 0x04, 0x14, 0xd4, 0x18, 0xfa, 0xb2, 0xcf, 0x5c,
		0xa1, 0xe6, 0xfc, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xb5, 0xfa, 0x19, 0x0b, 0x04, 0x92, 0x42, 0x2b, 0xc6, 0x27, 0x21, 0x51,
		0x22, 0x4f, 0x28, 0x51, 0x5b, 0xfe, 0x73, 0xbc, 0x42, 0xa8, 0xab, 0x5a, 0x8f, 0xc0, 0x19, 0x58,
		0xc1, 0x61, 0xa8, 0x85 };
	memcpy(&pubKeyVerify, pubKeyVerifyValue, sizeof(pubKeyVerify));

	// 08a5da1e2e379f51231f0d7a189d83cb9e588e1182af05d17aba905c608440f1
	unsigned char rawDataForVerify[] = {
		0x08, 0xa5, 0xda, 0x1e, 0x2e, 0x37, 0x9f, 0x51, 0x23, 0x1f, 0x0d, 0x7a, 0x18, 0x9d, 0x83, 0xcb,
		0x9e, 0x58, 0x8e, 0x11, 0x82, 0xaf, 0x05, 0xd1, 0x7a, 0xba, 0x90, 0x5c, 0x60, 0x84, 0x40, 0xf1 };

	// 0000000000000000000000000000000000000000000000000000000000000000
	// 521305ded0ad032b6d60bf51ecca9ed28f3d6757c5126cadfa947f953146588a
	// 0000000000000000000000000000000000000000000000000000000000000000
	// a44f6256fd9180705f68f5f487b1d110ad5dcf2a383dd6985f3a40d9040c15b9
	unsigned char signatureData[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x52, 0x13, 0x05, 0xde, 0xd0, 0xad, 0x03, 0x2b, 0x6d, 0x60, 0xbf, 0x51, 0xec, 0xca, 0x9e, 0xd2,
		0x8f, 0x3d, 0x67, 0x57, 0xc5, 0x12, 0x6c, 0xad, 0xfa, 0x94, 0x7f, 0x95, 0x31, 0x46, 0x58, 0x8a,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xa4, 0x4f, 0x62, 0x56, 0xfd, 0x91, 0x80, 0x70, 0x5f, 0x68, 0xf5, 0xf4, 0x87, 0xb1, 0xd1, 0x10,
		0xad, 0x5d, 0xcf, 0x2a, 0x38, 0x3d, 0xd6, 0x98, 0x5f, 0x3a, 0x40, 0xd9, 0x04, 0x0c, 0x15, 0xb9 };

	ulRslt = SKF_ECCVerify(hdev, &pubKeyVerify, rawDataForVerify, sizeof(rawDataForVerify), (PECCSIGNATUREBLOB)signatureData);
	//PRINT_LOG("SKF_ECCVerify signature from other manufacture, return 0x%lx", ulRslt);
	ERROR_THROW(ulRslt)

	PRINT_LOG("SKF_ECCVerify signature from other manufacture succeed");

	return ulRslt;
}

ULONG localDigestSignatureVerify(HANDLE hdev, HANDLE hcont)
{
	ULONG ulRslt = SAR_OK;
	ECCPUBLICKEYBLOB	eccPubSign = { 0 };
	ULONG	ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	unsigned char privKeyExternal[32] = { 0x12, 0xaf, 0x0e, 0x78, 0x13, 0x24, 0x38, 0x1b, 0x12, 0x3a, 0x70, 0x38, 0x7c, 0x55, 0x7a, 0xdb, \
		0x2e, 0x7c, 0x03, 0xc2, 0x72, 0xee, 0x20, 0x0b, 0x5a, 0x34, 0x5e, 0x88, 0x21, 0x25, 0x35, 0x39 };
	// public key: 
	// c11de2420eb3d3ed0233ca1bbaa45340cdda2e8c95fb43b6843d913b7999ddea
	// 6a559ae8880eec9206319892bdf2a6cf55b34a0b88806dff1245705e10166395
	unsigned char pubKeyExternal[64] = { 0xc1, 0x1d, 0xe2, 0x42, 0x0e, 0xb3, 0xd3, 0xed, 0x02, 0x33, 0xca, 0x1b, 0xba, 0xa4, 0x53, 0x40, \
		0xcd, 0xda, 0x2e, 0x8c, 0x95, 0xfb, 0x43, 0xb6, 0x84, 0x3d, 0x91, 0x3b, 0x79, 0x99, 0xdd, 0xea, \
		0x6a, 0x55, 0x9a, 0xe8, 0x88, 0x0e, 0xec, 0x92, 0x06, 0x31, 0x98, 0x92, 0xbd, 0xf2, 0xa6, 0xcf, \
		0x55, 0xb3, 0x4a, 0x0b, 0x88, 0x80, 0x6d, 0xff, 0x12, 0x45, 0x70, 0x5e, 0x10, 0x16, 0x63, 0x95 };
	unsigned char expectedHashOut[] = { 0x08, 0xa5, 0xda, 0x1e, 0x2e, 0x37, 0x9f, 0x51, 0x23, 0x1f, 0x0d, 0x7a, 0x18, 0x9d, 0x83, 0xcb, \
										0x9e, 0x58, 0x8e, 0x11, 0x82, 0xaf, 0x05, 0xd1, 0x7a, 0xba, 0x90, 0x5c, 0x60, 0x84, 0x40, 0xf1 };
	ECCPUBLICKEYBLOB externalPubKeyStruct;
	memset(&externalPubKeyStruct, 0, sizeof(externalPubKeyStruct));
	ECCPRIVATEKEYBLOB externalPrivKeyStruct;
	memset(&externalPrivKeyStruct, 0, sizeof(externalPrivKeyStruct));
	externalPubKeyStruct.BitLen = 256;
	memcpy(externalPubKeyStruct.XCoordinate + 32, pubKeyExternal, 32);
	memcpy(externalPubKeyStruct.YCoordinate + 32, pubKeyExternal + 32, 32);
	externalPrivKeyStruct.BitLen = 256;
	memcpy(externalPrivKeyStruct.PrivateKey + 32, privKeyExternal, 32);
	HANDLE hHash = NULL;
	ECCSIGNATUREBLOB	ecc_sign = { 0 };
	BYTE	pHashData[256] = { 0 };
	ULONG	ulHashDataLen = 256;
	char *pubid = "1234567812345678";

	memset(&eccPubSign, 0, sizeof(eccPubSign));
	ulRslt = SKF_ExportPublicKey(hcont, TRUE, (BYTE *)(&eccPubSign), &ulEccpubLen);
	//PRINT_LOG("SKF_ExportPublicKey, hcont = %p, return 0x%lx, ulEccpubLen %ld", hcont, ulRslt, ulEccpubLen);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DigestInit(hdev, SGD_SM3, &externalPubKeyStruct, (BYTE *)pubid, 16, &hHash);
	//PRINT_LOG("SKF_DigestInit, hdev = %p, return 0x%lx, hHash = %p", hdev, ulRslt, hHash);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_Digest(hHash, (BYTE *)pubid, 16, NULL, &ulHashDataLen);
	ERROR_THROW(ulRslt)
		
	if (ulHashDataLen > 5) {
		ULONG ulHashDataLenBak = ulHashDataLen;
		ulHashDataLen = ulHashDataLen -3;
		ulRslt = SKF_Digest(hHash, (BYTE *)pubid, 16, pHashData, &ulHashDataLen);
		//PRINT_LOG("SKF_Digest return 0x%x", ulRslt);
		if(SAR_BUFFER_TOO_SMALL == ulRslt) {
			ulRslt = SAR_OK;
		}
		else {
			ulRslt = SAR_FAIL;
		}
		ERROR_THROW(ulRslt)
		ulHashDataLen = ulHashDataLenBak;
	}
	
	memset(pHashData, 0, sizeof(pHashData));
	ulRslt = SKF_Digest(hHash, (BYTE *)pubid, 16, pHashData, &ulHashDataLen);
	//PRINT_LOG("SKF_Digest, hHash = %p, return 0x%lx, ulHashDataLen = %ld", hHash, ulRslt, ulHashDataLen);
	ERROR_THROW(ulRslt)

	// hash result check
	ULONG diff = memcmp(pHashData, expectedHashOut, sizeof(expectedHashOut));
	if (diff)
	{
		PRINT_LOG("digest result incorrect, failed");
		ulRslt = SAR_FAIL;
	}
	else
	{
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CloseHandle(hHash);
	//PRINT_LOG("SKF_CloseHandle %p get result 0x%lx", hHash, ulRslt);
	ERROR_THROW(ulRslt)

	PRINT_LOG("SKF 2 step digest with pre-process operation succeed");

	memset(&ecc_sign, 0, sizeof(ecc_sign));
	ulRslt = SKF_ECCSignData(hcont, pHashData, ulHashDataLen, &ecc_sign);
	//PRINT_LOG("SKF_ECCSignData, hcont = %p, return 0x%lx", hcont, ulRslt);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ECCVerify(hdev, &eccPubSign, pHashData, ulHashDataLen, &ecc_sign);
	//PRINT_LOG("SKF_ECCVerify, hdev = %p, return 0x%lx", hdev, ulRslt);
	ERROR_THROW(ulRslt)

	PRINT_LOG("SKF sign verify operation succeed");

	// check 3 section hash without pre-process
	ulRslt = SKF_DigestInit(hdev, SGD_SM3, NULL, NULL, 0, &hHash);
	//PRINT_LOG("SKF_DigestInit, hdev = %p, return 0x%lx, hHash = %p:", hdev, ulRslt, hHash);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DigestUpdate(hHash, (BYTE *)pubid, 16);
	//PRINT_LOG("SKF_DigestUpdate, hHash = %p, return 0x%lx", hHash, ulRslt);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DigestUpdate(hHash, (BYTE *)pubid, 16);
	//PRINT_LOG("SKF_DigestUpdate, hHash = %p, return 0x%lx", hHash, ulRslt);
	ERROR_THROW(ulRslt)


	ulRslt = SKF_DigestFinal(hHash, NULL, &ulHashDataLen);
	ERROR_THROW(ulRslt)
		
	if (ulHashDataLen > 5) {
		memset(pHashData, 0, sizeof(pHashData));
		ULONG ulHashDataLenBak = ulHashDataLen;
		ulHashDataLen = ulHashDataLen -3;
		ulRslt = SKF_DigestFinal(hHash, pHashData, &ulHashDataLen);
		if(SAR_BUFFER_TOO_SMALL == ulRslt) {
			ulRslt = SAR_OK;
		}
		else {
			ulRslt = SAR_FAIL;
		}
		ERROR_THROW(ulRslt)
		ulHashDataLen = ulHashDataLenBak;
	}
	
	memset(pHashData, 0, sizeof(pHashData));
	ulRslt = SKF_DigestFinal(hHash, pHashData, &ulHashDataLen);
	//PRINT_LOG("SKF_DigestFinal, hHash = %p, return 0x%lx, ulHashDataLen = %ld", hHash, ulRslt, ulHashDataLen);
	ERROR_THROW(ulRslt)

	PRINT_LOG("SKF 3 step digest operation succeed");

	return ulRslt;
}


ULONG importSm2KeyPair(HANDLE hdev, HANDLE hcont)
{
	ULONG ulRslt = SAR_OK;

	ECCPUBLICKEYBLOB	eccPubSign = { 0 };
	ULONG	ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	BLOCKCIPHERPARAM bp = { 0 };
	unsigned char tempSessKey[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
	// private key: 
	// 12af0e781324381b123a70387c557adb2e7c03c272ee200b5a345e8821253539
	unsigned char privKeyExternal[32] = { 0x12, 0xaf, 0x0e, 0x78, 0x13, 0x24, 0x38, 0x1b, 0x12, 0x3a, 0x70, 0x38, 0x7c, 0x55, 0x7a, 0xdb, \
		0x2e, 0x7c, 0x03, 0xc2, 0x72, 0xee, 0x20, 0x0b, 0x5a, 0x34, 0x5e, 0x88, 0x21, 0x25, 0x35, 0x39 };
	// public key: 
	// c11de2420eb3d3ed0233ca1bbaa45340cdda2e8c95fb43b6843d913b7999ddea
	// 6a559ae8880eec9206319892bdf2a6cf55b34a0b88806dff1245705e10166395
	unsigned char pubKeyExternal[64] = { 0xc1, 0x1d, 0xe2, 0x42, 0x0e, 0xb3, 0xd3, 0xed, 0x02, 0x33, 0xca, 0x1b, 0xba, 0xa4, 0x53, 0x40, \
		0xcd, 0xda, 0x2e, 0x8c, 0x95, 0xfb, 0x43, 0xb6, 0x84, 0x3d, 0x91, 0x3b, 0x79, 0x99, 0xdd, 0xea, \
		0x6a, 0x55, 0x9a, 0xe8, 0x88, 0x0e, 0xec, 0x92, 0x06, 0x31, 0x98, 0x92, 0xbd, 0xf2, 0xa6, 0xcf, \
		0x55, 0xb3, 0x4a, 0x0b, 0x88, 0x80, 0x6d, 0xff, 0x12, 0x45, 0x70, 0x5e, 0x10, 0x16, 0x63, 0x95 };
	ECCPUBLICKEYBLOB externalPubKeyStruct;
	memset(&externalPubKeyStruct, 0, sizeof(externalPubKeyStruct));
	ECCPRIVATEKEYBLOB externalPrivKeyStruct;
	memset(&externalPrivKeyStruct, 0, sizeof(externalPrivKeyStruct));
	externalPubKeyStruct.BitLen = 256;
	memcpy(externalPubKeyStruct.XCoordinate + 32, pubKeyExternal, 32);
	memcpy(externalPubKeyStruct.YCoordinate + 32, pubKeyExternal + 32, 32);
	externalPrivKeyStruct.BitLen = 256;
	memcpy(externalPrivKeyStruct.PrivateKey + 32, privKeyExternal, 32);

	PECCCIPHERBLOB  cryptSessKey = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB)+128);
    cryptSessKey->CipherLen = 128;
	PENVELOPEDKEYBLOB cryptKeyEnv = (PENVELOPEDKEYBLOB)malloc(sizeof(ENVELOPEDKEYBLOB)+128);
	memset(cryptKeyEnv, 0, sizeof(ENVELOPEDKEYBLOB)+128);
    cryptKeyEnv->ECCCipherBlob.CipherLen = 128;
	HANDLE tempKeyHandle = 0;
	unsigned char cipherPrivateKey[128] = { 0 };
	ULONG cipherPrivateKeyLen = 128;
	// step 2.1, get signature public key
	memset(&eccPubSign, 0, sizeof(eccPubSign));
	ulEccpubLen = sizeof(eccPubSign);
	ulRslt = SKF_ExportPublicKey(hcont, TRUE, (BYTE *)&eccPubSign, &ulEccpubLen);
	//PRINT_LOG("SKF_ExportPublicKey to get signature, hcont = %p, return 0x%lx, signPubkeyLen = %ld", hcont, ulRslt, ulEccpubLen);
	ERROR_THROW(ulRslt)

	// step 2.2, encrypt SM4 key with signature public key
	memset(cryptSessKey, 0, sizeof(ECCCIPHERBLOB)+128);
    cryptSessKey->CipherLen = 128;
	ulRslt = SKF_ExtECCEncrypt(hdev, &eccPubSign, tempSessKey, 16, cryptSessKey);
	//PRINT_LOG("SKF_ExtECCEncrypt to crypted session key, return 0x%lx", ulRslt);
	ERROR_THROW(ulRslt)


	// step 3, encrypt crypt private key with SM4 key
	// step 3.1, set sym key
	ulRslt = SKF_SetSymmKey(hdev, (unsigned char*)tempSessKey, SGD_SMS4_ECB, &tempKeyHandle);
	//PRINT_LOG("SKF_SetSymmKey get result 0x%lx and return keyHandle %p", ulRslt, tempKeyHandle);
	ERROR_THROW(ulRslt)
	// step 3.2 encrypt crypt private key
	ulRslt = SKF_EncryptInit(tempKeyHandle, bp);
	//PRINT_LOG("SKF_EncryptInit get result 0x%lx", ulRslt);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_Encrypt(tempKeyHandle, (unsigned char *)externalPrivKeyStruct.PrivateKey, sizeof(externalPrivKeyStruct.PrivateKey), cipherPrivateKey, &cipherPrivateKeyLen);
	//PRINT_LOG("SKF_Encrypt get result 0x%lx and return cipherPrivateKeyLen %ld", ulRslt, cipherPrivateKeyLen);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CloseHandle(tempKeyHandle);
	//PRINT_LOG("SKF_CloseHandle %p get result 0x%lx", tempKeyHandle, ulRslt);
	ERROR_THROW(ulRslt)

	// assembly input keypair parameter
	cryptKeyEnv->Version = 1;
	//cryptKeyEnv->Version = 0x01000000;
	cryptKeyEnv->ulSymmAlgID = SGD_SMS4_ECB;
	cryptKeyEnv->ulBits = 256;
	//cryptKeyEnv->ulBits = 0x80000000;
	memset(cryptKeyEnv->cbEncryptedPriKey, 0, 64);
	memcpy(cryptKeyEnv->cbEncryptedPriKey, cipherPrivateKey, cipherPrivateKeyLen);
	cryptKeyEnv->PubKey.BitLen = 256;
	//cryptKeyEnv->PubKey.BitLen = 0x00010000;
	memcpy(cryptKeyEnv->PubKey.XCoordinate + 32, pubKeyExternal, 32);
	memcpy(cryptKeyEnv->PubKey.YCoordinate + 32, pubKeyExternal + 32, 32);
	memcpy(&(cryptKeyEnv->ECCCipherBlob), cryptSessKey, sizeof(ECCCIPHERBLOB)+128);

	// step 4, import crypt key pair
	ulRslt = SKF_ImportECCKeyPair(hcont, cryptKeyEnv);
	//PRINT_LOG("SKF_ImportECCKeyPair, return 0x%lx", ulRslt);
	ERROR_THROW(ulRslt)

	PRINT_LOG("SKF import keypair operation succeed");

	return ulRslt;
}

ULONG sessionKeyExportImport(HANDLE hdev, HANDLE hcont)
{
	ULONG ulRslt = SAR_OK;
	HANDLE tempKeyHandle1 = 0;
	BLOCKCIPHERPARAM bp = { 0 };

	// private key: 
	// 12af0e781324381b123a70387c557adb2e7c03c272ee200b5a345e8821253539
	unsigned char privKeyExternal[32] = { 0x12, 0xaf, 0x0e, 0x78, 0x13, 0x24, 0x38, 0x1b, 0x12, 0x3a, 0x70, 0x38, 0x7c, 0x55, 0x7a, 0xdb, \
		0x2e, 0x7c, 0x03, 0xc2, 0x72, 0xee, 0x20, 0x0b, 0x5a, 0x34, 0x5e, 0x88, 0x21, 0x25, 0x35, 0x39 };
	// public key: 
	// c11de2420eb3d3ed0233ca1bbaa45340cdda2e8c95fb43b6843d913b7999ddea
	// 6a559ae8880eec9206319892bdf2a6cf55b34a0b88806dff1245705e10166395
	unsigned char pubKeyExternal[64] = { 0xc1, 0x1d, 0xe2, 0x42, 0x0e, 0xb3, 0xd3, 0xed, 0x02, 0x33, 0xca, 0x1b, 0xba, 0xa4, 0x53, 0x40, \
		0xcd, 0xda, 0x2e, 0x8c, 0x95, 0xfb, 0x43, 0xb6, 0x84, 0x3d, 0x91, 0x3b, 0x79, 0x99, 0xdd, 0xea, \
		0x6a, 0x55, 0x9a, 0xe8, 0x88, 0x0e, 0xec, 0x92, 0x06, 0x31, 0x98, 0x92, 0xbd, 0xf2, 0xa6, 0xcf, \
		0x55, 0xb3, 0x4a, 0x0b, 0x88, 0x80, 0x6d, 0xff, 0x12, 0x45, 0x70, 0x5e, 0x10, 0x16, 0x63, 0x95 };
	ECCPUBLICKEYBLOB externalPubKeyStruct;
	memset(&externalPubKeyStruct, 0, sizeof(externalPubKeyStruct));
	ECCPRIVATEKEYBLOB externalPrivKeyStruct;
	memset(&externalPrivKeyStruct, 0, sizeof(externalPrivKeyStruct));
	externalPubKeyStruct.BitLen = 256;
	memcpy(externalPubKeyStruct.XCoordinate + 32, pubKeyExternal, 32);
	memcpy(externalPubKeyStruct.YCoordinate + 32, pubKeyExternal + 32, 32);
	externalPrivKeyStruct.BitLen = 256;
	memcpy(externalPrivKeyStruct.PrivateKey + 32, privKeyExternal, 32);

	PECCCIPHERBLOB  tempCipherKey = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB)+128);
	memset(tempCipherKey, 0, sizeof(ECCCIPHERBLOB)+128);

	ulRslt = SKF_ECCExportSessionKey(hcont, SGD_SMS4_ECB, &externalPubKeyStruct, tempCipherKey, &tempKeyHandle1);
	if(SAR_BUFFER_TOO_SMALL == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	
    tempCipherKey->CipherLen = 128;
	// test export session key interface
	ulRslt = SKF_ECCExportSessionKey(hcont, SGD_SMS4_ECB, &externalPubKeyStruct, tempCipherKey, &tempKeyHandle1);
	//PRINT_LOG("SKF_ECCExportSessionKey, return 0x%lx tempKeyHandle1 %p", ulRslt, tempKeyHandle1);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CloseHandle(tempKeyHandle1);
	//PRINT_LOG("SKF_CloseHandle %p get result 0x%lx", tempKeyHandle1, ulRslt);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_EncryptInit(tempKeyHandle1, bp);
	PRINT_LOG("SKF_EncryptInit, return 0x%lx for closed key handle %p", ulRslt, tempKeyHandle1);

	// opposite side SKF_ECCExportSessionKey output: generated key
	// below key exported from LongMai SKF, verify if can import successfully
#if 0
	0000000000000000000000000000000000000000000000000000000000000000
		53f6cb280fc3c08e70c832c91eff3fd4862d220c580b9644f0343ecf4ed11cba
		0000000000000000000000000000000000000000000000000000000000000000
		c23475ec68748f7247dc496546bdb9b24cf7855c3766670c39592c9887db25a8
		426fc01f7b9f9046222bb41114b4cfdff033ed512162e829ecbef4543d899d9c
		10000000c908460409b3707d9e4c8b70615aa121
#endif
		unsigned char oppositeSideKeyCipher[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x53, 0xf6, 0xcb, 0x28, 0x0f, 0xc3, 0xc0, 0x8e, 0x70, 0xc8, 0x32, 0xc9, 0x1e, 0xff, 0x3f, 0xd4,
		0x86, 0x2d, 0x22, 0x0c, 0x58, 0x0b, 0x96, 0x44, 0xf0, 0x34, 0x3e, 0xcf, 0x4e, 0xd1, 0x1c, 0xba,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc2, 0x34, 0x75, 0xec, 0x68, 0x74, 0x8f, 0x72, 0x47, 0xdc, 0x49, 0x65, 0x46, 0xbd, 0xb9, 0xb2,
		0x4c, 0xf7, 0x85, 0x5c, 0x37, 0x66, 0x67, 0x0c, 0x39, 0x59, 0x2c, 0x98, 0x87, 0xdb, 0x25, 0xa8,
		0x42, 0x6f, 0xc0, 0x1f, 0x7b, 0x9f, 0x90, 0x46, 0x22, 0x2b, 0xb4, 0x11, 0x14, 0xb4, 0xcf, 0xdf,
		0xf0, 0x33, 0xed, 0x51, 0x21, 0x62, 0xe8, 0x29, 0xec, 0xbe, 0xf4, 0x54, 0x3d, 0x89, 0x9d, 0x9c,
		0x10, 0x00, 0x00, 0x00, 0xc9, 0x08, 0x46, 0x04, 0x09, 0xb3, 0x70, 0x7d, 0x9e, 0x4c, 0x8b, 0x70,
		0x61, 0x5a, 0xa1, 0x21 };
	ulRslt = SKF_ImportSessionKey(hcont, SGD_SMS4_ECB, oppositeSideKeyCipher, sizeof(oppositeSideKeyCipher), &tempKeyHandle1);
	//PRINT_LOG("SKF_ImportSessionKey, return 0x%lx tempKeyHandle1 %p", ulRslt, tempKeyHandle1);
	ERROR_THROW(ulRslt)

	PRINT_LOG("SKF import session key operation succeed");

	return ulRslt;
}

// two session key generated in this code, only one closed before exit
ULONG sessionKeyEncDec(HANDLE hdev, HANDLE hcont, ULONG ulAlgId, BYTE * iv, ULONG ivLen)
{
	ULONG ulRslt = SAR_OK;

	ECCPUBLICKEYBLOB	eccPubEnc = { 0 };
	ULONG	ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	BLOCKCIPHERPARAM bp = { 0 };
	PECCCIPHERBLOB  tempCipherKey = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB)+128);
	memset(tempCipherKey, 0, sizeof(ECCCIPHERBLOB)+128);
    tempCipherKey->CipherLen = 128;
	HANDLE sessionKeyHandleExport = 0;
	HANDLE sessionKeyHandleImport = 0;

	unsigned char testRandomPlain[32] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, \
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
	unsigned long testRandomLength = 32;
	unsigned char testRandomEncOut[32] = { 0 };
	unsigned long testRandomEncOutLen = 32;
	unsigned char testRandomDecOut[32] = { 0 };
	unsigned long testRandomDecOutLen = 32;
	unsigned char testRandomEncOut2[32] = { 0 };
	unsigned long testRandomEncOutLen2 = 32;
	unsigned char testRandomDecOut2[32] = { 0 };
	unsigned long testRandomDecOutLen2 = 32;

	bp.IVLen = ivLen;
#ifdef _WIN32
	memcpy_s(bp.IV, MAX_IV_LEN, iv, ivLen);
#else
	memcpy(bp.IV, iv, ivLen);
#endif

	memset(&eccPubEnc, 0, sizeof(eccPubEnc));
	ulEccpubLen = 0;

	ulRslt = SKF_ExportPublicKey(hcont, FALSE, NULL, &ulEccpubLen);
	//PRINT_LOG("SKF_ExportPublicKey hcont = %p, return 0x%lx, PubkeyLen = %ld", hcont, ulRslt, ulEccpubLen);
	if (sizeof(eccPubEnc) != ulEccpubLen) {
		ulRslt = SAR_FAIL;
		}
	ERROR_THROW(ulRslt)

	ulEccpubLen = sizeof(eccPubEnc) - 5;
	ulRslt = SKF_ExportPublicKey(hcont, FALSE, (BYTE *)&eccPubEnc, &ulEccpubLen);
	if (SAR_BUFFER_TOO_SMALL != ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	//PRINT_LOG("SKF_ExportPublicKey hcont = %p, return 0x%lx, PubkeyLen = %ld", hcont, ulRslt, ulEccpubLen);
	ERROR_THROW(ulRslt)

	ulEccpubLen = sizeof(eccPubEnc);
	ulRslt = SKF_ExportPublicKey(hcont, FALSE, (BYTE *)&eccPubEnc, &ulEccpubLen);
	//PRINT_LOG("SKF_ExportPublicKey hcont = %p, return 0x%lx, PubkeyLen = %ld", hcont, ulRslt, ulEccpubLen);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ECCExportSessionKey(hcont, ulAlgId, &eccPubEnc, tempCipherKey, &sessionKeyHandleExport);
	//PRINT_LOG("SKF_ECCExportSessionKey, return 0x%lx tempKeyHandle1 %p", ulRslt, sessionKeyHandleExport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ImportSessionKey(hcont, ulAlgId, (BYTE *)tempCipherKey, sizeof(ECCCIPHERBLOB)+128, &sessionKeyHandleImport);
	//PRINT_LOG("SKF_ImportSessionKey, return 0x%lx tempKeyHandle1 %p", ulRslt, sessionKeyHandleImport);
	ERROR_THROW(ulRslt)

	//=================================================================================================================
	// 2 section operation verification, enc/dec done with generated key
	memset(testRandomEncOut, 0, sizeof(testRandomEncOut));
	testRandomEncOutLen = 32;
	memset(testRandomDecOut, 0, sizeof(testRandomDecOut));
	testRandomDecOutLen = 32;

	ulRslt = SKF_EncryptInit(sessionKeyHandleExport, bp);
	//PRINT_LOG("SKF_EncryptInit, return 0x%lx sessionKeyHandleExport %p", ulRslt, sessionKeyHandleExport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_Encrypt(sessionKeyHandleExport, (unsigned char *)testRandomPlain, 32, testRandomEncOut, &testRandomEncOutLen);
	//PRINT_LOG("SKF_Encrypt, return 0x%lx sessionKeyHandleExport %p", ulRslt, sessionKeyHandleExport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DecryptInit(sessionKeyHandleExport, bp);
	//PRINT_LOG("SKF_DecryptInit, return 0x%lx sessionKeyHandleExport %p", ulRslt, sessionKeyHandleExport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_Decrypt(sessionKeyHandleExport, testRandomEncOut, testRandomEncOutLen, testRandomDecOut, &testRandomDecOutLen);
	//PRINT_LOG("SKF_Decrypt, return 0x%lx sessionKeyHandleExport %p", ulRslt, sessionKeyHandleExport);
	ERROR_THROW(ulRslt)

	// dec output should be same as enc input
	ULONG diff = memcmp(testRandomPlain, testRandomDecOut, sizeof(testRandomPlain));
	if (0 != diff)
	{
		ERROR_THROW(diff)
	}

	PRINT_LOG("SKF 2 step encrypt decrypt operation with generated session key succeed");

	// 2 section operation verification, enc/dec done with imported key
	memset(testRandomEncOut2, 0, sizeof(testRandomEncOut2));
	testRandomEncOutLen2 = 32;
	memset(testRandomDecOut2, 0, sizeof(testRandomDecOut2));
	testRandomDecOutLen2 = 32;
	ulRslt = SKF_EncryptInit(sessionKeyHandleImport, bp);
	//PRINT_LOG("SKF_EncryptInit, return 0x%lx sessionKeyHandleImport %p", ulRslt, sessionKeyHandleImport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_Encrypt(sessionKeyHandleImport, (unsigned char *)testRandomPlain, 32, testRandomEncOut2, &testRandomEncOutLen2);
	//PRINT_LOG("SKF_Encrypt, return 0x%lx sessionKeyHandleImport %p", ulRslt, sessionKeyHandleImport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DecryptInit(sessionKeyHandleImport, bp);
	//PRINT_LOG("SKF_DecryptInit, return 0x%lx sessionKeyHandleImport %p", ulRslt, sessionKeyHandleImport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_Decrypt(sessionKeyHandleImport, testRandomEncOut2, testRandomEncOutLen2, testRandomDecOut2, &testRandomDecOutLen2);
	//PRINT_LOG("SKF_Decrypt, return 0x%lx sessionKeyHandleImport %p", ulRslt, sessionKeyHandleImport);
	ERROR_THROW(ulRslt)

	// dec output should be same as enc input
	diff = memcmp(testRandomPlain, testRandomDecOut2, sizeof(testRandomPlain));
	if (0 != diff)
	{
		ERROR_THROW(diff)
	}
	// both key shall get same encrypted output
	diff = memcmp(testRandomEncOut, testRandomEncOut2, testRandomEncOutLen2);
	if (0 != diff)
	{
		ERROR_THROW(diff)
	}

	PRINT_LOG("SKF 2 step encrypt decrypt operation with imported session key succeed");
	//=================================================================================================================
	// end of 2 section verification, check 3 section operation
	//=================================================================================================================
	memset(testRandomEncOut, 0, sizeof(testRandomEncOut));
	testRandomEncOutLen = 32;
	memset(testRandomDecOut, 0, sizeof(testRandomDecOut));
	testRandomDecOutLen = 32;
	ulRslt = SKF_EncryptInit(sessionKeyHandleExport, bp);
	//PRINT_LOG("SKF_EncryptInit, return 0x%lx sessionKeyHandleExport %p", ulRslt, sessionKeyHandleExport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_EncryptUpdate(sessionKeyHandleExport, (unsigned char *)testRandomPlain, 16, testRandomEncOut, &testRandomEncOutLen);
	//PRINT_LOG("SKF_EncryptUpdate, return 0x%lx sessionKeyHandleExport %p", ulRslt, sessionKeyHandleExport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_EncryptUpdate(sessionKeyHandleExport, (unsigned char *)testRandomPlain + 16, 16, testRandomEncOut + 16, &testRandomEncOutLen);
	//PRINT_LOG("SKF_EncryptUpdate, return 0x%lx sessionKeyHandleExport %p", ulRslt, sessionKeyHandleExport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_EncryptFinal(sessionKeyHandleExport, testRandomEncOut, &testRandomEncOutLen);
	//PRINT_LOG("SKF_EncryptFinal, return 0x%lx sessionKeyHandleExport %p", ulRslt, sessionKeyHandleExport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DecryptInit(sessionKeyHandleExport, bp);
	//PRINT_LOG("SKF_DecryptInit, return 0x%lx sessionKeyHandleExport %p", ulRslt, sessionKeyHandleExport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DecryptUpdate(sessionKeyHandleExport, testRandomEncOut, 16, testRandomDecOut, &testRandomDecOutLen);
	//PRINT_LOG("SKF_DecryptUpdate, return 0x%lx sessionKeyHandleExport %p", ulRslt, sessionKeyHandleExport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DecryptUpdate(sessionKeyHandleExport, testRandomEncOut + 16, 16, testRandomDecOut + 16, &testRandomDecOutLen);
	//PRINT_LOG("SKF_DecryptUpdate, return 0x%lx sessionKeyHandleExport %p", ulRslt, sessionKeyHandleExport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DecryptFinal(sessionKeyHandleExport, testRandomDecOut, &testRandomDecOutLen);
	//PRINT_LOG("SKF_DecryptFinal, return 0x%lx sessionKeyHandleExport %p", ulRslt, sessionKeyHandleExport);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CloseHandle(sessionKeyHandleExport);
	//PRINT_LOG("SKF_CloseHandle %p get result 0x%lx", sessionKeyHandleExport, ulRslt);
	ERROR_THROW(ulRslt)

	diff = memcmp(testRandomPlain, testRandomDecOut, sizeof(testRandomPlain));
	if (0 != diff)
	{
		ERROR_THROW(diff)
	}

	PRINT_LOG("SKF 3 step encrypt decrypt operation with generated session key succeed");

	ulRslt = SAR_OK;

	return ulRslt;

}

ULONG extEccOperationTest(HANDLE hdev, HANDLE hcont)
{
	ULONG ulRslt = SAR_OK;

	unsigned char inputRaw[32] = {0};
	
	// private key: 
	// 12af0e781324381b123a70387c557adb2e7c03c272ee200b5a345e8821253539
	unsigned char privKeyExternal[32] = { 0x12, 0xaf, 0x0e, 0x78, 0x13, 0x24, 0x38, 0x1b, 0x12, 0x3a, 0x70, 0x38, 0x7c, 0x55, 0x7a, 0xdb, \
		0x2e, 0x7c, 0x03, 0xc2, 0x72, 0xee, 0x20, 0x0b, 0x5a, 0x34, 0x5e, 0x88, 0x21, 0x25, 0x35, 0x39 };
	// public key: 
	// c11de2420eb3d3ed0233ca1bbaa45340cdda2e8c95fb43b6843d913b7999ddea
	// 6a559ae8880eec9206319892bdf2a6cf55b34a0b88806dff1245705e10166395
	unsigned char pubKeyExternal[64] = { 0xc1, 0x1d, 0xe2, 0x42, 0x0e, 0xb3, 0xd3, 0xed, 0x02, 0x33, 0xca, 0x1b, 0xba, 0xa4, 0x53, 0x40, \
		0xcd, 0xda, 0x2e, 0x8c, 0x95, 0xfb, 0x43, 0xb6, 0x84, 0x3d, 0x91, 0x3b, 0x79, 0x99, 0xdd, 0xea, \
		0x6a, 0x55, 0x9a, 0xe8, 0x88, 0x0e, 0xec, 0x92, 0x06, 0x31, 0x98, 0x92, 0xbd, 0xf2, 0xa6, 0xcf, \
		0x55, 0xb3, 0x4a, 0x0b, 0x88, 0x80, 0x6d, 0xff, 0x12, 0x45, 0x70, 0x5e, 0x10, 0x16, 0x63, 0x95 };
	ECCPUBLICKEYBLOB externalPubKeyStruct;
	memset(&externalPubKeyStruct, 0, sizeof(externalPubKeyStruct));
	ECCPRIVATEKEYBLOB externalPrivKeyStruct;
	memset(&externalPrivKeyStruct, 0, sizeof(externalPrivKeyStruct));
	externalPubKeyStruct.BitLen = 256;
	memcpy(externalPubKeyStruct.XCoordinate + 32, pubKeyExternal, 32);
	memcpy(externalPubKeyStruct.YCoordinate + 32, pubKeyExternal + 32, 32);
	externalPrivKeyStruct.BitLen = 256;
	memcpy(externalPrivKeyStruct.PrivateKey + 32, privKeyExternal, 32);

	memcpy(inputRaw, privKeyExternal, 32);
	ECCSIGNATUREBLOB mySign;
	memset(&mySign, 0, sizeof(mySign));
	ulRslt = SKF_ExtECCSign(hdev, &externalPrivKeyStruct, inputRaw, 32, &mySign);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ExtECCVerify(hdev, &externalPubKeyStruct, inputRaw, 32, &mySign);
	ERROR_THROW(ulRslt)

	PECCCIPHERBLOB pCipher = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB) + 32);
	memset(pCipher, 0, sizeof(ECCCIPHERBLOB) + 32);
	ulRslt = SKF_ExtECCEncrypt(hdev, &externalPubKeyStruct, inputRaw, 32, pCipher);
	if(SAR_BUFFER_TOO_SMALL == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)
		
	pCipher->CipherLen = 32;
	ulRslt = SKF_ExtECCEncrypt(hdev, &externalPubKeyStruct, inputRaw, 32, pCipher);
	ERROR_THROW(ulRslt)

	// test decrypt
	unsigned char outPlain[32] = {0};
	ULONG outLen = 0;
	ulRslt = SKF_ExtECCDecrypt(hdev, &externalPrivKeyStruct, pCipher, NULL, &outLen);
	ERROR_THROW(ulRslt)

	outLen = 30;
	ulRslt = SKF_ExtECCDecrypt(hdev, &externalPrivKeyStruct, pCipher, outPlain, &outLen);
	if(SAR_BUFFER_TOO_SMALL == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	outLen = 32;
	ulRslt = SKF_ExtECCDecrypt(hdev, &externalPrivKeyStruct, pCipher, outPlain, &outLen);
	ERROR_THROW(ulRslt)

	if(memcmp(outPlain, inputRaw, 32))
	{
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	PRINT_LOG("external ECC key operation test done!");

	return SAR_OK;
	
}


ULONG testKeyUsage(HANDLE hdev, HANDLE hcont, bool generateKeyOnly)
{
//#ifdef TEST_INTER_OPERATE
	ULONG ulRslt = SAR_OK;
	
	ECCPUBLICKEYBLOB	eccPubSign = { 0 };
	ECCSIGNATUREBLOB	eccPubEncrypt = { 0 };
	ECCSIGNATUREBLOB	eccPubTemp = { 0 };
	BYTE	pHashData[256] = { 0 };
	ULONG	ulHashDataLen = 256;
	ULONG	ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	BLOCKCIPHERPARAM bp = { 0 };
	
	HANDLE hHash = NULL;
	ECCSIGNATUREBLOB	ecc_sign = { 0 };


	if (!generateKeyOnly)
	{
		ulRslt = test2Padding(hdev);
		
		// verify SM2 verify algorithm correctness by verify signature from external card (data from LongMai)
		ulRslt = externalSignatureVerification(hdev);
		ERROR_THROW(ulRslt)
	}

	// generate local signature SM2 keypair
	memset(&eccPubSign, 0, sizeof(eccPubSign));
	ulRslt = SKF_GenECCKeyPair(hcont, SGD_SM2_1, &eccPubSign);
	//PRINT_LOG("SKF_GenECCKeyPair, hcont = %p, return 0x%lx", hcont, ulRslt);
	ERROR_THROW(ulRslt)

	PRINT_LOG("SKF_GenECCKeyPair test done");

	if (!generateKeyOnly)
	{
		// test local digest, signature for digest result, and verify the signature
		ulRslt = localDigestSignatureVerify(hdev, hcont);
		ERROR_THROW(ulRslt)

		ulRslt = extEccOperationTest(hdev, hcont);
		ERROR_THROW(ulRslt)
	}

	// import keypair test
	ulRslt = importSm2KeyPair(hdev, hcont);
	ERROR_THROW(ulRslt)

	// test export session key, and import session key exported from other SKF manufacture
	ulRslt = sessionKeyExportImport(hdev, hcont);
	ERROR_THROW(ulRslt)

	if (!generateKeyOnly)
	{
		ulRslt = sessionKeyEncDec(hdev, hcont, SGD_SMS4_ECB, NULL, 0);
		ERROR_THROW(ulRslt)
		PRINT_LOG("SMS4 ECB encrypt decrypt test succeed");

		unsigned char iv[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
		ulRslt = sessionKeyEncDec(hdev, hcont, SGD_SMS4_CBC, iv, 16);
		ERROR_THROW(ulRslt)
		PRINT_LOG("SMS4 CBC encrypt decrypt test succeed");

		ulRslt = sessionKeyEncDec(hdev, hcont, SGD_SMS4_OFB, iv, 16);
		ERROR_THROW(ulRslt)
		PRINT_LOG("SMS4 OFB encrypt decrypt test succeed");

		// verify random data generation
		unsigned char testRandomDecOut[32] = { 0 };
		unsigned long testRandomDecOutLen = 32;
		memset(testRandomDecOut, 0, sizeof(testRandomDecOut));
		testRandomDecOutLen = 32;
		ulRslt = SKF_GenRandom(hdev, testRandomDecOut, testRandomDecOutLen);
		//PRINT_LOG("SKF_GenRandom, return 0x%lx", ulRslt);
		ERROR_THROW(ulRslt)

		PRINT_LOG("SKF generate random test succeed");
		
	}

	return SAR_OK;
//#endif
}


ULONG testCertification(HANDLE hdev, HANDLE hcont)
{
	ULONG ulRslt = SAR_OK;
	BYTE certBuf[4096] = { 0 };
	ULONG cerLen = sizeof(certBuf);

	memset(certBuf, 0, sizeof(certBuf));
	ulRslt = SKF_ImportCertificate(hcont, 1, (BYTE *)"testContainer_cert_sign", strlen("testContainer_cert_sign"));
	ERROR_THROW(ulRslt)
		ulRslt = SKF_ImportCertificate(hcont, 0, (BYTE *)"testContainer_cert_encrypt", strlen("testContainer_cert_encrypt"));
	ERROR_THROW(ulRslt)

	cerLen = sizeof(certBuf);
	memset(certBuf, 0, sizeof(certBuf));
	ulRslt = SKF_ExportCertificate(hcont, 1, NULL, &cerLen);
	ERROR_THROW(ulRslt)

	if (cerLen > 5) {
		ULONG cerLenBak = cerLen;
		cerLen = cerLen -3;
		ulRslt = SKF_ExportCertificate(hcont, 1, certBuf, &cerLen);
		if(SAR_BUFFER_TOO_SMALL == ulRslt) {
			ulRslt = SAR_OK;
		}
		else {
			ulRslt = SAR_FAIL;
		}
		ERROR_THROW(ulRslt)
		cerLen = cerLenBak;
	}

	ulRslt = SKF_ExportCertificate(hcont, 1, certBuf, &cerLen);
	ERROR_THROW(ulRslt)
	printf("SKF_ExportCertificate get: %s\n", certBuf); 

	cerLen = sizeof(certBuf);
	memset(certBuf, 0, sizeof(certBuf));
	ulRslt = SKF_ExportCertificate(hcont, 0, certBuf, &cerLen);
	ERROR_THROW(ulRslt)
	printf("SKF_ExportCertificate get: %s\n", certBuf); 

	PRINT_LOG("SKF certification import export test succeed");

	return SAR_OK;

}
