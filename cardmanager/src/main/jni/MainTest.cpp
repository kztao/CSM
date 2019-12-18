#include "skf.h"
#include <iostream>
#ifdef _WIN32
#include <Windows.h>
#else
#include <stdlib.h>
//#include "proxy.h"
#endif
#include <string.h>
#include <errno.h>
#include <stdio.h>

//#define ENABLE_TEST_CALL_P11

using namespace std;

#define ERROR_THROW(r) {if((r) != SAR_OK) {std::cout<<__FILE__<<"["<<dec<<__LINE__<<"] ------------------->>>>>> ERROR_THROW ret = 0x"<<hex<<r<<endl;return 0;}}

#include <vector>


typedef struct TT_t{
	int l1;
	int l2;
}TT;

vector<TT> vectorTT;


#define INIT_ENABLE 1
#define DELETE_TEST_APP 0

//#define TEST_INTER_OPERATE
#define TEST_APP_OPERATION
extern "C" {
	//void listSkfHandle();
}

#ifdef _WIN32
#define PRINT_LOG(...)													\
do																		\
{																		\
	std::printf(__VA_ARGS__);												\
	std::printf("\n");														\
} while (0)
#else
#define PRINT_LOG(...)													\
do																		\
{																		\
	printf(__VA_ARGS__);												\
	printf("\n");														\
} while (0)
#endif

// this function print p11 data objects number, SM2 key objects number, symmetric key object number respectively
ULONG checkObjNum();

// this function remove all p11 objects inside token
ULONG tokenCleanUp();

ULONG authorityManagementCheck(HANDLE hdev);

// 
ULONG deviceAuth(DEVHANDLE	hdev);

//
ULONG testKeyUsage(HANDLE hdev, HANDLE hcont, bool generateKeyOnly);

//
ULONG checkPinOperation(HANDLE hdev);

//
ULONG testCertification(HANDLE hdev, HANDLE hcont);

ULONG listP11Object();

ULONG checkHistoryState();

#if 0
void logData(unsigned char * pData, unsigned long ulDataLen)
{
	char buffer0[256] = { 0 };
	int printfRet = 0;
	int currentIdx = 0;
	unsigned int writeIdx = 0;

	for (writeIdx = 0, currentIdx = 0; writeIdx < ulDataLen; writeIdx++)
	{
		printfRet = sprintf_s(buffer0 + currentIdx, 256 - currentIdx, "%02x", pData[writeIdx]);
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
#endif

// ------------ input happ shall point to invalid app handle----------------- 
ULONG testInvalidApp(DEVHANDLE hdev, HAPPLICATION happ)
{
	ULONG ulRslt = SAR_OK;
	ULONG maxRe = 0, remainC = 0;
	BOOL def;
	ULONG contSize = 0;
	CHAR contName[1024] = { 0 };
	HCONTAINER hcont0, hcont1, hcont2, hcont3;
	HAPPLICATION hApplication;

	// try to open application which not exist
	ulRslt = SKF_OpenApplication(hdev, "testAPPNow", &hApplication);
	if(SAR_APPLICATION_NOT_EXISTS == ulRslt || SAR_APPLICATION_NAME_INVALID == ulRslt ) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	// try delete application which not exist
	ulRslt = SKF_DeleteApplication(hdev, "testAPPNow");
	if(SAR_APPLICATION_NOT_EXISTS == ulRslt || SAR_APPLICATION_NAME_INVALID == ulRslt ) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)
	
	ulRslt = SKF_ChangePIN(happ, USER_TYPE, "123456", "888888", &remainC);
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_GetPINInfo(happ, USER_TYPE, &maxRe, &remainC, &def);
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, USER_TYPE, "123456", &remainC);
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_UnblockPIN(happ, "123456", "888888", &remainC);
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ClearSecureState(happ);
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CloseApplication(happ);
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CreateFile(happ, "appFile0Test", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DeleteFile(happ, "appFile011");
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt);

	ulRslt = SKF_DeleteFile(happ, "appFile1");
	PRINT_LOG("SKF_DeleteFile %p get return 0x%x", happ, ulRslt);
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt);

	ULONG fileSize = 0;
	ulRslt = SKF_EnumFiles(happ, NULL, &fileSize);
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt);

	FILEATTRIBUTE fileInfo;
	memset(&fileInfo, 0, sizeof(FILEATTRIBUTE));
	ulRslt = SKF_GetFileInfo(happ, "appFile1", &fileInfo);
	PRINT_LOG("SKF_GetFileInfo input %p get return 0x%x", happ, ulRslt);
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ULONG readLen = sizeof(contName);
	memset(contName, 0, sizeof(contName));
	ulRslt = SKF_ReadFile(happ, "appFile1", 0, 100, (unsigned char *)contName, &readLen);
	memset(contName, 0, sizeof(contName));
	PRINT_LOG("SKF_ReadFile input %p get return 0x%x", happ, ulRslt);
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(happ, "appFile1dd", 0, (BYTE *)"this is app file 1", strlen("this is app file 1"));
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_EnumContainer(happ, NULL, &contSize);
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt);

	ulRslt = SKF_DeleteContainer(happ, "container_1234");
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	
	ulRslt = SKF_OpenContainer(happ, "container_1234", &hcont0);
	if(SAR_INVALIDHANDLEERR == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	return SAR_OK;
}

ULONG testInvalidContainer(DEVHANDLE hdev, HAPPLICATION happ, HCONTAINER hcont)
{
	ULONG ulRslt = SAR_OK;
	BYTE certBuf[4096] = { 0 };
	ULONG cerLen = sizeof(certBuf);
	ECCPUBLICKEYBLOB	eccPubSign = { 0 };
	ECCSIGNATUREBLOB	eccPubEncrypt = { 0 };
	ECCSIGNATUREBLOB	eccPubTemp = { 0 };
	BYTE	pHashData[256] = { 0 };
	ULONG	ulHashDataLen = 256;
	ULONG	ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	BLOCKCIPHERPARAM bp = { 0 };
	
	HANDLE hHash = NULL;
	ECCSIGNATUREBLOB	ecc_sign = { 0 };

	// try delete container which not exist
	ulRslt = SKF_DeleteContainer(happ, "testContainer111Now");
	if(SAR_OK == ulRslt ) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CloseContainer(hcont);
	if(SAR_INVALIDHANDLEERR == ulRslt ) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ULONG contType = 0xff;
	ulRslt = SKF_GetContainerType(hcont, &contType);
	if(SAR_INVALIDHANDLEERR == ulRslt ) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt);

	memset(&eccPubSign, 0, sizeof(eccPubSign));
	ulRslt = SKF_GenECCKeyPair(hcont, SGD_SM2_1, &eccPubSign);
	if(SAR_INVALIDHANDLEERR == ulRslt ) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	PENVELOPEDKEYBLOB cryptKeyEnv = (PENVELOPEDKEYBLOB)malloc(sizeof(ENVELOPEDKEYBLOB)+128);
	memset(cryptKeyEnv, 0, sizeof(ENVELOPEDKEYBLOB)+128);
    cryptKeyEnv->ECCCipherBlob.CipherLen = 128;
	cryptKeyEnv->Version = 1;
	cryptKeyEnv->ulSymmAlgID = SGD_SMS4_ECB;
	cryptKeyEnv->ulBits = 256;
	cryptKeyEnv->PubKey.BitLen = 256;
	cryptKeyEnv->ECCCipherBlob.CipherLen = 16;
	ulRslt = SKF_ImportECCKeyPair(hcont, cryptKeyEnv);
	if(SAR_INVALIDHANDLEERR == ulRslt ) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ECCPUBLICKEYBLOB externalPubKeyStruct;
	memset(&externalPubKeyStruct, 0, sizeof(externalPubKeyStruct));
	externalPubKeyStruct.BitLen = 256;
	PECCCIPHERBLOB  tempCipherKey = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB)+128);
	memset(tempCipherKey, 0, sizeof(ECCCIPHERBLOB)+128);
	HANDLE tempKeyHandle1 = 0;
	tempCipherKey->CipherLen = 16;
	ulRslt = SKF_ECCExportSessionKey(hcont, SGD_SMS4_ECB, &externalPubKeyStruct, tempCipherKey, &tempKeyHandle1);
	if(SAR_INVALIDHANDLEERR == ulRslt ) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	ulRslt = SKF_ExportPublicKey(hcont, TRUE, (BYTE *)(&eccPubSign), &ulEccpubLen);
	if(SAR_INVALIDHANDLEERR == ulRslt ) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

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
	if(SAR_INVALIDHANDLEERR == ulRslt ) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ImportCertificate(hcont, 1, (BYTE *)"testContainer_cert_sign_test", strlen("testContainer_cert_sign_test"));
	if(SAR_INVALIDHANDLEERR == ulRslt ) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ExportCertificate(hcont, 0, certBuf, &cerLen);
	if(SAR_INVALIDHANDLEERR == ulRslt ) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_GetContainerProperty(hcont, &contType);
	if(SAR_INVALIDHANDLEERR == ulRslt ) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt);
		
	return SAR_OK;
}

ULONG testFile(HAPPLICATION happ, bool createOnly)
{
	ULONG ulRslt = SAR_OK;
	ULONG fileSize = 0;
	CHAR * pFileName = NULL;

	ulRslt = SKF_CreateFile(happ, "appFile0", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile appFile0 return 0x%x\n", ulRslt);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CreateFile(happ, "appFile1", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile appFile1 return 0x%x\n", ulRslt);
	ERROR_THROW(ulRslt)

	PRINT_LOG("SKF file create test succeed");

	if (createOnly)
	{
		return ulRslt;
	}

	ulRslt = SKF_WriteFile(happ, "appFile1", 0, (BYTE *)"this is app file 1", strlen("this is app file 1"));
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(happ, "appFile1", strlen("this is app file 1"), (BYTE *)"this is app file 1", strlen("this is app file 1"));
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(happ, "appFile0", strlen("this is app file 0"), (BYTE *)"this is app file 0", strlen("this is app file 0"));
	ERROR_THROW(ulRslt)

		
	ulRslt = SKF_EnumFiles(happ, pFileName, &fileSize);
	ERROR_THROW(ulRslt);

	if (fileSize) {
		pFileName = new CHAR[fileSize];
	}

	if (fileSize > 5) {
		ULONG fileSizeBak = fileSize;
		fileSize = fileSize -3;
		ulRslt = SKF_EnumFiles(happ, pFileName, &fileSize);
		if(SAR_BUFFER_TOO_SMALL == ulRslt) {
			ulRslt = SAR_OK;
		}
		else {
			ulRslt = SAR_FAIL;
		}
		ERROR_THROW(ulRslt);
		fileSize = fileSizeBak;
	}

	ulRslt = SKF_EnumFiles(happ, pFileName, &fileSize);
	ERROR_THROW(ulRslt);

	printf("SKF_EnumFiles result: \n");
	for (unsigned int i = 0; i < fileSize; i++) {
		printf("%c", pFileName[i]);
	}
	printf("\n");

	ulRslt = SKF_DeleteFile(happ, "appFile0");
	ERROR_THROW(ulRslt);


	BYTE readOut[100] = { 0 };
	ULONG readLen = sizeof(readOut);
	memset(readOut, 0, sizeof(readOut));
	ulRslt = SKF_ReadFile(happ, "appFile0", 0, strlen("this is app file 1"), readOut, &readLen);
	//printf("SKF_ReadFile read delete file get 0x%lx\n", ulRslt);
	if(SAR_FILE_NOT_EXIST == ulRslt) {
		ulRslt = SAR_OK;
	}
	else {
		ulRslt = SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	FILEATTRIBUTE fileInfo;
	memset(&fileInfo, 0, sizeof(FILEATTRIBUTE));
	ulRslt = SKF_GetFileInfo(happ, "appFile1", &fileInfo);
	ERROR_THROW(ulRslt)

	readLen = 0;
	ulRslt = SKF_ReadFile(happ, "appFile1", 0, 2*strlen("this is app file 1"), NULL, &readLen);
	ERROR_THROW(ulRslt)
		
	//readLen = sizeof(readOut);
	memset(readOut, 0, sizeof(readOut));
	ulRslt = SKF_ReadFile(happ, "appFile1", 0, 2*strlen("this is app file 1"), readOut, &readLen);
	ERROR_THROW(ulRslt)
	for (unsigned int i = 0; i < readLen; i++) {
		printf("%c", readOut[i]);
	}
	printf("\n");

	PRINT_LOG("SKF file operation test succeed");

	return SAR_OK;
}

ULONG testContainer(DEVHANDLE hdev, HAPPLICATION happ)
{
	ULONG ulRslt = SAR_OK;
	ULONG contSize = 0;
	CHAR contName[1024] = { 0 };
	HCONTAINER hcont0, hcont1, hcont2, hcont3;

	ulRslt = SKF_EnumContainer(happ, NULL, &contSize);
	ERROR_THROW(ulRslt);

	contSize = sizeof(contName);
	memset(contName, 0, sizeof(contName));
	ulRslt = SKF_EnumContainer(happ, contName, &contSize);
	ERROR_THROW(ulRslt);

#ifdef _WIN32
	std::printf("SKF_EnumContainer result: \n");
	for (unsigned int i = 0; i < contSize; i++) {
		std::printf("%c", contName[i]);
	}
	std::printf("\n");
#else
	printf("SKF_EnumContainer result: \n");
	for (unsigned int i = 0; i < contSize; i++) {
		printf("%c", contName[i]);
	}
	printf("\n");
#endif

	ulRslt = SKF_CreateContainer(happ, "container_0", &hcont0);
	ERROR_THROW(ulRslt);

	ulRslt = SKF_CreateContainer(happ, "container_1", &hcont1);
	ERROR_THROW(ulRslt);

	ulRslt = SKF_CreateContainer(happ, "container_2", &hcont2);
	ERROR_THROW(ulRslt);

	// try to create container with name already exist
	ulRslt = SKF_CreateContainer(happ, "container_2", &hcont3);
	ERROR_THROW(ulRslt);

	ulRslt = SKF_CloseContainer(hcont2);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_OpenContainer(happ, "container_2", &hcont2);
	ERROR_THROW(ulRslt)

	ULONG contType = 0xff;
	ulRslt = SKF_GetContainerType(hcont0, &contType);
	ERROR_THROW(ulRslt);

	PRINT_LOG("SKF container created successfully for test");

	ulRslt = testKeyUsage(hdev, hcont0, false);
	ERROR_THROW(ulRslt);

	contType = 0xff;
	ulRslt = SKF_GetContainerType(hcont0, &contType);
	ERROR_THROW(ulRslt);

	ulRslt = testKeyUsage(hdev, hcont1, true);
	ERROR_THROW(ulRslt);

	ulRslt = testKeyUsage(hdev, hcont2, true);
	ERROR_THROW(ulRslt);

	ulRslt = testCertification(hdev, hcont0);
	ERROR_THROW(ulRslt);

	ulRslt = testCertification(hdev, hcont1);
	ERROR_THROW(ulRslt);

	ulRslt = testCertification(hdev, hcont2);
	ERROR_THROW(ulRslt);

	ulRslt = SKF_EnumContainer(happ, NULL, &contSize);
	ERROR_THROW(ulRslt);

	contSize = sizeof(contName);
	memset(contName, 0, sizeof(contName));
	ulRslt = SKF_EnumContainer(happ, contName, &contSize);
	ERROR_THROW(ulRslt);
	
#ifdef _WIN32
	std::printf("SKF_EnumContainer result: \n");
	for (unsigned int i = 0; i < contSize; i++) {
		std::printf("%c", contName[i]);
	}
	std::printf("\n");
#else
	printf("SKF_EnumContainer result: \n");
	for (unsigned int i = 0; i < contSize; i++) {
		printf("%c", contName[i]);
	}
	printf("\n");
#endif

	ulRslt = SKF_CloseContainer(hcont2);
	ERROR_THROW(ulRslt)

	// test correctness for input container which already closed
	//PRINT_LOG("-------test correctness for input container which already closed -------");
	testInvalidContainer(hdev, happ, hcont2);
	//PRINT_LOG("-------test correctness for input container which already closed done -------");

	ulRslt = SKF_DeleteContainer(happ, "container_1");
	ERROR_THROW(ulRslt)

	// test correctness for input container which already deleted
	//PRINT_LOG("-------test correctness for input container which already deleted -------");
	testInvalidContainer(hdev, happ, hcont1);
	//PRINT_LOG("-------test correctness for input container which already deleted done -------");

	contType = 0xff;
	ulRslt = SKF_GetContainerProperty(hcont0, &contType);
	if(CONTAINER_PROPERTY_ECC != contType) {ulRslt = SAR_FAIL;}
	ERROR_THROW(ulRslt);

	ulRslt = SKF_EnumContainer(happ, NULL, &contSize);
	ERROR_THROW(ulRslt);

	if (contSize > 5) {
		ULONG contSizeBak = contSize;
		contSize = contSize -3;
		ulRslt = SKF_EnumContainer(happ, contName, &contSize);
		if(SAR_BUFFER_TOO_SMALL == ulRslt) {
			ulRslt = SAR_OK;
		}
		else {
			ulRslt = SAR_FAIL;
		}
		ERROR_THROW(ulRslt);
		contSize = contSizeBak;
	}

	contSize = sizeof(contName);
	memset(contName, 0, sizeof(contName));
	ulRslt = SKF_EnumContainer(happ, contName, &contSize);
	ERROR_THROW(ulRslt);

#ifdef _WIN32
	std::printf("SKF_EnumContainer result: \n");
	for (unsigned int i = 0; i < contSize; i++) {
		std::printf("%c", contName[i]);
	}
	std::printf("\n");
#else
	printf("SKF_EnumContainer result: \n");
	for (unsigned int i = 0; i < contSize; i++) {
		printf("%c", contName[i]);
	}
	printf("\n");
#endif

	PRINT_LOG("SKF container test done");

	return SAR_OK;
}


int main(){

	ULONG		ulRslt;
	DEVHANDLE	hdev = NULL;
	BYTE		pbRandom[32] = { 0 };
	char		*szDevName = NULL;
	ULONG		ulNameLen = 0;
	char		new_auth_key[33] = { 0 };
	BYTE		mac[4] = { 0 };
	BYTE		data[128] = { 0 };
	HANDLE		hkey = NULL;
	BLOCKCIPHERPARAM bp = { 0 };
	CHAR pApp[1024] = { 0 };
	ULONG appSize = 0;
	HAPPLICATION appHandle0 = 0;
	HAPPLICATION appHandle1 = 0;
	HAPPLICATION appHandle2 = 0;

	printf("skftest start, enter main...\r\n");

#ifndef _WIN32
    //CK_RV proxyRev = Proxy_Init();
    //printf("proxy_init return 0x%x", proxyRev);
#endif

	ulRslt = listP11Object();
		
	ulRslt = tokenCleanUp();
	printf("clean token done, return 0x%x...\r\n", ulRslt);
	ERROR_THROW(ulRslt)

	ulRslt = checkHistoryState();
	ERROR_THROW(ulRslt)

    getchar();
	
	ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
	//printf("SKF_EnumDev done, return 0x%x and ulNameLen %d...\r\n", ulRslt, ulNameLen);
	ERROR_THROW(ulRslt)
	szDevName = new char[ulNameLen];

	if(ulNameLen > 5) {
		ULONG ulNameLenBak = ulNameLen;
		ulNameLen = ulNameLen -3;
		ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
		if(SAR_BUFFER_TOO_SMALL == ulRslt) {
			ulRslt = SAR_OK;
		}
		else {
			ulRslt = SAR_FAIL;
		}
		ERROR_THROW(ulRslt);

		ulNameLen = ulNameLenBak;
	}
	
	ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
	//printf("SKF_EnumDev done, return 0x%x...\r\n", ulRslt);
	ERROR_THROW(ulRslt)
	char *pszdev = szDevName;

	ULONG pulDevState = 0;
	ulRslt = SKF_GetDevState(
		szDevName, &pulDevState);
	ERROR_THROW(ulRslt)
    if(pulDevState != DEV_PRESENT_STATE){ulRslt = SAR_FAIL;}
    ERROR_THROW(ulRslt)

	ulRslt = SKF_ConnectDev(pszdev, &hdev);
	ERROR_THROW(ulRslt)

	DEVINFO myDevInfo;
	memset(&myDevInfo, 0, sizeof(myDevInfo));
	ulRslt = SKF_GetDevInfo(hdev, &myDevInfo);
	ERROR_THROW(ulRslt)

	// check - expect create application fail before dev auth
    DWORD maxusercount = 8;
    DWORD maxadmincount = 7;
	ulRslt = SKF_CreateApplication(hdev, "testApp0", "123456789", maxadmincount, "1234567", maxusercount, SECURE_USER_ACCOUNT, &appHandle0);
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt);

    //PRINT_LOG("======================= mark function %s line %d ======================", __FUNCTION__, __LINE__);
	//
	ulRslt = deviceAuth(hdev);
	ERROR_THROW(ulRslt)

	// dump and clean up SKF applications...
	for (;;) {
		memset(pApp, 0, sizeof(pApp));
		appSize = sizeof(pApp);
		ulRslt = SKF_EnumApplication(hdev, pApp, &appSize);
		ERROR_THROW(ulRslt);

        printf("SKF_EnumApplication result: \n");
        for (unsigned int i = 0; i < appSize; i++) {
            printf("%c", pApp[i]);
        }
        printf("\n");

		if (appSize > 2) {
			printf("############     notice: application %s found, will be deleted\n", pApp);
			ulRslt = SKF_DeleteApplication(hdev, pApp);
			ERROR_THROW(ulRslt)
		}
		else {
			break;
		}
	}

	getchar();
	// verfiy all pin operation
	ulRslt = checkPinOperation(hdev);
	ERROR_THROW(ulRslt)

    getchar();
	ulRslt = authorityManagementCheck(hdev);
	ERROR_THROW(ulRslt)

    getchar();
//	ulRslt = SKF_CreateApplication(hdev, "testApp0", "123456", 6, "123456", 6, SECURE_USER_ACCOUNT, &appHandle0);
//	ERROR_THROW(ulRslt);

	ulRslt = SKF_CreateApplication(hdev, "testApp1", "123456", 6, "123456", 6, SECURE_USER_ACCOUNT, &appHandle1);
	ERROR_THROW(ulRslt);

	ulRslt = SKF_CreateApplication(hdev, "testApp2", "123456", 6, "123456", 6, SECURE_EVERYONE_ACCOUNT, &appHandle2);
	ERROR_THROW(ulRslt);

	// log in for app1 and app2
	ULONG remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandle1, USER_TYPE, "123456", &remainC);
    printf("SKF_VerifyPIN after create result 0x%x\n", ulRslt);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ClearSecureState(appHandle1);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_EnumApplication(hdev, NULL, &appSize);
	ERROR_THROW(ulRslt);

	if(appSize > 5) {
		ULONG appSizeBak = appSize;
		appSize = appSize - 3;
		ulRslt = SKF_EnumApplication(hdev, pApp, &appSize);
		if(SAR_BUFFER_TOO_SMALL == ulRslt) {
			ulRslt = SAR_OK;
		}
		else {
			ulRslt = SAR_FAIL;
		}
		ERROR_THROW(ulRslt);
		appSize = appSizeBak;
	}

    //PRINT_LOG("======================= mark function %s line %d ======================", __FUNCTION__, __LINE__);

	memset(pApp, 0, sizeof(pApp));
	appSize = sizeof(pApp);
	ulRslt = SKF_EnumApplication(hdev, pApp, &appSize);
	ERROR_THROW(ulRslt);

    char* enumapplication_result[2] = {"testApp1","testApp2"};

#ifdef _WIN32
	std::printf("SKF_EnumApplication result: \n");
	for (unsigned int i = 0; i < appSize; i++) {
		std::printf("%c", pApp[i]);
	}
	std::printf("\n");
#else
	printf("SKF_EnumApplication result: \n");
	for (unsigned int i = 0; i < appSize; i++) {
		printf("%c", pApp[i]);
/*        if(pApp[i] != (char)(&enumapplication_result + i))
        {
            printf("error enum result: %d, %c",i,(char)(&enumapplication_result + i));
            ulRslt = SAR_FAIL;
            ERROR_THROW(ulRslt);
        }*/
	}
	printf("\n");

#endif
	getchar();

    //PRINT_LOG("======================= mark function %s line %d ======================", __FUNCTION__, __LINE__);

	ulRslt = SKF_OpenApplication(hdev, "testApp0", &appHandle0);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_OpenApplication(hdev, "testApp1", &appHandle1);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_OpenApplication(hdev, "testApp2", &appHandle2);
	ERROR_THROW(ulRslt)
		
	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandle0, USER_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

    //PRINT_LOG("======================= mark function %s line %d ======================", __FUNCTION__, __LINE__);

	// log in for app1 and app2
	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandle1, USER_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle2, USER_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

		// test all file interface on app0
		ulRslt = testFile(appHandle0, false);
	ERROR_THROW(ulRslt)

    //PRINT_LOG("======================= mark function %s line %d ======================", __FUNCTION__, __LINE__);

		// create file with app1 and app2
		ulRslt = testFile(appHandle1, true);
	ERROR_THROW(ulRslt)

		ulRslt = testFile(appHandle2, true);
	ERROR_THROW(ulRslt)

		ulRslt = testContainer(hdev, appHandle0);
	ERROR_THROW(ulRslt)

		ulRslt = testContainer(hdev, appHandle1);
	ERROR_THROW(ulRslt)

		ulRslt = testContainer(hdev, appHandle2);
	ERROR_THROW(ulRslt)

		ulRslt = SKF_ClearSecureState(appHandle2);
	ERROR_THROW(ulRslt)

	//ulRslt = listP11Object();

    //PRINT_LOG("======================= mark function %s line %d ======================", __FUNCTION__, __LINE__);

	//listSkfHandle();
	checkObjNum();

		ulRslt = SKF_CloseApplication(appHandle2);
	ERROR_THROW(ulRslt)

	//PRINT_LOG("-------test correctness for input application which already closed -------");
	testInvalidApp(hdev, appHandle2);
	//PRINT_LOG("-------test correctness for input application which already closed done -------");

		ulRslt = SKF_DeleteApplication(hdev, "testApp1");
	ERROR_THROW(ulRslt)

	//PRINT_LOG("-------test correctness for input application which already deleted -------");
	testInvalidApp(hdev, appHandle1);
	//PRINT_LOG("-------test correctness for input application which already deleted done -------");

		// SKF_EnumApplication again...
		ulRslt = SKF_EnumApplication(hdev, NULL, &appSize);
	ERROR_THROW(ulRslt);

	memset(pApp, 0, sizeof(pApp));
	appSize = sizeof(pApp);
	ulRslt = SKF_EnumApplication(hdev, pApp, &appSize);
	ERROR_THROW(ulRslt);

    //PRINT_LOG("======================= mark function %s line %d ======================", __FUNCTION__, __LINE__);

#ifdef _WIN32
	std::printf("SKF_EnumApplication result: \n");
	for (unsigned int i = 0; i < appSize; i++) {
		std::printf("%c", pApp[i]);
	}
	std::printf("\n");
#else
	printf("SKF_EnumApplication result: \n");
	for (unsigned int i = 0; i < appSize; i++) {
		printf("%c", pApp[i]);
	}
	printf("\n");
#endif

	//listSkfHandle();
	checkObjNum();

	// try disconnect device, re-connect
	ulRslt = SKF_DisConnectDev(hdev);
	ERROR_THROW(ulRslt)

    //PRINT_LOG("======================= mark function %s line %d ======================", __FUNCTION__, __LINE__);

	//listSkfHandle();
	checkObjNum();

		ulRslt = SKF_ConnectDev(pszdev, &hdev);
	ERROR_THROW(ulRslt)

    //PRINT_LOG("======================= mark function %s line %d ======================", __FUNCTION__, __LINE__);

	//
	ulRslt = deviceAuth(hdev);
	ERROR_THROW(ulRslt)

	// SKF_EnumApplication again...
	ulRslt = SKF_EnumApplication(hdev, NULL, &appSize);
	ERROR_THROW(ulRslt);

    //PRINT_LOG("======================= mark function %s line %d ======================", __FUNCTION__, __LINE__);

	memset(pApp, 0, sizeof(pApp));
	appSize = sizeof(pApp);
	ulRslt = SKF_EnumApplication(hdev, pApp, &appSize);
	ERROR_THROW(ulRslt);

#ifdef _WIN32
	std::printf("SKF_EnumApplication result: \n");
	for (unsigned int i = 0; i < appSize; i++) {
		std::printf("%c", pApp[i]);
	}
	std::printf("\n");
#else
	printf("SKF_EnumApplication result: \n");
	for (unsigned int i = 0; i < appSize; i++) {
		printf("%c", pApp[i]);
	}
	printf("\n");
#endif

	ulRslt = SKF_OpenApplication(hdev, "testApp2", &appHandle2);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle2, USER_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

		ulRslt = testContainer(hdev, appHandle2);
	ERROR_THROW(ulRslt)

    //PRINT_LOG("======================= mark function %s line %d ======================", __FUNCTION__, __LINE__);

	//listSkfHandle(); 
	checkObjNum();


	// try again, enum device will clear all buffer information
	ulRslt = SKF_EnumDev(1, NULL, &ulNameLen);
	ERROR_THROW(ulRslt)

	if (szDevName)
	{
		delete szDevName;
		szDevName = NULL;
	}
	szDevName = new char[ulNameLen];
	ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
	ERROR_THROW(ulRslt)
	pszdev = szDevName;

    //PRINT_LOG("======================= mark function %s line %d ======================", __FUNCTION__, __LINE__);

	//listSkfHandle();
	checkObjNum();

	ulRslt = SKF_ConnectDev(pszdev, &hdev);
	ERROR_THROW(ulRslt)

    //PRINT_LOG("======================= mark function %s line %d ======================", __FUNCTION__, __LINE__);

	//listSkfHandle();
	checkObjNum();

		//
		ulRslt = deviceAuth(hdev);
	ERROR_THROW(ulRslt)

	// dump and clean up SKF applications...
	for (;;) {
		memset(pApp, 0, sizeof(pApp));
		appSize = sizeof(pApp);
		ulRslt = SKF_EnumApplication(hdev, pApp, &appSize);
		ERROR_THROW(ulRslt);

		if (appSize > 2) {
			printf("############     notice: application %s found, will be deleted\n", pApp);
			ulRslt = SKF_DeleteApplication(hdev, pApp);
			ERROR_THROW(ulRslt)
		}
		else {
			break;
		}
	}

	return 0;

}
