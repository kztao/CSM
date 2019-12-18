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


// this function print p11 data objects number, SM2 key objects number, symmetric key object number respectively
ULONG checkObjNum();

ULONG deviceAuth(DEVHANDLE	hdev)
{
	ULONG ulRslt = SAR_OK;

	BYTE * tempSessKey = (BYTE *)"1234567812345678";
	HANDLE tempKeyHandle = 0;
	BLOCKCIPHERPARAM bp = { 0 };

	BYTE devRandom[16] = { 0 };
	BYTE devAuth[16] = { 0 };
	ULONG devAuthLen = 16;
#ifdef _WIN32
	std::memset(devRandom, 0, 16);
	std::memset(devAuth, 0, 16);
#else
	memset(devRandom, 0, 16);
	memset(devAuth, 0, 16);
#endif
	ulRslt = SKF_GenRandom(hdev, devRandom, 8);
	ERROR_THROW(ulRslt)

	//listSkfHandle();
	checkObjNum();

	ulRslt = SKF_SetSymmKey(hdev, (unsigned char*)tempSessKey, SGD_SMS4_ECB, &tempKeyHandle);
	//PRINT_LOG("SKF_SetSymmKey get result 0x%lx and return keyHandle %p", ulRslt, tempKeyHandle);
	ERROR_THROW(ulRslt)

	// step 3.2 encrypt crypt private key
	ulRslt = SKF_EncryptInit(tempKeyHandle, bp);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_Encrypt(tempKeyHandle, (unsigned char *)devRandom, sizeof(devRandom), devAuth, &devAuthLen);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CloseHandle(tempKeyHandle);
	//PRINT_LOG("SKF_CloseHandle %p get result 0x%lx", tempKeyHandle, ulRslt);
	ERROR_THROW(ulRslt)

	//listSkfHandle();
	checkObjNum();

	ulRslt = SKF_DevAuth(hdev, devAuth, devAuthLen);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangeDevAuthKey(hdev, (BYTE *)"1234567812345678", strlen("1234567812345678"));
	//printf("SKF_ChangeDevAuthKey return 0x%x\n", ulRslt);
	ERROR_THROW(ulRslt)

	printf("deviceAuth operation done successfully!!\n");

	return SAR_OK;
}

ULONG checkUserPin(HAPPLICATION	happ)
{
	ULONG ulRslt = SAR_OK;
	ULONG maxRe = 0, remainC = 0;
	BOOL def;
	ulRslt = SKF_GetPINInfo(happ, USER_TYPE, &maxRe, &remainC, &def);
	if((6 != maxRe) || (6!=remainC) || (!def)) {ulRslt = SAR_FAIL;}
	ERROR_THROW(ulRslt)

//	ulRslt = SKF_VerifyPIN(happ, USER_TYPE, "123456", &remainC);
//	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, USER_TYPE, "123456", "888888", &remainC);
	ERROR_THROW(ulRslt)

	// try to get user pin locked
	ulRslt = SKF_VerifyPIN(happ, USER_TYPE, "123456", &remainC);
	if(SAR_PIN_INCORRECT != ulRslt || remainC != 5) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)
	//printf("SKF_VerifyPIN with old PIN return 0x%x\n", ulRslt);

	ulRslt = SKF_VerifyPIN(happ, USER_TYPE, "123456", &remainC);
	if(SAR_PIN_INCORRECT != ulRslt|| remainC != 4) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)
	//printf("SKF_VerifyPIN with old PIN return 0x%x\n", ulRslt);

	ulRslt = SKF_VerifyPIN(happ, USER_TYPE, "123456", &remainC);
	if(SAR_PIN_INCORRECT != ulRslt|| remainC != 3) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)
	//printf("SKF_VerifyPIN with old PIN return 0x%x\n", ulRslt);

	ulRslt = SKF_VerifyPIN(happ, USER_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if(SAR_PIN_INCORRECT != ulRslt|| remainC != 2) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)
	//printf("SKF_VerifyPIN with old PIN return 0x%x\n", ulRslt);

	ulRslt = SKF_VerifyPIN(happ, USER_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if(SAR_PIN_INCORRECT != ulRslt|| remainC != 1) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)
	//printf("SKF_VerifyPIN with old PIN return 0x%x\n", ulRslt);

	ulRslt = SKF_VerifyPIN(happ, USER_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if(SAR_PIN_LOCKED != ulRslt|| remainC != 0) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)
	//printf("SKF_VerifyPIN with old PIN return 0x%x\n", ulRslt);

	ulRslt = SKF_VerifyPIN(happ, USER_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if(SAR_PIN_LOCKED != ulRslt|| remainC != 0) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)
	//printf("SKF_VerifyPIN with old PIN return 0x%x\n", ulRslt);

	ulRslt = SKF_VerifyPIN(happ, USER_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if(SAR_PIN_LOCKED != ulRslt|| remainC != 0) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)
	//printf("SKF_VerifyPIN with old PIN return 0x%x\n", ulRslt);

	// unblock pin with wrong admin pin
	ulRslt = SKF_UnblockPIN(happ, "888888", "888888", &remainC);
	if(SAR_PIN_INCORRECT != ulRslt || remainC != 5) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)
	//printf("SKF_UnblockPIN with old PIN return 0x%x\n", ulRslt);

	// unblock pin with correct admin pin
	ulRslt = SKF_UnblockPIN(happ, "123456", "88888888", &remainC);
	ERROR_THROW(ulRslt)

	// verify with new setting user pin
	ulRslt = SKF_VerifyPIN(happ, USER_TYPE, "88888888", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if(ulRslt!=SAR_OK || remainC!= 6)
	{
		ulRslt == SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	// change user pin
	ulRslt = SKF_ChangePIN(happ, USER_TYPE, "88888888", "123456", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if(ulRslt!=SAR_OK || remainC!= 6)
	{
		ulRslt == SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	// verify user pin again
	ulRslt = SKF_VerifyPIN(happ, USER_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if(ulRslt!=SAR_OK || remainC!= 6)
	{
		ulRslt == SAR_FAIL;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, USER_TYPE, "888888", "123456", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt || remainC != 5) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, USER_TYPE, "888888", "123456", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 4) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, USER_TYPE, "888888", "123456", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 3) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, USER_TYPE, "888888", "123456", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 2) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, USER_TYPE, "888888", "123456", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 1) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, USER_TYPE, "888888", "123456", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if ( (SAR_PIN_LOCKED != ulRslt)|| remainC != 0) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, USER_TYPE, "888888", "123456", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_LOCKED != ulRslt|| remainC != 0) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_UnblockPIN(happ, "123456", "123456", &remainC);
	//printf("SKF_UnblockPIN with return 0x%x\n", ulRslt);
	ERROR_THROW(ulRslt)

	// verify user pin again
	ulRslt = SKF_VerifyPIN(happ, USER_TYPE, "123456", &remainC);
    if(remainC != 6)
    {
        ulRslt = SAR_FAIL;
    }
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	ERROR_THROW(ulRslt)

	printf("check user pin operation done!!\n");

	return ulRslt;
}

ULONG lockSoPinByVerifyPin(HAPPLICATION	happ)
{
	ULONG ulRslt = SAR_OK;
	ULONG maxRe = 0, remainC = 0;
	BOOL def;

	printf("try lock so pin by SKF_VerifyPIN\n");

	ulRslt = SKF_GetPINInfo(happ, ADMIN_TYPE, &maxRe, &remainC, &def);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, ADMIN_TYPE, "123456", "888888", &remainC);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 5) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "888888", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 5) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 4) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 3) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 2) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 1) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if ((SAR_PIN_LOCKED != ulRslt)|| remainC != 0) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_LOCKED != ulRslt|| remainC != 0) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "888888", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_LOCKED != ulRslt|| remainC != 0) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	printf("try lock so pin by SKF_VerifyPIN done!\n");

	return ulRslt;
}



ULONG lockSoPinByChangePin(HAPPLICATION	happ)
{
	ULONG ulRslt = SAR_OK;
	ULONG maxRe = 0, remainC = 0;
	BOOL def;

	printf("try lock so pin by SKF_ChangePIN\n");

	ulRslt = SKF_GetPINInfo(happ, ADMIN_TYPE, &maxRe, &remainC, &def);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, ADMIN_TYPE, "123456", "888888", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	ERROR_THROW(ulRslt)

    ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "888888", &remainC);
    if(remainC!=6)
    {
        ulRslt = SAR_FAIL;
    }
    ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, ADMIN_TYPE, "888888", "123456", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
    if(remainC!=6)
    {
        ulRslt = SAR_FAIL;
    }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, ADMIN_TYPE, "888888", "888888", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt || remainC != 5) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, ADMIN_TYPE, "888888", "888888", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 4) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, ADMIN_TYPE, "888888", "888888", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 3) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, ADMIN_TYPE, "888888", "888888", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 2) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, ADMIN_TYPE, "888888", "888888", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 1) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, ADMIN_TYPE, "888888", "888888", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if ((SAR_PIN_LOCKED != ulRslt)|| remainC != 0) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, ADMIN_TYPE, "888888", "888888", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_LOCKED != ulRslt|| remainC != 0) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(happ, ADMIN_TYPE, "888888", "888888", &remainC);
//	printf("line %03d SKF_ChangePIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_LOCKED != ulRslt|| remainC != 0) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "888888", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	//printf("SKF_VerifyPIN with old PIN return 0x%x\n", ulRslt);
	if (SAR_PIN_LOCKED != ulRslt|| remainC != 0) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	printf("try lock so pin by SKF_ChangePIN done!\n");

	return ulRslt;
}


ULONG lockSoPinByUnblockUserPin(HAPPLICATION	happ)
{
	ULONG ulRslt = SAR_OK;
	ULONG maxRe = 0, remainC = 0;
	BOOL def;

	printf("try lock so pin by SKF_UnblockPIN\n");

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_UnblockPIN(happ, "asdefag", "123456", &remainC);
//	printf("line %03d SKF_UnblockPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt || remainC != 5) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_UnblockPIN(happ, "asdefag", "123456", &remainC);
//	printf("line %03d SKF_UnblockPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt || remainC != 4) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_UnblockPIN(happ, "asdefag", "123456", &remainC);
//	printf("line %03d SKF_UnblockPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt || remainC != 3) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_UnblockPIN(happ, "asdefag", "123456", &remainC);
//	printf("line %03d SKF_UnblockPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 2) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_UnblockPIN(happ, "asdefag", "123456", &remainC);
//	printf("line %03d SKF_UnblockPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_INCORRECT != ulRslt|| remainC != 1) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_UnblockPIN(happ, "asdefag", "123456", &remainC);
//	printf("line %03d SKF_UnblockPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if ((SAR_PIN_LOCKED != ulRslt)|| remainC != 0) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_UnblockPIN(happ, "asdefag", "123456", &remainC);
//	printf("line %03d SKF_UnblockPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_LOCKED != ulRslt|| remainC != 0) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_UnblockPIN(happ, "asdefag", "123456", &remainC);
//	printf("line %03d SKF_UnblockPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_LOCKED != ulRslt|| remainC != 0) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(happ, ADMIN_TYPE, "123456", &remainC);
//	printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
	if (SAR_PIN_LOCKED != ulRslt|| remainC != 0) { ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	printf("try lock so pin by SKF_UnblockPIN done!\n");

	return ulRslt;
}


ULONG checkPinOperation(HANDLE hdev)
{
	ULONG ulRslt = SAR_OK;
	HAPPLICATION appHandle0 = 0;
	HAPPLICATION appHandle1 = 0;
	HAPPLICATION appHandle2 = 0;

	printf("==================test pin operations start==================\n");
	
	ulRslt = SKF_CreateApplication(hdev, "testPinApp0", "123456", 6, "123456", 6, SECURE_USER_ACCOUNT, &appHandle0);
	ERROR_THROW(ulRslt);

	ulRslt = SKF_CreateApplication(hdev, "testPinApp1", "123456", 6, "123456", 6, SECURE_USER_ACCOUNT, &appHandle1);
	ERROR_THROW(ulRslt);

	ulRslt = SKF_CreateApplication(hdev, "testPinApp2", "123456", 6, "123456", 6, SECURE_USER_ACCOUNT, &appHandle2);
	ERROR_THROW(ulRslt);

	ulRslt = checkUserPin(appHandle0);
	ERROR_THROW(ulRslt);

	ulRslt = lockSoPinByChangePin(appHandle0);
	ERROR_THROW(ulRslt);

	ulRslt = lockSoPinByVerifyPin(appHandle1);
	ERROR_THROW(ulRslt);

	ulRslt = lockSoPinByUnblockUserPin(appHandle2);
	ERROR_THROW(ulRslt);

	ulRslt = SKF_DeleteApplication(hdev, "testPinApp0");
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DeleteApplication(hdev, "testPinApp1");
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DeleteApplication(hdev, "testPinApp2");
	ERROR_THROW(ulRslt)

	printf("==================test pin operations end ==================\n");
	
	return SAR_OK;
}
