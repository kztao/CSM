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

#define ENABLE_TEST_CALL_P11
#ifdef ENABLE_TEST_CALL_P11
#include "cryptoki.h"
#endif

using namespace std;

ULONG deviceAuth(DEVHANDLE	hdev);

#define JWPIN "88888888"

#define ERROR_THROW(r) {if((r) != SAR_OK) {std::cout<<__FILE__<<"["<<dec<<__LINE__<<"] ------------------->>>>>> ERROR_THROW ret = 0x"<<hex<<r<<endl;return 0;}}

ULONG authorityManagementCheck(HANDLE hdev)
{
	ULONG ulRslt = SAR_OK;
	ULONG fileSize = 0;
	CHAR * pFileName = NULL;
	ULONG maxRe = 0, remainC = 0;
	BOOL def;
	HAPPLICATION appHandle0, appHandle1, appHandle2, appHandle3;

	printf("authorityManagementCheck start, check file operations authority...\n");

//// start test 1: app which cannot create file
	ulRslt = SKF_CreateApplication(hdev, "authApp0", "123456", 6, "123456", 6, SECURE_NEVER_ACCOUNT, &appHandle0);
	ERROR_THROW(ulRslt);
	
	// create file within app which cannot create file. expect failure
    DWORD rights[4] = {SECURE_NEVER_ACCOUNT,SECURE_ADM_ACCOUNT,SECURE_USER_ACCOUNT,SECURE_EVERYONE_ACCOUNT};
    for(int i=0;i<4;i++)
    {
        ulRslt = SKF_CreateFile(appHandle0, "authFile0", 100, rights[i], rights[i]);
        //printf("SKF_CreateFile in app which cannot create file get 0x%x\n", ulRslt);
        if(SAR_OK == ulRslt) {
            ulRslt = SAR_FAIL;
        }
        else {
            ulRslt = SAR_OK;
        }
        ERROR_THROW(ulRslt)
    }

	ulRslt = SKF_DeleteApplication(hdev, "authApp0");
	ERROR_THROW(ulRslt)
///// done test 1

//// start test 2: app can create file by admin
	ulRslt = SKF_CreateApplication(hdev, "authApp1", "123456", 6, "123456", 6, SECURE_ADM_ACCOUNT, &appHandle1);
	ERROR_THROW(ulRslt);
	
	// create file before log in. expect failure
	ulRslt = SKF_CreateFile(appHandle1, "authFile0", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile in app before log in get 0x%x which requires admin to create\n", ulRslt);
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle1, ADMIN_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	// create file by expected user
	ulRslt = SKF_CreateFile(appHandle1, "authFile0", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile in admin login app get 0x%x which requires admin to create\n", ulRslt);
	ERROR_THROW(ulRslt)

	// create file by expected user
	ulRslt = SKF_CreateFile(appHandle1, "authFile1", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile in admin login app get 0x%x which requires admin to create\n", ulRslt);
	ERROR_THROW(ulRslt)

	// delete file by expected user
	ulRslt = SKF_DeleteFile(appHandle1, "authFile0");
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle1, USER_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	// try create file by user. expect failure
	ulRslt = SKF_CreateFile(appHandle1, "authFile0", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile in user login app get 0x%x which requires admin to create\n", ulRslt);
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	// try delete file by user, expect failure
	ulRslt = SKF_DeleteFile(appHandle1, "authFile1");
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle1, ADMIN_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	// delete file by expected user
	ulRslt = SKF_DeleteFile(appHandle1, "authFile1");
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DeleteApplication(hdev, "authApp1");
	ERROR_THROW(ulRslt)
///// done test 2

//// start test 3: app can create file by user
	ulRslt = SKF_CreateApplication(hdev, "authApp2", "123456", 6, "123456", 6, SECURE_USER_ACCOUNT, &appHandle2);
	ERROR_THROW(ulRslt);
	
	// create file before log in. expect failure
	ulRslt = SKF_CreateFile(appHandle2, "authFile0", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile in app before log in get 0x%x which requires admin to create\n", ulRslt);
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle2, USER_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	// create file by expected user
	ulRslt = SKF_CreateFile(appHandle2, "authFile0", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile in admin login app get 0x%x which requires admin to create\n", ulRslt);
	ERROR_THROW(ulRslt)

	// create file by expected user
	ulRslt = SKF_CreateFile(appHandle2, "authFile1", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile in admin login app get 0x%x which requires admin to create\n", ulRslt);
	ERROR_THROW(ulRslt)

	// delete file by expected user
	ulRslt = SKF_DeleteFile(appHandle2, "authFile0");
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle2, ADMIN_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	// try create file by user. expect failure
	ulRslt = SKF_CreateFile(appHandle2, "authFile0", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile in user login app get 0x%x which requires admin to create\n", ulRslt);
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	// try delete file by user, expect failure
	ulRslt = SKF_DeleteFile(appHandle2, "authFile1");
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle2, USER_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	// delete file by expected user
	ulRslt = SKF_DeleteFile(appHandle2, "authFile1");
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DeleteApplication(hdev, "authApp2");
	ERROR_THROW(ulRslt)
///// done test 3


//// start test 4: app can create file by anyone
	ulRslt = SKF_CreateApplication(hdev, "authApp3", "123456", 6, "123456", 6, SECURE_EVERYONE_ACCOUNT, &appHandle3);
	ERROR_THROW(ulRslt);
	
	// create file within app which cannot create file. expect failure
	ulRslt = SKF_CreateFile(appHandle3, "authFile0", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile in app before log in get 0x%x which everyone can create\n", ulRslt);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle3, USER_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CreateFile(appHandle3, "authFile1", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile in admin login app get 0x%x which requires admin to create\n", ulRslt);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CreateFile(appHandle3, "authFile2", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile in admin login app get 0x%x which requires admin to create\n", ulRslt);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DeleteFile(appHandle3, "authFile0");
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DeleteFile(appHandle3, "authFile1");
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle3, ADMIN_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DeleteFile(appHandle3, "authFile2");
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DeleteApplication(hdev, "authApp3");
	ERROR_THROW(ulRslt)
///// done test 4


//// start test 5: file read/write test
	ulRslt = SKF_CreateApplication(hdev, "authApp2", "123456", 6, "123456", 6, SECURE_EVERYONE_ACCOUNT, &appHandle2);
	ERROR_THROW(ulRslt);

	// create file by expected user
	ulRslt = SKF_CreateFile(appHandle2, "authFile0", 100, SECURE_NEVER_ACCOUNT, SECURE_NEVER_ACCOUNT);
	//printf("SKF_CreateFile in admin login app get 0x%x which requires admin to create\n", ulRslt);
	ERROR_THROW(ulRslt)

	// create file by expected user
	ulRslt = SKF_CreateFile(appHandle2, "authFile1", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile in admin login app get 0x%x which requires admin to create\n", ulRslt);
	ERROR_THROW(ulRslt)

	// create file by expected user
	ulRslt = SKF_CreateFile(appHandle2, "authFile2", 100, SECURE_USER_ACCOUNT, SECURE_USER_ACCOUNT);
	//printf("SKF_CreateFile in admin login app get 0x%x which requires admin to create\n", ulRslt);
	ERROR_THROW(ulRslt)

	// create file by expected user
	ulRslt = SKF_CreateFile(appHandle2, "authFile3", 100, SECURE_ADM_ACCOUNT, SECURE_ADM_ACCOUNT);
	//printf("SKF_CreateFile in admin login app get 0x%x which requires admin to create\n", ulRslt);
	ERROR_THROW(ulRslt)

	// create file by expected user
	ulRslt = SKF_CreateFile(appHandle2, "authFile4", 100, SECURE_ADM_ACCOUNT, SECURE_USER_ACCOUNT);
	//printf("SKF_CreateFile in admin login app get 0x%x which requires admin to create\n", ulRslt);
	ERROR_THROW(ulRslt)

	// create file by expected user
	ulRslt = SKF_CreateFile(appHandle2, "authFile5", 100, SECURE_USER_ACCOUNT, SECURE_ADM_ACCOUNT);
	//printf("SKF_CreateFile in admin login app get 0x%x which requires admin to create\n", ulRslt);
	ERROR_THROW(ulRslt)

	///// write/read file check with no login
	ulRslt = SKF_WriteFile(appHandle2, "authFile0", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile1", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile2", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile3", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile4", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile5", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	unsigned char readFileBuf[200] = {0};
	ULONG fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile0", 0, strlen("this is test file content, test only..."), readFileBuf,  &fileReadLen);
	if(SAR_OK == ulRslt|| fileReadLen != 0) {
        printf("fileReadLen is %d",fileReadLen);
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile1", 0, strlen("this is test file content, test only..."), readFileBuf,  &fileReadLen);
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile2", 0, strlen("this is test file content, test only..."), readFileBuf,  &fileReadLen);
	if(SAR_OK == ulRslt|| fileReadLen != 0) {
        printf("fileReadLen is %d",fileReadLen);
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile3", 0, strlen("this is test file content, test only..."), readFileBuf,  &fileReadLen);
	if(SAR_OK == ulRslt|| fileReadLen != 0) {
        printf("fileReadLen is %d",fileReadLen);
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile4", 0, strlen("this is test file content, test only..."), readFileBuf,  &fileReadLen);
	if(SAR_OK == ulRslt|| fileReadLen != 0) {
        printf("fileReadLen is %d",fileReadLen);
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile5", 0, strlen("this is test file content, test only..."), readFileBuf,  &fileReadLen);
	if(SAR_OK == ulRslt|| fileReadLen != 0) {
        printf("fileReadLen is %d",fileReadLen);
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)



///// write/read file check for user
	ulRslt = SKF_VerifyPIN(appHandle2, USER_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile0", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile1", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile2", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile3", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile4", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile5", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile0", 0, strlen("this is test file content, test only..."), readFileBuf,  &fileReadLen);
	if(SAR_OK == ulRslt|| fileReadLen != 0) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile1", 0, strlen("this is test file content, test only..."), readFileBuf,  &fileReadLen);
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile2", 0, strlen("this is test file content, test only..."), readFileBuf,  &fileReadLen);
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile3", 0, strlen("this is test file content, test only..."), readFileBuf,  &fileReadLen);
	if(SAR_OK == ulRslt|| fileReadLen != 0) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile4", 0, strlen("this is test file content, test only..."), readFileBuf,  &fileReadLen);
	if(SAR_OK == ulRslt|| fileReadLen != 0) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile5", 0, strlen("this is test file content, test only..."), readFileBuf,  &fileReadLen);
	ERROR_THROW(ulRslt)

///// write/read file check for user
	ulRslt = SKF_VerifyPIN(appHandle2, ADMIN_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile0", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile1", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
		ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile2", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
		if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile3", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile4", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	if(SAR_OK == ulRslt) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle2, "authFile5", 0, (unsigned char *)"this is test file content, test only...", strlen("this is test file content, test only..."));
	ERROR_THROW(ulRslt)
	
	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile0", 0, strlen("this is test file content, test only..."), readFileBuf,	&fileReadLen);
	if(SAR_OK == ulRslt|| fileReadLen != 0) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile1", 0, strlen("this is test file content, test only..."), readFileBuf,	&fileReadLen);
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile2", 0, strlen("this is test file content, test only..."), readFileBuf,	&fileReadLen);
	if(SAR_OK == ulRslt|| fileReadLen != 0) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile3", 0, strlen("this is test file content, test only..."), readFileBuf,	&fileReadLen);
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile4", 0, strlen("this is test file content, test only..."), readFileBuf,	&fileReadLen);
	ERROR_THROW(ulRslt)

	fileReadLen = sizeof(readFileBuf);
	ulRslt = SKF_ReadFile(appHandle2, "authFile5", 0, strlen("this is test file content, test only..."), readFileBuf,	&fileReadLen);
	if(SAR_OK == ulRslt|| fileReadLen != 0) {
		ulRslt = SAR_FAIL;
	}
	else {
		ulRslt = SAR_OK;
	}
	ERROR_THROW(ulRslt)
////////////////////////  

	// delete file by expected user
	ulRslt = SKF_DeleteFile(appHandle2, "authFile0");
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DeleteFile(appHandle2, "authFile1");
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DeleteFile(appHandle2, "authFile2");
	ERROR_THROW(ulRslt)
	
	ulRslt = SKF_DeleteApplication(hdev, "authApp2");
	ERROR_THROW(ulRslt)
///// done test 5

	printf("%s done\n", __FUNCTION__);
	return SAR_OK;
}


// this function remove all p11 objects inside token
ULONG tokenCleanUp()
{
	ULONG ret_skf = SAR_OK;

#ifdef ENABLE_TEST_CALL_P11
	CK_RV ret = C_Initialize(NULL);
	//printf("C_Initialize return 0x%x\r\n", ret);
	if (ret != CKR_OK && ret != CKR_CRYPTOKI_ALREADY_INITIALIZED){
		return -1;
	}

	CK_ULONG slotCount = 0;
	ret = C_GetSlotList(CK_TRUE, NULL, &slotCount);
	//printf("C_GetSlotList return 0x%x and slotCount %d \r\n", ret, slotCount);
	if (ret != CKR_OK || slotCount == 0){
		return -1;
	}

	CK_SLOT_ID_PTR slotID = new CK_SLOT_ID[slotCount];
	ret = C_GetSlotList(CK_TRUE, slotID, &slotCount);
	//printf("C_GetSlotList return 0x%x and slotCount %d\r\n", ret, slotCount);
	if (ret != CKR_OK || slotCount == 0){
		delete[] slotID;
		return -1;
	}

	CK_TOKEN_INFO info = { 0 };
	ret = C_GetTokenInfo(slotID[0], &info);
	//printf("C_GetTokenInfo return 0x%x\r\n", ret);
	if (ret != CKR_OK){
		return ret;
	}

	CK_SESSION_HANDLE session;

	ret = C_OpenSession(slotID[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
	//printf("C_OpenSession return 0x%x\r\n", ret);
	if (ret != CKR_OK){
		return ret;
	}

	ret = C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)JWPIN, strlen(JWPIN));
	//printf("C_Login return 0x%x\r\n", ret);
	if ((ret != CKR_OK) && (CKR_USER_ALREADY_LOGGED_IN != ret)){
		return ret;
	}

	CK_OBJECT_CLASS dataClass = CKO_DATA;
	CK_ATTRIBUTE attributesInit[] = {
		{ CKA_CLASS, &dataClass, sizeof(dataClass) }
	};

	CK_OBJECT_HANDLE handle[4096] = { 0 };
	CK_ULONG count = 0;

	//ret = C_FindObjectsInit(session,attributesInit,sizeof(attributesInit) / sizeof(CK_ATTRIBUTE));
	ret = C_FindObjectsInit(session, NULL, 0);
	//printf("C_FindObjectsInit return 0x%x\r\n", ret);
	if (ret != CKR_OK){
		return ret;
	}

	ret = C_FindObjects(session, handle, 4096, &count);
	//printf("C_FindObjects return 0x%x and count %d\r\n", ret, count);
	if (ret != CKR_OK){
		return ret;
	}

	ret = C_FindObjectsFinal(session);
	//printf("C_FindObjectsFinal return 0x%x\r\n", ret);
	if (ret != CKR_OK){
		return ret;
	}

	for (unsigned int i = 0; i < count; i++){
		printf("object 0x%x to be deleted\n", handle[i]);
		ret = C_DestroyObject(session, handle[i]);
		//printf("C_DestroyObject return 0x%x\r\n", ret);
		if (ret != CKR_OK){
			return ret;
		}
	}

	ret = C_Logout(session);

	C_CloseAllSessions(slotID[0]);
#endif

	return ret_skf;
}


// this function print p11 data objects number, SM2 key objects number, symmetric key object number respectively
ULONG checkObjNum()
{
#ifdef ENABLE_TEST_CALL_P11
	CK_RV ret = CKR_OK;

	CK_OBJECT_HANDLE handle[4096] = { 0 };
	CK_ULONG dataObjNum = 0;
	CK_ULONG asmKeyNum = 0;
	CK_ULONG symKeyNum = 0;

	CK_SESSION_HANDLE session;
	ret = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
	if (ret != CKR_OK){
		return -1;
	}

	CK_OBJECT_CLASS dataClass = CKO_DATA;
	CK_ATTRIBUTE dataTemplate[] = {
		{ CKA_CLASS, &dataClass, sizeof(dataClass) }
	};
	//ret = C_FindObjectsInit(session,attributesInit,sizeof(attributesInit) / sizeof(CK_ATTRIBUTE));
	ret = C_FindObjectsInit(session, dataTemplate, 1);
	if (ret != CKR_OK){
		C_CloseSession(session);
		return -1;
	}
	ret = C_FindObjects(session, handle, 4096, &dataObjNum);
	if (ret != CKR_OK){
		C_CloseSession(session);
		return -1;
	}
	ret = C_FindObjectsFinal(session);
	if (ret != CKR_OK){
		C_CloseSession(session);
		return -1;
	}

	CK_KEY_TYPE  keyType = CKK_SM2;
	CK_ATTRIBUTE AsymTemplate[] = {
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	//ret = C_FindObjectsInit(session,attributesInit,sizeof(attributesInit) / sizeof(CK_ATTRIBUTE));
	ret = C_FindObjectsInit(session, AsymTemplate, 1);
	if (ret != CKR_OK){
		C_CloseSession(session);
		return -1;
	}
	ret = C_FindObjects(session, handle, 4096, &asmKeyNum);
	if (ret != CKR_OK){
		C_CloseSession(session);
		return -1;
	}
	ret = C_FindObjectsFinal(session);
	if (ret != CKR_OK){
		C_CloseSession(session);
		return -1;
	}

	CK_OBJECT_CLASS symmKeyClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE SymTemplate[] = {
		{ CKA_CLASS, &symmKeyClass, sizeof(symmKeyClass) }
	};
	//ret = C_FindObjectsInit(session,attributesInit,sizeof(attributesInit) / sizeof(CK_ATTRIBUTE));
	ret = C_FindObjectsInit(session, SymTemplate, 1);
	if (ret != CKR_OK){
		C_CloseSession(session);
		return -1;
	}
	ret = C_FindObjects(session, handle, 4096, &symKeyNum);
	if (ret != CKR_OK){
		C_CloseSession(session);
		return -1;
	}
	ret = C_FindObjectsFinal(session);
	if (ret != CKR_OK){
		C_CloseSession(session);
		return -1;
	}

	ret = C_CloseSession(session);

	//printf("\np11 dataObj num %d, asymmetric key num %d, symmetric key num %d\n", dataObjNum, asmKeyNum, symKeyNum);
#endif

	return 0;
}


ULONG listP11Object()
{
	ULONG ret_skf = SAR_OK;

#ifdef ENABLE_TEST_CALL_P11

	CK_RV ret = C_Initialize(NULL);
	//printf("C_Initialize return 0x%x\r\n", ret);
	if (ret != CKR_OK && ret != CKR_CRYPTOKI_ALREADY_INITIALIZED){
		return -1;
	}

	CK_ULONG slotCount = 0;
	ret = C_GetSlotList(CK_TRUE, NULL, &slotCount);
	//printf("C_GetSlotList return 0x%x and slotCount %d \r\n", ret, slotCount);
	if (ret != CKR_OK || slotCount == 0){
		return -1;
	}
	
	CK_SLOT_ID_PTR slotID = new CK_SLOT_ID[slotCount];
	ret = C_GetSlotList(CK_TRUE, slotID, &slotCount);
	//printf("C_GetSlotList return 0x%x and slotCount %d\r\n", ret, slotCount);
	if (ret != CKR_OK || slotCount == 0){
		delete[] slotID;
		return -1;
	}
	
	CK_TOKEN_INFO info = { 0 };
	ret = C_GetTokenInfo(slotID[0], &info);
	//printf("C_GetTokenInfo return 0x%x\r\n", ret);
	if (ret != CKR_OK){
		return ret;
	}
	
	CK_SESSION_HANDLE session;
	
	ret = C_OpenSession(slotID[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
	//printf("C_OpenSession return 0x%x\r\n", ret);
	if (ret != CKR_OK){
		return ret;
	}
	
	ret = C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)JWPIN, strlen(JWPIN));
	//printf("C_Login return 0x%x\r\n", ret);
	if ((ret != CKR_OK) && (CKR_USER_ALREADY_LOGGED_IN != ret)){
		return ret;
	}

		ret = C_FindObjectsInit(session, NULL_PTR, 0);
		if(ret != CKR_OK)
		{
			printf("C_FindObjectsInit failed with return 0x%08x\n", ret);
			return SAR_FAIL;
		}
	
		CK_OBJECT_HANDLE handles[256] = { 0 };
		CK_ULONG maxObjectCount = 256;
		CK_ULONG count = 0;
	
		ret = C_FindObjects( session, handles, maxObjectCount, &count );
		if(ret!=CKR_OK)
		{
			printf("C_FindObjects failed with return 0x%08x\n", ret);
			return FALSE;
		}
		else
		{
			printf("pC_FindObjects get object count as %d\n", count);
		}
	
		ret = C_FindObjectsFinal( session);
	
		CK_UTF8CHAR application[256] = {0};
		CK_UTF8CHAR label[256] = {0};
		CK_ATTRIBUTE_TYPE classType = 0x12345678;
		CK_ULONG appLen = sizeof(application);
		CK_ULONG labelLen = sizeof(label);
		CK_ULONG classLen = sizeof(classType);
		int printCount = 0;
		int tempCount=0;
		CK_UTF8CHAR dataValue[1024*5] = {0};
		CK_ULONG dataLen = 1024*5;
		CK_ATTRIBUTE getDataObjInfo[] = {
			{ CKA_APPLICATION, application, appLen },
			{ CKA_VALUE, dataValue, 1024*5 },
			{ CKA_LABEL, label, labelLen}
		};
		CK_ATTRIBUTE getCkaClass[] = {
			{ CKA_CLASS, &classType, classLen},
		};
	
		CK_UTF8CHAR cakId[256] = {0};
		CK_ATTRIBUTE getSM2CkaId[] = {
			{ CKA_ID, cakId, 256}
		};
	
		CK_ATTRIBUTE getDataValue[] = {
			{ CKA_VALUE, dataValue, 1024*5}
		};
	
		printf("total object in TF card is %d\n", count);
		
		for(tempCount=0; tempCount < count; tempCount++)
		{
			printf("start to read infomation of object %d (handle 0x%08x)\n", tempCount+1, handles[tempCount]);
			printf("-------------------------------------------------------------------------------------------\n");
			classType = 0x12345678;
			getCkaClass[0].ulValueLen = 4;
			
			ret = C_GetAttributeValue(session, handles[tempCount], getCkaClass, 1);
			if(ret!=CKR_OK)
			{
				printf("C_GetAttributeValue 1 failed with return 0x%08x for object 0x%08x\n", ret, handles[tempCount]);
				continue;
			}
	
			if (CKO_DATA == classType)
			{
				memset(application, 0, sizeof(application));
				memset(label, 0, sizeof(label));
				memset(dataValue, 0, 1024*5);
	
				getDataObjInfo[0].ulValueLen = sizeof(application);
				getDataObjInfo[1].ulValueLen = 1024*5;
				getDataObjInfo[2].ulValueLen = sizeof(label);
			
				ret = C_GetAttributeValue(session, handles[tempCount], getDataObjInfo, 3);
	
				if(ret!=CKR_OK)
				{
					printf("pC_GetAttributeValue 2 failed with return 0x%08x for object 0x%08x\n", ret, handles[tempCount]);
					continue;
				}

				printf("CKA_CLASS is: 0x%08x as CKO_DATA\n", classType);
	
				printf("CKA_APPLICATION is: ");
				for(printCount=0; printCount < getDataObjInfo[0].ulValueLen; printCount++)
				{
					printf("%c", application[printCount]);
				}
				printf("\nCKA_LABEL char is: ");
				for(printCount=0; printCount < getDataObjInfo[2].ulValueLen; printCount++)
				{
					printf("%c", label[printCount]);
				}

				printf("     binary as: ");
				for(printCount=0; printCount < getDataObjInfo[2].ulValueLen; printCount++)
				{
					printf("%02x", label[printCount]);
				}
	
				//if(0 == strncmp((char *)label, "KMC_INFO", 8))
				{
					printf("\nCKA_VALUE information is:\n");
					for(printCount=0; printCount < getDataObjInfo[1].ulValueLen; printCount++)
					{
						printf("%02x", dataValue[printCount]);
						if((printCount%32) == 31)
						{
							printf("\n");
						}
					}
				}
	
				printf("\nobject 0x%08x information end\n", handles[tempCount]);
			}
			else if ((CKO_PRIVATE_KEY == classType))
			{
				getSM2CkaId[0].ulValueLen = 256;
				memset(cakId, 0, 256);
	
	
				ret = C_GetAttributeValue(session, handles[tempCount], getSM2CkaId, 1);
	
				if(ret!=CKR_OK)
				{
					printf("C_GetAttributeValue 2 failed with return 0x%08x for object 0x%08x\n", ret, handles[tempCount]);
					continue;
				}
				
				printf("CKA_CLASS is: 0x%08x as CKO_PRIVATE_KEY\n", classType);
				
				printf("CKA_ID is: ");
				for(printCount=0; printCount < getSM2CkaId[0].ulValueLen; printCount++)
				{
					printf("%0c", cakId[printCount]);
				}
				printf("  binary as: ");
				for(printCount=0; printCount < getSM2CkaId[0].ulValueLen; printCount++)
				{
					printf("%02x", cakId[printCount]);
				}
	
				printf("\nobject 0x%08x information end\n", handles[tempCount]);
			}
			else if ((CKO_PUBLIC_KEY == classType))
			{
				getSM2CkaId[0].ulValueLen = 256;
				memset(cakId, 0, 256);
				
				ret = C_GetAttributeValue(session, handles[tempCount], getSM2CkaId, 1);
	
				if(ret!=CKR_OK)
				{
					printf("pC_GetAttributeValue 3 failed with return 0x%08x for object 0x%08x\n", ret, handles[tempCount]);
					continue;
				}
				
				printf("CKA_CLASS is: 0x%08x as CKO_PUBLIC_KEY\n", classType);
				
				printf("CKA_ID is: ");
				for(printCount=0; printCount < getSM2CkaId[0].ulValueLen; printCount++)
				{
					printf("%0c", cakId[printCount]);
				}
				printf("  binary as: ");
				for(printCount=0; printCount < getSM2CkaId[0].ulValueLen; printCount++)
				{
					printf("%02x", cakId[printCount]);
				}
	
				printf("\nobject 0x%08x information end\n", handles[tempCount]);
			}
			else
			{
				printf("object 0x%08x \nCKA_CLASS is: 0x%08x\n", handles[tempCount], classType);
				printf("object 0x%08x information end\n", handles[tempCount]);
			}
			printf("-------------------------------------------------------------------------------------------\n");
	
		}

	ret = C_CloseSession(session);
#endif

	return 0;

}


ULONG checkHistoryState()
{
	ULONG ulRslt = SAR_OK;
	ULONG ulNameLen = 0;
	char *szDevName = NULL;
	DEVHANDLE hdev = NULL;
	HANDLE appHandle0, appHandle1, hcont0, hcont1;
	ECCPUBLICKEYBLOB	eccPubSign = { 0 };
	ULONG remainC = 0;
	ULONG remainUsr = 0;
	ULONG remainAdm = 0;
    DWORD maxusercount = 8;
    DWORD maxadmincount = 8;

	printf("================check history record consistency start=================\n");

	//tokenCleanUp();

	ulRslt = SKF_EnumDev(1, NULL, &ulNameLen);
	//printf("SKF_EnumDev done, return 0x%x and ulNameLen %d...\r\n", ulRslt, ulNameLen);

	ERROR_THROW(ulRslt)
	szDevName = new char[ulNameLen];

	ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
	//printf("SKF_EnumDev done, return 0x%x...\r\n", ulRslt);
	ERROR_THROW(ulRslt)

    printf("CHECK: SKF_EnumDev result: \n");
    for (unsigned int i = 0; i < ulNameLen; i++) {
        printf("%c", szDevName[i]);
    }
    printf("\n");
    getchar();

	char *pszdev = szDevName;
	ulRslt = SKF_ConnectDev(pszdev, &hdev);
	ERROR_THROW(ulRslt)

    ulRslt = SKF_CreateApplication(hdev, "testHistoryApp0", "12345678", maxadmincount, "123456", maxusercount, SECURE_EVERYONE_ACCOUNT, &appHandle0);
    if(ulRslt==SAR_OK)
    {
        ulRslt = SAR_FAIL;
    } else{
        ulRslt=SAR_OK;
    }
    ERROR_THROW(ulRslt);

    ulRslt = deviceAuth(hdev);
	ERROR_THROW(ulRslt)

    getchar();

	ulRslt = SKF_CreateApplication(hdev, "testHistoryApp0", "12345678", maxadmincount, "123456", maxusercount, SECURE_EVERYONE_ACCOUNT, &appHandle0);
	ERROR_THROW(ulRslt);

	ulRslt = SKF_VerifyPIN(appHandle0, USER_TYPE, "123456", &remainC);
	//printf("line %03d SKF_VerifyPIN return 0x%x and remain count %d\n", __LINE__, ulRslt, remainC);
    if(remainC != maxusercount)
    {
        ulRslt = SAR_FAIL;
    }
	//printf("SKF_VerifyPIN with new PIN return 0x%x\n", ulRslt);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CreateFile(appHandle0, "appHistoryFile0", 100, SECURE_EVERYONE_ACCOUNT, SECURE_EVERYONE_ACCOUNT);
	//printf("SKF_CreateFile appFile0 return 0x%x\n", ulRslt);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandle0, "appHistoryFile0", 0, (BYTE *)"this is app history file 0", strlen("this is app history file 0"));
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CreateContainer(appHandle0, "containerHistory_0", &hcont0);
	ERROR_THROW(ulRslt);

	// generate local signature SM2 keypair
	memset(&eccPubSign, 0, sizeof(eccPubSign));
	ulRslt = SKF_GenECCKeyPair(hcont0, SGD_SM2_1, &eccPubSign);
	//PRINT_LOG("SKF_GenECCKeyPair, hcont = %p, return 0x%lx", hcont, ulRslt);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ImportCertificate(hcont0, 1, (BYTE *)"testContainer_cert_sign_history", strlen("testContainer_cert_sign_history"));
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle0, USER_TYPE, "888888", &remainUsr);
	if (SAR_PIN_INCORRECT != ulRslt ) { ulRslt = SAR_FAIL; }
    else if(remainUsr != (maxusercount - 1)) {ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle0, USER_TYPE, "888888", &remainUsr);
	if (SAR_PIN_INCORRECT != ulRslt) { ulRslt = SAR_FAIL; }
    else if(remainUsr != (maxusercount - 2)) {ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle0, ADMIN_TYPE, "888888", &remainAdm);
	if (SAR_PIN_INCORRECT != ulRslt) { ulRslt = SAR_FAIL; }
    else if(remainAdm != (maxadmincount - 1)) {ulRslt = SAR_FAIL; }
	else { ulRslt = SAR_OK; }
	ERROR_THROW(ulRslt)

//    printf("diesconnect dev");
	ulRslt = SKF_DisConnectDev(hdev);
	ERROR_THROW(ulRslt)
    getchar();

	ulRslt = SKF_EnumDev(1, NULL, &ulNameLen);
	//printf("SKF_EnumDev done, return 0x%x and ulNameLen %d...\r\n", ulRslt, ulNameLen);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
	//printf("SKF_EnumDev done, return 0x%x...\r\n", ulRslt);
	ERROR_THROW(ulRslt)

	pszdev = szDevName;
	ulRslt = SKF_ConnectDev(pszdev, &hdev);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_OpenApplication(hdev, "testHistoryApp0", &appHandle1);
	ERROR_THROW(ulRslt)

	char szContName[100] = {0};
	memset(szContName, 0, sizeof(szContName));
	ULONG szContNameSize = sizeof(szContName);

	ULONG maxCount = 0;
	ULONG remCount = 0;
	BOOL isDefault = 0;
	ulRslt = SKF_GetPINInfo(appHandle1, USER_TYPE, &maxCount, &remCount, &isDefault);
	//printf("user pin info: %d %d %d\n", maxCount, remCount, isDefault);
	if(remainUsr != remCount || maxCount != maxusercount) {
		printf("userpin count check failed\n");
		ulRslt = SAR_FAIL;}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_GetPINInfo(appHandle1, ADMIN_TYPE, &maxCount, &remCount, &isDefault);
	//printf("admin pin info: %d %d %d\n", maxCount, remCount, isDefault);
	if(remainAdm != remCount || maxCount != maxadmincount) {
		printf("adminpin count check failed\n");
		ulRslt = SAR_FAIL;}
	ERROR_THROW(ulRslt)

	ulRslt = SKF_VerifyPIN(appHandle1, USER_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

    ulRslt = SKF_GetPINInfo(appHandle1, USER_TYPE, &maxCount, &remCount, &isDefault);
    //printf("user pin info: %d %d %d\n", maxCount, remCount, isDefault);
    if(remCount != maxusercount || maxCount != maxusercount) {
        printf("userpin count check again failed, \n");
        ulRslt = SAR_FAIL;}
    ERROR_THROW(ulRslt)

    ulRslt = SKF_VerifyPIN(appHandle1, ADMIN_TYPE, "12345678", &remainC);
    ERROR_THROW(ulRslt)

    ulRslt = SKF_GetPINInfo(appHandle1, ADMIN_TYPE, &maxCount, &remCount, &isDefault);
    //printf("user pin info: %d %d %d\n", maxCount, remCount, isDefault);
    if(remCount != maxadmincount || maxCount != maxadmincount) {
        printf("adminpin count check again failed\n");
        ulRslt = SAR_FAIL;}
    ERROR_THROW(ulRslt)

	char szFileName[256] = {0};
	memset(szFileName, 0, sizeof(szFileName));
	ULONG fileSize = sizeof(szFileName);
	ulRslt = SKF_EnumFiles(appHandle1, szFileName, &fileSize);
    if (memcmp(szFileName, "appHistoryFile0", strlen("appHistoryFile0")))
    {
        printf("file %s found, shoud be appHistoryFile0. filesize is %lu\n", szFileName,fileSize);
        ulRslt = SAR_FAIL;
    }
//	printf("file %s found, shoud be appHistoryFile0. filesize is %lu\n", szFileName,fileSize);
	ERROR_THROW(ulRslt);

	char readOut[256] = {0};
	memset(readOut, 0, sizeof(readOut));
	ULONG readLen = sizeof(readOut);
	memset(readOut, 0, sizeof(readOut));
	ulRslt = SKF_ReadFile(appHandle1, szFileName, 0, 256, (BYTE *)readOut, &readLen);
	ERROR_THROW(ulRslt)
	if (memcmp(readOut, "this is app history file 0", strlen("this is app history file 0")))
	{
		printf("file check failed\n");
		ulRslt = SAR_FAIL;
		ERROR_THROW(ulRslt)
	}
//	printf("SKF_ReadFile get: %s\n", readOut);
    getchar();

	ulRslt = SKF_EnumContainer(appHandle1, szContName, &szContNameSize);
    if (memcmp(szContName, "containerHistory_0", strlen("containerHistory_0")))
    {
        printf("container check failed\n");
        ulRslt = SAR_FAIL;
        ERROR_THROW(ulRslt)
    }
//	printf("container %s found, should be containerHistory_0. size is %lu\n", szContName,szContNameSize);
	ERROR_THROW(ulRslt);

	ulRslt = SKF_OpenContainer(appHandle1, szContName, &hcont1);
	ERROR_THROW(ulRslt)

	char certBuf[256] = {0};
	memset(certBuf, 0, sizeof(certBuf));
	ULONG cerLen = sizeof(certBuf);
	ulRslt = SKF_ExportCertificate(hcont1, 1, (BYTE *)certBuf, &cerLen);
	ERROR_THROW(ulRslt)
	if (memcmp(certBuf, "testContainer_cert_sign_history", strlen("testContainer_cert_sign_history")))
	{
		printf("cert check failed\n");
		ulRslt = SAR_FAIL;
		ERROR_THROW(ulRslt)
	}
//	printf("SKF_ExportCertificate get: %s\n", certBuf);

    ulRslt = SKF_DeleteApplication(hdev, "testHistoryApp0");
    if(ulRslt == SAR_OK)
    {
        ulRslt = SAR_FAIL;
    }else{
        ulRslt=SAR_OK;
    }
    ERROR_THROW(ulRslt)

    ulRslt = deviceAuth(hdev);
    ERROR_THROW(ulRslt)

	ulRslt = SKF_DeleteApplication(hdev, "testHistoryApp0");
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DisConnectDev(hdev);
	ERROR_THROW(ulRslt)

	printf("\n================check history record consistency end=================\n");

	return SAR_OK;

	
}

