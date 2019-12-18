// skf_jw_sanity_test.cpp : 定义控制台应用程序的入口点。
//

//#include "stdafx.h"

#include "skf.h"
#include <iostream>
#ifdef _WIN32
#include <Windows.h>
#include "sm2.h"
#include "libsm.h"
#include "sms4.h"
#include <tchar.h>
#include <winbase.h>
#else
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <WinSCard.h>

//#define SM1_SUPPORT_TEST
#define ENCDEC_UPDATE_OPERATION_ENABLE 
//#define EXTERNAL_SM2
#define SINGLE_CONTAINER_ONLY
//#define NO_FILE_OPERATION
#define ENABLE_CLOSE_HANDLE

using std::string;

#define SM4_KEY_LEN  16
#define DEV_AUTH_RANDOM_LEN 8
#define HASH_OUTPUT_LEN  32

#define ERROR_THROW(r) {if((r) != SAR_OK) {std::cout<<__FILE__<<"["<<std::dec<<__LINE__<<"] ------>>>>>> ERROR_THROW ret = 0x"<<std::hex<<r<<std::endl;return r;}}
#define ERROR_BREAK(r) {if((r) != SAR_OK) {std::cout<<__FILE__<<"["<<std::dec<<__LINE__<<"] ------>>>>>> ERROR_THROW ret = 0x"<<std::hex<<r<<std::endl; break;}}
#define ERROR_EXIT(r) {if((r) != SAR_OK) {std::cout<<__FILE__<<"["<<std::dec<<__LINE__<<"] ------>>>>>> ERROR_THROW ret = 0x"<<std::hex<<r<<std::endl;return r;}}


ULONG create_application();
ULONG delete_application();
ULONG configure_container();
ULONG sign_verify();
ULONG message_cryption();
ULONG operate_file();
ULONG deviceAuth(DEVHANDLE	hdev);
ULONG importSm2KeyPair(HANDLE hdev, HANDLE hcont, unsigned char * privKeyExternal, unsigned char * pubKeyExternal);

#ifdef SM1_SUPPORT_TEST
ULONG sm1_verify(DEVHANDLE	hdev);
#endif

//BYTE * tempSessKey = (BYTE *)"1234567812345678";
BYTE * devAuthKey = (BYTE *)"1234567812345678";

typedef ULONG (*TYPE_SKF_EnumDev)(BOOL ,LPSTR ,ULONG* );
//static TYPE_SKF_EnumDev pSKF_EnumDev = NULL;

static void test_reader()
{
#ifdef TEST_READERS
	SCARDCONTEXT    hSC;
	ULONG           lReturn;
	ULONG           lReturn2;
	LPTSTR          pmszReaders = NULL;
	LPTSTR          pReader;
	LPTSTR pmszCards = NULL;
	LPTSTR pCard;
	DWORD           cch = SCARD_AUTOALLOCATE;
	int i = 0;
	OPENCARDNAME cardNamePre;
	OPENCARDNAME cardNamePst;
	const char readerNameAcs[] = "ACS CCID USB Reader 0";
	const char readerNameEz[] = "CASTLES EZ100PU 0";
	

	// Establish the context.
	lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
									NULL,
									NULL,
									&hSC);
	if ( SCARD_S_SUCCESS != lReturn ){
		printf("Failed SCardEstablishContext\n");
		return;
	}


#if 1
	lReturn = SCardListCards(NULL,
                         NULL,
                         NULL,
                         NULL,
                         (LPTSTR)&pmszCards,
                         &cch );
	if ( SCARD_S_SUCCESS != lReturn )
	{
		printf("Failed SCardListCards\n");
		return; // Or other appropriate error action
	}
	// Do something with the multi string of cards.
	// Output the values.
	// A double-null terminates the list of values.
	pCard = pmszCards;
	while ((0 != *pCard) && (0 != *(pCard+1)))
	{
		// Display the value.
		printf("%s\n", pCard );
		// Advance to the next value.
		pCard = pCard + strlen((char *)pCard) + 1;
	}
	lReturn2 = SCardFreeMemory( hSC, pmszCards );
#endif

	cch = SCARD_AUTOALLOCATE;
	lReturn = SCardListReaders(hSC,
                           NULL,
                           (LPTSTR)&pmszReaders,
                           &cch );

	switch( lReturn )
	{
    case SCARD_E_NO_READERS_AVAILABLE:
        printf("Reader is not in groups, return 0x%lx\n", lReturn);
        // Take appropriate action.
        // ...
        return;

    case SCARD_S_SUCCESS:
        // Do something with the multi string of readers.
        // Output the values.
        // A double-null terminates the list of values.
        pReader = pmszReaders;
		while ((0 != *pReader) && (0 != *(pReader+1)))
        {
            // Display the value.
            printf("Reader: %s\n", pReader );
            // Advance to the next value.
            pReader = pReader + strlen((char *)pReader) + 1;
        }
        // Free the memory.
        lReturn2 = SCardFreeMemory( hSC,
                                   pmszReaders );
        if ( SCARD_S_SUCCESS != lReturn2 )
            printf("Failed SCardFreeMemory\n");
		break;
	default:
        printf("Failed SCardListReaders 0x%lx\n", lReturn);
        // Take appropriate action.
        // ...
        return;
	}


	OPENCARDNAME_EX  dlgStruct;
	WCHAR            szReader[256];
	WCHAR            szCard[256];

	// Initialize the structure.
	memset(&dlgStruct, 0, sizeof(dlgStruct));
	dlgStruct.dwStructSize = sizeof(dlgStruct);
	dlgStruct.hSCardContext = hSC;
	dlgStruct.dwFlags = SC_DLG_FORCE_UI;
	dlgStruct.lpstrRdr = (LPSTR) szReader;
	dlgStruct.nMaxRdr = 256;
	dlgStruct.lpstrCard = (LPSTR) szCard;
	dlgStruct.nMaxCard = 256;
	//dlgStruct.lpstrTitle = (LPSTR) "Identity Device (NIST SP 800-73 [PIV])";
	//dlgStruct.lpstrTitle = (LPSTR) "/NIST SP 800-73 [PIV]";
	dlgStruct.lpstrTitle = (LPSTR) "My Select Card Title";

	// Display the select card dialog box.
	lReturn = SCardUIDlgSelectCard(&dlgStruct);
	if ( SCARD_S_SUCCESS != lReturn )
		printf("Failed SCardUIDlgSelectCard - %x\n", lReturn );
	else
		printf("Reader: %S\nCard: %S\n", szReader, szCard );

#if 0
	unsigned char readerName[256] = {0};
	unsigned char cardName[256] = {0};
	memcpy(readerName, readerNameEz, strlen(readerNameEz));
	memset(&cardNamePre, 0, sizeof(cardNamePre));
	cardNamePre.dwStructSize = sizeof(cardNamePre);
	cardNamePre.hSCardContext = hSC;
	cardNamePre.lpstrRdr = (LPSTR)readerName;
	cardNamePre.nMaxRdr = 256;
	cardNamePre.lpstrCard = (LPSTR)cardName;
	cardNamePre.nMaxCard = 256;
	cardNamePre.dwShareMode = SCARD_SHARE_SHARED;
	cardNamePre.dwPreferredProtocols = SCARD_PROTOCOL_T0;


	lReturn = GetOpenCardName(&cardNamePre);

	memset(&cardNamePst, 0, sizeof(cardNamePst));
	memcpy(readerName, readerNameEz, strlen(readerNameEz));
	cardNamePst.dwStructSize = sizeof(cardNamePre);
	cardNamePst.hSCardContext = hSC;
	cardNamePst.lpstrRdr = (LPSTR)readerName;
	cardNamePst.nMaxRdr = 256;
	cardNamePst.lpstrCard = (LPSTR)cardName;
	cardNamePst.nMaxCard = 256;
	cardNamePst.dwShareMode = SCARD_SHARE_SHARED;
	cardNamePst.dwPreferredProtocols = SCARD_PROTOCOL_T0;
	lReturn = GetOpenCardName(&cardNamePst);
#endif

	SCARDHANDLE hCardHandle;
	DWORD dwAP;
	lReturn = SCardConnect(hSC, (LPCTSTR)"ACS CCID USB Reader 0",SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCardHandle, &dwAP);
	if(SCARD_S_SUCCESS != lReturn)
	{
		printf("Failed SCardConnect ACS CCID USB Reader 0 with return 0x%lx\n", lReturn);
		lReturn = SCardConnect(hSC, (LPCTSTR)"CASTLES EZ100PU 0",SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCardHandle, &dwAP);
		if(SCARD_S_SUCCESS != lReturn)
		{
			printf("Failed SCardConnect CASTLES EZ100PU 0 with return 0x%lx\n", lReturn);
			return;
		}
	}

	switch(dwAP)
	{
	case SCARD_PROTOCOL_T0:
		printf("Active protocol T0\n");
		break;
	case SCARD_PROTOCOL_T1:
		printf("Active protocol T1\n");
		break;
	case SCARD_PROTOCOL_UNDEFINED:
	default:
		printf("Active protocol unnegotiated or unknown\n");
		break;
	}

	LPBYTE   pbAttr = NULL;
	DWORD    cByte = SCARD_AUTOALLOCATE;
	lReturn = SCardGetAttrib(hCardHandle, SCARD_ATTR_VENDOR_NAME, (LPBYTE)&pbAttr, &cByte);
	if ( SCARD_S_SUCCESS != lReturn )
	{
		printf("Failed SCardGetAttrib with 0x%lx\n", lReturn);
		return;  // Or other appropriate action.
	}
	else
	{
		// Output the bytes.
		printf("SCardGetAttrib get vendor name: ");
		for (i = 0; i < cByte; i++)
			printf("%c", *(pbAttr+i));
		printf("\n");

		// Free the memory when done.
		// hContext was set earlier by SCardEstablishContext
		lReturn = SCardFreeMemory( hSC, pbAttr );
	}

	pbAttr = NULL;
	cByte = SCARD_AUTOALLOCATE;
	lReturn = SCardGetAttrib(hCardHandle, SCARD_ATTR_ATR_STRING, (LPBYTE)&pbAttr, &cByte);
	if ( SCARD_S_SUCCESS != lReturn )
	{
		printf("Failed SCardGetAttrib with 0x%lx\n", lReturn);
		return;  // Or other appropriate action.
	}
	else
	{
		// Output the bytes.
		printf("SCardGetAttrib get ATR: ");
		for (i = 0; i < cByte; i++)
			printf("%02x ", *(pbAttr+i));
		printf("\n");

		// Free the memory when done.
		// hContext was set earlier by SCardEstablishContext
		lReturn = SCardFreeMemory( hSC, pbAttr );
	}


	//lReturn = SCardBeginTransaction(hCardHandle);

	lReturn = SCardDisconnect(hCardHandle, SCARD_LEAVE_CARD);
	if ( SCARD_S_SUCCESS != lReturn )
	{
		printf("Failed SCardDisconnect\n");
		return;  // Or other appropriate action.
	}

	lReturn = SCardReleaseContext(hSC);
if ( SCARD_S_SUCCESS != lReturn )
    printf("Failed SCardReleaseContext\n");

#endif

	return;
}

ULONG cryptoki_3_step_operations(DEVHANDLE hdev)
{
	ULONG ulRslt = SAR_OK;
	HANDLE tempKeyHandle = NULL;
	BLOCKCIPHERPARAM bp = { 0 };
	unsigned char plainData[SM4_KEY_LEN] = {1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1};
	unsigned char encOut[SM4_KEY_LEN] = {0};
	unsigned char decOut[SM4_KEY_LEN] = {0};
	unsigned char finalOut[SM4_KEY_LEN] = {0};
	ULONG finalLen = SM4_KEY_LEN;
	ULONG encLen = SM4_KEY_LEN;
	ULONG decLen = SM4_KEY_LEN;
	unsigned char hash1[HASH_OUTPUT_LEN] = {0};
	unsigned char hash2[HASH_OUTPUT_LEN] = {0};
	ULONG hashLen = HASH_OUTPUT_LEN;


#ifdef ENCDEC_UPDATE_OPERATION_ENABLE
	ulRslt = SKF_SetSymmKey(hdev, (unsigned char*)devAuthKey, SGD_SMS4_ECB, &tempKeyHandle);
	//ulRslt = SKF_SetSymmKey(hdev, (unsigned char*)devAuthKey, SGD_SM1_ECB, &tempKeyHandle);
	//ulRslt = SKF_SetSymmKey(hdev, (unsigned char*)tempSessKey, SGD_SMS4_ECB, &tempKeyHandle);
	//PRINT_LOG("SKF_SetSymmKey get result 0x%lx and return keyHandle %p", ulRslt, tempKeyHandle);
	ERROR_THROW(ulRslt)

	// step 3.1 encrypt initialize with created session key handle. bp.paddingType shall be 0
	ulRslt = SKF_EncryptInit(tempKeyHandle, bp);
	ERROR_THROW(ulRslt)

	// step 3.2 encrypt 16 bytes raw data. first 8 bytes get by SKF_GenRandom, following 8 bytes fill with 0 for SM4 ECB encryption
	ulRslt = SKF_EncryptUpdate(tempKeyHandle, (unsigned char *)plainData, sizeof(plainData), encOut, &encLen);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_EncryptFinal(tempKeyHandle, (unsigned char *)finalOut, &finalLen);
	ERROR_THROW(ulRslt)


	ulRslt = SKF_DecryptInit(tempKeyHandle, bp);
	ERROR_THROW(ulRslt)

	// step 3.2 encrypt 16 bytes raw data. first 8 bytes get by SKF_GenRandom, following 8 bytes fill with 0 for SM4 ECB encryption
	ulRslt = SKF_DecryptUpdate(tempKeyHandle, (unsigned char *)encOut, encLen, decOut, &decLen);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DecryptFinal(tempKeyHandle, (unsigned char *)finalOut, &finalLen);
	ERROR_THROW(ulRslt)

	if (memcmp(plainData, decOut, SM4_KEY_LEN))
	{
		ERROR_THROW(-1)
	}

	// step 4, close session key handle
	ulRslt = SKF_CloseHandle(tempKeyHandle);
	ERROR_THROW(ulRslt)
#endif

	// digest interface
	ulRslt = SKF_DigestInit(hdev, SGD_SM3, NULL, NULL, 0, &tempKeyHandle);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_Digest(tempKeyHandle, plainData, SM4_KEY_LEN, hash1, &hashLen);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CloseHandle(tempKeyHandle);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DigestInit(hdev, SGD_SM3, NULL, NULL, 0, &tempKeyHandle);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DigestUpdate(tempKeyHandle, plainData, SM4_KEY_LEN);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DigestFinal(tempKeyHandle, hash2, &hashLen);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CloseHandle(tempKeyHandle);
	ERROR_THROW(ulRslt)

	if (memcmp(hash1, hash2, HASH_OUTPUT_LEN))
	{
		ERROR_THROW(-1)
	}


	return SAR_OK;
}

#if 0
ULONG create_jdzy_app()
{
	ULONG ulRslt = SAR_OK;
	char  *szDevName = NULL;
	ULONG  ulNameLen = 0;
	DEVHANDLE hdev = NULL;
	char * currentDevName = NULL;
	BYTE tempSessKey[SM4_KEY_LEN] = {0};
	HANDLE tempKeyHandle = 0;
	BLOCKCIPHERPARAM bp = { 0 };
	HANDLE hMyAppHandle = NULL;
	HANDLE hcontA = NULL;
	BYTE devRandom[SM4_KEY_LEN] = { 0 };
	BYTE devAuth[SM4_KEY_LEN] = { 0 };
	ULONG devAuthLen = SM4_KEY_LEN;

	printf("%s start...\n", __FUNCTION__);

	memset(devAuth, 0, SM4_KEY_LEN);
	memset(tempSessKey, 0, SM4_KEY_LEN);

	// get dev list name length by put 2nd parameter as NULL
	ulRslt = SKF_EnumDev(1, NULL, &ulNameLen);

	// allocate enough memory to get device name list
	// device name ended with 0x0 and list ended with 0x0 0x0
	szDevName = new char[ulNameLen];
	ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);

	// operate 1st device here
	currentDevName = szDevName;
	ulRslt = SKF_ConnectDev(currentDevName, &hdev);

		ulRslt = SKF_GenRandom(hdev, devRandom, DEV_AUTH_RANDOM_LEN);
	ERROR_THROW(ulRslt)

	// step 2, create session key, 3rd parameter shall always be SGD_SMS4_ECB
	//ulRslt = SKF_SetSymmKey(hdev, (unsigned char*)devAuthKey, SGD_SMS4_ECB, &tempKeyHandle);
	ulRslt = SKF_SetSymmKey(hdev, (unsigned char*)tempSessKey, SGD_SMS4_ECB, &tempKeyHandle);
	//PRINT_LOG("SKF_SetSymmKey get result 0x%lx and return keyHandle %p", ulRslt, tempKeyHandle);
	ERROR_THROW(ulRslt)

	// step 3.1 encrypt initialize with created session key handle. bp.paddingType shall be 0
	ulRslt = SKF_EncryptInit(tempKeyHandle, bp);
	ERROR_THROW(ulRslt)

	// step 3.2 encrypt 16 bytes raw data. first 8 bytes get by SKF_GenRandom, following 8 bytes fill with 0 for SM4 ECB encryption
	ulRslt = SKF_Encrypt(tempKeyHandle, (unsigned char *)devRandom, sizeof(devRandom), devAuth, &devAuthLen);
	ERROR_THROW(ulRslt)

	// step 4, close session key handle
#ifdef ENABLE_CLOSE_HANDLE
	ulRslt = SKF_CloseHandle(tempKeyHandle);
	ERROR_THROW(ulRslt)
#endif

	// step 5, pass encrypted data to device. device will return authorization pass or fail
	ulRslt = SKF_DevAuth(hdev, devAuth, devAuthLen);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CreateApplication(hdev, "JITAPPLICATION_SM2", "11111111", 8, "11111111", 8, SECURE_USER_ACCOUNT, &hMyAppHandle);
	ERROR_THROW(ulRslt);

	ulRslt = SKF_OpenApplication(hdev, "JITAPPLICATION_SM2", &hMyAppHandle);
	ERROR_THROW(ulRslt)

	ULONG remainC = 0;
	ulRslt = SKF_VerifyPIN(hMyAppHandle, USER_TYPE, "11111111", &remainC);
	ERROR_THROW(ulRslt)
	
	ulRslt = SKF_CreateContainer(hMyAppHandle, "1CF68ADF-3FD9-4437-8D19-C07918E3A9DA", &hcontA);
	ERROR_THROW(ulRslt);
	
	ulRslt = SKF_CloseContainer(hcontA);

	ulRslt = SKF_CloseApplication(hMyAppHandle);

	// disconnect device after operation
	ulRslt = SKF_DisConnectDev(hdev);

	delete[]szDevName;

	return 0;
}
#endif

ULONG read_app()
{
	ULONG ulRslt = SAR_OK;
	char  *szDevName = NULL;
	ULONG  ulNameLen = 0;
	DEVHANDLE hdev = NULL;
	char * currentDevName = NULL;

	// get dev list name length by put 2nd parameter as NULL
	ulRslt = SKF_EnumDev(1, NULL, &ulNameLen);

	// allocate enough memory to get device name list
	// device name ended with 0x0 and list ended with 0x0 0x0
	szDevName = new char[ulNameLen];
	ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);

	// operate 1st device here
	currentDevName = szDevName;
	ulRslt = SKF_ConnectDev(currentDevName, &hdev);
	
	ULONG  ulAppNameLen = 0;
	ulRslt = SKF_EnumApplication(hdev, NULL, &ulAppNameLen);

	char * enumAppOut = new char[ulAppNameLen];
	ulRslt = SKF_EnumApplication(hdev, enumAppOut, &ulAppNameLen);
	printf("application %s found...\n", enumAppOut);

	HANDLE hMyAppHandle = NULL;
	ulRslt = SKF_OpenApplication(hdev, enumAppOut, &hMyAppHandle);

	ULONG remainC = 0;
	ulRslt = SKF_VerifyPIN(hMyAppHandle, USER_TYPE, "11111111", &remainC);

	ULONG  ulContNameLen = 0;
	ulRslt = SKF_EnumContainer(hMyAppHandle, NULL, &ulContNameLen);

	char * enumContainerOut = new char[ulContNameLen];
	ulRslt = SKF_EnumContainer(hMyAppHandle, enumContainerOut, &ulContNameLen);
	printf("container %s found...\n", enumContainerOut);

	HANDLE hcontA = NULL;
	ulRslt = SKF_OpenContainer(hMyAppHandle, enumContainerOut, &hcontA);

#if 1
	ULONG certEncLen = 0;
	ulRslt = SKF_ExportCertificate(hcontA, 0, NULL, &certEncLen);
	// read certificate for enc/dec
	char * certEnc = new char[certEncLen];
	ulRslt = SKF_ExportCertificate(hcontA, 0, (BYTE *)certEnc, &certEncLen);
	printf("SKF_ExportCertificate get length %02d for cert encrypt ------------------\n", certEncLen);
  for (int i = 0; i < certEncLen; i++)
  {
   printf("%02x", (unsigned char)certEnc[i]);
  }
  printf("\r\n\r\n");


	ULONG certSignLen = 0;
	ulRslt = SKF_ExportCertificate(hcontA, 1, NULL, &certSignLen);
	// read certificate for signature
	char * certSign = new char[certSignLen];
	ulRslt = SKF_ExportCertificate(hcontA, 1, (BYTE *)certSign, &certSignLen);
	printf("SKF_ExportCertificate get length %02d for cert sign ------------------\n", certSignLen);
	  for (int i = 0; i < certSignLen; i++)
	  {
	   printf("%02x", (unsigned char)certSign[i]);
	  }
	  printf("\r\n\r\n");
#endif

	ulRslt = SKF_CloseContainer(hcontA);

	ulRslt = SKF_CloseApplication(hMyAppHandle);

	// disconnect device after operation
	ulRslt = SKF_DisConnectDev(hdev);

	delete[]szDevName;
	delete[]enumAppOut;
	delete[]enumContainerOut;
//	delete[]certEnc;
//	delete[]certSign;

	return ulRslt;
}

int _tmain(int argc, _TCHAR* argv[])
{
	ULONG ulRslt = SAR_OK;
	TYPE_SKF_EnumDev pSKF_EnumDev = NULL;

	printf("demo %s start...\n", __FUNCTION__);

	//test_reader();
	
	//create_jdzy_app();
	//read_app();
	//return;
	
	// try delete demo application firstly to clean up demo environment
	// return value not checked as possibly there is no demo application in device
	ulRslt = delete_application();

	// start demo process...

	// create demo application
	ulRslt = create_application();
	ERROR_EXIT(ulRslt)

	// create container and configure keypair, certification. 
	ulRslt = configure_container();
	ERROR_EXIT(ulRslt)

	// demo for sign/verify process
	ulRslt = sign_verify();
	ERROR_EXIT(ulRslt)

	// demo for encrypt/decrypt process
	ulRslt = message_cryption();
	ERROR_EXIT(ulRslt)

#ifndef NO_FILE_OPERATION
	// demo for file operations
	ulRslt = operate_file();
	ERROR_EXIT(ulRslt)
#endif

	// clean up demo environment
	ulRslt = delete_application();
	ERROR_EXIT(ulRslt)

	printf("demo %s done successfully!!\n", __FUNCTION__);
	return 0;
}

// function to create demo application in device
ULONG create_application()
{
	ULONG ulRslt = SAR_OK;
	char		*szDevName = NULL;
	ULONG		ulNameLen = 0;
	DEVHANDLE	hdev = NULL;
	HAPPLICATION appHandleDemo = 0;
	char * currentDevName = NULL;
	ULONG ulDevState = 0;
	DEVINFO myInfo;

	printf("%s start...\n", __FUNCTION__);

	do {
		// get dev list name length by put 2nd parameter as NULL
		ulRslt = SKF_EnumDev(1, NULL, &ulNameLen);
		ERROR_BREAK(ulRslt)

		// allocate enough memory to get device name list
		// device name ended with 0x0 and list ended with 0x0 0x0
		szDevName = new char[ulNameLen];
		ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
		ERROR_BREAK(ulRslt)

		ulRslt = SKF_GetDevState(szDevName, &ulDevState);
		ERROR_BREAK(ulRslt)

		// operate 1st device here
		currentDevName = szDevName;
		// connect 1st device and get device handle
		ulRslt = SKF_ConnectDev(currentDevName, &hdev);
		ERROR_BREAK(ulRslt)

		ulRslt = SKF_GetDevInfo(hdev, &myInfo);
		ERROR_BREAK(ulRslt)

		ulRslt = SKF_GetDevState(szDevName, &ulDevState);
		ERROR_BREAK(ulRslt)

		char		enumAppOut[1024] = { 0 };
		ULONG		ulAppNameLen = sizeof(enumAppOut);
		ulRslt = SKF_EnumApplication(hdev, enumAppOut, &ulAppNameLen);
		ERROR_BREAK(ulRslt)
		if (SAR_OK == ulRslt)
		{
			printf("SKF_EnumApplication get length %02d for AppName and content: %s\n", ulAppNameLen, enumAppOut);
		}

		// must get device authority before create application
		ulRslt = deviceAuth(hdev);
		ERROR_BREAK(ulRslt)

		// create aplication name as "app_demo_0" and get application handle appHandleDemo
		// admin pin "12345678" with max retry time 8, user pin "123456" with max retry time 6
		// set SECURE_USER_ACCOUNT, only user can create/delete file for this application
		ulRslt = SKF_CreateApplication(hdev, "app_demo_0", "12345678", 8, "123456", 4, SECURE_USER_ACCOUNT, &appHandleDemo);
		ERROR_BREAK(ulRslt);

		ulAppNameLen = sizeof(enumAppOut);
		memset(enumAppOut, 0, sizeof(enumAppOut));
		ulRslt = SKF_EnumApplication(hdev, enumAppOut, &ulAppNameLen);
		ERROR_BREAK(ulRslt)
		if (SAR_OK == ulRslt)
		{
			printf("SKF_EnumApplication get length %02d for contName and content: %s\n", ulAppNameLen, enumAppOut);
		}

		ulRslt = SKF_OpenApplication(hdev, "app_demo_0", &appHandleDemo);
		ERROR_BREAK(ulRslt)

		// close application handle here as no more operation with thie application now
		ulRslt = SKF_CloseApplication(appHandleDemo);
		ERROR_BREAK(ulRslt)

		ulAppNameLen = sizeof(enumAppOut);
		memset(enumAppOut, 0, sizeof(enumAppOut));
		ulRslt = SKF_EnumApplication(hdev, enumAppOut, &ulAppNameLen);
		ERROR_BREAK(ulRslt)
		if (SAR_OK == ulRslt)
		{
			printf("SKF_EnumApplication get length %02d for contName and content: %s\n", ulAppNameLen, enumAppOut);
		}

		// disconnect device after operation
		ulRslt = SKF_DisConnectDev(hdev);
		ERROR_BREAK(ulRslt)
	} while (0);

	if (szDevName)
	{
		delete[]szDevName;
		szDevName = NULL;
	}

	ERROR_THROW(ulRslt)

	printf("%s done successfully!!\n", __FUNCTION__);

	return ulRslt;
}

// function to delete application in device
ULONG delete_application()
{
	ULONG ulRslt = SAR_OK;
	char		*szDevName = NULL;
	ULONG		ulNameLen = 0;
	DEVHANDLE	hdev = NULL;
	char * currentDevName = NULL;
	DEVINFO myInfo;
	//BYTE tempSessKey[SM4_KEY_LEN] = {0};

	printf("%s start...\n", __FUNCTION__);

	do {
		// get dev list name length by put 2nd parameter as NULL
		ulRslt = SKF_EnumDev(1, NULL, &ulNameLen);
		ERROR_BREAK(ulRslt)

		// allocate enough memory to get device name list
		// device name ended with 0x0 and list ended with 0x0 0x0
		szDevName = new char[ulNameLen];
		ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
		ERROR_BREAK(ulRslt)

		// operate 1st device here
		currentDevName = szDevName;
		// connect 1st device and get device handle
		ulRslt = SKF_ConnectDev(currentDevName, &hdev);
		ERROR_BREAK(ulRslt)

#if 0
		HANDLE hHashA = NULL;
		HANDLE hHashB = NULL;
		unsigned char rawDataSign[96] = {0};
		ulRslt = SKF_DigestInit(hdev, SGD_SM3, NULL, NULL, 0, &hHashA);
		ERROR_THROW(ulRslt)

		ulRslt = SKF_DigestInit(hdev, SGD_SM3, NULL, NULL, 0, &hHashB);
		ERROR_THROW(ulRslt)

		// close hash handle
		ulRslt = SKF_CloseHandle(hHashA);
		ERROR_THROW(ulRslt)

		ulRslt = SKF_CloseHandle(hHashB);
		ERROR_THROW(ulRslt)
#endif

		ulRslt = SKF_GetDevInfo(hdev, &myInfo);
		ERROR_BREAK(ulRslt)

		// must get device authority before delete application
		ulRslt = deviceAuth(hdev);
		ERROR_BREAK(ulRslt)

		//memset(tempSessKey, 0, sizeof(tempSessKey));
		ulRslt = SKF_ChangeDevAuthKey(hdev, devAuthKey, SM4_KEY_LEN);
		ERROR_BREAK(ulRslt)

		char		enumAppOut[1024] = { 0 };
		ULONG		ulAppNameLen = sizeof(enumAppOut);
		ulRslt = SKF_EnumApplication(hdev, enumAppOut, &ulAppNameLen);
		ERROR_BREAK(ulRslt)
		if (SAR_OK == ulRslt)
		{
			printf("SKF_EnumApplication get length %02d for AppName and content: %s\n", ulAppNameLen, enumAppOut);
		}

		// delete aplication name as "app_demo_0"
		ulRslt = SKF_DeleteApplication(hdev, "app_demo_0");
		//ERROR_BREAK(ulRslt);
		printf("SKF_DeleteApplication done with return value 0x%08x!!\n", ulRslt);

		// disconnect device after operation
		ulRslt = SKF_DisConnectDev(hdev);
		ERROR_BREAK(ulRslt)
	} while (0);

	if (szDevName)
	{
		delete[]szDevName;
		szDevName = NULL;
	}

	ERROR_THROW(ulRslt)

	printf("%s done successfully!!\n", __FUNCTION__);

	return ulRslt;
}

// this function create container in specified application
// within the created container, generate signature keypair, import encrypt keypair, and import sign/enc certification
// two containers ("container_demo_A" and "container_demo_B") are created for latter signature/verification, encrypt/decrypt demo
// in normal scenario, "container_demo_A" and "container_demo_B" shall be two containers in different SKF devices
ULONG configure_container()
{
	ULONG ulRslt = SAR_OK;
	char		szDevName[1024] = { 0 };
	ULONG		ulNameLen = sizeof(szDevName);
	DEVHANDLE	hdev = NULL;
	char * currentDevName = NULL;
	HAPPLICATION appHandleDemo = 0;
	ULONG remainC = 0;
	HCONTAINER hcontA, hcontB;
	ECCPUBLICKEYBLOB	eccPubSignA = { 0 };
	ECCPUBLICKEYBLOB	eccPubSignB = { 0 };
	ECCPUBLICKEYBLOB	eccPubEncA = { 0 };
	ECCPUBLICKEYBLOB	eccPubEncB = { 0 };
	ULONG ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);

	printf("%s start...\n", __FUNCTION__);

	// device name ended with 0x0 and list ended with 0x0 0x0
	ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
	ERROR_THROW(ulRslt)

	// operate 1st device here
	currentDevName = szDevName;
	// connect 1st device and get device handle
	ulRslt = SKF_ConnectDev(currentDevName, &hdev);
	ERROR_THROW(ulRslt)

	// open application named as "app_demo_0" and get handle appHandleDemo
	ulRslt = SKF_OpenApplication(hdev, "app_demo_0", &appHandleDemo);
	ERROR_THROW(ulRslt)

	ULONG ulMaxRetryCount = 0;
	ULONG ulRemainRetryCount = 0;
	BOOL bDefaultPin = false;
	ulRslt = SKF_GetPINInfo(appHandleDemo, USER_TYPE, &ulMaxRetryCount, &ulRemainRetryCount, &bDefaultPin);
	ERROR_THROW(ulRslt)
	printf("USER PIN infor: max count %d, remain count %d\r\n", ulMaxRetryCount, ulRemainRetryCount);
#if 0
	ulMaxRetryCount = 0;
	ulRemainRetryCount = 0;
	bDefaultPin = false;
	ulRslt = SKF_GetPINInfo(appHandleDemo, ADMIN_TYPE, &ulMaxRetryCount, &ulRemainRetryCount, &bDefaultPin);
	ERROR_THROW(ulRslt)
	printf("AMDIN PIN infor: max count %d, remain count %d\r\n", ulMaxRetryCount, ulRemainRetryCount);

	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, ADMIN_TYPE, "1234567", &remainC);
	printf("SKF_VerifyPIN ADMIN_TYPE return 0x%x and remain count %d\r\n", ulRslt, remainC);

	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, ADMIN_TYPE, "1234567", &remainC);
	printf("SKF_VerifyPIN ADMIN_TYPE return 0x%x and remain count %d\r\n", ulRslt, remainC);

	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "1234567", &remainC);
	printf("SKF_VerifyPIN USER_TYPE return 0x%x and remain count %d\r\n", ulRslt, remainC);

	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "1234567", &remainC);
	printf("SKF_VerifyPIN USER_TYPE return 0x%x and remain count %d\r\n", ulRslt, remainC);

	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "123456", &remainC);
	printf("SKF_VerifyPIN USER_TYPE return 0x%x and remain count %d\r\n", ulRslt, remainC);

	ulMaxRetryCount = 0;
	ulRemainRetryCount = 0;
	bDefaultPin = false;
	ulRslt = SKF_GetPINInfo(appHandleDemo, USER_TYPE, &ulMaxRetryCount, &ulRemainRetryCount, &bDefaultPin);
	ERROR_THROW(ulRslt)
	printf("USER_TYPE PIN infor: max count %d, remain count %d\r\n", ulMaxRetryCount, ulRemainRetryCount);

	ulMaxRetryCount = 0;
	ulRemainRetryCount = 0;
	bDefaultPin = false;
	ulRslt = SKF_GetPINInfo(appHandleDemo, ADMIN_TYPE, &ulMaxRetryCount, &ulRemainRetryCount, &bDefaultPin);
	ERROR_THROW(ulRslt)
	printf("AMDIN PIN infor: max count %d, remain count %d\r\n", ulMaxRetryCount, ulRemainRetryCount);
#endif

	ulRslt = SKF_ChangePIN(appHandleDemo, USER_TYPE, "123456", "12345678", &ulRemainRetryCount);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_GetPINInfo(appHandleDemo, USER_TYPE, &ulMaxRetryCount, &ulRemainRetryCount, &bDefaultPin);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_ChangePIN(appHandleDemo, USER_TYPE, "12345678", "123456", &ulRemainRetryCount);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_GetPINInfo(appHandleDemo, USER_TYPE, &ulMaxRetryCount, &ulRemainRetryCount, &bDefaultPin);
	ERROR_THROW(ulRslt)

	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "1234567", &remainC);
	printf("SKF_VerifyPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);

	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "1234567", &remainC);
	printf("SKF_VerifyPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);

	ulRslt = SKF_GetPINInfo(appHandleDemo, USER_TYPE, &ulMaxRetryCount, &ulRemainRetryCount, &bDefaultPin);
	ERROR_THROW(ulRslt)
	printf("SKF_GetPINInfo return 0x%x and ulMaxRetryCount %d remain count %d\r\n", ulRslt, ulMaxRetryCount, ulRemainRetryCount);

	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "1234567", &remainC);
	printf("SKF_VerifyPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);

	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "1234567", &remainC);
	printf("SKF_VerifyPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);

	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "1234567", &remainC);
	printf("SKF_VerifyPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);

	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "1234567", &remainC);
	printf("SKF_VerifyPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);

	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "1234567", &remainC);
	printf("SKF_VerifyPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);

	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "1234567", &remainC);
	printf("SKF_VerifyPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);

	ulRslt = SKF_UnblockPIN(appHandleDemo, "12345677", "123456", &remainC);
	printf("SKF_UnblockPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);

	ulRslt = SKF_UnblockPIN(appHandleDemo, "12345677", "123456", &remainC);
	printf("SKF_UnblockPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);

	ulRslt = SKF_UnblockPIN(appHandleDemo, "12345677", "123456", &remainC);
	printf("SKF_UnblockPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);

	ulRslt = SKF_UnblockPIN(appHandleDemo, "12345677", "123456", &remainC);
	printf("SKF_UnblockPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);

	ulRslt = SKF_GetPINInfo(appHandleDemo, ADMIN_TYPE, &ulMaxRetryCount, &ulRemainRetryCount, &bDefaultPin);
	ERROR_THROW(ulRslt)
	printf("SKF_GetPINInfo return 0x%x and ulMaxRetryCount %d remain count %d\r\n", ulRslt, ulMaxRetryCount, ulRemainRetryCount);

	ulRslt = SKF_UnblockPIN(appHandleDemo, "12345678", "123456", &remainC);
	printf("SKF_UnblockPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_UnblockPIN(appHandleDemo, "12345677", "123456", &remainC);
	printf("SKF_UnblockPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);

	ulRslt = SKF_UnblockPIN(appHandleDemo, "12345678", "123456", &remainC);
	printf("SKF_UnblockPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);
	ERROR_THROW(ulRslt)

	// log in application as user to access private key
	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "123456", &remainC);
	printf("SKF_VerifyPIN return 0x%x and remain count %d\r\n", ulRslt, remainC);
	ERROR_THROW(ulRslt)

	// create container named as "container_demo_A" and get handle hcontA
	ulRslt = SKF_CreateContainer(appHandleDemo, "container_demo_Del", &hcontA);
	ERROR_THROW(ulRslt);

	ulRslt = SKF_DeleteContainer(appHandleDemo, "container_demo_Del");
	ERROR_THROW(ulRslt);

	ulRslt = SKF_CreateContainer(appHandleDemo, "container_demo_A", &hcontA);
	ERROR_THROW(ulRslt);

	// generate sign/verify keypair in container "container_demo_A"
	memset(&eccPubSignA, 0, sizeof(eccPubSignA));
	ulRslt = SKF_GenECCKeyPair(hcontA, SGD_SM2_1, &eccPubSignA);
	ERROR_THROW(ulRslt)

	// for demo only, hardcode SM2 encrypt keypair value here. 
	// actually the keypair shall be generated by KeyManagementServer in system
	unsigned char privKeyExternalA[32] = { 0x12, 0xaf, 0x0e, 0x78, 0x13, 0x24, 0x38, 0x1b, 0x12, 0x3a, 0x70, 0x38, 0x7c, 0x55, 0x7a, 0xdb, \
		0x2e, 0x7c, 0x03, 0xc2, 0x72, 0xee, 0x20, 0x0b, 0x5a, 0x34, 0x5e, 0x88, 0x21, 0x25, 0x35, 0x39 };
	unsigned char pubKeyExternalA[64] = { 0xc1, 0x1d, 0xe2, 0x42, 0x0e, 0xb3, 0xd3, 0xed, 0x02, 0x33, 0xca, 0x1b, 0xba, 0xa4, 0x53, 0x40, \
		0xcd, 0xda, 0x2e, 0x8c, 0x95, 0xfb, 0x43, 0xb6, 0x84, 0x3d, 0x91, 0x3b, 0x79, 0x99, 0xdd, 0xea, \
		0x6a, 0x55, 0x9a, 0xe8, 0x88, 0x0e, 0xec, 0x92, 0x06, 0x31, 0x98, 0x92, 0xbd, 0xf2, 0xa6, 0xcf, \
		0x55, 0xb3, 0x4a, 0x0b, 0x88, 0x80, 0x6d, 0xff, 0x12, 0x45, 0x70, 0x5e, 0x10, 0x16, 0x63, 0x95 };
	ulRslt = importSm2KeyPair(hdev, hcontA, privKeyExternalA, pubKeyExternalA);
	ERROR_THROW(ulRslt);

	// export sign public key in container "container_demo_A", the public key could be passed to CA to generate sign certification
	ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	memset(&eccPubSignA, 0, sizeof(eccPubSignA));
	ulRslt = SKF_ExportPublicKey(hcontA, TRUE, (BYTE *)(&eccPubSignA), &ulEccpubLen);
	ERROR_THROW(ulRslt)

	// export encrypt public key in container "container_demo_A", the public key could be passed to CA to generate encrypt certification
	ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	memset(&eccPubEncA, 0, sizeof(eccPubEncA));
	ulRslt = SKF_ExportPublicKey(hcontA, FALSE, (BYTE *)(&eccPubEncA), &ulEccpubLen);
	ERROR_THROW(ulRslt)

	// import sign certification. 
	// content "testContainerA_cert_sign" here only for demo, actually certification shall come from CA
	ulRslt = SKF_ImportCertificate(hcontA, TRUE, (BYTE *)"testContainerA_cert_sign", strlen("testContainerA_cert_sign"));
	ERROR_THROW(ulRslt)

	// import encrypt certification. 
	// content "testContainerA_cert_sign" here only for demo, actually certification shall come from CA
	ulRslt = SKF_ImportCertificate(hcontA, FALSE, (BYTE *)"testContainerA_cert_encrypt", strlen("testContainerA_cert_encrypt"));
	ERROR_THROW(ulRslt)

	ECCPUBLICKEYBLOB eccPubSign;
	PECCCIPHERBLOB  cryptSessKey = NULL;
	cryptSessKey = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN);
	memset(cryptSessKey, 0, sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN);
	cryptSessKey->CipherLen = SM4_KEY_LEN;
	unsigned char tempSessKey[SM4_KEY_LEN] = {0};
	memset(&eccPubSign, 0, sizeof(eccPubSign));
	ulEccpubLen = sizeof(eccPubSign);
	ulRslt = SKF_ExportPublicKey(hcontA, TRUE, (BYTE *)&eccPubSign, &ulEccpubLen);
	ERROR_THROW(ulRslt)
	//ulRslt = SKF_ExtECCEncrypt(hdev, &eccPubSign, tempSessKey, SM4_KEY_LEN, cryptSessKey);
	//ERROR_THROW(ulRslt)

	// close container "container_demo_A"
	ulRslt = SKF_CloseContainer(hcontA);
	ERROR_THROW(ulRslt)

#ifndef SINGLE_CONTAINER_ONLY
	// create container named as "container_demo_B" and get handle hcontB
	// this container is created to demo sign/verify encrypt/decrypt between different containers/devices
	ulRslt = SKF_CreateContainer(appHandleDemo, "container_demo_B", &hcontB);
	ERROR_THROW(ulRslt);

	// generate sign/verify keypair in container "container_demo_B"
	memset(&eccPubSignB, 0, sizeof(eccPubSignB));
	ulRslt = SKF_GenECCKeyPair(hcontB, SGD_SM2_1, &eccPubSignB);
	ERROR_THROW(ulRslt)

	// for demo only, hardcode SM2 encrypt keypair value here. 
	// actually the keypair shall be generated by KeyManagementServer in system
	unsigned char privKeyExternalB[32] = { 0x10, 0x66, 0x33, 0x0d, 0x28, 0x53, 0x58, 0xda, 0x08, 0xc7, 0x7d, 0x3e, 0x62, 0xf9, 0x3a, 0x70, \
		0x6d, 0xb2, 0x64, 0xb7, 0x6d, 0x02, 0x30, 0xdb, 0x0c, 0xfd, 0x55, 0x65, 0x28, 0x5e, 0x3c, 0x39 };
	unsigned char pubKeyExternalB[64] = { 0x0f, 0x95, 0xf7, 0x10, 0xd1, 0xe0, 0x23, 0x5b, 0xb3, 0x51, 0xcb, 0x08, 0x06, 0xc3, 0xf2, 0x2c, \
		0x0e, 0x15, 0x7f, 0x1c, 0x5c, 0x5f, 0xff, 0x2f, 0x66, 0x97, 0xc8, 0x4f, 0xab, 0x57, 0x09, 0x9e, \
		0x3d, 0x50, 0xce, 0x89, 0x3d, 0x48, 0x21, 0xf6, 0xf9, 0x86, 0xaa, 0xf2, 0xa4, 0xec, 0x18, 0x73, \
		0x42, 0xa7, 0x1b, 0xcc, 0x2e, 0xd3, 0x2b, 0xa5, 0xf1, 0xf6, 0xd9, 0xe8, 0x80, 0x34, 0x11, 0x76 };
	ulRslt = importSm2KeyPair(hdev, hcontB, privKeyExternalB, pubKeyExternalB);
	ERROR_THROW(ulRslt);

	// export sign public key in container "container_demo_B", the public key could be passed to CA to generate sign certification
	ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	memset(&eccPubSignB, 0, sizeof(eccPubSignB));
	ulRslt = SKF_ExportPublicKey(hcontB, TRUE, (BYTE *)(&eccPubSignB), &ulEccpubLen);
	ERROR_THROW(ulRslt)

	// export encrypt public key in container "container_demo_B", the public key could be passed to CA to generate encrypt certification
	ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	memset(&eccPubEncB, 0, sizeof(eccPubEncB));
	ulRslt = SKF_ExportPublicKey(hcontB, FALSE, (BYTE *)(&eccPubEncB), &ulEccpubLen);
	ERROR_THROW(ulRslt)

	// import sign certification. 
	// content "testContainerB_cert_sign" here only for demo, actually certification shall come from CA
	ulRslt = SKF_ImportCertificate(hcontB, 1, (BYTE *)"testContainerB_cert_sign", strlen("testContainerB_cert_sign"));
	ERROR_THROW(ulRslt)

	// import encrypt certification. 
	// content "testContainerA_cert_sign" here only for demo, actually certification shall come from CA
	ulRslt = SKF_ImportCertificate(hcontB, 0, (BYTE *)"testContainerB_cert_encrypt", strlen("testContainerB_cert_encrypt"));
	ERROR_THROW(ulRslt)

	// close container "container_demo_B"
	ulRslt = SKF_CloseContainer(hcontB);
	ERROR_THROW(ulRslt)
#endif

	// close container "app_demo_0"
	ulRslt = SKF_CloseApplication(appHandleDemo);
	ERROR_THROW(ulRslt)

	// disconnect device
	ulRslt = SKF_DisConnectDev(hdev);
	ERROR_THROW(ulRslt)

	printf("%s done successfully!!\n", __FUNCTION__);

	return ulRslt;
}

// this function read the certification from containers
// the function implement: container A sign with raw data hash and then verify signature by same device
// the real scenario shall be container A in device 1 sign hash of raw data, pass container A sign certification, raw data together with signature to device 2
// device 2 caculate hash or raw data, verify the signature from device 1 with the public key in received certification
ULONG sign_verify()
{
	ULONG ulRslt = SAR_OK;
	char		szDevName[1024] = { 0 };
	ULONG		ulNameLen = sizeof(szDevName);
	DEVHANDLE	hdev = NULL;
	char * currentDevName = NULL;
	HAPPLICATION appHandleDemo = 0;
	ULONG remainC = 0;
	HCONTAINER hcontA;
	ECCPUBLICKEYBLOB	eccPubSignA = { 0 };
	ULONG ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	BYTE rawDataSign[50] = { 0 };
	BYTE hashOutA[HASH_OUTPUT_LEN] = { 0 };
	BYTE hashOutB[HASH_OUTPUT_LEN] = { 0 };
	ULONG hashLenA = sizeof(hashOutA);
	ULONG hashLenB = sizeof(hashOutB);
	HANDLE hHashA = NULL;
	HANDLE hHashB = NULL;
	ECCSIGNATUREBLOB	ecc_sign = { 0 };
	ULONG certLen = 0;
	BYTE * certBuf = NULL;
	char		enumContainerOut[1024] = { 0 };
	ULONG		ulContNameLen = sizeof(enumContainerOut);

	printf("%s start...\n", __FUNCTION__);

	// device name ended with 0x0 and list ended with 0x0 0x0
	ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
	ERROR_THROW(ulRslt)

	// operate 1st device here
	currentDevName = szDevName;
	// connect 1st device and get device handle
	ulRslt = SKF_ConnectDev(currentDevName, &hdev);
	ERROR_THROW(ulRslt)

	// get some random data as plain input for latter hash/sign operation
	ulRslt = SKF_GenRandom(hdev, rawDataSign, sizeof(rawDataSign));
	ERROR_THROW(ulRslt)

	// open application named as "app_demo_0" and get handle appHandleDemo
	ulRslt = SKF_OpenApplication(hdev, "app_demo_0", &appHandleDemo);
	ERROR_THROW(ulRslt)

	// log in application as user to access private key
	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_EnumContainer(appHandleDemo, enumContainerOut, &ulContNameLen);
	ERROR_THROW(ulRslt)
	if (SAR_OK == ulRslt)
	{
		printf("SKF_EnumContainer get length %02d for contName and content: %s\n", ulContNameLen, enumContainerOut);
	}

	// open container named as "container_demo_A" and get handle hcontA
	ulRslt = SKF_OpenContainer(appHandleDemo, "container_demo_A", &hcontA);
	ERROR_THROW(ulRslt);

	// initialize digest operation and get handle, no pre-process in demo
	// set valid 3rd/4th/5th parameter to configure pre-process. digest in sign/verify side should have same configuration
	ulRslt = SKF_DigestInit(hdev, SGD_SM3, NULL, NULL, 0, &hHashA);
	ERROR_THROW(ulRslt)

	// get raw data hash output as sign input
	ulRslt = SKF_Digest(hHashA, (BYTE *)rawDataSign, sizeof(rawDataSign), hashOutA, &hashLenA);
	ERROR_THROW(ulRslt)

	// close hash handle
	ulRslt = SKF_CloseHandle(hHashA);
	ERROR_THROW(ulRslt)

	// container A sign the hash output with its own sign private key
	memset(&ecc_sign, 0, sizeof(ecc_sign));
	ulRslt = SKF_ECCSignData(hcontA, hashOutA, hashLenA, &ecc_sign);
	ERROR_THROW(ulRslt)

	// export sign public key in container "container_demo_A", the public key could be passed to opposite side to verify signature
	// or get public key by pass the certification
	ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	memset(&eccPubSignA, 0, sizeof(eccPubSignA));
	ulRslt = SKF_ExportPublicKey(hcontA, TRUE, (BYTE *)(&eccPubSignA), &ulEccpubLen);
	ERROR_THROW(ulRslt)

	// export sign cert. for demo only. no sign pub key in demo cert.
	ulRslt = SKF_ExportCertificate(hcontA, 1, NULL, &certLen); // 2nd parameter 1 indicate read sign cert, 3rd parameter NULL indicate get length only
	ERROR_THROW(ulRslt)

	certBuf = (BYTE *)malloc(certLen+1); // extra 1 byte for printf ending 0
	memset(certBuf, 0, certLen + 1);
	ulRslt = SKF_ExportCertificate(hcontA, 1, certBuf, &certLen); // 2nd parameter 1 to read sign cert
	if (SAR_OK == ulRslt)
	{
		printf("SKF_ExportCertificate get length %02d for sign cert and content: %s\n", certLen, certBuf);
	}
	free(certBuf);
	ERROR_THROW(ulRslt)

	// close container "container_demo_A"
	ulRslt = SKF_CloseContainer(hcontA);
	ERROR_THROW(ulRslt)

	// for demo only, below verify the signature in same device...

	// initialize digest operation. configuration shall be same as digest before sign
	ulRslt = SKF_DigestInit(hdev, SGD_SM3, NULL, NULL, 0, &hHashB);
	ERROR_THROW(ulRslt)

	// get raw data hash output as verification input
	ulRslt = SKF_Digest(hHashB, (BYTE *)rawDataSign, sizeof(rawDataSign), hashOutB, &hashLenB);
	ERROR_THROW(ulRslt)

	// verify signature from containerA
	ulRslt = SKF_ECCVerify(hdev, &eccPubSignA, hashOutB, hashLenB, &ecc_sign);
	ERROR_THROW(ulRslt)

	// close digest handle
	ulRslt = SKF_CloseHandle(hHashB);
	ERROR_THROW(ulRslt)


	// close application "app_demo_0"
	ulRslt = SKF_CloseApplication(appHandleDemo);
	ERROR_THROW(ulRslt)

	// disconnect device
	ulRslt = SKF_DisConnectDev(hdev);
	ERROR_THROW(ulRslt)

	printf("%s done successfully!!\n", __FUNCTION__);

	return ulRslt;
}

// demo for session key export/import and message encrypt/decrypt process
// the demo is done in same device/application. 
// normal usage will be export/import key and encrypt/decrypt message done in different devices
ULONG message_cryption()
{
	ULONG ulRslt = SAR_OK;
	char		szDevName[1024] = { 0 };
	ULONG		ulNameLen = sizeof(szDevName);
	DEVHANDLE	hdev = NULL;
	char * currentDevName = NULL;
	HAPPLICATION appHandleDemo = 0;
	ULONG remainC = 0;
	HCONTAINER hcontA = NULL;
	HCONTAINER hcontB = NULL;
	ECCPUBLICKEYBLOB	eccPub = { 0 };
	ULONG ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	BYTE plainData[SM4_KEY_LEN * 2] = { 0 };
	BYTE encryptOutBuf[SM4_KEY_LEN * 2] = { 0 };
	BYTE decryptOutBuf[SM4_KEY_LEN * 2] = { 0 };
	ULONG plainDataLen = sizeof(plainData);
	ULONG encryptOutLen = sizeof(encryptOutBuf);
	ULONG decryptOutLen = sizeof(decryptOutBuf);
	HANDLE hKeyEnc = NULL;
	HANDLE hKeyDec = NULL;
	PECCCIPHERBLOB  tempCipherKey = NULL; 
	BLOCKCIPHERPARAM blockCipherParam = { 0 };
	ULONG ulAlgId = SGD_SMS4_ECB;
	ULONG certLen = 0;
	BYTE * certBuf = NULL;
	ECCPUBLICKEYBLOB	eccPubSoft = { 0 };
	ULONG ulEccpubLenSoft = sizeof(ECCPUBLICKEYBLOB);
	unsigned char sm2SoftPubBytes[64];
	unsigned char sm2SoftPrivBytes[32];
	int sm2SoftPubLen = 64;
	int sm2SoftPrivLen = 32;

	printf("%s start...\n", __FUNCTION__);

	ulRslt = SM2Init();
	memset((void *)&eccPubSoft, 0, sizeof(eccPubSoft));
	memset(sm2SoftPubBytes, 0, 64);
	memset(sm2SoftPrivBytes, 0, 32);
	ulRslt = SM2GenKey(sm2SoftPrivBytes, &sm2SoftPrivLen, sm2SoftPubBytes, &sm2SoftPubLen);
	memcpy(eccPubSoft.XCoordinate + 32, sm2SoftPubBytes, 32);
	memcpy(eccPubSoft.YCoordinate + 32, sm2SoftPubBytes + 32, 32);
	eccPubSoft.BitLen = 256;

	// device name ended with 0x0 and list ended with 0x0 0x0
	ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
	ERROR_THROW(ulRslt)

	// operate 1st device here
	currentDevName = szDevName;
	// connect 1st device and get device handle
	ulRslt = SKF_ConnectDev(currentDevName, &hdev);
	ERROR_THROW(ulRslt)

	// get some random data as plain input for latter hash/sign operation
	ulRslt = SKF_GenRandom(hdev, plainData, plainDataLen);
	ERROR_THROW(ulRslt)

	// open application named as "app_demo_0" and get handle appHandleDemo
	ulRslt = SKF_OpenApplication(hdev, "app_demo_0", &appHandleDemo);
	ERROR_THROW(ulRslt)

	// log in application as user to access private key
	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

#ifdef SM1_SUPPORT_TEST
	sm1_verify(hdev);
#endif

	// open container named as "container_demo_A" and get handle hcontA
	ulRslt = SKF_OpenContainer(appHandleDemo, "container_demo_A", &hcontA);
	ERROR_THROW(ulRslt);

	// export encrypt public key in container "container_demo_A", the public key could be passed to opposite side to encrypt session key
	// or get public key by export and pass the certification
	ulEccpubLen = sizeof(eccPub);
	ulRslt = SKF_ExportPublicKey(hcontA, FALSE, (BYTE *)&eccPub, &ulEccpubLen);
	ERROR_THROW(ulRslt)

	// export encrypt cert. for demo only. no encrypt pub key in demo cert.
	// application can pass cert to opposite side, opposite side parse the pub key in cert for session key export
	ulRslt = SKF_ExportCertificate(hcontA, 0, NULL, &certLen); // 2nd parameter 0 indicate read encrypt cert, 3rd parameter NULL indicate get length only
	ERROR_THROW(ulRslt)

	certBuf = (BYTE *)malloc(certLen + 1); // extra 1 byte for printf ending 0
	memset(certBuf, 0, certLen + 1);
	ulRslt = SKF_ExportCertificate(hcontA, 0, certBuf, &certLen); // 2nd parameter 0 to read encrypt cert
	if (SAR_OK == ulRslt)
	{
		printf("SKF_ExportCertificate get length %02d for encrypt cert and content: %s\n", certLen, certBuf);
	}
	free(certBuf);
	ERROR_THROW(ulRslt)

	// generate session key in "container_demo_B" get handle. also export encrypted session key (encrypted by input pulbic key)
	tempCipherKey = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN);
	memset(tempCipherKey, 0, sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN);
	tempCipherKey->CipherLen = SM4_KEY_LEN; // set cipher section buffer len
	ulRslt = SKF_ECCExportSessionKey(hcontA, SGD_SMS4_ECB, &eccPubSoft, tempCipherKey, &hKeyEnc);
	if (ulRslt) 
	{ free(tempCipherKey); }
	ERROR_THROW(ulRslt)

#if 0
	// import encrypted session key value to container A, get key handle
	ulRslt = SKF_ImportSessionKey(hcontA, SGD_SMS4_ECB, (BYTE *)tempCipherKey, sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN, &hKeyDec);
	free(tempCipherKey);
	ERROR_THROW(ulRslt)
#endif

	// initialize encrypt operation 
	// no padding. no IV for ECB mode
	memset(&blockCipherParam, 0, sizeof(blockCipherParam));
	ulRslt = SKF_EncryptInit(hKeyEnc, blockCipherParam);
	ERROR_THROW(ulRslt)

	if (SAR_OK == ulRslt)
	{
		printf("sm4 input plain data as: ");
		for (unsigned int ii = 0; ii < plainDataLen; ii++)
		{
			printf("%02x", plainData[ii]);
		}
		printf("\n");
	}

	// encrypt plain message.
	// also could be a series SKF_EncryptUpdate followed by a SKF_EncryptFinal operation.
	ulRslt = SKF_Encrypt(hKeyEnc, plainData, plainDataLen, encryptOutBuf, &encryptOutLen);
	//ulRslt = SKF_EncryptUpdate(hKeyEnc, plainData, SM4_KEY_LEN, encryptOutBuf, &encryptOutLen);
	ERROR_THROW(ulRslt)


	unsigned char encryptedSm4Key[112];
	unsigned char decryptedSm4Key[16];
	int sm4KeyLen = 16;
	memset(encryptedSm4Key, 0, sizeof(encryptedSm4Key));
	memset(decryptedSm4Key, 0, sizeof(decryptedSm4Key));
	memcpy(encryptedSm4Key,      tempCipherKey->XCoordinate + 32, 32);
	memcpy(encryptedSm4Key + 32, tempCipherKey->YCoordinate + 32, 32);
	memcpy(encryptedSm4Key + 64, tempCipherKey->Cipher, 16);
	memcpy(encryptedSm4Key + 80, tempCipherKey->HASH, 32);
	SM2Init();
	SM2Decrypt(encryptedSm4Key, 112, sm2SoftPrivBytes, sm2SoftPrivLen, decryptedSm4Key, &sm4KeyLen);

	sms4_key_t tempSm4KeyStruct;
	memset((void *)&tempSm4KeyStruct, 0, sizeof(tempSm4KeyStruct));
	sms4_set_decrypt_key(&tempSm4KeyStruct, decryptedSm4Key);
	sms4_ecb_encrypt(encryptOutBuf, decryptOutBuf, &tempSm4KeyStruct, 0);
	sms4_ecb_encrypt(encryptOutBuf + SM4_KEY_LEN, decryptOutBuf + SM4_KEY_LEN, &tempSm4KeyStruct, 0);
	//if (SAR_OK == ulRslt)
	{
		printf("sm4 output plain data as: ");
		for (unsigned int ii = 0; ii < plainDataLen; ii++)
		{
			printf("%02x", decryptOutBuf[ii]);
		}
		printf("\n");
	}
#ifdef SINGLE_CONTAINER_ONLY
	
	
#else
	// initialize decrypt operation 
	// no padding. no IV for ECB mode
	memset(&blockCipherParam, 0, sizeof(blockCipherParam));
	ulRslt = SKF_DecryptInit(hKeyDec, blockCipherParam);
	ERROR_THROW(ulRslt)

	// decrypt to get plain message.
	// also could be a series SKF_DecryptUpdate followed by a SKF_DecryptFinal operation.
	ulRslt = SKF_Decrypt(hKeyDec, encryptOutBuf, encryptOutLen, decryptOutBuf, &decryptOutLen);
	ERROR_THROW(ulRslt)
#endif

	// for demo only.
	// dec output should be same as enc input
	ULONG diff = memcmp(plainData, decryptOutBuf, plainDataLen);
	if (0 != diff)
	{
		ERROR_THROW(diff)
	}

	// close key handle
	ulRslt = SKF_CloseHandle(hKeyEnc);
	ERROR_THROW(ulRslt)
	
	for (int ii=0; ii<sizeof(decryptedSm4Key); ii++)
	{
		decryptedSm4Key[ii] = ii + 5;
	}

	memcpy(sm2SoftPubBytes, eccPub.XCoordinate + 32 , 32 );
	memcpy(sm2SoftPubBytes + 32, eccPub.YCoordinate + 32 , 32 );
	
	SM2Init();
	int sm2EncOutLen = sizeof(encryptedSm4Key);
	SM2Encrypt(decryptedSm4Key, 16, sm2SoftPubBytes, sm2SoftPubLen, encryptedSm4Key, &sm2EncOutLen);

	memset(tempCipherKey, 0, sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN);
	tempCipherKey->CipherLen = SM4_KEY_LEN;
	memcpy(tempCipherKey->XCoordinate + 32,  encryptedSm4Key, 32);
	memcpy(tempCipherKey->YCoordinate + 32,  encryptedSm4Key + 32, 32);
	memcpy(tempCipherKey->Cipher,  encryptedSm4Key + 64, 16);
	memcpy(tempCipherKey->HASH,  encryptedSm4Key + 80, 32);
	// import encrypted session key value to container A, get key handle
	//HANDLE hKeyDec2 = 0;
	//ulRslt = SKF_ImportSessionKey(hcontA, SGD_SMS4_ECB, (BYTE *)tempCipherKey, sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN, &hKeyDec2);
	ulRslt = SKF_ImportSessionKey(hcontA, SGD_SMS4_ECB, (BYTE *)tempCipherKey, sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN, &hKeyDec);
	free(tempCipherKey);
	ERROR_THROW(ulRslt)

	memset((void *)&tempSm4KeyStruct, 0, sizeof(tempSm4KeyStruct));
	sms4_set_encrypt_key(&tempSm4KeyStruct, decryptedSm4Key);
	sms4_ecb_encrypt(plainData, encryptOutBuf, &tempSm4KeyStruct, 1);
	sms4_ecb_encrypt(plainData + SM4_KEY_LEN, encryptOutBuf + SM4_KEY_LEN, &tempSm4KeyStruct, 1);

	ulRslt = SKF_DecryptInit(hKeyDec, blockCipherParam);
	ERROR_THROW(ulRslt)

	memset(decryptOutBuf, 0, sizeof(decryptOutBuf));
	ulRslt = SKF_Decrypt(hKeyDec, encryptOutBuf, SM4_KEY_LEN * 2, decryptOutBuf, &decryptOutLen);
	ERROR_THROW(ulRslt)
	//if (SAR_OK == ulRslt)
	{
		printf("sm4 decryptOutBuf plain data as: ");
		for (unsigned int ii = 0; ii < decryptOutLen; ii++)
		{
			printf("%02x", decryptOutBuf[ii]);
		}
		printf("\n");
	}
	diff = memcmp(plainData, decryptOutBuf, plainDataLen);
	if (0 != diff)
	{
		ERROR_THROW(diff)
	}

	// close container "container_demo_A"
	ulRslt = SKF_CloseContainer(hcontA);
	ERROR_THROW(ulRslt)

#ifdef SINGLE_CONTAINER_ONLY
#else
	// close key handle
	ulRslt = SKF_CloseHandle(hKeyDec);
	ERROR_THROW(ulRslt)

	// close container "container_demo_B"
	ulRslt = SKF_CloseContainer(hcontB);
	ERROR_THROW(ulRslt)
#endif

	// close application "app_demo_0"
	ulRslt = SKF_CloseApplication(appHandleDemo);
	ERROR_THROW(ulRslt)

	cryptoki_3_step_operations(hdev);

	// disconnect device
	ulRslt = SKF_DisConnectDev(hdev);
	ERROR_THROW(ulRslt)

	printf("%s done successfully!!\n", __FUNCTION__);

	return ulRslt;
}

// demo file create/write/read/delete operations
ULONG operate_file()
{
	ULONG ulRslt = SAR_OK;
	char		szDevName[1024] = { 0 };
	ULONG		ulNameLen = sizeof(szDevName);
	DEVHANDLE	hdev = NULL;
	char * currentDevName = NULL;
	HAPPLICATION appHandleDemo = 0;
	ULONG remainC = 0;

	printf("%s start...\n", __FUNCTION__);

	// device name ended with 0x0 and list ended with 0x0 0x0
	ulRslt = SKF_EnumDev(1, szDevName, &ulNameLen);
	ERROR_THROW(ulRslt)

	// operate 1st device here
	currentDevName = szDevName;
	// connect 1st device and get device handle
	ulRslt = SKF_ConnectDev(currentDevName, &hdev);
	ERROR_THROW(ulRslt)

	// open application named as "app_demo_0" and get handle appHandleDemo
	ulRslt = SKF_OpenApplication(hdev, "app_demo_0", &appHandleDemo);
	ERROR_THROW(ulRslt)

	// log in application as user to access private key
	remainC = 0;
	ulRslt = SKF_VerifyPIN(appHandleDemo, USER_TYPE, "123456", &remainC);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_CreateFile(appHandleDemo, "file_demo_0", 20, SECURE_USER_ACCOUNT, SECURE_USER_ACCOUNT);
	ERROR_THROW(ulRslt)
	printf("file_demo_0 created with initialize size 20 bytes\n");

	ulRslt = SKF_WriteFile(appHandleDemo, "file_demo_0", 0, (BYTE *)"0123456789abcdef", strlen("0123456789abcdef"));
	ERROR_THROW(ulRslt)
	printf("file_demo_0 write 16 bytes character \"0123456789abcdef\"\n");

	FILEATTRIBUTE fileInfo;
	memset(&fileInfo, 0, sizeof(FILEATTRIBUTE));
	ulRslt = SKF_GetFileInfo(appHandleDemo, "file_demo_0", &fileInfo);
	ERROR_THROW(ulRslt)

	ULONG readLen = 0;
	// expected output readLen as 20
	ulRslt = SKF_ReadFile(appHandleDemo, "file_demo_0", 0, 100, NULL, &readLen);
	ERROR_THROW(ulRslt)

	BYTE * readOut = (BYTE *)malloc(readLen);
	memset(readOut, 0, readLen);
	ulRslt = SKF_ReadFile(appHandleDemo, "file_demo_0", 0, 100, readOut, &readLen);
	// printf out read output for demo, expect output 3031323334353637383961626364656600000000
	// 16 byte valid info followed by padding to fill up 20 bytes memory initialized by file creation
	if (SAR_OK == ulRslt)
	{
		printf("file_demo_0 read get length %d and binary content as: ", readLen);
		for (unsigned int ii = 0; ii < readLen; ii++)
		{
			printf("%02x", readOut[ii]);
		}
		printf("\n");
	}
	free(readOut);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_WriteFile(appHandleDemo, "file_demo_0", strlen("0123456789abcdef"), (BYTE *)"0123456789abcdef", strlen("0123456789abcdef"));
	ERROR_THROW(ulRslt)
	printf("file_demo_0 write 16 bytes character \"0123456789abcdef\" at end of history string\n");

	readLen = 0;
	// expected output readLen as 32
	ulRslt = SKF_ReadFile(appHandleDemo, "file_demo_0", 0, 100, NULL, &readLen);
	ERROR_THROW(ulRslt)

	readOut = (BYTE *)malloc(readLen);
	memset(readOut, 0, readLen);
	ulRslt = SKF_ReadFile(appHandleDemo, "file_demo_0", 0, 100, readOut, &readLen);
	// print out read output for demo, expect output 3031323334353637383961626364656630313233343536373839616263646566
	// 16 byte valid info followed by 16 byte history info. totally 32 byte
	if (SAR_OK == ulRslt)
	{
		printf("file_demo_0 read get length %d and binary content as: ", readLen);
		for (unsigned int ii = 0; ii < readLen; ii++)
		{
			printf("%02x", readOut[ii]);
		}
		printf("\n");
	}
	free(readOut);
	ERROR_THROW(ulRslt)

	ulRslt = SKF_DeleteFile(appHandleDemo, "file_demo_0");
	ERROR_THROW(ulRslt);

	// close application "app_demo_0"
	ulRslt = SKF_CloseApplication(appHandleDemo);
	ERROR_THROW(ulRslt)

	// disconnect device
	ulRslt = SKF_DisConnectDev(hdev);
	ERROR_THROW(ulRslt)

	printf("%s done successfully!!\n", __FUNCTION__);

	return ulRslt;
}


// process to complete device authorization
// this process shall be done before create or delete application in device
ULONG deviceAuth(DEVHANDLE	hdev)
{
	ULONG ulRslt = SAR_OK;

	//BYTE * tempSessKey = (BYTE *)"1234567812345678";
	BYTE tempSessKey[SM4_KEY_LEN] = {0};
	HANDLE tempKeyHandle = 0;
	BLOCKCIPHERPARAM bp = { 0 };

	BYTE devRandom[SM4_KEY_LEN] = { 0 };
	BYTE devAuth[SM4_KEY_LEN] = { 0 };
	ULONG devAuthLen = SM4_KEY_LEN;

	printf("%s start...\n", __FUNCTION__);

#ifdef _WIN32
	std::memset(tempSessKey, 0, SM4_KEY_LEN);
	std::memset(devRandom, 0, SM4_KEY_LEN);
	std::memset(devAuth, 0, SM4_KEY_LEN);
#else
	memset(devRandom, 0, 16);
	memset(devAuth, 0, 16);
#endif
	// step 1, generate 8 bytes random data as GM/T 0016 required
	ulRslt = SKF_GenRandom(hdev, devRandom, DEV_AUTH_RANDOM_LEN);
	ERROR_THROW(ulRslt)

	// step 2, create session key, 3rd parameter shall always be SGD_SMS4_ECB
	ulRslt = SKF_SetSymmKey(hdev, (unsigned char*)devAuthKey, SGD_SMS4_ECB, &tempKeyHandle);
	//ulRslt = SKF_SetSymmKey(hdev, (unsigned char*)tempSessKey, SGD_SMS4_ECB, &tempKeyHandle);
	//PRINT_LOG("SKF_SetSymmKey get result 0x%lx and return keyHandle %p", ulRslt, tempKeyHandle);
	ERROR_THROW(ulRslt)

	// step 3.1 encrypt initialize with created session key handle. bp.paddingType shall be 0
	ulRslt = SKF_EncryptInit(tempKeyHandle, bp);
	ERROR_THROW(ulRslt)

	// step 3.2 encrypt 16 bytes raw data. first 8 bytes get by SKF_GenRandom, following 8 bytes fill with 0 for SM4 ECB encryption
	ulRslt = SKF_Encrypt(tempKeyHandle, (unsigned char *)devRandom, sizeof(devRandom), devAuth, &devAuthLen);
	ERROR_THROW(ulRslt)

	// step 4, close session key handle
#ifdef ENABLE_CLOSE_HANDLE
	ulRslt = SKF_CloseHandle(tempKeyHandle);
	ERROR_THROW(ulRslt)
#endif

	// step 5, pass encrypted data to device. device will return authorization pass or fail
	ulRslt = SKF_DevAuth(hdev, devAuth, devAuthLen);
	ERROR_THROW(ulRslt)

	printf("%s done successfully!!\n", __FUNCTION__);

	return SAR_OK;
}

// this function import input plain SM2 keypair into specified container
ULONG importSm2KeyPair(HANDLE hdev, HANDLE hcont, unsigned char * privKeyExternal, unsigned char * pubKeyExternal)
{
	ULONG ulRslt = SAR_OK;

	ECCPUBLICKEYBLOB	eccPubSign = { 0 };
	ULONG	ulEccpubLen = sizeof(ECCPUBLICKEYBLOB);
	BLOCKCIPHERPARAM bp = { 0 };
	//unsigned char tempSessKey[SM4_KEY_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
	unsigned char tempSessKey[SM4_KEY_LEN] = { 0 };
	ECCPRIVATEKEYBLOB externalPrivKeyStruct;
	HANDLE tempKeyHandle = 0;
	unsigned char cipherPrivateKey[ECC_MAX_MODULUS_BITS_LEN / 8] = { 0 };
	ULONG cipherPrivateKeyLen = ECC_MAX_MODULUS_BITS_LEN / 8;
	PECCCIPHERBLOB  cryptSessKey = NULL;
	PENVELOPEDKEYBLOB cryptKeyEnv = NULL;

	ECCPUBLICKEYBLOB	eccPub = { 0 };
	ULONG ulEccpubLenTest = sizeof(ECCPUBLICKEYBLOB);
	PECCCIPHERBLOB  tempCipherKey = NULL; 
	HANDLE hKeyExportImport = NULL;
	
	printf("%s start...\n", __FUNCTION__);
	
	do {
		// NOTICE: 
		// step 0~2 could be done outside the device in normal scenarioes. 
		// external module (like KMS) could generate and assemble ENVELOPEDKEYBLOB, simply call SKF_ImportECCKeyPair to import keypair
		// here step 0~2 for demo only. generate input for demo, also demonstrate how the input parameter is generated

		// step 0, generate SM4 key which will be used to encrypt SM2 private key
		// the key could be pre-defined or random generated
		ulRslt = SKF_GenRandom(hdev, tempSessKey, SM4_KEY_LEN);
		ERROR_BREAK(ulRslt)

		// step 1, encrypt SM4 key by sign public key
		// step 1.1, get signature public key within target container
		memset(&eccPubSign, 0, sizeof(eccPubSign));
		ulEccpubLen = sizeof(eccPubSign);
		ulRslt = SKF_ExportPublicKey(hcont, TRUE, (BYTE *)&eccPubSign, &ulEccpubLen);
		ERROR_BREAK(ulRslt)
			printf("signature pub key:\r\n");
		for (int i = 0; i < 64; i++)
		{
			printf("%02x", eccPubSign.XCoordinate[i]);
		}
		printf("\r\n");
		for (int i = 0; i < 64; i++)
		{
			printf("%02x", eccPubSign.YCoordinate[i]);
		}
		printf("\r\n");

		// step 1.2, encrypt SM4 key with signature public key
		cryptSessKey = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN);
		cryptSessKey->CipherLen = SM4_KEY_LEN;
		memset(cryptSessKey, 0, sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN);
		cryptSessKey->CipherLen = SM4_KEY_LEN;
#ifdef EXTERNAL_SM2
		#define EXT_SM2_BUF_SIZE 512
		unsigned char extSm2OutBuf[EXT_SM2_BUF_SIZE] = {0};
		int extSm2OutLen = EXT_SM2_BUF_SIZE;
		unsigned char eccPubSign64[64] = {0};
		memcpy(eccPubSign64, &eccPubSign.XCoordinate[0] + 32, 32);
		memcpy(eccPubSign64 + 32, &eccPubSign.YCoordinate[0] + 32, 32);
		SM2Init();
		//extSm2OutLen format C1(64 bytes):C2(plainLen):C3(32 bytes hash)
		SM2Encrypt(tempSessKey, SM4_KEY_LEN, eccPubSign64, 64, extSm2OutBuf, &extSm2OutLen);
		for (int i = 0; i < 64; i++)
		{
			printf("%02x", eccPubSign64[i]);
		}
		printf("\r\n");
		printf("external SM2 encrypt input len 16 output len %d for input:\r\n", extSm2OutLen);
		memcpy(&cryptSessKey->XCoordinate[0] + 32, extSm2OutBuf, 32);
		memcpy(&cryptSessKey->YCoordinate[0] + 32, extSm2OutBuf + 32, 32);
		memcpy(&cryptSessKey->Cipher[0], extSm2OutBuf + 64, 16);
		memcpy(&cryptSessKey->HASH[0], extSm2OutBuf + 80, 32);
		//memcpy(cryptSessKey->HASH, extSm2OutBuf + 64, 32);
		//memcpy(cryptSessKey->Cipher, extSm2OutBuf + 96, 16);
		
		for (int i = 0; i < SM4_KEY_LEN; i++)
		{
			printf("0x%02x, ", tempSessKey[i]);
		}
		printf("\r\n");
		for (int i = 0; i < extSm2OutLen; i++)
		{
			printf("0x%02x, ", extSm2OutBuf[i]);
		}
		printf("\r\n");
#if 0
		unsigned char testRaw[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0};
		unsigned char testCipher[112] = {0};
		unsigned char testReorg[112] = {0};
		unsigned char testSm2Dec[16] = {0};
		int encLen = 112;
		int decLen = 16;
		memset(testCipher, 0, 112);
		memset(testReorg, 0, 112);
		memset(testSm2Dec, 0, 16);
		SM2Init();
		SM2Encrypt(testRaw, SM4_KEY_LEN, pubKeyExternal, 64, testCipher, &encLen);
		SM2Init();
		SM2Decrypt(testCipher, encLen, privKeyExternal, 64, testSm2Dec, &decLen);
		for (int i = 0; i < decLen; i++) 
		{ 
			printf("%02x", testSm2Dec[i]);
		}
		printf("\r\nSM2 enc output:\r\n");
		memcpy(testReorg, testCipher, 64);
		memcpy(testReorg + 64, testCipher + 80, 32);
		memcpy(testReorg + 96, testCipher + 64, 16);
		for (int i = 0; i < encLen; i++)
		{
			printf("0x%02x, ", testReorg[i]);
		}
		printf("\r\n");
#endif
#else
		ulRslt = SKF_ExtECCEncrypt(hdev, &eccPubSign, tempSessKey, SM4_KEY_LEN, cryptSessKey);
		ERROR_BREAK(ulRslt)
#endif

		// step 2, encrypt crypt private key with SM4 key
		// step 2.1, set sym key, 3rd parameter shall be SGD_SMS4_ECB
#ifdef SM1_SUPPORT_TEST
		ulRslt = SKF_SetSymmKey(hdev, (unsigned char*)tempSessKey, SGD_SM1_ECB, &tempKeyHandle);
#else
		ulRslt = SKF_SetSymmKey(hdev, (unsigned char*)tempSessKey, SGD_SMS4_ECB, &tempKeyHandle);
#endif
		ERROR_BREAK(ulRslt)

		// step 2.2 encrypt initialize. bp.paddingType shall be 0
		ulRslt = SKF_EncryptInit(tempKeyHandle, bp);
		ERROR_BREAK(ulRslt)

		// step 2.3 encrypt crypt private key
		memset(&externalPrivKeyStruct, 0, sizeof(externalPrivKeyStruct));
		externalPrivKeyStruct.BitLen = 256;
		memcpy(externalPrivKeyStruct.PrivateKey + 32, privKeyExternal, 32);
		ulRslt = SKF_Encrypt(tempKeyHandle, (unsigned char *)externalPrivKeyStruct.PrivateKey, sizeof(externalPrivKeyStruct.PrivateKey), cipherPrivateKey, &cipherPrivateKeyLen);
		ERROR_BREAK(ulRslt)

		// step 2.4, close session key handle
		ulRslt = SKF_CloseHandle(tempKeyHandle);
		ERROR_BREAK(ulRslt)

		// assembly input keypair parameter
		cryptKeyEnv = (PENVELOPEDKEYBLOB)malloc(sizeof(ENVELOPEDKEYBLOB)+SM4_KEY_LEN);
		memset(cryptKeyEnv, 0, sizeof(ENVELOPEDKEYBLOB)+SM4_KEY_LEN);
		cryptKeyEnv->ECCCipherBlob.CipherLen = SM4_KEY_LEN;
		cryptKeyEnv->Version = 1;
#ifdef SM1_SUPPORT_TEST
		cryptKeyEnv->ulSymmAlgID = SGD_SM1_ECB;
#else
		cryptKeyEnv->ulSymmAlgID = SGD_SMS4_ECB;
#endif
		cryptKeyEnv->ulBits = 256;
		memset(cryptKeyEnv->cbEncryptedPriKey, 0, ECC_MAX_MODULUS_BITS_LEN / 8);
		memcpy(cryptKeyEnv->cbEncryptedPriKey, cipherPrivateKey, cipherPrivateKeyLen);
		cryptKeyEnv->PubKey.BitLen = 256;
		memcpy(cryptKeyEnv->PubKey.XCoordinate + 32, pubKeyExternal, 32);
		memcpy(cryptKeyEnv->PubKey.YCoordinate + 32, pubKeyExternal + 32, 32);
		//memcpy(&(cryptKeyEnv->ECCCipherBlob), cryptSessKey, sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN);
		memcpy(&(cryptKeyEnv->ECCCipherBlob.XCoordinate), cryptSessKey->XCoordinate, ECC_MAX_XCOORDINATE_BITS_LEN/8);
		memcpy(&(cryptKeyEnv->ECCCipherBlob.YCoordinate), cryptSessKey->YCoordinate, ECC_MAX_YCOORDINATE_BITS_LEN/8);
		memcpy(&(cryptKeyEnv->ECCCipherBlob.HASH), cryptSessKey->HASH, 32);
		memcpy(&(cryptKeyEnv->ECCCipherBlob.Cipher), cryptSessKey->Cipher, SM4_KEY_LEN);
		cryptKeyEnv->ECCCipherBlob.CipherLen = SM4_KEY_LEN;
		// step 3, import crypt key pair
		ulRslt = SKF_ImportECCKeyPair(hcont, cryptKeyEnv);
		ERROR_BREAK(ulRslt)

		// verify sm2 keypair functionality
		ulEccpubLenTest = sizeof(eccPub);
		ulRslt = SKF_ExportPublicKey(hcont, FALSE, (BYTE *)&eccPub, &ulEccpubLenTest);
		ERROR_BREAK(ulRslt)

		tempCipherKey = (PECCCIPHERBLOB)malloc(sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN);
		memset(tempCipherKey, 0, sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN);
		tempCipherKey->CipherLen = SM4_KEY_LEN; // set cipher section buffer len
		ulRslt = SKF_ECCExportSessionKey(hcont, SGD_SMS4_ECB, &eccPub, tempCipherKey, &hKeyExportImport);
		if (ulRslt) 
		{ free(tempCipherKey); }
		ERROR_BREAK(ulRslt)

		unsigned char plaintext[16] = {
		0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00
		};

		unsigned char encryptOutput[16] = {0};
		unsigned char decryptOutput[16] = {0};
		ULONG encryptOutLen = 16;
		ULONG decryptOutLen = 16;

		ulRslt = SKF_EncryptInit(hKeyExportImport, bp);
		if (ulRslt) 
		{ free(tempCipherKey); }
		ERROR_BREAK(ulRslt)

		ulRslt = SKF_Encrypt(hKeyExportImport, (unsigned char *)plaintext, sizeof(plaintext), encryptOutput, &encryptOutLen);
		if (ulRslt) 
		{ free(tempCipherKey); }
		ERROR_BREAK(ulRslt)
	
		ulRslt = SKF_CloseHandle(hKeyExportImport);
		if (ulRslt) 
		{ free(tempCipherKey); }
		ERROR_BREAK(ulRslt)
	
		ulRslt = SKF_ImportSessionKey(hcont, SGD_SMS4_ECB, (BYTE *)tempCipherKey, sizeof(ECCCIPHERBLOB)+SM4_KEY_LEN, &hKeyExportImport);
		free(tempCipherKey);
		ERROR_BREAK(ulRslt)

		ulRslt = SKF_DecryptInit(hKeyExportImport, bp);
		ERROR_BREAK(ulRslt)

		// step 3.2 encrypt 16 bytes raw data. first 8 bytes get by SKF_GenRandom, following 8 bytes fill with 0 for SM4 ECB encryption
		ulRslt = SKF_Decrypt(hKeyExportImport, (unsigned char *)encryptOutput, encryptOutLen, decryptOutput, &decryptOutLen);
		ERROR_BREAK(ulRslt)

		ULONG diff = memcmp(decryptOutput, plaintext, sizeof(plaintext));
		if (0 != diff)
		{
			ERROR_BREAK(diff)
		}
	
		ulRslt = SKF_CloseHandle(hKeyExportImport);
		ERROR_BREAK(ulRslt)
	} while (0);

	if (cryptKeyEnv)
	{
		free(cryptKeyEnv);
		cryptKeyEnv = NULL;
	}

	if (cryptSessKey)
	{
		free(cryptSessKey);
		cryptSessKey = NULL;
	}

	ERROR_THROW(ulRslt)

	printf("%s done successfully!!\n", __FUNCTION__);

	return ulRslt;
}


#ifdef SM1_SUPPORT_TEST
ULONG sm1_verify(DEVHANDLE	hdev)
{
	ULONG ulRslt = SAR_OK;
	HANDLE tempKeyHandle = NULL;
	BLOCKCIPHERPARAM bp = { 0 };

	unsigned char sm1key[16] = {
		0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26
	};
	unsigned char plaintext[16] = {
		0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00
	};

	unsigned char ciphertext[16] = {
		0x6d,0x7f,0x45,0xb0,0x8b,0xc4,0xd9,0x66,0x44,0x4c,0x86,0xc2,0xb0,0x7d,0x29,0x93};

	unsigned char encryptOutput[16] = {0};
	unsigned char decryptOutput[16] = {0};
	ULONG encryptOutLen = 16;
	ULONG decryptOutLen = 16;

	printf("%s start...\n", __FUNCTION__);

	ulRslt = SKF_SetSymmKey(hdev, (unsigned char*)sm1key, SGD_SM1_ECB, &tempKeyHandle);
	ERROR_THROW(ulRslt)
	
	ulRslt = SKF_EncryptInit(tempKeyHandle, bp);
	ERROR_THROW(ulRslt)

	// step 3.2 encrypt 16 bytes raw data. first 8 bytes get by SKF_GenRandom, following 8 bytes fill with 0 for SM4 ECB encryption
	ulRslt = SKF_Encrypt(tempKeyHandle, (unsigned char *)plaintext, sizeof(plaintext), encryptOutput, &encryptOutLen);
	ERROR_THROW(ulRslt)

	ULONG diff = memcmp(encryptOutput, ciphertext, sizeof(plaintext));
	if (0 != diff)
	{
		ERROR_THROW(diff)
	}
	
	ulRslt = SKF_DecryptInit(tempKeyHandle, bp);
	ERROR_THROW(ulRslt)

	// step 3.2 encrypt 16 bytes raw data. first 8 bytes get by SKF_GenRandom, following 8 bytes fill with 0 for SM4 ECB encryption
	ulRslt = SKF_Decrypt(tempKeyHandle, (unsigned char *)encryptOutput, encryptOutLen, decryptOutput, &decryptOutLen);
	ERROR_THROW(ulRslt)

	diff = memcmp(decryptOutput, plaintext, sizeof(plaintext));
	if (0 != diff)
	{
		ERROR_THROW(diff)
	}
	
	ulRslt = SKF_CloseHandle(tempKeyHandle);
	ERROR_THROW(ulRslt)

	return SAR_OK;
}
#endif



