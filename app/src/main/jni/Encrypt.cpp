#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <android/log.h>
#include "cryptoki.h"
#include "sm2.h"
#include "P11TestFuncList.h"
#include "sm3.h"
#include "sm4ofb.h"
#include <string>

extern CK_SESSION_HANDLE hSession;
extern CK_SLOT_ID testslot;
unsigned char pSOPin[16] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
//extern CK_SESSION_HANDLE session;
//extern CK_SESSION_HANDLE session1;

//extern char  *pusrpin;
//extern char *default_so_pin;

//??????free???????
#define FREE_0	0
#define FREE_1	1
#define FREE_2	2
#define FREE_3	3
#define FREE_4	4
#define FREE_5	5
#define FREE_6	6
#define FREE_7	7
#define FREE_8	8
#define FREE_9	9

#define RUN_CORRECT 0			//generalcall??????????????
#define RUN_INCORRECT 1			//generalcall??????????????

#define SHOW_ERROR_TEST

#define RV_NOT_OK_RETURN_FALSE(_func_name,_rtn)\
	do\
	{\
		if(_rtn!=CKR_OK && (_rtn == CKR_USER_NOT_LOGGED_IN || _rtn == 0x80000001UL) )\
	{\
		printf("Error: %s ,rv=0x%08x.\n", #_func_name, (unsigned int)_rtn);\
		bRtn = 0;\
	}\
	else if(_rtn!=CKR_OK )\
	{\
		printf("Error: %s ,rv=0x%08x.\n", #_func_name, (unsigned int)_rtn);\
		bRtn = 1;\
		return bRtn;\
	}\
	} while(0)

#ifdef SHOW_ERROR_TEST
#define RV_NOT_OK_RETURN_TRUE(_func_name,_rtn)\
		do\
	{\
		if(_rtn!=CKR_OK)\
	{\
		printf("Should failed: %s ,rv=0x%08x.\n", #_func_name, (unsigned int)_rtn);\
		bRtn=0;\
	}\
	else\
	{\
		printf("May succeed?: %s ,rv=0x%08x.\n", #_func_name, (unsigned int)_rtn);\
		bRtn=1;\
		return bRtn;\
	}\
	} while(0)
#else
#define RV_NOT_OK_RETURN_TRUE(_func_name,_rtn)\
		do\
	{\
		if(_rtn!=CKR_OK)\
	{\
		bRtn=0;\
	}\
	else\
	{\
		printf("May succeed?: %s ,rv=0x%08x.\n", #_func_name, (unsigned int)_rtn);\
		bRtn=1;\
		return bRtn;\
	}\
	} while(0)
#endif


#define RV_FALSE_RETURN(_rtn)\
	do\
	{\
		if(_rtn == 1)\
		{\
			return 1;\
		}\
	} while(0)

//Set all buffer data to zero
#define BUFFER_REFRESH_ZERO(data1,data1len,data2,data2len)\
		do\
	{\
		data1len = sizeof(data1);\
		memset(data1, 0, data1len);\
		data2len=sizeof(data2);\
		memset(data2, 0, data2len);\
	}while(0)


void RandomGenerate(unsigned char* dataaddress, unsigned int cnt)
{
	int i,randt,randmaxx=0x7FFFFFFF-0x7FFFFFFF%0xFF;
	for(i=0;i<cnt;i++)
	{
		randt = rand();
		while( randt > randmaxx ) 
		{
			randt = rand();
		}
		dataaddress[i] = (unsigned char)(randt % 0x100); // ????????
	}
}

CK_RV Rv_False_Free_Memory(unsigned int _rv, unsigned int _free_nums, ...) //????9???free,?????????
{
	va_list arg_ptr;
	void** p[9] = { 0 };
	int i = 0;

	
	if (_rv == 0)
	{
		return 0;
	}

	va_start(arg_ptr, _free_nums);

	if (_free_nums >= 10)
	{
		printf("Free numbers overflow!\n");
		return FALSE;
	}

	for (i = 0; i < _free_nums; ++i)
	{
		p[i] = va_arg(arg_ptr, void**);
		free(*p[i]);
		*p[i] = NULL;
	}
	va_end(arg_ptr);
	return 1;
}


CK_ULONG Free_Memory(unsigned int _free_nums, ...)
{
	va_list arg_ptr;
	void** p[9] = { 0 };
	int i = 0;
	
	if (_free_nums >= 10)
	{
		printf("Free numbers overflow!\n");
		return 1;
	}

	va_start(arg_ptr, _free_nums);

	for (i = 0; i < _free_nums; ++i)
	{

		p[i] = va_arg(arg_ptr, void**);
		free(*p[i]);
		*p[i] = NULL_PTR;
	}
	
	va_end(arg_ptr);
	
	return 0;
}
CK_ULONG test_SM4RAMValue(CK_MECHANISM_TYPE mAlgType, CK_BYTE *label,CK_ULONG labelsize)
{
    int bRtn = 0;
    CK_RV rv=0;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL ttrue = CK_TRUE;
    CK_BBOOL ffalse = CK_FALSE;
    CK_KEY_TYPE SM4keyType = CKK_SM4;
    string info;
    char n[1024*1024]={0};

    unsigned char	SM4keyVal_Enc[]={0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
    unsigned char	SM4iv_Enc[16] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
    unsigned char	SM4plain_Enc[192]={0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    unsigned char	SM4cipher_Enc_OFB[192]={0x73, 0xa3, 0x37, 0x80, 0x40, 0xad, 0x2f, 0x7c, 0x91, 0x81, 0x8e, 0xcd, 0x49, 0x6a, 0xe2, 0x62, 0xb8, 0x83, 0xc1, 0x38, 0x12, 0xfa, 0x3d, 0xb4, 0xfc, 0x2a, 0xf4, 0x97, 0x2b, 0xa9, 0xaf, 0xae, 0xcc, 0x8d, 0x58, 0x49, 0x07, 0x67, 0xd3, 0x76, 0xab, 0xb8, 0x1e, 0xe6, 0x8d, 0x19, 0xfa, 0xfb, 0x18, 0x3d, 0x10, 0xa9, 0x2f, 0xbb, 0xf1, 0x21, 0xa4, 0xd7, 0x2d, 0xb4, 0x1b, 0xf2, 0x42, 0x9e, 0x4b, 0x44, 0xfd, 0x08, 0x89, 0x20, 0x78, 0xf8, 0xd5, 0x7d, 0x48, 0xd1, 0x4e, 0x0a, 0x39, 0xa3, 0x88, 0xec, 0xfa, 0x04, 0x84, 0xa6, 0x24, 0x88, 0xd5, 0x91, 0xea, 0x27, 0xaa, 0x99, 0x9f, 0x29, 0xe4, 0xf0, 0x12, 0xde, 0x35, 0x07, 0x5f, 0xe2, 0x34, 0x96, 0xfb, 0x61, 0xc1, 0xff, 0xa2, 0xc7, 0x00, 0x4a, 0xd1, 0xca, 0x3b, 0xc2, 0xdb, 0x49, 0xc7, 0xd5, 0x7a, 0x04, 0x82, 0x9d, 0xfa, 0xff, 0xd2, 0xd8, 0x6c, 0x77, 0x4f, 0xa8, 0x44, 0x47, 0xdd, 0x84, 0xd4, 0xf1, 0x8e, 0xc6, 0x36, 0xfc, 0xa4, 0xd8, 0x1a, 0xa5, 0x38, 0x30, 0xc3, 0xf6, 0xde, 0xe8, 0x69, 0xb5, 0x37, 0x1b, 0x47, 0x26, 0x41, 0xf7, 0x9f, 0xac, 0x29, 0x69, 0x2e, 0xba, 0xbd, 0x55, 0x8d, 0x28, 0xa6, 0x03, 0x0e, 0xaf, 0xeb, 0x6b, 0xe9, 0xb3, 0x75, 0xe0, 0x81, 0x76, 0xc9, 0x60, 0xaa, 0x8c, 0xab, 0x70, 0x2f, 0x42};
    unsigned char	SM4cipher_Enc_ECB[192]={0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91,
                                             0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91,
                                             0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91,
                                             0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91,
                                             0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91,
                                             0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91,
                                             0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91,
                                             0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91,
                                             0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91,
                                             0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91,
                                             0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91,
                                             0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91};
    unsigned char	SM4cipher_Enc_CBC[192]={0x94, 0x0f, 0x58, 0xdf, 0xb5, 0x3e, 0x53, 0x48, 0x70, 0x14, 0xf6, 0x4d, 0x95, 0x9e, 0x12, 0x2e, 0x24, 0xd8, 0x02, 0xa7, 0x69, 0x09, 0x2f, 0xcb, 0xcd, 0xa7, 0xc0, 0x8b, 0xe3, 0x2c, 0xe8, 0x99, 0x94, 0xb3, 0x56, 0xe2, 0x90, 0x75, 0xc9, 0x82, 0x13, 0x53, 0x02, 0xc8, 0xf3, 0xe6, 0xc5, 0x7d, 0xed, 0x17, 0x16, 0x50, 0xed, 0x45, 0x2e, 0xa3, 0xaf, 0x2d, 0xce, 0xf2, 0x85, 0x42, 0x45, 0x17, 0x6c, 0xe7, 0x2e, 0x78, 0x3b, 0xfd, 0x9a, 0x8a, 0x9e, 0x6a, 0x7c, 0xa6, 0xad, 0xfa, 0x7d, 0xec, 0xde, 0xd6, 0x87, 0x3e, 0x45, 0xcd, 0x9a, 0xe9, 0x7f, 0xf5, 0x4a, 0x71, 0xe4, 0x04, 0x2b, 0x14, 0xca, 0xca, 0x43, 0x3a, 0x5a, 0x9d, 0xf3, 0x22, 0xee, 0x78, 0x7d, 0x27, 0xd1, 0x26, 0x15, 0x35, 0x5b, 0xf6, 0x78, 0x08, 0x67, 0xe8, 0xe2, 0xfd, 0xd8, 0x85, 0xbb, 0x2b, 0x41, 0xe7, 0xd3, 0xf7, 0xcb, 0x7c, 0xb3, 0x6c, 0x92, 0xdf, 0x9a, 0x07, 0x09, 0x81, 0x97, 0xec, 0x36, 0x93, 0xab, 0x96, 0xad, 0xb7, 0x61, 0x89, 0xa9, 0xa5, 0x20, 0x82, 0x5f, 0xba, 0x5f, 0xbc, 0x73, 0xdb, 0xba, 0x43, 0xc4, 0x46, 0x6f, 0xbd, 0x1e, 0x71, 0xfd, 0xb1, 0xd3, 0x80, 0xbe, 0x2d, 0xb1, 0x76, 0xbd, 0xb9, 0x3f, 0x5c, 0x58, 0x2a, 0x6d, 0x9a, 0x94, 0xca, 0x7f, 0x92, 0x8f, 0x56, 0x30, 0x9f, 0x06, 0x43};
    unsigned char	*SM4cipher_Enc = NULL;
    CK_BYTE nSessKeyID_Enc = CK_SESSKEY_PRESET_ID1;
    CK_BYTE nSessKeyID_Dec = CK_SESSKEY_PRESET_ID2;
    CK_BYTE id[] = {0x11,0x22,0x33,0x44,0x55};

    CK_ATTRIBUTE SM4keyTemplate_Enc[] =
    {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_TOKEN, &ffalse, sizeof(ffalse)},
        {CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
        {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
        {CKA_DECRYPT, &ffalse, sizeof(ttrue)},
        {CKA_VALUE,SM4keyVal_Enc,sizeof(SM4keyVal_Enc)},
        {CKA_LABEL, label, labelsize},
   //     {CKA_ID, id, sizeof(id)},
        {CKA_EXTRACTABLE,&ttrue, sizeof(ttrue)},   //for softcard test
        {CKA_SESSKEY_ID, &nSessKeyID_Enc, sizeof(CK_BYTE)}
    };

    CK_MECHANISM SM4mechanism_Enc = {mAlgType, SM4iv_Enc, sizeof(SM4iv_Enc)};
    CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

    CK_ATTRIBUTE SM4keyTemplate_Dec[] =
    {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_TOKEN, &ffalse, sizeof(ffalse)},
        {CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
        {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
        {CKA_ENCRYPT, &ffalse, sizeof(ttrue)},
        {CKA_VALUE,SM4keyVal_Enc,sizeof(SM4keyVal_Enc)},
        {CKA_LABEL, label, labelsize},
    //    {CKA_ID, id, sizeof(id)},
        {CKA_EXTRACTABLE,&ttrue, sizeof(ttrue)},   //for softcard test
        {CKA_SESSKEY_ID, &nSessKeyID_Dec, sizeof(CK_BYTE)}
    };

    CK_ATTRIBUTE SM4keyTemplate_find[] =
    {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_TOKEN, &ffalse, sizeof(ffalse)},
        {CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
        {CKA_LABEL, label, labelsize},
    //    {CKA_ID, id, sizeof(id)},
        {CKA_SESSKEY_ID, &nSessKeyID_Enc, sizeof(CK_BYTE)}
    };

    CK_MECHANISM SM4mechanism_Dec = {mAlgType, SM4iv_Enc, sizeof(SM4iv_Enc)};
    CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

    CK_BYTE indata[256] = {0};
    CK_ULONG indatalen=sizeof(indata);
    CK_BYTE outdata[256] = {0};
    CK_ULONG outdatalen=sizeof(outdata);

    CK_BYTE indata1[256] = {0};
    CK_ULONG indatalen1=sizeof(indata1);
    CK_BYTE outdata1[256] = {0};
    CK_ULONG outdatalen1=sizeof(outdata1);

    char  fname[4] = {0x00};
    char* fNameECB = "ECB";
    char* fNameCBC = "CBC";
    char* fNameOFB = "OFB";

    if (mAlgType == CKM_SM4_ECB)
    {
        SM4cipher_Enc = SM4cipher_Enc_ECB;
        SM4mechanism_Enc.pParameter = NULL;
        SM4mechanism_Enc.ulParameterLen = 0;
        SM4mechanism_Dec.pParameter = NULL;
        SM4mechanism_Dec.ulParameterLen = 0;
        strcpy(fname, fNameECB);
    }
    else if (mAlgType == CKM_SM4_CBC)
    {
        SM4cipher_Enc = SM4cipher_Enc_CBC;
        strcpy(fname, fNameCBC);
    }
    else if (mAlgType == CKM_SM4_OFB)
    {
        SM4cipher_Enc = SM4cipher_Enc_OFB;
        strcpy(fname, fNameOFB);
    }

    info.clear();
    info.append("Enter ");
    info.append(fname);

    CK_SESSION_HANDLE  session = hSession;
    hKey_Enc = NULL_PTR;
    info.append(" hKey_Enc: ");
    TimeStart();
    rv = C_CreateObject(session, SM4keyTemplate_Enc, sizeof(SM4keyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
    sprintf(n,"0x%08x",hKey_Enc);
    info.append(n);
    Save("C_CreateObject",rv,info,TimeEnd());

    indatalen = sizeof(indata);
    memset(indata, 0, indatalen);
    outdatalen=sizeof(outdata);
    memset(outdata, 0, outdatalen);

    indatalen1 = sizeof(indata1);
    memset(indata1, 0, indatalen1);
    outdatalen1=sizeof(outdata1);
    memset(outdata1, 0, outdatalen1);

    memcpy(indata, SM4plain_Enc, sizeof(SM4plain_Enc));
    indatalen = sizeof(SM4plain_Enc);

    /*******************????**********************/

  /*  if (mAlgType != CKM_SM4_OFB)
    {
        rv = (C_EncryptInit)(session, &SM4mechanism_Enc, hKey_Enc);

        rv = (C_Encrypt)(session, indata, indatalen-1, outdata, &outdatalen);
        RV_NOT_OK_RETURN_TRUE(pC_Encrypt,rv);
    }*/
    TimeStart();
    rv = C_EncryptInit(session, &SM4mechanism_Enc, hKey_Enc);
    Save("C_EncryptInit",rv,"",TimeEnd());

    TimeStart();
    rv = C_Encrypt(session, indata, indatalen, NULL, &outdatalen);
    Save("C_Encrypt1",rv,"",TimeEnd());

    info.clear();
    TimeStart();
    rv = C_Encrypt(session, indata, indatalen, outdata, &outdatalen);
    if (((outdatalen != indatalen) || memcmp(outdata, SM4cipher_Enc, outdatalen)))
    {
        info.append("test_SM4RAMValue failed, encrypt value ERROR!");
    }
    Save("C_Encrypt2",rv,info,TimeEnd());

    memset(outdata,0,outdatalen);
    TimeStart();
    rv = C_EncryptInit(session, &SM4mechanism_Enc, hKey_Enc);
    Save("C_Encrypt3",rv,"",TimeEnd());

    info.clear();
    TimeStart();
    rv = C_EncryptUpdate(session, indata, indatalen, outdata, &outdatalen);
    if (((outdatalen != indatalen) || memcmp(outdata, SM4cipher_Enc, outdatalen)))
    {
        info.append("test_SM4RAMValue failed, encryptupdate value ERROR!.\n");
    }
    else
    {
        info.append("Encrypt Correct!");
    }
    Save("C_EncryptUpdate",rv,info,TimeEnd());

    TimeStart();
    rv = C_EncryptFinal(session, outdata1, &outdatalen1);
    Save("C_EncryptFinal",rv,"",TimeEnd());

    /******************????***********************/
    hKey_Dec = NULL_PTR;
    info.clear();
    info.append("hKey_Dec: ");
    TimeStart();
    rv = C_CreateObject(session, SM4keyTemplate_Dec, sizeof(SM4keyTemplate_Dec)/sizeof(CK_ATTRIBUTE), &hKey_Dec);
    sprintf(n,"0x%08x",hKey_Dec);
    info.append(n);
    Save("C_CreateObject",rv,info,TimeEnd());

    memcpy(indata1, outdata, outdatalen);
    indatalen1 = outdatalen;

    TimeStart();
    rv = C_DecryptInit(session, &SM4mechanism_Dec, hKey_Dec);
    Save("C_DecryptInit",rv,"",TimeEnd());

    TimeStart();
    rv = C_Decrypt(session, indata1, indatalen1, NULL, &outdatalen1);
    Save("C_Decrypt1",rv,"",TimeEnd());

    TimeStart();
    info.clear();
    rv = C_Decrypt(session, indata1, indatalen1, outdata1, &outdatalen1);

    if ((outdatalen1 != sizeof(SM4plain_Enc)) || (memcmp(outdata1, SM4plain_Enc, outdatalen1)))
    {
        info.append("test_SM4RAMValue.decrypt value ERROR!");
    }
    Save("C_Decrypt2",rv,info,TimeEnd());

    memset(outdata1,0,outdatalen1);
    TimeStart();
    rv = C_DecryptInit(session, &SM4mechanism_Dec, hKey_Dec);
    Save("C_DecryptInit",rv,"",TimeEnd());

    TimeStart();
    rv = C_DecryptUpdate(session, indata1, indatalen1, outdata1, &outdatalen1);
    info.clear();
    if ((outdatalen1 != sizeof(SM4plain_Enc)) || (memcmp(outdata1, SM4plain_Enc, outdatalen1)))
    {
        info.append("test_SM4RAMValue.decryptupdate ERROR!");
    }
    else
    {
        info.append("Decrypt Correct!");
    }
    Save("C_DecryptUpdate",rv,info,TimeEnd());

    TimeStart();
    rv = C_DecryptFinal(session, outdata, &outdatalen);
    Save("C_DecryptFinal",rv,"",TimeEnd());




END:
    return bRtn;
}

CK_ULONG xtest_SM4RAMnoValue(CK_MECHANISM_TYPE mAlgType, unsigned char *label,  CK_ULONG labelsize, CK_BBOOL bEncrypt, CK_BBOOL bDecrypt)
{
    int bRtn = 0;
    CK_RV rv=0;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL ttrue = CK_TRUE;
    CK_BBOOL ffalse = CK_FALSE;
    CK_KEY_TYPE SM4keyType = CKK_SM4;
    string info;
    char n[1024*1024]={0};

    unsigned char	SM4keyVal_Enc[]={0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
    unsigned char	SM4iv_Enc[16] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
    unsigned char	SM4plain_Enc[192]={0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    unsigned char	SM4cipher_Enc_OFB[192]={0x73, 0xa3, 0x37, 0x80, 0x40, 0xad, 0x2f, 0x7c, 0x91, 0x81, 0x8e, 0xcd, 0x49, 0x6a, 0xe2, 0x62, 0xb8, 0x83, 0xc1, 0x38, 0x12, 0xfa, 0x3d, 0xb4, 0xfc, 0x2a, 0xf4, 0x97, 0x2b, 0xa9, 0xaf, 0xae, 0xcc, 0x8d, 0x58, 0x49, 0x07, 0x67, 0xd3, 0x76, 0xab, 0xb8, 0x1e, 0xe6, 0x8d, 0x19, 0xfa, 0xfb, 0x18, 0x3d, 0x10, 0xa9, 0x2f, 0xbb, 0xf1, 0x21, 0xa4, 0xd7, 0x2d, 0xb4, 0x1b, 0xf2, 0x42, 0x9e, 0x4b, 0x44, 0xfd, 0x08, 0x89, 0x20, 0x78, 0xf8, 0xd5, 0x7d, 0x48, 0xd1, 0x4e, 0x0a, 0x39, 0xa3, 0x88, 0xec, 0xfa, 0x04, 0x84, 0xa6, 0x24, 0x88, 0xd5, 0x91, 0xea, 0x27, 0xaa, 0x99, 0x9f, 0x29, 0xe4, 0xf0, 0x12, 0xde, 0x35, 0x07, 0x5f, 0xe2, 0x34, 0x96, 0xfb, 0x61, 0xc1, 0xff, 0xa2, 0xc7, 0x00, 0x4a, 0xd1, 0xca, 0x3b, 0xc2, 0xdb, 0x49, 0xc7, 0xd5, 0x7a, 0x04, 0x82, 0x9d, 0xfa, 0xff, 0xd2, 0xd8, 0x6c, 0x77, 0x4f, 0xa8, 0x44, 0x47, 0xdd, 0x84, 0xd4, 0xf1, 0x8e, 0xc6, 0x36, 0xfc, 0xa4, 0xd8, 0x1a, 0xa5, 0x38, 0x30, 0xc3, 0xf6, 0xde, 0xe8, 0x69, 0xb5, 0x37, 0x1b, 0x47, 0x26, 0x41, 0xf7, 0x9f, 0xac, 0x29, 0x69, 0x2e, 0xba, 0xbd, 0x55, 0x8d, 0x28, 0xa6, 0x03, 0x0e, 0xaf, 0xeb, 0x6b, 0xe9, 0xb3, 0x75, 0xe0, 0x81, 0x76, 0xc9, 0x60, 0xaa, 0x8c, 0xab, 0x70, 0x2f, 0x42};
    unsigned char	SM4cipher_Enc_ECB[192]={0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91};
    unsigned char	SM4cipher_Enc_CBC[192]={0x94, 0x0f, 0x58, 0xdf, 0xb5, 0x3e, 0x53, 0x48, 0x70, 0x14, 0xf6, 0x4d, 0x95, 0x9e, 0x12, 0x2e, 0x24, 0xd8, 0x02, 0xa7, 0x69, 0x09, 0x2f, 0xcb, 0xcd, 0xa7, 0xc0, 0x8b, 0xe3, 0x2c, 0xe8, 0x99, 0x94, 0xb3, 0x56, 0xe2, 0x90, 0x75, 0xc9, 0x82, 0x13, 0x53, 0x02, 0xc8, 0xf3, 0xe6, 0xc5, 0x7d, 0xed, 0x17, 0x16, 0x50, 0xed, 0x45, 0x2e, 0xa3, 0xaf, 0x2d, 0xce, 0xf2, 0x85, 0x42, 0x45, 0x17, 0x6c, 0xe7, 0x2e, 0x78, 0x3b, 0xfd, 0x9a, 0x8a, 0x9e, 0x6a, 0x7c, 0xa6, 0xad, 0xfa, 0x7d, 0xec, 0xde, 0xd6, 0x87, 0x3e, 0x45, 0xcd, 0x9a, 0xe9, 0x7f, 0xf5, 0x4a, 0x71, 0xe4, 0x04, 0x2b, 0x14, 0xca, 0xca, 0x43, 0x3a, 0x5a, 0x9d, 0xf3, 0x22, 0xee, 0x78, 0x7d, 0x27, 0xd1, 0x26, 0x15, 0x35, 0x5b, 0xf6, 0x78, 0x08, 0x67, 0xe8, 0xe2, 0xfd, 0xd8, 0x85, 0xbb, 0x2b, 0x41, 0xe7, 0xd3, 0xf7, 0xcb, 0x7c, 0xb3, 0x6c, 0x92, 0xdf, 0x9a, 0x07, 0x09, 0x81, 0x97, 0xec, 0x36, 0x93, 0xab, 0x96, 0xad, 0xb7, 0x61, 0x89, 0xa9, 0xa5, 0x20, 0x82, 0x5f, 0xba, 0x5f, 0xbc, 0x73, 0xdb, 0xba, 0x43, 0xc4, 0x46, 0x6f, 0xbd, 0x1e, 0x71, 0xfd, 0xb1, 0xd3, 0x80, 0xbe, 0x2d, 0xb1, 0x76, 0xbd, 0xb9, 0x3f, 0x5c, 0x58, 0x2a, 0x6d, 0x9a, 0x94, 0xca, 0x7f, 0x92, 0x8f, 0x56, 0x30, 0x9f, 0x06, 0x43};
    unsigned char	*SM4cipher_Enc = NULL;

    CK_BYTE nSessKeyID_Enc = CK_SESSKEY_PRESET_ID1;
    CK_BYTE nSessKeyID_Dec = CK_SESSKEY_PRESET_ID2;
    CK_ATTRIBUTE SM4keyTemplate_Enc[] =
    {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_TOKEN, &ffalse, sizeof(ffalse)},
            {CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
            {CKA_ENCRYPT, &bEncrypt, sizeof(ttrue)},
            {CKA_DECRYPT, &bDecrypt, sizeof(ttrue)},
            {CKA_LABEL, label, labelsize},
            {CKA_SESSKEY_ID, &nSessKeyID_Enc, sizeof(CK_BYTE)}
    };
    CK_MECHANISM SM4mechanism_Enc = {mAlgType, SM4iv_Enc, sizeof(SM4iv_Enc)};
    CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

    CK_ATTRIBUTE SM4keyTemplate_Dec[] =
    {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_TOKEN, &ffalse, sizeof(ffalse)},
        {CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
        {CKA_DECRYPT, &bEncrypt, sizeof(ttrue)},
        {CKA_ENCRYPT, &bDecrypt, sizeof(ttrue)},
        {CKA_LABEL, label, labelsize},
        {CKA_SESSKEY_ID, &nSessKeyID_Dec, sizeof(CK_BYTE)}
    };
    CK_MECHANISM SM4mechanism_Dec = {mAlgType, SM4iv_Enc, sizeof(SM4iv_Enc)};
    CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

    CK_BYTE indata[256] = {0};
    CK_ULONG indatalen=sizeof(indata);
    CK_BYTE outdata[256] = {0};
    CK_ULONG outdatalen=sizeof(outdata);

    CK_BYTE indata1[256] = {0};
    CK_ULONG indatalen1=sizeof(indata1);
    CK_BYTE outdata1[256] = {0};
    CK_ULONG outdatalen1=sizeof(outdata1);
    int loopTime = 1;
    unsigned int i = 0;
    char  fname[4] = {0x00};
    char* fNameECB = "ECB";
    char* fNameCBC = "CBC";
    char* fNameOFB = "OFB";

    CK_ULONG ulObjectCount = 0;

    if (mAlgType == CKM_SM4_ECB)
    {
        SM4cipher_Enc = SM4cipher_Enc_ECB;
        SM4mechanism_Enc.pParameter = NULL;
        SM4mechanism_Enc.ulParameterLen = 0;
        SM4mechanism_Dec.pParameter = NULL;
        SM4mechanism_Dec.ulParameterLen = 0;
        strcpy(fname, fNameECB);
    }
    else if (mAlgType == CKM_SM4_CBC)
    {
        SM4cipher_Enc = SM4cipher_Enc_CBC;
        strcpy(fname, fNameCBC);
    }
    else if (mAlgType == CKM_SM4_OFB)
    {
        SM4cipher_Enc = SM4cipher_Enc_OFB;
        strcpy(fname, fNameOFB);
    }

    info.clear();
    info.append("Enter ");
    info.append(fname);

    CK_SESSION_HANDLE  session = hSession;
    //////////////////////////////////////
    CK_OBJECT_HANDLE hObject[16] = {0};
    CK_ULONG ulfindObjectCount = 0;
    TimeStart();
    rv = C_FindObjectsInit(hSession, SM4keyTemplate_Enc, sizeof(SM4keyTemplate_Enc)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit",rv,info,TimeEnd());

    TimeStart();
    rv = C_FindObjects(hSession, hObject, 16, &ulfindObjectCount);
    info.clear();
    sprintf(n,"%ld",ulfindObjectCount);
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulfindObjectCount;i++)
    {
        sprintf(n,",0x%08x ",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects",rv,info,TimeEnd());

    TimeStart();
    rv = C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal",rv,"",TimeEnd());

    hKey_Enc = hObject[0];

    memset(hObject,0,sizeof(hObject));
    TimeStart();
    rv = C_FindObjectsInit(hSession, SM4keyTemplate_Dec, sizeof(SM4keyTemplate_Dec)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit2",rv,"",TimeEnd());

    TimeStart();
    rv = C_FindObjects(hSession, hObject, 16, &ulfindObjectCount);
    info.clear();
    sprintf(n,"%ld",ulfindObjectCount);
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulfindObjectCount;i++)
    {
        sprintf(n,",0x%08x ",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects2",rv,info,TimeEnd());

    TimeStart();
    rv = C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal2",rv,"",TimeEnd());

    hKey_Dec = hObject[0];

    for (i=0; i<loopTime; i++)
    {
        indatalen = sizeof(indata);
        memset(indata, 0, indatalen);
        outdatalen=sizeof(outdata);
        memset(outdata, 0, outdatalen);

        indatalen1 = sizeof(indata1);
        memset(indata1, 0, indatalen1);
        outdatalen1=sizeof(outdata1);
        memset(outdata1, 0, outdatalen1);

        memcpy(indata, SM4plain_Enc, sizeof(SM4plain_Enc));
        indatalen = sizeof(SM4plain_Enc);

        /*******************????**********************/
        TimeStart();
        rv = C_EncryptInit(session, &SM4mechanism_Enc, hKey_Enc);
        Save("C_EncryptInit",rv,"",TimeEnd());

        TimeStart();
        rv = C_EncryptUpdate(session, indata, indatalen, outdata, &outdatalen);
        info.clear();
        if ((/*(outdatalen != sizeof(SM4cipher_Enc)) || */memcmp(outdata, SM4cipher_Enc, outdatalen)) && (i == 0))
        {
            info.append("Calc Error: xtest_SM4RAMnoValue.");
        }
        else
        {
            info.append("Calc Correct!\n");
        }
        Save("C_EncryptUpdate",rv,info,TimeEnd());

        TimeStart();
        rv = C_EncryptFinal(session, outdata1, &outdatalen1);
        Save("C_EncryptFinal",rv,"",TimeEnd());

        /******************????***********************/
        TimeStart();
        rv = C_DecryptInit(session, &SM4mechanism_Dec, hKey_Dec);
        Save("C_DecryptInit",rv,"",TimeEnd());

        memcpy(indata1, outdata, outdatalen);
        indatalen1 = outdatalen;

        TimeStart();
        rv = (C_DecryptUpdate)(session, indata1, indatalen1, NULL, &outdatalen1);
        Save("C_DecryptUpdateNULL",rv,"",TimeEnd());

        TimeStart();
        info.clear();
        rv = (C_DecryptUpdate)(session, indata1, indatalen1, outdata1, &outdatalen1);
        if ((outdatalen1 != sizeof(SM4plain_Enc)) || (memcmp(outdata1, SM4plain_Enc, outdatalen1)))
        {
            info.append("Calc Error: xtest_SM4RAMnoValue");
        }
        else
        {
            info.append("Calc Correct!\n");
        }
        Save("C_DecryptUpdate",rv,info,TimeEnd());

        TimeStart();
        rv = (C_DecryptFinal)(session, outdata, &outdatalen);
        Save("C_DecryptFinal",rv,"",TimeEnd());

    }

    return bRtn;
}

CK_ULONG xtest_SM4_KEY(CK_MECHANISM_TYPE mAlgType)
{
    int xnRtn = 0;
    CK_RV rv = -1;
    CK_BYTE label_ram[] = "12345";
    CK_BYTE label[] = "123456";

    xnRtn = test_SM4RAMValue(mAlgType,label_ram, sizeof(label_ram)-1);//RAM??
    if(xnRtn == 1)
    {
        return 1;
    }

    xnRtn = xtest_SM4RAMnoValue(mAlgType,label_ram, sizeof(label_ram)-1, TRUE, FALSE);
    if(xnRtn == 1)
    {
        return 1;
    }
/*
    xnRtn = test_SM4FLASHValue(mAlgType,label,sizeof(label)-1);//FLASH??,????
    if(xnRtn == 1)
    {
        return 1;
    }

    xnRtn = xtest_SM4FLASHnoValue(mAlgType,label,sizeof(label)-1, TRUE, FALSE);//FLASH??????
    if(xnRtn == 1)
    {
        return 1;
    }
*/
    return 0;

}

CK_ULONG xtest_symkey_test()
{
    CK_RV rv = 0;
    string info;
    char n[1024*1024]={0};
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL ttrue = CK_TRUE;
    CK_BBOOL ffalse = CK_FALSE;
    CK_KEY_TYPE ZUCkeyType = CKK_ZUC;
    CK_KEY_TYPE SM4keyType = CKK_SM4;
    CK_OBJECT_HANDLE hkeyzuc = 0;
    CK_OBJECT_HANDLE hkeysm4 = 0;
    CK_BYTE id[] = {0x01,0x10,0x10};

    CK_BYTE nSessKeyID = CK_SESSKEY_PRESET_ID1;
    CK_BYTE sessIDimport = CK_SESSKEY_PRESET_ID2;

    //SM4
    CK_MECHANISM SM4mechanismGen = {CKM_SM4_KEY_GEN, NULL_PTR, 0};
    CK_MECHANISM SM4ECBmechanism = {CKM_SM4_ECB, NULL_PTR, 0};
    CK_ATTRIBUTE SM4keyTemplate_Gen[] =
    {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_TOKEN, &ttrue, sizeof(ttrue)},
        {CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
 //       {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
 //       {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
        {CKA_UNWRAP, &ttrue, sizeof(ttrue)},
        //         {CKA_WRAP_WITH_TRUSTED,&ttrue, sizeof(ttrue)},
        //           {CKA_ID,id,sizeof(id)},
        {CKA_SESSKEY_ID, &nSessKeyID, sizeof(nSessKeyID)}

    };

    CK_ATTRIBUTE importKeyTemplate[] =
    {
            { CKA_CLASS, &keyClass, sizeof(keyClass) },
            { CKA_TOKEN, &ttrue, sizeof(ttrue) },
            { CKA_KEY_TYPE, &SM4keyType, sizeof(SM4keyType) },
            { CKA_ENCRYPT, &ttrue, sizeof(ttrue) },
            { CKA_DECRYPT, &ttrue, sizeof(ttrue) },
            { CKA_UNWRAP, &ttrue, sizeof(ttrue) },
            { CKA_WRAP, &ttrue, sizeof(ttrue) },
            { CKA_EXTRACTABLE, &ttrue, sizeof(ttrue) },
            { CKA_WRAP_WITH_TRUSTED, &ttrue, sizeof(ttrue) },
            { CKA_SESSKEY_ID, &sessIDimport, sizeof(CK_BYTE) }
    };

    //find
    CK_OBJECT_HANDLE hObject[16] = {0};
    CK_ULONG ulObjectCount = 0;
    CK_ATTRIBUTE keyTemplateimport_find[] =
    {
            { CKA_CLASS, &keyClass, sizeof(keyClass) },
            { CKA_TOKEN, &ttrue, sizeof(ttrue) },
            { CKA_KEY_TYPE, &SM4keyType, sizeof(SM4keyType) },
            { CKA_ENCRYPT, &ttrue, sizeof(ttrue) },
            { CKA_DECRYPT, &ttrue, sizeof(ttrue) },
            { CKA_EXTRACTABLE, &ttrue, sizeof(ttrue) },
            { CKA_WRAP_WITH_TRUSTED, &ttrue, sizeof(ttrue) },
            { CKA_SESSKEY_ID, &sessIDimport, sizeof(CK_BYTE) }
    };

    CK_ATTRIBUTE keyTemplate_find[] =
    {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_TOKEN, &ttrue, sizeof(ttrue)},
            {CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
   //         {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
   //         {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
            //         {CKA_WRAP_WITH_TRUSTED,&ttrue, sizeof(ttrue)},
            //           {CKA_ID,id,sizeof(id)},
            {CKA_SESSKEY_ID, &nSessKeyID, sizeof(nSessKeyID)}
    };

    TimeStart();
    rv = C_FindObjectsInit(hSession, keyTemplate_find, sizeof(keyTemplate_find)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit",rv,"",TimeEnd());

    TimeStart();
    rv = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
    sprintf(n,"%ld",ulObjectCount);
    info.clear();
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulObjectCount;i++)
    {
        sprintf(n," 0x%08x",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects",rv,info,TimeEnd());

    TimeStart();
    rv =C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal",rv,"",TimeEnd());

    for(int i=0;i<ulObjectCount;i++)
    {
        TimeStart();
        rv = C_DestroyObject(hSession,hObject[i]);
        Save("C_DestroyObject",rv,"",TimeEnd());
    }

    info.clear();
    TimeStart();
    rv = C_GenerateKey(hSession, &SM4mechanismGen,SM4keyTemplate_Gen, sizeof(SM4keyTemplate_Gen)/sizeof(CK_ATTRIBUTE), &hkeysm4);
    info.append("hkeysm4: ");
    sprintf(n,"0x%08x",hkeysm4);
    info.append(n);
    Save("C_GenerateKey",rv,info,TimeEnd());



    for(int i=0;i<1;i++)
    {
        TimeStart();
        rv = C_FindObjectsInit(hSession, SM4keyTemplate_Gen, sizeof(SM4keyTemplate_Gen)/sizeof(CK_ATTRIBUTE));
        Save("C_FindObjectsInit",rv,"",TimeEnd());

        TimeStart();
        rv = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
        sprintf(n,"%ld",ulObjectCount);
        info.clear();
        info.append("object count = ");
        info.append(n);
        for(int i=0;i<ulObjectCount;i++)
        {
            sprintf(n," 0x%08x",hObject[i]);
            info.append(n);
        }
        Save("C_FindObjects",rv,info,TimeEnd());

        TimeStart();
        rv =C_FindObjectsFinal(hSession);
        Save("C_FindObjectsFinal",rv,"",TimeEnd());
    }

    CK_OBJECT_HANDLE hwrappingkey = hObject[0];

    ///////
    TimeStart();
    rv = C_FindObjectsInit(hSession, keyTemplateimport_find, sizeof(keyTemplateimport_find)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInitimport",rv,"",TimeEnd());

    TimeStart();
    rv = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
    sprintf(n,"%ld",ulObjectCount);
    info.clear();
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulObjectCount;i++)
    {
        sprintf(n," 0x%08x",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjectsimport",rv,info,TimeEnd());

    TimeStart();
    rv =C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinalimport",rv,"",TimeEnd());

    for(int i=0;i<ulObjectCount;i++)
    {
        TimeStart();
        rv = C_DestroyObject(hSession,hObject[i]);
        Save("C_DestroyObject",rv,"",TimeEnd());
    }

    CK_BYTE wrappedkey[16] = {0};
    CK_OBJECT_HANDLE himportkey = 0;
    info.clear();
    TimeStart();
    rv = C_UnwrapKey(hSession,&SM4ECBmechanism,hwrappingkey,wrappedkey,sizeof(wrappedkey),importKeyTemplate,
                     sizeof(importKeyTemplate)/sizeof(CK_ATTRIBUTE),&himportkey);
    info.append("himportkey: ");
    sprintf(n,"0x%08x",himportkey);
    info.append(n);
    Save("000 C_UnwrapKey",rv,info,TimeEnd());

    for(int i=0;i<1;i++)
    {
        TimeStart();
        rv = C_FindObjectsInit(hSession, keyTemplateimport_find, sizeof(keyTemplateimport_find)/sizeof(CK_ATTRIBUTE));
        Save("C_FindObjectsInitimport2",rv,"",TimeEnd());

        TimeStart();
        rv = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
        sprintf(n,"%ld",ulObjectCount);
        info.clear();
        info.append("object count = ");
        info.append(n);
        for(int i=0;i<ulObjectCount;i++)
        {
            sprintf(n," 0x%08x",hObject[i]);
            info.append(n);
        }
        Save("C_FindObjectsmport2",rv,info,TimeEnd());

        TimeStart();
        rv =C_FindObjectsFinal(hSession);
        Save("C_FindObjectsFinalmport2",rv,"",TimeEnd());
    }

    return 0;

}

CK_RV test_Encrypt_Sesskey(CK_OBJECT_HANDLE hsesskey)
{
    CK_RV rv=0;
    int looptime = 1, datalen = 16;
    string info;
    char n[1024*1024]={0};

/*    unsigned char	ZUCplain[32] = {0};
    unsigned char	ZUCcipher[32] = {0x27,0xBE,0xDE,0x74,0x01,0x80,0x82,0xDA,0x87,0xD4,0xE5,0xB6,0x9F,0x18,0xBF,0x66,
                                          0x32,0x07,0x0E,0x0F,0x39,0xB7,0xB6,0x92,0xB4,0x67,0x3E,0xDC,0x31,0x84,0xA4,0x8E};
    unsigned char	ZUCiv_Enc[16] = {0};
    unsigned char	ZUCiv_Dec[16] = {0};*/

    unsigned char	ZUCplain[] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50,
                                   0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50};

    unsigned char	ZUCcipher[] = {0x08,0x2F, 0x5A, 0x65, 0x3E, 0xCD, 0x08, 0x0E, 0xBB, 0x76, 0xD3, 0x6D, 0xAE, 0x3D, 0x1D, 0x22,
                                    0x08,0x2F, 0x5A, 0x65, 0x3E, 0xCD, 0x08, 0x0E, 0xBB, 0x76, 0xD3, 0x6D, 0xAE, 0x3D, 0x1D, 0x22};

    unsigned char	ZUCiv_Enc[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};
    unsigned char	ZUCiv_Dec[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};
    datalen = sizeof(ZUCplain);

    CK_MECHANISM ZUCmechanism_Enc = {CKM_ZUC_EEA, NULL, 0};
    CK_MECHANISM ZUCmechanism_Dec = {CKM_ZUC_EEA, NULL, 0};

    CK_BYTE indata[141] = {0};
    CK_ULONG indatalen=sizeof(indata);
    CK_BYTE outdata[141] = {0};
    CK_ULONG outdatalen=sizeof(outdata);

    CK_BYTE indata1[141] = {0};
    CK_ULONG indatalen1=sizeof(indata1);
    CK_BYTE outdata1[141] = {0};
    CK_ULONG outdatalen1=sizeof(outdata1);

    CK_SESSION_HANDLE session = hSession;

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL ttrue = CK_TRUE;
    CK_BBOOL ffalse = CK_FALSE;
    CK_KEY_TYPE SessKeyExchangeKeyType = CKK_SESSKEY_EXCHANGE;
    CK_BYTE keyID3 = CK_SESSKEY_ID2;
    CK_ATTRIBUTE SessKeyDeriveTemplate[] =
    {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_TOKEN, &ffalse, sizeof(ffalse)},
        {CKA_KEY_TYPE, &SessKeyExchangeKeyType, sizeof(CK_KEY_TYPE)},
        {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
        {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
        {CKA_SESSKEY_ID, &keyID3, sizeof(CK_BYTE)}
    };

    unsigned int i = 0,j=0;

    srand( (unsigned)time( NULL ) );

    for (i=0; i<looptime; i++)
    {
//        RandomGenerate(ZUCplain,datalen);
//       RandomGenerate(ZUCiv_Enc,16);
//        memcpy(ZUCiv_Dec,ZUCiv_Enc,16);

        BUFFER_REFRESH_ZERO(indata,indatalen,outdata,outdatalen);
        BUFFER_REFRESH_ZERO(indata1,indatalen1,outdata1,outdatalen1);

        memcpy(indata, ZUCplain, datalen);
        indatalen = datalen;

        /*******************????**********************/
        TimeStart();
        rv = C_Extend_EncryptInit(session,&ZUCmechanism_Enc,SessKeyDeriveTemplate,sizeof(SessKeyDeriveTemplate)/sizeof(CK_ATTRIBUTE));
        Save("C_Extend_EncryptInit",rv,"",TimeEnd());

        if(rv !=0)
            return rv;

        int count = 0;

        while (count++ < 1000){

            outdatalen = 0;
            TimeStart();
            rv = C_Extend_EncryptUpdate(session, ZUCiv_Enc, 16, indata, indatalen, NULL_PTR, &outdatalen);
            Save("C_Extend_EncryptUpdate(NULL)",rv,"",TimeEnd());

            if(rv !=0)
                return rv;


            TimeStart();
            rv = C_Extend_EncryptUpdate(session, ZUCiv_Enc, 16, indata, indatalen, outdata, &outdatalen);
            Save("C_Extend_EncryptUpdate",rv,"",TimeEnd());

            if(rv !=0)
                return rv;

            /******************????***********************/
            memcpy(indata1, outdata, outdatalen);
            indatalen1 = outdatalen;

            TimeStart();
            rv = C_Extend_DecryptInit(session, &ZUCmechanism_Dec, SessKeyDeriveTemplate,sizeof(SessKeyDeriveTemplate)/sizeof(CK_ATTRIBUTE));
            Save("C_Extend_DecryptInit",rv,"",TimeEnd());

            if(rv !=0)
                return rv;

            TimeStart();
            rv = C_Extend_DecryptUpdate(session, ZUCiv_Dec, 16,indata1,indatalen1, outdata1, &outdatalen1);
            Save("C_Extend_DecryptUpdate",rv,"",TimeEnd());

            if(rv !=0)
                return rv;

            if ((outdatalen1 != datalen) || (memcmp(outdata1, ZUCplain, outdatalen1)) || (memcmp(outdata, ZUCcipher, outdatalen)))
            {
                //Error
                info.clear();
                info.append("sesskey encrypt ERROR!!");

                for(int i=0;i<outdatalen;i++)
                {
                    sprintf(n,"%02x",outdata[i]);
                    info.append(n);
                }

                TimeStart();
                rv = C_Extend_EncryptFinalize(session,outdata,&outdatalen);
                Save("C_Extend_EncryptFinalize",rv,"",TimeEnd());

                if(rv !=0)
                    return rv;

                TimeStart();
                rv = C_Extend_DecryptFinalize(session,outdata1,&outdatalen1);
                Save("C_Extend_DecryptFinalize",rv,info,TimeEnd());

                rv = -1;

            } else{
                info.clear();
                info.append("sesskey encrypt correct!!");

                TimeStart();
                rv = C_Extend_EncryptFinalize(session,outdata,&outdatalen);
                Save("C_Extend_EncryptFinalize",rv,"",TimeEnd());

                if(rv !=0)
                    return rv;

                TimeStart();
                rv = C_Extend_DecryptFinalize(session,outdata1,&outdatalen1);
                Save("C_Extend_DecryptFinalize",rv,info,TimeEnd());
            }
        }

    }

    return rv;
}

int findexchangekeypair(CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    string info;
    char n[1024*1024]={0};
    CK_RV rv = 0;
    CK_OBJECT_HANDLE hObjectpub[16] = {0};
    CK_OBJECT_HANDLE hObjectpri[16] = {0};
    CK_ULONG ulObjectCount1 = 0;
    CK_ULONG ulObjectCount2 = 0;
    CK_SESSION_HANDLE session = hSession;

    CK_BYTE      idid[] = {0x01,0x01,0x01,0x03};
    CK_MECHANISM      ECCMechanism = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_KEY_TYPE  ECCKeyType = CKK_SM2;
    CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY,priclass=CKO_PRIVATE_KEY;
    CK_BBOOL ttrue = CK_TRUE;
    CK_BBOOL ffalse = CK_FALSE;

    CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)},
            {CKA_ISEXCHANGEKEY, &ttrue, sizeof(CK_BBOOL)},
            {CKA_WRAP, &ttrue, sizeof(CK_BBOOL)},
            {CKA_KEY_TYPE,&ECCKeyType,sizeof(CK_KEY_TYPE)}
    };
    CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)},
            {CKA_PRIVATE, &ttrue, sizeof(CK_BBOOL)},
            {CKA_SENSITIVE, &ttrue, sizeof(CK_BBOOL)},
            {CKA_ISEXCHANGEKEY, &ttrue, sizeof(CK_BBOOL)},
            {CKA_UNWRAP, &ttrue, sizeof(CK_BBOOL)},
            {CKA_KEY_TYPE,&ECCKeyType,sizeof(CK_KEY_TYPE)}
    };

    TimeStart();
    rv = C_FindObjectsInit(session, publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit",rv,"",TimeEnd());

    TimeStart();
    info.clear();
    rv = C_FindObjects(session, hObjectpub, 16, &ulObjectCount1);
    if(ulObjectCount1 != 1)
    {
        info.append("pubkey No.Error!");
        sprintf(n,"%d",ulObjectCount1);
        info.append(n);
    }
    else
    {
        info.append("hobjectpub: ");
        sprintf(n,"0x%08x",hObjectpub[0]);
        info.append(n);
    }
    Save("C_FindObjects(exchangekeypair)",rv,info,TimeEnd());

    TimeStart();
    rv = C_FindObjectsFinal(session);
    Save("C_FindObjectsFinal",rv,"",TimeEnd());

    if(ulObjectCount1 != 1)
    {
        return ulObjectCount1;
    }

    /////////////////////////////
    TimeStart();
    rv = C_FindObjectsInit(session, privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit2",rv,"",TimeEnd());

    TimeStart();
    info.clear();
    rv = C_FindObjects(session, hObjectpri, 16, &ulObjectCount2);
    if(ulObjectCount2 !=1)
    {
        info.append("prikey No.Error!");
        sprintf(n,"%d",ulObjectCount2);
        info.append(n);
    }
    else
    {
        info.append("hobjectpri: ");
        sprintf(n,"0x%08x",hObjectpri[0]);
        info.append(n);
    }
    Save("C_FindObjects2",rv,info,TimeEnd());

    TimeStart();
    rv = C_FindObjectsFinal(session);
    Save("C_FindObjectsFinal2",rv,"",TimeEnd());

    if(ulObjectCount2 != 1)
    {
        return ulObjectCount2;
    }

    *phPublicKey = hObjectpub[0];
    *phPrivateKey = hObjectpri[0];

    return ulObjectCount2;
}

CK_OBJECT_HANDLE xtest_KeyExchange()
{
	CK_RV rv = 0;
	CK_OBJECT_HANDLE hPartKey1 = NULL_PTR, hPartKey2 = NULL_PTR, hSessKey_find = NULL_PTR;
	CK_BYTE keyID1 = CK_SESSKEY_ID0, keyID2 = CK_SESSKEY_ID1, keyID3 = CK_SESSKEY_ID2;
	//for C_GenerateKey
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;

	CK_KEY_TYPE SessKeyExchangeKeyType = CKK_SESSKEY_EXCHANGE;
	CK_MECHANISM SessKeyExchangeMechanism = {CKM_SESSKEY_EXCHANGE_GEN, NULL, 0};
	CK_ATTRIBUTE SessKeyExchangeTemplate1[] =
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &SessKeyExchangeKeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
        {CKA_EXTRACTABLE, &ttrue, sizeof(CK_BBOOL)},
		{CKA_SESSKEY_ID, &keyID1, sizeof(CK_BYTE)}
	};

	//for C_GenerateKeyPair
    CK_BYTE      idid[] = {0x01,0x01,0x01,0x03};
	CK_MECHANISM      ECCMechanism = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_KEY_TYPE  ECCKeyType = CKK_SM2;
	CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY,priclass=CKO_PRIVATE_KEY;
	CK_ATTRIBUTE publicKeyTemplate[] = {
		{CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)},
		{CKA_WRAP, &ttrue, sizeof(CK_BBOOL)},
		{CKA_KEY_TYPE,&ECCKeyType,sizeof(CK_KEY_TYPE)},
        {CKA_ISEXCHANGEKEY, &ttrue, sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE, &ttrue, sizeof(CK_BBOOL)},
        {CKA_ENCRYPT,&ttrue, sizeof(CK_BBOOL)}
       // {CKA_ID, idid, sizeof(idid)}
	};
	CK_ATTRIBUTE privateKeyTemplate[] = {
		{CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)},
		{CKA_PRIVATE, &ttrue, sizeof(CK_BBOOL)},
		{CKA_SENSITIVE, &ttrue, sizeof(CK_BBOOL)},
		{CKA_UNWRAP, &ttrue, sizeof(CK_BBOOL)},
		{CKA_KEY_TYPE,&ECCKeyType,sizeof(CK_KEY_TYPE)},
        {CKA_ISEXCHANGEKEY, &ttrue, sizeof(CK_BBOOL)},
        {CKA_DECRYPT, &ttrue, sizeof(CK_BBOOL)}
     //   {CKA_ID, idid, sizeof(idid)}
	};
	CK_OBJECT_HANDLE hPublicKey = NULL_PTR, hPrivateKey = NULL_PTR, hSessKey = NULL_PTR, hLocalSessKey_find = NULL_PTR;
	CK_OBJECT_HANDLE * phSessKey = &hSessKey;
	CK_OBJECT_HANDLE * phPublicKey = &hPublicKey, *phPrivateKey = &hPrivateKey;

	//for get exchange public key
	CK_BYTE			pSM2PublicKey[64] = {0};
	CK_ULONG			nSM2PublicKeyLen = sizeof(pSM2PublicKey);

	//for C_WrapKey
	CK_MECHANISM	SM2WrapMechanism = {CKM_WRAP_SESSKEY, pSM2PublicKey, nSM2PublicKeyLen};
	CK_BYTE			pbWrappedKey[128] = {0};
	CK_ULONG		ulWrappedKeyLen = sizeof(pbWrappedKey);
	CK_BYTE			getIV[16] = {0};
	CK_ULONG		ulgetIVLen = sizeof(getIV);

	//for C_UnwrapKey
	CK_MECHANISM	SM2UnwrapMechanism = {CKM_UNWRAP_SESSKEY, NULL, 0};
	CK_ATTRIBUTE SessKeyExchangeTemplate2[] =
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &SessKeyExchangeKeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_SESSKEY_ID, &keyID2, sizeof(CK_BYTE)}
	};

	//for C_DeriveKey
	CK_MECHANISM	DeriveKeyMechanism = {CKM_SESSKEY_DERIVE, NULL, 0};

	CK_ATTRIBUTE SessKeyDeriveTemplate[] =
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &SessKeyExchangeKeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
        {CKA_EXTRACTABLE, &ttrue, sizeof(CK_BBOOL)},
		{CKA_SESSKEY_ID, &keyID3, sizeof(CK_BYTE)}
	};

	//for get exchange part key 1
	CK_BYTE			pMonitorSM2PublicKey[64] ={0xec,0x91,0x81,0x8d,0xe0,0xb7,0x01,0x21,0x73,0xf5,0x1c,0x33,0x75,0x43,0x6e,0x43,
			0xb6,0xa9,0xa2,0x6a,0xbd,0x6d,0xbc,0xb7,0x9f,0x85,0x1c,0xde,0xaf,0x7a,0x0f,0x6c,
			0xcb,0xf4,0xb5,0xa1,0x5f,0xb8,0x7e,0x60,0xfc,0x0b,0x3a,0x92,0x3d,0x12,0xe8,0x66,
			0x36,0x4a,0x93,0x5f,0xfb,0x30,0x84,0x2b,0xc9,0x13,0x9e,0xbd,0x2d,0xdc,0xe9,0x61};

	//for get exchange part key 1
	CK_BYTE			pExchangeSessKey1[128] = {0};
	CK_UINT			nExchangeSessKey1Len = sizeof(pExchangeSessKey1);

	hPartKey1 = NULL_PTR;
	hPartKey2 = NULL_PTR;
	hSessKey = NULL_PTR;

    string info;
    char n[1024*1024]={0};

    //1.generate or find keypair used in keyexchange, then get the value of public key
    int keypairnum = findexchangekeypair(&hPublicKey, &hPrivateKey);
    if(keypairnum == 0)
    {
        TimeStart();
        rv = C_GenerateKeyPair(hSession, &ECCMechanism,publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
                               privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE), &hPublicKey, &hPrivateKey);
        info.clear();
        info.append("hpubkey: ");
        sprintf(n,"0x%08x",hPublicKey);
        info.append(n);
        info.append("hprikey: ");
        sprintf(n,"0x%08x",hPrivateKey);
        info.append(n);
        Save("C_GenerateKeyPair",rv,info,TimeEnd());

        if(rv != 0)
            return 0;
    }

    if(keypairnum>1)
    {
        TimeStart();
        info.clear();
        info.append("More than 1 pair of exchange key!");
        Save("findexchangekeypair",rv,info,TimeEnd());
        return 0;
    }

    CK_ATTRIBUTE SM2GetPubKeyTemplate[] = {
           {CKA_VALUE, pSM2PublicKey, nSM2PublicKeyLen}
    };

    TimeStart();
 //   rv = C_GetAttributeValue(hSession, hPublicKey, SM2GetPubKeyTemplate, sizeof(SM2GetPubKeyTemplate)/sizeof(CK_ATTRIBUTE));
    rv = C_Extend_Get_ExchangePubKey(hSession, pSM2PublicKey,&nSM2PublicKeyLen);
    info.clear();
    info.append("pubvalue: 0x");
    for(int i=0;i<nSM2PublicKeyLen;i++)
    {
        sprintf(n,"%02x",*((CK_BYTE_PTR)(SM2GetPubKeyTemplate[0].pValue)+i));
        info.append(n);
    }
    Save("C_GetAttributeValue pub",rv,info,TimeEnd());
    if(rv != 0)
        return 0;

    //2.generate sesskey1
	CK_ULONG ulObjectCount14 = 0;
    TimeStart();
    rv = C_GenerateKey(hSession, &SessKeyExchangeMechanism, SessKeyExchangeTemplate1, sizeof(SessKeyExchangeTemplate1)/sizeof(CK_ATTRIBUTE), &hPartKey1);
    Save("C_GenerateKey",rv,"",TimeEnd());
    if(rv != 0)
        return 0;
    //3. wrapout sesskey1
    memset(pbWrappedKey,0,ulWrappedKeyLen);
    TimeStart();
	rv = C_WrapKey(hSession, &SM2WrapMechanism, 0, hPartKey1, pbWrappedKey, &ulWrappedKeyLen);
    info.clear();
    info.append(" ulWrappedKeyLen:");
    sprintf(n,"%d",ulWrappedKeyLen);
    info.append(n);
    info.append("pbWrappedKey: 0x");
    for(int i=0;i<ulWrappedKeyLen;i++)
    {
        sprintf(n,"%02x",pbWrappedKey[i]);
        info.append(n);
    }
    Save("C_WrapKey",rv,info,TimeEnd());
    if(rv != 0)
        return 0;
	//4.unwrap remote sesskey
    TimeStart();
	rv = C_UnwrapKey(hSession, &SM2UnwrapMechanism, hPrivateKey, pbWrappedKey, ulWrappedKeyLen, SessKeyExchangeTemplate2, sizeof(SessKeyExchangeTemplate2)/sizeof(CK_ATTRIBUTE), &hPartKey2);
    Save("C_UnwrapKey",rv,"",TimeEnd());
    if(rv != 0)
        return 0;
    //5.derive sesskey
    TimeStart();
	rv = C_Extend_DeriveSessionKey(hSession, &DeriveKeyMechanism, hPartKey1, hPartKey2, SessKeyDeriveTemplate, sizeof(SessKeyDeriveTemplate)/sizeof(CK_ATTRIBUTE), &hSessKey, getIV, &ulgetIVLen);
    info.clear();
    info.append("sesskeyiv: 0x");
    for(int i=0;i<ulgetIVLen;i++)
    {
        sprintf(n,"%02x",getIV[i]);
        info.append(n);
    }
    //should be all 0
    Save("C_Extend_DeriveSessionKey",rv,info,TimeEnd());
    if(rv != 0)
        return 0;
    //get the sesskey handle
    CK_OBJECT_HANDLE hObject[16] = {0};
    CK_ULONG ulfindObjectCount = 16;

    TimeStart();
    rv = C_FindObjectsInit(hSession, SessKeyDeriveTemplate, sizeof(SessKeyDeriveTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit",rv,"",TimeEnd());
    if(rv != 0)
        return 0;
    TimeStart();
    rv = C_FindObjects(hSession, hObject, 16, &ulfindObjectCount);
    info.clear();
    if(ulfindObjectCount!=1)
    {
        info.append("Seeskey Handle NO.Error!");
    }
    sprintf(n,"%ld",ulfindObjectCount);
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulfindObjectCount;i++)
    {
        sprintf(n,",0x%08x ",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects",rv,info,TimeEnd());
    if(rv != 0)
        return 0;
    TimeStart();
    rv = C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal",rv,"",TimeEnd());
    if(rv != 0)
        return 0;

    hSessKey = hObject[0];
    //TT get sesskey
/*    CK_BYTE encryptedSesskey[128] = {0};
    CK_ULONG ulencryptedSesskey = sizeof(encryptedSesskey);
    TimeStart();
    rv = C_Extend_GetExchangeSessionKey(hSession, hSessKey, encryptedSesskey,&ulencryptedSesskey);
    Save("C_Extend_GetExchangeSessionKey",rv,"",TimeEnd());
    if(rv != 0)
        return 0;
)*/
	test_Encrypt_Sesskey(hSessKey);


END:
	if(hPartKey1)
	{
        TimeStart();
		rv = C_DestroyObject(hSession, hPartKey1);
        Save("C_DestroyObject1",rv,"",TimeEnd());
		hPublicKey = NULL_PTR;
	}
	if(hPartKey2)
	{
        TimeStart();
		rv = C_DestroyObject(hSession, hPartKey2);
        Save("C_DestroyObject2",rv,"",TimeEnd());
		hPublicKey = NULL_PTR;
	}

    return hSessKey;
}

CK_ULONG TT()
{
    CK_BYTE     pub_key[64]={
            0xec,0x91,0x81,0x8d,0xe0,0xb7,0x01,0x21,0x73,0xf5,0x1c,0x33,0x75,0x43,0x6e,0x43,
            0xb6,0xa9,0xa2,0x6a,0xbd,0x6d,0xbc,0xb7,0x9f,0x85,0x1c,0xde,0xaf,0x7a,0x0f,0x6c,
            0xcb,0xf4,0xb5,0xa1,0x5f,0xb8,0x7e,0x60,0xfc,0x0b,0x3a,0x92,0x3d,0x12,0xe8,0x66,
            0x36,0x4a,0x93,0x5f,0xfb,0x30,0x84,0x2b,0xc9,0x13,0x9e,0xbd,0x2d,0xdc,0xe9,0x61
    };

    CK_BYTE     pri_key[32]={
            0xc5,0x6a,0x2b,0x58,0xa0,0x94,0xef,0x24,0x41,0x03,0x79,0x45,0xba,0xb1,0x39,0x8c,
            0xc0,0xdf,0x9f,0xc4,0xf9,0x9e,0x9a,0x60,0x2c,0xd8,0x6f,0xc2,0xc3,0x88,0xad,0x0c
    };

    string info;
    char n[1024 * 1024] = {0};
    CK_RV rv=0;
    CK_BYTE EncryptedData[128] = {0};
    CK_ULONG ulEncryptedDataLen = sizeof(EncryptedData);
    CK_BYTE plainsesskey[32] = {0};
    int plainlen = sizeof(plainsesskey);

    CK_OBJECT_HANDLE hsesskey = xtest_KeyExchange();

    TimeStart();
    rv = C_Extend_GetExchangeSessionKey(hSession, hsesskey, EncryptedData, &ulEncryptedDataLen);
    info.clear();
    if (SM2Init() != SM2_OK)
    {
        info.append("SM2Init fail");
    }
    Save("C_Extend_GetExchangeSessionKey",rv,info,TimeEnd());
    /*if(rv != 0)
        return 0;*/

    return 0;
}

CK_RV Get_Update_Data_Version(CK_OBJECT_CLASS DataType, unsigned char * pVersion_Update)
{
    CK_RV rv = 0;
    string info;
    char n[1024 * 1024] = {0};

    unsigned char pbBuffer[4] = {0};
    CK_ULONG ulen = sizeof(pbBuffer);

    info.clear();
    TimeStart();
    rv = C_Extend_Get_Special_Object_Version(hSession, DataType, pbBuffer, &ulen);
    if(rv == CKR_OK)
    {
        info.append("current version; 0x");
        for(int i=0;i<ulen;i++)
        {
            sprintf(n,"%02x",pbBuffer[i]);
            info.append(n);
        }
        Save("C_Extend_Get_Special_Object_Version",rv,info,TimeEnd());

        memcpy(pVersion_Update, pbBuffer, 3);
        pVersion_Update[3] = pbBuffer[3] + 1;
        return rv;
    } else{
        info.append("Get_Update_Data_Version error");
        Save("C_Extend_Get_Special_Object_Version",rv,info,TimeEnd());
        return rv;
    }

}

#define KEY_LEN 16
#define PIN_LEN_MAX 24
#define PIN_LEN_MIN 6
#define T_LEN  80
#define IV_LEN  16
#define REMOTE_DATA_VERSION_LEN 4
#define TT_R_LEN 32
#define PUB_KEY_LEN 64
#define PRI_KEY_LEN 32
#define TT_WRAPPED_LEN TT_R_LEN+96
#define REMOTE_VERSION_LEN 4
#define REMOTE_IV_LEN 16
#define SM3_DATA_LEN 32
#define SWAP8(x)	((x)&0xFF)
#define SWAP16(x)	((SWAP8(x)<<8)|SWAP8((x)>>8))

#define CRC_INIT 0xffff   //CCITT初始CRC为全1
//#define GOOD_CRC 0xf0b8   //校验时计算出的固定结果值
/****下表是常用ccitt 16,生成式1021反转成8408后的查询表格****/
unsigned short crc16_ccitt_table[256] =
{
        0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
        0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
        0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
        0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
        0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
        0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
        0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
        0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
        0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
        0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
        0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
        0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
        0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
        0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
        0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
        0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
        0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
        0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
        0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
        0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
        0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
        0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
        0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
        0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
        0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
        0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
        0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
        0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
        0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
        0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
        0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
        0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

unsigned short do_crc(unsigned short reg_init, unsigned char *message, unsigned int len)
{
    unsigned short crc_reg = reg_init;

    while (len--)
        crc_reg = (crc_reg >> 8) ^ crc16_ccitt_table[(crc_reg ^ *message++) & 0xff];

    return crc_reg^0xFFFF;
}


CK_ULONG Generate_T(unsigned char *remoteSetData, unsigned short remoteSetDataLen, unsigned char *remoteSetIv, unsigned char *remoteSoPin,
                  unsigned short remoteSoPinLen, unsigned char *remoteSetDataVersion, unsigned char *remoteGeneratedT,unsigned short* remoteGeneratedTLen)
{
    int rv = 0;
    unsigned short remoteSetDataLenBigEndian = 0;
    unsigned int modTemp = 0;

    unsigned char* SM3InData = 0;
    unsigned char* SM3OutData = 0 ;
    unsigned int SM3InDatalen = 0;
    unsigned int SM3OutDatalen = 0;

    unsigned char* SM4InData = 0;
    unsigned char* SM4OutData = 0;
    unsigned int SM4InDatalen = 0;
    unsigned int SM4OutDatalen = 0;
    unsigned int SM4AddDataLen = 0;

    unsigned char* CRCInData = 0;
    unsigned int CRCInDatalen = 0;
    unsigned short CRCResult = 0;
    unsigned short CRCResultBigEndian = 0;

    if((remoteSetData == NULL)||(remoteSetIv == NULL)||(remoteSoPin == NULL)||(remoteSetDataVersion == NULL)||(remoteGeneratedT == NULL))
    {
 //       printf("Generate_T Error:Some Input == NULL\n");
        return 1;
    }

    if(remoteSetDataLen == 0)
    {
 //       printf("Generate_T Error:remoteSetDataLen length is 0.\n");
        return 1;
    }

    if((remoteSoPinLen > PIN_LEN_MAX) || (remoteSoPinLen < PIN_LEN_MIN))
    {
//      printf("Generate_T Error:So pin length %d range.\n",remoteSoPinLen);
        return 1;
    }

    SM3InDatalen = REMOTE_IV_LEN + remoteSoPinLen;
    SM3OutDatalen = SM3_DATA_LEN;
    SM3InData  = (unsigned char*)malloc(sizeof(unsigned char) * SM3InDatalen);
    SM3OutData = (unsigned char*)malloc(sizeof(unsigned char) * SM3OutDatalen);
    memcpy(SM3InData, remoteSoPin, remoteSoPinLen);
    memcpy(SM3InData + remoteSoPinLen, remoteSetIv, REMOTE_IV_LEN);

    SM3_Data(SM3InData, SM3InDatalen, SM3OutData, SM3OutDatalen);
//	UtilsPrintData(VNAME(SM3OutData),SM3OutDatalen,0);

    remoteSetDataLenBigEndian = SWAP16(remoteSetDataLen);
    CRCInDatalen = REMOTE_VERSION_LEN + sizeof(remoteSetDataLenBigEndian) + remoteSetDataLen;
    CRCInData = (unsigned char*)malloc(sizeof(unsigned char) * CRCInDatalen);
    memcpy(CRCInData, remoteSetDataVersion, REMOTE_VERSION_LEN);
    memcpy(CRCInData + REMOTE_VERSION_LEN, &remoteSetDataLenBigEndian, sizeof(remoteSetDataLenBigEndian));
    memcpy(CRCInData + REMOTE_VERSION_LEN + sizeof(remoteSetDataLenBigEndian), remoteSetData, remoteSetDataLen);
//	UtilsPrintData(VNAME(CRCInData),CRCInDatalen,0);

    CRCResult = do_crc(CRC_INIT,CRCInData,CRCInDatalen);
//	printf("\n******CRCResult****************:\n");
//	printf("CRCResult = 0x%x\n",CRCResult);
    CRCResultBigEndian = SWAP16(CRCResult);

    modTemp = REMOTE_VERSION_LEN + sizeof(remoteSetDataLenBigEndian) + sizeof(CRCResultBigEndian) - remoteSetDataLen;
    SM4AddDataLen = modTemp%16;
    SM4InDatalen = REMOTE_VERSION_LEN + sizeof(remoteSetDataLenBigEndian) + remoteSetDataLen + sizeof(CRCResultBigEndian) + SM4AddDataLen;
    SM4OutDatalen = SM4InDatalen;
    SM4InData  = (unsigned char*)malloc(sizeof(unsigned char) * SM4InDatalen);
    SM4OutData = (unsigned char*)malloc(sizeof(unsigned char) * SM4OutDatalen);
    memcpy(SM4InData, remoteSetDataVersion, REMOTE_VERSION_LEN);
    memcpy(SM4InData + REMOTE_VERSION_LEN, &remoteSetDataLenBigEndian, sizeof(remoteSetDataLenBigEndian));
    memcpy(SM4InData + REMOTE_VERSION_LEN + sizeof(remoteSetDataLenBigEndian), remoteSetData, remoteSetDataLen);
    memcpy(SM4InData + REMOTE_VERSION_LEN + sizeof(remoteSetDataLenBigEndian) + remoteSetDataLen, &CRCResultBigEndian, sizeof(CRCResultBigEndian));
    memset(SM4InData + REMOTE_VERSION_LEN + sizeof(remoteSetDataLenBigEndian) + remoteSetDataLen + sizeof(CRCResultBigEndian), 0xFF, SM4AddDataLen);
//	UtilsPrintData(VNAME(SM4InData),SM4InDatalen,0);

    rv = SEA_Encrypt(SM3OutData, KEY_LEN, remoteSetIv, REMOTE_IV_LEN, SM4InData, SM4InDatalen, SM4OutData, &SM4OutDatalen);
//	UtilsPrintData(VNAME(SM4OutData),SM4OutDatalen,0);

    if(rv != 0)
    {
//      printf("Generate_T Error:SEA_Encrypt,rv=%d\n",rv);
        return Rv_False_Free_Memory(FALSE,FREE_5, &SM3InData, &SM3OutData, &CRCInData, &SM4InData, &SM4OutData);
    }

    if(*remoteGeneratedTLen != SM4OutDatalen)
    {
        printf("Generate_T Error:remoteGeneratedTLen(%d) length not match SM4OutDatalen(%d).\n" ,*remoteGeneratedTLen,(int)SM4OutDatalen);
        return Rv_False_Free_Memory(FALSE,FREE_5, &SM3InData, &SM3OutData, &CRCInData, &SM4InData, &SM4OutData);
    }

    memcpy(remoteGeneratedT, SM4OutData,SM4OutDatalen);
//    printf("*remoteGeneratedTLen = %d\n", *remoteGeneratedTLen);
//	printbuf(remoteGeneratedT, *remoteGeneratedTLen);
//	UtilsPrintData(VNAME(remoteGeneratedT),*remoteGeneratedTLen,0);
//    printf("Generate_T ok!\n");
    return Free_Memory(FREE_5, &SM3InData, &SM3OutData, &CRCInData, &SM4InData, &SM4OutData);
}



CK_ULONG Remote_Set_Data(unsigned char *remoteGeneratedT, CK_ULONG remoteGeneratedTLen, unsigned char *remoteSetIv, unsigned int remoteDataType)
{
    CK_ULONG bRtn = 0;
    unsigned int remoteSetType = remoteDataType;
    CK_RV rv = 0;
    unsigned char* pbBuffer_T = NULL_PTR;

    if((remoteGeneratedT == NULL)||(remoteSetIv == NULL))
    {
//        printf("Remote_Set_Data Error:Some Input == NULL\n");
        return 1;
    }

    if(remoteGeneratedTLen == 0)
    {
//        printf("Remote_Set_Data Error:remoteSetDataLen length is 0.\n");
        return 1;
    }

    if(remoteDataType == CKO_REMOTE_TT)
    {
        TimeStart();
        rv = C_Extend_Reset_TT(hSession,remoteGeneratedT,remoteGeneratedTLen,remoteSetIv,IV_LEN);
        Save("C_Extend_Reset_TT",rv,"",TimeEnd());
    }
    else if(remoteDataType == CKO_REMOTE_SECRET_KEY)
    {
        TimeStart();
        rv = C_Extend_Reset_BK(hSession,remoteGeneratedT,remoteGeneratedTLen,remoteSetIv,IV_LEN);
        Save("C_Extend_Reset_BK",rv,"",TimeEnd());
    }
    else if(remoteDataType == CKO_REMOTE_OTP)
    {
        TimeStart();
        rv = C_Extend_Reset_OTP(hSession,remoteGeneratedT,remoteGeneratedTLen,remoteSetIv,IV_LEN);
        Save("C_Extend_Reset_OTP",rv,"",TimeEnd());
    }
    else if(remoteDataType == CKO_REMOTE_DESTORY_RND)
    {
        TimeStart();
        rv = C_Extend_Set_DestroyKey(hSession,remoteGeneratedT,remoteGeneratedTLen,remoteSetIv,IV_LEN);
        Save("C_Extend_Set_DestroyKey",rv,"",TimeEnd());
    }

    return rv;
}

CK_ULONG Generate_R_for_TT(unsigned char *RA_TT,unsigned char *RB_TT,unsigned char *R_TT,int length_TT)
{
    int i = 0;

    if((RA_TT == NULL)||(RB_TT == NULL)||(R_TT == NULL))
    {
 //       printf("Error:Some Input == NULL\n");
        return 1;
    }

    if(length_TT!= TT_R_LEN)
    {
 //       printf("Error:length_TT(%d) != TT_R_LEN\n",length_TT);
        return 1;
    }

    for(i = 0;i < TT_R_LEN; ++i)
    {
        R_TT[i] = RA_TT[i] ^ RB_TT[i];
    }

    return 0;
}


CK_ULONG Result_Compare(BYTE* outdata, int outdatalen, BYTE* srcdata, int srcdatalen)
{
    if((outdata == NULL_PTR)||(outdatalen == 0)||(srcdata == NULL_PTR)||(srcdatalen == 0))
    {
//        printf("Error:Some Input == NULL\n");
        return 1;
    }

    if(outdatalen != srcdatalen)
    {
 //       printf("Error: Datalen not Match.\n");
//		*storage_address += sprintf(storage_start + *storage_address, "Error: Datalen not Match.<br>");
        return 2;
    }

    if(memcmp(outdata, srcdata, outdatalen))
    {
//        printf("Error: Data not Match.\n");
//		*storage_address += sprintf(storage_start + *storage_address, "Error: Data not Match.<br>");
        return 3;
    }

    return 0;
}

CK_ULONG setcokek()
{
    CK_RV rv = 0;
    string info;
    char n[1024*1024]={0};


    CK_OBJECT_HANDLE_PTR hObject = NULL_PTR;
    CK_ULONG ulObjectCount = 0;
    CK_OBJECT_HANDLE hCokdk = NULL_PTR;

    hObject = NULL_PTR;
    hObject = (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16);
    ulObjectCount = 16;

    CK_KEY_TYPE cokdkType = CKK_SM4;
    CK_BBOOL ttrue = CK_TRUE;
    CK_BBOOL ffalse = CK_FALSE;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;

    CK_ATTRIBUTE cokdkTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(CK_OBJECT_CLASS)},
        {CKA_KEY_TYPE,&cokdkType,sizeof(CK_KEY_TYPE)},
        {CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)},
        //{CKA_TOKEN, &ffalse, sizeof(CK_BBOOL)},
        {CKA_PRIVATE, &ttrue, sizeof(CK_BBOOL)},
        {CKA_SENSITIVE, &ttrue, sizeof(CK_BBOOL)},
        {CKA_MODIFIABLE, &ffalse, sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE, &ffalse, sizeof(CK_BBOOL)},
        {CKA_ENCRYPT, &ffalse, sizeof(CK_BBOOL)},
        {CKA_DECRYPT, &ffalse, sizeof(CK_BBOOL)},
        {CKA_WRAP, &ffalse, sizeof(CK_BBOOL)},
        {CKA_UNWRAP, &ffalse, sizeof(CK_BBOOL)},
        {CKA_ID, (CK_CHAR_PTR)"cokdk_wst_cloud", strlen("cokdk_wst_cloud")},
    };

    CK_MECHANISM  TestGenECCMechanism = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_OBJECT_CLASS pubclass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS priclass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ECCKeyType = CKK_SM2;
    CK_ATTRIBUTE testPublicKeyTemplate[] = {
            {CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_TOKEN, &ffalse, sizeof(CK_BBOOL)},
            {CKA_WRAP, &ttrue, sizeof(CK_BBOOL)},
            {CKA_KEY_TYPE,&ECCKeyType,sizeof(CK_KEY_TYPE)},
            {CKA_EXTRACTABLE,&ttrue, sizeof(CK_BBOOL)},
            {CKA_ENCRYPT, &ttrue, sizeof(CK_BBOOL)}
    };

    CK_ATTRIBUTE testPrivateKeyTemplate[] = {
            {CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_TOKEN, &ffalse, sizeof(CK_BBOOL)},
            {CKA_PRIVATE, &ttrue, sizeof(CK_BBOOL)},
            {CKA_SENSITIVE, &ttrue, sizeof(CK_BBOOL)},
            {CKA_UNWRAP, &ttrue, sizeof(CK_BBOOL)},
            {CKA_KEY_TYPE,&ECCKeyType,sizeof(CK_KEY_TYPE)},
            {CKA_DECRYPT, &ttrue, sizeof(CK_BBOOL)}
    };

    CK_OBJECT_HANDLE hPublicKey = NULL_PTR;
    CK_OBJECT_HANDLE hPrivateKey = NULL_PTR;
    CK_BYTE keyvalue[64] = {0};

    CK_ATTRIBUTE get_value[] = {
            {CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_VALUE, keyvalue, sizeof(keyvalue)}
    };

    CK_MECHANISM  testmechanismcalc = {CKM_SM2, NULL_PTR, 0};
    CK_MECHANISM  unwrap_key_mechanism = {CKM_SM2, NULL_PTR, 0};

    CK_BYTE_PTR cokdk = pSOPin;
    CK_UINT nCokdkLen = sizeof(pSOPin);

    CK_BYTE pTestCiphertext[16+96] = {0};
    CK_UINT nTestCiphertextLen = sizeof(pTestCiphertext);

    CK_BYTE pTestOutData[16+96] = {0};
    CK_ULONG nTestOutDataLen = sizeof(pTestOutData);

    TimeStart();
    rv = C_FindObjectsInit(hSession, cokdkTemplate, sizeof(cokdkTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit",rv,"",TimeEnd());
    if (rv != CKR_OK)
    {
        free(hObject);
        hObject = NULL;
        return rv;
    }


    info.clear();
    TimeStart();
    rv = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
    info.append("ulObjectCount: ");
    sprintf(n,"%d",ulObjectCount);
    info.append(n);
    Save("C_FindObjects",rv,info,TimeEnd());
    if (rv != CKR_OK)
    {
        return rv;
    }

    if(ulObjectCount != 0)
    {
        hCokdk = *((CK_OBJECT_HANDLE_PTR)&hObject[0]);
    }

    info.clear();
    TimeStart();
    rv = C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal",rv,"",TimeEnd());
    if (rv != CKR_OK)
    {
        return rv;
    }
    free(hObject);


    if(ulObjectCount == 0)
    {
        /* generator sm2 keypair */
        info.clear();
        TimeStart();
        rv = C_GenerateKeyPair(hSession, &TestGenECCMechanism,
            testPublicKeyTemplate, sizeof(testPublicKeyTemplate)/sizeof(CK_ATTRIBUTE),
            testPrivateKeyTemplate, sizeof(testPrivateKeyTemplate)/sizeof(CK_ATTRIBUTE),
            &hPublicKey, &hPrivateKey);
        Save("C_GenerateKeyPair",rv,"",TimeEnd());
        if (rv != CKR_OK)
        {
            return rv;
        }

        /* get public key */
        info.clear();
        TimeStart();
        rv = C_GetAttributeValue(hSession, hPublicKey, get_value, sizeof(get_value)/sizeof(CK_ATTRIBUTE));
        Save("C_GetAttributeValue",rv,"",TimeEnd());
        if (rv != CKR_OK)
        {
            return rv;
        }


        /* encrypt cokdk(sm4 key) */
        info.clear();
        TimeStart();
        rv = C_EncryptInit(hSession, &testmechanismcalc, hPublicKey);
        Save("C_EncryptInit",rv,"",TimeEnd());
        if (rv != CKR_OK)
        {
            return rv;
        }

        info.clear();
        TimeStart();
        rv = C_Encrypt(hSession, cokdk, nCokdkLen, NULL_PTR, &nTestOutDataLen);
        Save("C_Encrypt",rv,"",TimeEnd());
        if (rv != CKR_OK)
        {
            return rv;
        }

        memset(pTestOutData, 0x00, nTestOutDataLen);

        info.clear();
        TimeStart();
        rv = C_Encrypt(hSession, cokdk, nCokdkLen, pTestOutData, &nTestOutDataLen);
        Save("C_Encrypt",rv,"",TimeEnd());
        if (rv != CKR_OK)
        {
            return rv;
        }

        memcpy(pTestCiphertext, pTestOutData, nTestOutDataLen);
        nTestCiphertextLen = nTestOutDataLen;

        /* unwarp cokdk */
        info.clear();
        TimeStart();
        rv = C_UnwrapKey( hSession, &unwrap_key_mechanism, hPrivateKey, &pTestCiphertext[0], nTestCiphertextLen,
            cokdkTemplate, sizeof(cokdkTemplate)/sizeof(CK_ATTRIBUTE), &hCokdk);
        Save("C_UnwrapKey",rv,"",TimeEnd());
        if (rv != CKR_OK)
        {
            return rv;
        }
    }

    return rv;
}

CK_ULONG BKupdate()
{
    CK_RV rv = 0;
    CK_RV bRtn = 0;

    int ulSOPINLen_T = sizeof(pSOPin);
    unsigned int modTemp = 0;

    BYTE Version_MPK[REMOTE_DATA_VERSION_LEN] = {0x00};
    BYTE IV_mpk[IV_LEN] = { 0 };
    BYTE* T_mpk= NULL;
    unsigned short T_mpkLen = 0;
    CK_BYTE newBK[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};

    string info;
    char n[1024*1024]={0};

    info.clear();
    TimeStart();
    rv = 0;
    RandomGenerate(IV_mpk, IV_LEN);
    modTemp = 8 - sizeof(newBK);
    T_mpkLen = 8 + sizeof(newBK) + modTemp%16;
    T_mpk = (BYTE*)malloc(sizeof(BYTE) * T_mpkLen);

    bRtn =Get_Update_Data_Version(CKO_REMOTE_SECRET_KEY, Version_MPK);

    TimeStart();
    bRtn = Generate_T(newBK, sizeof(newBK), IV_mpk, pSOPin, ulSOPINLen_T, Version_MPK, T_mpk, &T_mpkLen);
    if(bRtn!=0)
    {
        rv = 1;
        info.append("Generate_T Error!!");
    }
    else
    {
        info.append("mpklen: ");
        sprintf(n,"%d",T_mpkLen);
        info.append(n);
    }
    Save("soft_genBKMPK",rv,info,TimeEnd());

    if(rv != CKR_OK){
        free(T_mpk);
        T_mpk = NULL;
        return rv;
    }


    // Set Monitor PubKey Remote
    bRtn = Remote_Set_Data(T_mpk, T_mpkLen, IV_mpk,CKO_REMOTE_SECRET_KEY);
    if(bRtn!=0)
        return bRtn;

    //Get Monitor PubKey Version
    bRtn =Get_Update_Data_Version(CKO_REMOTE_SECRET_KEY, Version_MPK);
    if(bRtn!=0)
        return bRtn;

    //find BK
    CK_SESSION_HANDLE session = hSession;

    CK_KEY_TYPE  BKKeyType = CKK_SM4;
    CK_OBJECT_CLASS BKclass=CKO_SECRET_KEY;
    CK_BBOOL ttrue = CK_TRUE;
    CK_BBOOL ffalse = CK_FALSE;
    CK_BYTE BKkeyID = CK_SESSKEY_PRESET_ID7;
    CK_OBJECT_HANDLE hObjectfind[16] = {0};
    CK_ULONG ulObjectCount = 0;

    CK_ATTRIBUTE BKTemplate[] = {
            {CKA_CLASS, &BKclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_KEY_TYPE,&BKKeyType,sizeof(CK_KEY_TYPE)},
            {CKA_SESSKEY_ID,&BKkeyID,sizeof(CK_BYTE)}
    };
    TimeStart();
    rv = C_FindObjectsInit(session, BKTemplate, sizeof(BKTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit",rv,"",TimeEnd());

    TimeStart();
    info.clear();
    rv = C_FindObjects(session, hObjectfind, 16, &ulObjectCount);
    if(ulObjectCount != 1)
    {
        info.append("BK No.Error!");
        sprintf(n,"%d",ulObjectCount);
        info.append(n);
    }
    else
    {
        info.append("BK handle: ");
        sprintf(n,"0x%08x",hObjectfind[0]);
        info.append(n);
    }
    Save("C_FindObjects(bk)",rv,info,TimeEnd());

    TimeStart();
    rv = C_FindObjectsFinal(session);
    Save("C_FindObjectsFinal",rv,"",TimeEnd());

    //try to enc by BK
    CK_BYTE iv[16] = {0};
    iv[0] = 1;
    iv[1] = 2;
    CK_MECHANISM SM4mechanism = {CKM_SM4_CBC, iv, sizeof(iv)};

    CK_BYTE indata[]={0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    CK_BYTE outdata[32] = {0};
    CK_ULONG outdatalen=sizeof(outdata);
    CK_BYTE outdata1[32] = {0};
    CK_ULONG outdatalen1=sizeof(outdata);

    TimeStart();
    rv = C_EncryptInit(session, &SM4mechanism, hObjectfind[0]);
    Save("C_EncryptInit",rv,"",TimeEnd());

    TimeStart();
    rv = C_EncryptUpdate(session, indata, sizeof(indata), outdata, &outdatalen);
    Save("C_EncryptUpdate",rv,"",TimeEnd());

    TimeStart();
    rv = C_EncryptFinal(session, outdata1, &outdatalen1);
    Save("C_EncryptFinal",rv,"",TimeEnd());

    return 0;
}


CK_ULONG OTPupdate()
{
    CK_RV rv = 0;
    CK_RV bRtn = 0;

    int ulSOPINLen_T = sizeof(pSOPin);
    unsigned int modTemp = 0;

    BYTE Version_MPK[REMOTE_DATA_VERSION_LEN] = {0x00};
    BYTE IV_mpk[IV_LEN] = { 0 };
    BYTE* T_mpk= NULL;
    unsigned short T_mpkLen = 0;
    CK_BYTE newOTPPIN[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    string info;
    char n[1024*1024]={0};

    info.clear();
    TimeStart();
    rv = 0;
    RandomGenerate(IV_mpk, IV_LEN);
    modTemp = 8 - sizeof(newOTPPIN);
    T_mpkLen = 8 + sizeof(newOTPPIN) + modTemp%16;
    T_mpk = (BYTE*)malloc(sizeof(BYTE) * T_mpkLen);

    bRtn =Get_Update_Data_Version(CKO_REMOTE_OTP, Version_MPK);

    TimeStart();
    bRtn = Generate_T(newOTPPIN, sizeof(newOTPPIN), IV_mpk, pSOPin, ulSOPINLen_T, Version_MPK, T_mpk, &T_mpkLen);
    if(bRtn!=0)
    {
        rv = 1;
        info.append("Generate_T Error!!");
    }
    else
    {
        info.append("mpklen: ");
        sprintf(n,"%d",T_mpkLen);
        info.append(n);
    }
    Save("soft_genTTMPK",rv,info,TimeEnd());

    if(rv != CKR_OK){
        free(T_mpk);
        T_mpk = NULL;
        return rv;
    }


    bRtn = Remote_Set_Data(T_mpk, T_mpkLen, IV_mpk,CKO_REMOTE_OTP);
    if(bRtn!=0)
        return bRtn;

    bRtn =Get_Update_Data_Version(CKO_REMOTE_OTP, Version_MPK);
    if(bRtn!=0)
        return bRtn;

    return 0;
}

CK_ULONG setDestroyRND()
{
    CK_RV rv = 0;
    CK_RV bRtn = 0;

    int ulSOPINLen_T = sizeof(pSOPin);
    unsigned int modTemp = 0;

    BYTE Version_MPK[REMOTE_DATA_VERSION_LEN] = {0x00};
    BYTE IV_mpk[IV_LEN] = { 0 };
    BYTE* T_mpk= NULL;
    unsigned short T_mpkLen = 0;
    BYTE* T_mpk1= NULL;
    unsigned short T_mpkLen1 = 0;
    BYTE* T_mpk2= NULL;
    unsigned short T_mpkLen2 = 0;
    CK_BYTE newRND1[32] = {0};
 //   memset(newRND1,2,sizeof(newRND1));
    CK_BYTE newRND2[32] = {0};
//    memset(newRND2,4,sizeof(newRND2));

    newRND1[0] = 5;
    newRND2[0] = 6;

    string info;
    char n[1024*1024]={0};

    info.clear();
    TimeStart();
    rv = 0;
    RandomGenerate(IV_mpk, IV_LEN);
    modTemp = 8 - sizeof(newRND1);
    T_mpkLen1 = 8 + sizeof(newRND1) + modTemp%16;
    T_mpk1 = (BYTE*)malloc(sizeof(BYTE) * T_mpkLen1);

//    Version_MPK[0] = 1;
    TimeStart();

    bRtn = Generate_T(newRND1, sizeof(newRND1), IV_mpk, pSOPin, ulSOPINLen_T, Version_MPK, T_mpk1, &T_mpkLen1);
    if(bRtn!=0)
    {
        rv = 1;
        info.append("Generate_T Error!!");
    }
    else
    {
        info.append("mpklen1: ");
        sprintf(n,"%d",T_mpkLen1);
        info.append(n);

        info.append("\niv: 0x");
        for(int i=0;i<16;i++)
        {
            sprintf(n,"%02x",IV_mpk[i]);
            info.append(n);
        }

        info.append("\nT_mpk1: 0x");
        for(int i=0;i<T_mpkLen1;i++)
        {
            sprintf(n,"%02x",T_mpk1[i]);
            info.append(n);
        }
    }
    Save("soft_genRNDMPK1",rv,info,TimeEnd());

    if(rv != CKR_OK){
        free(T_mpk1);
        T_mpk1 = NULL;
        return rv;
    }


    info.clear();
    TimeStart();
    rv = 0;
    modTemp = 8 - sizeof(newRND2);
    T_mpkLen2 = 8 + sizeof(newRND2) + modTemp%16;
    T_mpk2 = (BYTE*)malloc(sizeof(BYTE) * T_mpkLen2);

    TimeStart();
    bRtn = Generate_T(newRND2, sizeof(newRND2), IV_mpk, pSOPin, ulSOPINLen_T, Version_MPK, T_mpk2, &T_mpkLen2);
    if(bRtn!=0)
    {
        rv = 1;
        info.append("Generate_T Error!!");
    }
    else
    {
        info.append("mpklen2: ");
        sprintf(n,"%d",T_mpkLen2);
        info.append(n);

        info.append("\niv: 0x");
        for(int i=0;i<16;i++)
        {
            sprintf(n,"%02x",IV_mpk[i]);
            info.append(n);
        }

        info.append("\nT_mpk2: 0x");
        for(int i=0;i<T_mpkLen2;i++)
        {
            sprintf(n,"%02x",T_mpk2[i]);
            info.append(n);
        }
    }
    Save("soft_genRNDMPK2",rv,info,TimeEnd());

    if(rv != CKR_OK){
        free(T_mpk2);
        T_mpk2 = NULL;
        return rv;
    }


    T_mpkLen = T_mpkLen1+ T_mpkLen2;
    T_mpk = (BYTE*)malloc(sizeof(BYTE) * T_mpkLen);
    memcpy(T_mpk,T_mpk1,T_mpkLen1);
    memcpy(T_mpk+T_mpkLen1,T_mpk2,T_mpkLen2);

    bRtn = Remote_Set_Data(T_mpk, T_mpkLen, IV_mpk,CKO_REMOTE_DESTORY_RND);
    if(bRtn!=0)
        return bRtn;

    free(T_mpk);
    free(T_mpk1);
    free(T_mpk2);

    return 0;
}

CK_ULONG SCdestroyKey()
{

    string info;
    char n[1024*1024]={0};
    CK_RV rv = 0;
    CK_BYTE rIn[32] = {0};
    CK_BYTE rOut[32] = {0};
//    memset(rIn,2,sizeof(rIn));
    CK_ULONG outLen = sizeof(rOut);
    rIn[0] = 5;

    TimeStart();
    info.clear();
    rv = C_Extend_DestroyCard(testslot,rIn,sizeof(rIn),rOut,&outLen);
    info.append("rOut: 0x");
    for(int i=0;i<outLen;i++)
    {
        sprintf(n,"%02x",rOut[i]);
        info.append(n);
    }
    Save("C_Extend_DestroyCard",rv,info,TimeEnd());
    return rv;
}


CK_ULONG test_LockToken()
{
    string info;
    char n[1024*1024]={0};
    CK_RV rv=0;
    int i=0;
    CK_SESSION_HANDLE session = hSession;
    CK_ULONG pincount = 0;

    CK_USER_TYPE userType=CKU_USER;
    char *err_user_pin = "123456789";

    TimeStart();
    rv = C_Logout(session);
    Save("C_Logout",rv,"",TimeEnd());
    if (rv != CKR_OK)
    {
        return rv;
    }

    info.clear();
    TimeStart();
    rv = C_Extend_GetPinRemainCount(hSession, &pincount);
    info.append("count: ");
    sprintf(n,"%d", pincount);
    info.append(n);
    Save("C_Extend_GetPinRemainCount",rv,info,TimeEnd());

    //锁死
    for(i=0;i<=6;i++)
    {
        TimeStart();
        rv = C_Login(session,CKU_USER,(CK_UTF8CHAR_PTR)err_user_pin,strlen((char*)err_user_pin));
        Save("C_Login",rv,"",TimeEnd());
    }

    CK_STATUS_ENUM getstatus = CK_STATUS_ENUM_DEVICE_OFF;
    info.clear();
    TimeStart();
    rv = C_Extend_GetStatus(testslot, &getstatus);
    info.append("card status: (should be 4)");
    sprintf(n,"%d", getstatus);
    info.append(n);
    Save("C_Extend_GetStatus",rv,info,TimeEnd());


    info.clear();
    TimeStart();
    rv = C_Extend_GetPinRemainCount(hSession, &pincount);
    info.append("count: (should be 0)");
    sprintf(n,"%d", pincount);
    info.append(n);
    Save("C_Extend_GetPinRemainCount",rv,info,TimeEnd());

    END:
    return rv;
}


CK_ULONG test_check_OTP(unsigned char* pbDefaultOTPPin, unsigned char nOTPPinLen)
{
    CK_RV rv = 0;
    unsigned char pUserPin[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
    unsigned char nUserPinLen = sizeof(pUserPin);
    string info;
    char n[1024*1024]={0};
    CK_ULONG pincount = 0;

    TimeStart();
    info.clear();
    rv = C_Extend_Reset_Pin_With_OTP(hSession,pbDefaultOTPPin,nOTPPinLen,pUserPin,nUserPinLen);
    Save("C_Extend_Reset_Pin_With_OTP",rv,"",TimeEnd());

    //after reset userpin successful, then execute login
    TimeStart();
    info.clear();
    rv=C_Login(hSession,CKU_USER,pUserPin,nUserPinLen);
    Save("C_Login",rv,"",TimeEnd());

    //应返回6次
    info.clear();
    TimeStart();
    rv = C_Extend_GetPinRemainCount(hSession, &pincount);
    info.append("count: (should be 6)");
    sprintf(n,"%d", pincount);
    info.append(n);
    Save("C_Extend_GetPinRemainCount",rv,info,TimeEnd());

    CK_STATUS_ENUM getstatus = CK_STATUS_ENUM_DEVICE_OFF;
    info.clear();
    TimeStart();
    rv = C_Extend_GetStatus(testslot, &getstatus);
    info.append("card status: (should be 0)");
    sprintf(n,"%d", getstatus);
    info.append(n);
    Save("C_Extend_GetStatus",rv,info,TimeEnd());

    return rv;
}

CK_ULONG checkOTP()
{
    string info;
    char n[1024*1024]={0};
    CK_RV rv = 0;
    CK_RV bRtn = 0;
    CK_SESSION_HANDLE session = hSession;
    BYTE Version_otp[REMOTE_DATA_VERSION_LEN] = { 0 };
    CK_ULONG otpusecount = 0;
    CK_ULONG otplockcount = 0;
    CK_BYTE pbDefaultOTPPin[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};


    bRtn = Get_Update_Data_Version(CKO_REMOTE_OTP, Version_otp);
    RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

    TimeStart();
    info.clear();
    rv = C_Extend_Get_OTP_Remain_Count(session, &otpusecount);
    info.append("count: ");
    sprintf(n,"%d", otpusecount);
    info.append(n);
    Save("C_Extend_Get_OTP_Remain_Count",rv,info,TimeEnd());


    TimeStart();
    info.clear();
    rv = C_Extend_Get_OTP_Unlock_Count(session, &otplockcount);
    info.append("count: ");
    sprintf(n,"%d", otplockcount);
    info.append(n);
    Save("C_Extend_Get_OTP_Unlock_Count",rv,info,TimeEnd());

    bRtn = test_LockToken();

    bRtn = test_check_OTP(pbDefaultOTPPin, sizeof(pbDefaultOTPPin));

    TimeStart();
    info.clear();
    rv = C_Extend_Get_OTP_Remain_Count(session, &otpusecount);
    info.append("count: ");
    sprintf(n,"%d", otpusecount);
    info.append(n);
    Save("C_Extend_Get_OTP_Remain_Count",rv,info,TimeEnd());


    TimeStart();
    info.clear();
    rv = C_Extend_Get_OTP_Unlock_Count(session, &otplockcount);
    info.append("count: ");
    sprintf(n,"%d", otplockcount);
    info.append(n);
    Save("C_Extend_Get_OTP_Unlock_Count",rv,info,TimeEnd());

    return rv;
}

CK_ULONG TTupdate()
{
    CK_RV rv = 0;
    unsigned int modTemp = 0;

    CK_BYTE     pub_key_origin[64]={
            0xec,0x91,0x81,0x8d,0xe0,0xb7,0x01,0x21,0x73,0xf5,0x1c,0x33,0x75,0x43,0x6e,0x43,
            0xb6,0xa9,0xa2,0x6a,0xbd,0x6d,0xbc,0xb7,0x9f,0x85,0x1c,0xde,0xaf,0x7a,0x0f,0x6c,
            0xcb,0xf4,0xb5,0xa1,0x5f,0xb8,0x7e,0x60,0xfc,0x0b,0x3a,0x92,0x3d,0x12,0xe8,0x66,
            0x36,0x4a,0x93,0x5f,0xfb,0x30,0x84,0x2b,0xc9,0x13,0x9e,0xbd,0x2d,0xdc,0xe9,0x61
    };


    int ulSOPINLen_T = sizeof(pSOPin);

//    char  *default_so_pin = "12345678";
//    memcpy(pSOPin,default_so_pin,strlen(default_so_pin));

    BYTE Version_MPK[REMOTE_DATA_VERSION_LEN] = {0x00};
    BYTE IV_mpk[IV_LEN] = { 0 };
    BYTE* T_mpk= NULL;
    unsigned short T_mpkLen = 0;
    unsigned char pri_key_valueT[PRI_KEY_LEN] = {0};

    unsigned char pub_key_valueT[PUB_KEY_LEN] = {0};
    int pri_key_value_lenT = PRI_KEY_LEN;
    int pub_key_value_lenT = PUB_KEY_LEN;
    unsigned char pri_key_valueB[PRI_KEY_LEN] = {0};
    unsigned char pub_key_valueB[PUB_KEY_LEN] = {0};
    int pri_key_value_lenB = PRI_KEY_LEN;
    int pub_key_value_lenB = PUB_KEY_LEN;
    unsigned char RA[TT_R_LEN] = {0};
    unsigned char RB[TT_R_LEN] = {0};
    unsigned char R[TT_R_LEN] = {0};
    unsigned char RR[TT_R_LEN] = {0};
    int RALen = TT_R_LEN;
    int RRLen = TT_R_LEN;
    CK_BYTE pbWrappedKey[TT_WRAPPED_LEN] = {0};
    CK_ULONG ulWrappedKeyLen = TT_WRAPPED_LEN;
    unsigned char  WrappedKeyB[TT_WRAPPED_LEN] = { 0 };
    int WrappedKeyBLen = TT_WRAPPED_LEN;

    CK_OBJECT_HANDLE hPartKey1 = NULL_PTR, hPartKey2 = NULL_PTR, hSessKey = NULL_PTR;
    CK_BYTE keyID1 = CK_SESSKEY_ID0, keyID2 = CK_SESSKEY_ID1, keyID3 = CK_SESSKEY_ID2;
    CK_OBJECT_HANDLE hPublicKey = NULL_PTR, hPrivateKey = NULL_PTR;

    //for get exchange public key
    CK_BYTE			pSM2PublicKey[PUB_KEY_LEN] = {0};
    CK_UINT			nSM2PublicKeyLen = PUB_KEY_LEN;

    //for C_GenerateKey
    CK_BBOOL ttrue = CK_TRUE;
    CK_BBOOL ffalse = CK_FALSE;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE SessKeyExchangeKeyType = CKK_SESSKEY_EXCHANGE;
    CK_MECHANISM SessKeyExchangeMechanism = {CKM_SESSKEY_EXCHANGE_GEN, NULL, 0};
    CK_ATTRIBUTE SessKeyExchangeTemplate1[] =
    {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_TOKEN, &ffalse, sizeof(ffalse)},
            {CKA_KEY_TYPE, &SessKeyExchangeKeyType, sizeof(CK_KEY_TYPE)},
            {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
            {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
            {CKA_EXTRACTABLE,&ttrue, sizeof(ttrue)},
            {CKA_SESSKEY_ID, &keyID1, sizeof(CK_BYTE)}
    };
    //for C_WrapKey
    CK_MECHANISM	SM2WrapMechanism = {CKM_WRAP_SESSKEY, pub_key_valueB, 64};
    //for C_UnwrapKey
    CK_MECHANISM	SM2UnwrapMechanism = {CKM_UNWRAP_SESSKEY, NULL, 0};
    CK_ATTRIBUTE SessKeyExchangeTemplate2[] =
    {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_TOKEN, &ffalse, sizeof(ffalse)},
            {CKA_KEY_TYPE, &SessKeyExchangeKeyType, sizeof(CK_KEY_TYPE)},
            {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
            {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
            {CKA_SESSKEY_ID, &keyID2, sizeof(CK_BYTE)}
    };
    //for C_DeriveKey
    unsigned char* pMechanismParameter = NULL ;
    CK_MECHANISM	DeriveKeyMechanism = {CKM_SESSKEY_DERIVE, NULL, 0};
    CK_ATTRIBUTE SessKeyDeriveTemplate[] =
    {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_TOKEN, &ffalse, sizeof(ffalse)},
            {CKA_KEY_TYPE, &SessKeyExchangeKeyType, sizeof(CK_KEY_TYPE)},
            {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
            {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
            {CKA_EXTRACTABLE,&ttrue, sizeof(ttrue)},
            {CKA_SESSKEY_ID, &keyID3, sizeof(CK_BYTE)}
    };

    //for get exchange sess key
    CK_BYTE			pExchangeSessKey[128] = {0};
    CK_UINT			nExchangeSessKeyLen = sizeof(pExchangeSessKey);
    string info;
    char n[1024*1024]={0};


    srand( (unsigned)time( NULL ) );//随机数初始化

    //真实卡查找用于密钥交换的公私钥对（一个SD内只有一对）,并获取公钥
    CK_MECHANISM      ECCMechanism = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_KEY_TYPE  ECCKeyType = CKK_SM2;
    CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY,priclass=CKO_PRIVATE_KEY;
    CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)},
            {CKA_WRAP, &ttrue, sizeof(CK_BBOOL)},
            {CKA_KEY_TYPE,&ECCKeyType,sizeof(CK_KEY_TYPE)},
            {CKA_ISEXCHANGEKEY, &ttrue, sizeof(CK_BBOOL)},
            {CKA_EXTRACTABLE,&ttrue, sizeof(ttrue)},
            {CKA_ENCRYPT,&ttrue, sizeof(CK_BBOOL)}
  //           {CKA_ID, idid, sizeof(idid)}
    };
    CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)},
            {CKA_PRIVATE, &ttrue, sizeof(CK_BBOOL)},
            {CKA_SENSITIVE, &ttrue, sizeof(CK_BBOOL)},
            {CKA_UNWRAP, &ttrue, sizeof(CK_BBOOL)},
            {CKA_KEY_TYPE,&ECCKeyType,sizeof(CK_KEY_TYPE)},
            {CKA_ISEXCHANGEKEY, &ttrue, sizeof(CK_BBOOL)},
            {CKA_DECRYPT, &ttrue, sizeof(CK_BBOOL)}
  //          {CKA_ID, idid, sizeof(idid)}
    };
    int keypairnum = findexchangekeypair(&hPublicKey, &hPrivateKey);
    if(keypairnum == 0)
    {
        TimeStart();
        rv = C_GenerateKeyPair(hSession, &ECCMechanism,publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
                               privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE), &hPublicKey, &hPrivateKey);
        info.clear();
        info.append("hpubkey: ");
        sprintf(n,"0x%08x",hPublicKey);
        info.append(n);
        info.append("hprikey: ");
        sprintf(n,"0x%08x",hPrivateKey);
        info.append(n);
        Save("C_GenerateKeyPair(exchange)",rv,info,TimeEnd());

        if(rv != 0)
            return 0;
    }

    if(keypairnum>1)
    {
        TimeStart();
        info.clear();
        info.append("More than 1 pair of exchange key!");
        Save("findexchangekeypair",rv,info,TimeEnd());
        return 0;
    }

    //软算法,生成TT密钥对
    info.clear();
    TimeStart();
    rv = 0;
    if (SM2Init() != SM2_OK)
    {
        rv = 1;
        info.append("SM2InitA fail!!");
    }

    if (SM2GenKey(pri_key_valueT, &pri_key_value_lenT, pub_key_valueT, &pub_key_value_lenT) != SM2_OK)
    {
        rv = 1;
        info.append("SM2GenKeyA fail!!");
    }
    Save("soft_genkey",rv,info,TimeEnd());

    //Get Monitor PubKey Version
    CK_RV bRtn = 0;
    Get_Update_Data_Version(CKO_REMOTE_TT, Version_MPK);


    //生成在线更新特通的T
    info.clear();
    TimeStart();
    rv = 0;
    RandomGenerate(IV_mpk, IV_LEN);
    modTemp = 8 - PUB_KEY_LEN;
    T_mpkLen = 8 + PUB_KEY_LEN + modTemp%16;
    T_mpk = (BYTE*)malloc(sizeof(BYTE) * T_mpkLen);

    TimeStart();
    bRtn = Generate_T(pub_key_valueT, PUB_KEY_LEN, IV_mpk, pSOPin, ulSOPINLen_T, Version_MPK, T_mpk, &T_mpkLen);
    if(bRtn!=0)
    {
        rv = 1;
        info.append("Generate_T Error!!");
    }
    else
    {
        info.append("mpklen: ");
        sprintf(n,"%d",T_mpkLen);
        info.append(n);
    }
    Save("soft_genTTMPK",rv,info,TimeEnd());

    if(rv != CKR_OK){
        free(T_mpk);
        T_mpk = NULL;
        return rv;
    }


    // Set Monitor PubKey Remote
    bRtn = Remote_Set_Data(T_mpk, T_mpkLen, IV_mpk,CKO_REMOTE_TT);
    if(bRtn!=0)
        return bRtn;

    //Get Monitor PubKey Version
    bRtn =Get_Update_Data_Version(CKO_REMOTE_TT, Version_MPK);
    if(bRtn!=0)
        return bRtn;

    //start keyexchange process
    CK_ATTRIBUTE SM2GetPubKeyTemplate[] = {
            {CKA_VALUE, pSM2PublicKey, nSM2PublicKeyLen}
    };
    TimeStart();
    rv = C_GetAttributeValue(hSession, hPublicKey, SM2GetPubKeyTemplate, sizeof(SM2GetPubKeyTemplate)/sizeof(CK_ATTRIBUTE));
    info.append("pubvalue: 0x");
    for(int i=0;i<nSM2PublicKeyLen;i++)
    {
        sprintf(n,"%02x",*((CK_BYTE_PTR)(SM2GetPubKeyTemplate[0].pValue)+i));
        info.append(n);
    }
    Save("C_GetAttributeValue pub",rv,info,TimeEnd());

    //虚拟卡B生成用于密钥交换的公私钥对
    info.clear();
    if (SM2Init() != SM2_OK)
    {
        info.append("SM2InitB fail!");
    }

    if (SM2GenKey(pri_key_valueB, &pri_key_value_lenB, pub_key_valueB, &pub_key_value_lenB) != SM2_OK)
    {
        info.append("SM2GenKeyB fail!");
    }

    //卡A生成随机数RA，用公钥B打包生成EA(pbWrappedKey)，卡B用私钥B解密(解包)EA得到RA
//    printf("卡A\n");
    TimeStart();
    rv = C_GenerateKey(hSession, &SessKeyExchangeMechanism, SessKeyExchangeTemplate1, sizeof(SessKeyExchangeTemplate1)/sizeof(CK_ATTRIBUTE), &hPartKey1);
    Save("C_GenerateKey",rv,info,TimeEnd());

    TimeStart();
    rv = C_WrapKey(hSession, &SM2WrapMechanism, 0, hPartKey1, pbWrappedKey, &ulWrappedKeyLen);
    info.clear();
    info.append(" ulWrappedKeyLen:");
    sprintf(n,"%d",ulWrappedKeyLen);
    info.append(n);
    info.append("pbWrappedKey: 0x");
    for(int i=0;i<ulWrappedKeyLen;i++)
    {
        sprintf(n,"%02x",pbWrappedKey[i]);
        info.append(n);
    }
    Save("C_WrapKey",rv,info,TimeEnd());

    info.clear();
    TimeStart();
    if (SM2Decrypt(pbWrappedKey, ulWrappedKeyLen, pri_key_valueB, pri_key_value_lenB, RA, &RALen) != SM2_OK)
    {
        info.append("card B: SM2Decrypt fail!");
    }

    //卡B生成随机数RB，用公钥A打包（加密）成EB(WrappedKeyB)，卡A用私钥A解密(解包)EB得到RB
//    printf("卡B\n");
    RandomGenerate(RB, TT_R_LEN);
    if (SM2Encrypt(RB, TT_R_LEN, pSM2PublicKey, nSM2PublicKeyLen, WrappedKeyB, &WrappedKeyBLen) != SM2_OK)
    {
        info.append("card B: SM2Encrypt fail\n");
    }
    Save("card B unwrap",rv,info,TimeEnd());

    TimeStart();
    info.clear();
    rv = C_UnwrapKey(hSession, &SM2UnwrapMechanism, hPrivateKey, WrappedKeyB, WrappedKeyBLen, SessKeyExchangeTemplate2, sizeof(SessKeyExchangeTemplate2)/sizeof(CK_ATTRIBUTE), &hPartKey2);
    Save("C_UnwrapKey",rv,"",TimeEnd());

    if(rv != CKR_OK)
        return rv;


    //卡B，使用部分密钥RA（KEY）和部分密钥RB（KEY），异或（协商）生成密钥R（KEY）
//    printf("生成会话密钥\n");
    bRtn = Generate_R_for_TT(RA, RB, R, TT_R_LEN);

    CK_BYTE			getIV[16] = {0};
    CK_ULONG		ulgetIVLen = sizeof(getIV);

    //卡A
    TimeStart();
    rv = C_Extend_DeriveSessionKey(hSession, &DeriveKeyMechanism, hPartKey1, hPartKey2, SessKeyDeriveTemplate, sizeof(SessKeyDeriveTemplate)/sizeof(CK_ATTRIBUTE), &hSessKey, getIV, &ulgetIVLen);
    info.clear();
    info.append("hSessKey: ");
    sprintf(n,"0x%08x",hSessKey);
    info.append(n);
    info.append(" sesskeyiv: 0x");
    for(int i=0;i<ulgetIVLen;i++)
    {
        sprintf(n,"%02x",getIV[i]);
        info.append(n);
    }

 //   printf("\n比较IV\n");
    bRtn = Result_Compare(getIV, ulgetIVLen, R+TT_R_LEN/2, TT_R_LEN/2);
    if(bRtn!=0)
    {
        info.append("iv compare error!");
    }
    Save("C_Extend_DeriveSessionKey",rv,info,TimeEnd());

    if(rv != CKR_OK)
        return rv;

    //特通公钥A0加密R（KEY）得到M，私钥A0解密M得到RR
//    printf("\n导出sesskey，解密并比较\n");
    //get the sesskey handle
    CK_OBJECT_HANDLE hObject[16] = {0};
    CK_ULONG ulfindObjectCount = 16;

    TimeStart();
    rv = C_FindObjectsInit(hSession, SessKeyDeriveTemplate, sizeof(SessKeyDeriveTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit",rv,"",TimeEnd());

    TimeStart();
    rv = C_FindObjects(hSession, hObject, 16, &ulfindObjectCount);
    info.clear();
    if(ulfindObjectCount!=1)
    {
        info.append("Seeskey Handle NO.Error!");
    }
    sprintf(n,"%ld",ulfindObjectCount);
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulfindObjectCount;i++)
    {
        sprintf(n,",0x%08x ",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects",rv,info,TimeEnd());

    TimeStart();
    rv = C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal",rv,"",TimeEnd());

    hSessKey = hObject[0];

    CK_BYTE encryptedSesskey[128] = {0};
    CK_ULONG ulencryptedSesskey = sizeof(encryptedSesskey);
    TimeStart();
    rv = C_Extend_GetExchangeSessionKey(hSession, hSessKey, encryptedSesskey,&ulencryptedSesskey);
    info.clear();

    if (SM2Decrypt(encryptedSesskey, ulencryptedSesskey, pri_key_valueT, pri_key_value_lenT, RR, &RRLen) != SM2_OK)
    {
        info.append("SM2Decrypt sesskey fail!!");
    }
    bRtn = Result_Compare(RR, RRLen, R, TT_R_LEN);
    if(bRtn!=0)
    {
        info.append("decrypt sesskey compare ERROR: ");
        sprintf(n,"%d",bRtn);
        info.append(n);

        info.append("RR: 0x");
        for(int i=0;i<RRLen;i++)
        {
            sprintf(n,"%02x",RR[i]);
            info.append(n);
        }

        info.append("R: 0x");
        for(int i=0;i<TT_R_LEN;i++)
        {
            sprintf(n,"%02x",R[i]);
            info.append(n);
        }

    }
    else
    {
        info.append("TT update success!");
    }
    Save("C_Extend_GetExchangeSessionKey",rv,info,TimeEnd());

    free(T_mpk);
    return 0;
}

CK_ULONG xtest_generatekeytest()
{
    CK_RV rv = 0;
    string info;
    char n[1024*1024]={0};
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL ttrue = CK_TRUE;
    CK_BBOOL ffalse = CK_FALSE;
    CK_KEY_TYPE ZUCkeyType = CKK_ZUC;
    CK_KEY_TYPE SM4keyType = CKK_SM4;
    CK_OBJECT_HANDLE hkeyzuc = 0;
    CK_OBJECT_HANDLE hkeysm4 = 0;
    CK_BYTE id[] = {0x01,0x10,0x10};

    //ZUC
/*    CK_MECHANISM ZUCmechanismGen = {CKM_ZUC_KEY_GEN, NULL_PTR, 0};
    CK_ATTRIBUTE ZUCkeyTemplate_Gen[] =
    {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_TOKEN, &ttrue, sizeof(ttrue)},
            {CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
            {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
            {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
            {CKA_ID,id,sizeof(id)}
    };
    info.clear();
    TimeStart();
    rv = C_GenerateKey(hSession, &ZUCmechanismGen,ZUCkeyTemplate_Gen, sizeof(ZUCkeyTemplate_Gen)/sizeof(CK_ATTRIBUTE), &hkeyzuc);
    info.append("hkeyzuc: ");
    sprintf(n,"0x%08x",hkeyzuc);
    info.append(n);
    Save("C_GenerateKey",rv,info,TimeEnd());*/

    CK_BYTE nSessKeyID = CK_SESSKEY_PRESET_ID6;

    //SM4
    CK_MECHANISM SM4mechanismGen = {CKM_SM4_KEY_GEN, NULL_PTR, 0};
    CK_ATTRIBUTE SM4keyTemplate_Gen[] =
    {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_TOKEN, &ffalse, sizeof(ffalse)},
            {CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
            {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
            {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
 //         {CKA_WRAP_WITH_TRUSTED,&ttrue, sizeof(ttrue)},
 //           {CKA_ID,id,sizeof(id)},
            {CKA_SESSKEY_ID, &nSessKeyID, sizeof(nSessKeyID)}

    };

    //find
    CK_OBJECT_HANDLE hObject[16] = {0};
    CK_ULONG ulObjectCount = 0;
    CK_ATTRIBUTE keyTemplate_find[] =
    {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_TOKEN, &ffalse, sizeof(ffalse)},
            {CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
            {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
            {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
            //                  {CKA_WRAP_WITH_TRUSTED,&ttrue, sizeof(ttrue)},
//                    {CKA_ID,id,sizeof(id)},
           {CKA_SESSKEY_ID, &nSessKeyID, sizeof(nSessKeyID)}

    };

    TimeStart();
    rv = C_FindObjectsInit(hSession, keyTemplate_find, sizeof(keyTemplate_find)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit",rv,"",TimeEnd());

    TimeStart();
    rv = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
    sprintf(n,"%ld",ulObjectCount);
    info.clear();
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulObjectCount;i++)
    {
        sprintf(n," 0x%08x",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects",rv,info,TimeEnd());

    TimeStart();
    rv =C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal",rv,"",TimeEnd());

    for(int i=0;i<ulObjectCount;i++)
    {
        TimeStart();
        rv = C_DestroyObject(hSession,hObject[i]);
        Save("C_DestroyObject",rv,"",TimeEnd());
    }

    info.clear();
    TimeStart();
    rv = C_GenerateKey(hSession, &SM4mechanismGen,SM4keyTemplate_Gen, sizeof(SM4keyTemplate_Gen)/sizeof(CK_ATTRIBUTE), &hkeysm4);
    info.append("hkeysm4: ");
    sprintf(n,"0x%08x",hkeysm4);
    info.append(n);
    Save("C_GenerateKey",rv,info,TimeEnd());

    for(int i=0;i<2;i++)
    {
        TimeStart();
        rv = C_FindObjectsInit(hSession, keyTemplate_find, sizeof(keyTemplate_find)/sizeof(CK_ATTRIBUTE));
        Save("C_FindObjectsInit",rv,"",TimeEnd());

        TimeStart();
        rv = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
        sprintf(n,"%ld",ulObjectCount);
        info.clear();
        info.append("object count = ");
        info.append(n);
        for(int i=0;i<ulObjectCount;i++)
        {
            sprintf(n," 0x%08x",hObject[i]);
            info.append(n);
        }
        Save("C_FindObjects",rv,info,TimeEnd());

        TimeStart();
        rv =C_FindObjectsFinal(hSession);
        Save("C_FindObjectsFinal",rv,"",TimeEnd());
    }

    //try to enc by BK
    CK_BYTE iv[16] = {0};
    iv[0] = 1;
    iv[1] = 2;
    CK_MECHANISM SM4mechanism = {CKM_SM4_CBC, iv, sizeof(iv)};

    CK_BYTE indata[]={0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    CK_BYTE outdata[32] = {0};
    CK_ULONG outdatalen=sizeof(outdata);
    CK_BYTE outdata1[32] = {0};
    CK_ULONG outdatalen1=sizeof(outdata);
    CK_ULONG indatalen=sizeof(indata);

    for(int i=0;i<3;i++)
    {
        TimeStart();
        rv = C_EncryptInit(hSession, &SM4mechanism, hkeysm4);
        Save("C_EncryptInit",rv,"",TimeEnd());

        TimeStart();
        rv = C_EncryptUpdate(hSession, indata, sizeof(indata), outdata, &outdatalen);
        Save("C_EncryptUpdate",rv,"",TimeEnd());


        TimeStart();
        rv = C_EncryptFinal(hSession, outdata1, &outdatalen1);
        Save("C_EncryptFinal",rv,"",TimeEnd());

        /////////
        TimeStart();
        rv = C_DecryptInit(hSession, &SM4mechanism, hkeysm4);
        Save("C_DecryptInit",rv,"",TimeEnd());


        TimeStart();
        rv = C_DecryptUpdate(hSession, outdata, outdatalen, indata, &indatalen);
        Save("C_DecryptUpdate",rv,"",TimeEnd());

        TimeStart();
        rv = C_DecryptFinal(hSession, outdata1, &outdatalen1);
        Save("C_DecryptFinal",rv,"",TimeEnd());
    }


/*    TimeStart();
    rv = C_DestroyObject(hSession,hkeyzuc);
    Save("C_DestroyObject",rv,"",TimeEnd());*/
    TimeStart();
    rv = C_DestroyObject(hSession,hkeysm4);
    Save("C_DestroyObject",rv,"",TimeEnd());

    TimeStart();
    rv = C_FindObjectsInit(hSession, keyTemplate_find, sizeof(keyTemplate_find)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit",rv,"",TimeEnd());

    TimeStart();
    rv = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
    sprintf(n,"%ld",ulObjectCount);
    info.clear();
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulObjectCount;i++)
    {
        sprintf(n," 0x%08x",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects",rv,info,TimeEnd());

    TimeStart();
    rv =C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal",rv,"",TimeEnd());

    return 0;
}

CK_ULONG xtest_wrapkeybyBKtest()
{
    CK_RV rv = 0;
    string info;
    char n[1024*1024]={0};
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL ttrue = CK_TRUE;
    CK_BBOOL ffalse = CK_FALSE;
    CK_KEY_TYPE ZUCkeyType = CKK_ZUC;
    CK_KEY_TYPE SM4keyType = CKK_SM4;
    CK_OBJECT_HANDLE hkeyzuc = 0;
    CK_OBJECT_HANDLE hkeysm4 = 0;
    CK_BYTE id[] = {0x01,0x10,0x10};

    CK_BYTE nSessKeyID = CK_SESSKEY_PRESET_ID6;
    CK_BYTE nSessKeyIDBK = CK_SESSKEY_PRESET_ID7;

    //SM4
    CK_MECHANISM SM4mechanismGen = {CKM_SM4_KEY_GEN, NULL_PTR, 0};
    CK_BYTE keyvalue[16] = {0};
    keyvalue[0] = 1;

    CK_ATTRIBUTE SM4keyTemplate_tobewrapped[] =
    {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_TOKEN, &ffalse, sizeof(ffalse)},
            {CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
            {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
   //         {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
            {CKA_WRAP_WITH_TRUSTED,&ttrue, sizeof(ttrue)},
            {CKA_EXTRACTABLE,&ttrue, sizeof(ttrue)},
 //           {CKA_VALUE,keyvalue,sizeof(keyvalue)},
            {CKA_SESSKEY_ID, &nSessKeyID, sizeof(nSessKeyID)}

    };

    CK_ATTRIBUTE SM4keyTemplate_BK[] =
    {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_TOKEN, &ttrue, sizeof(ttrue)},
            {CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
            {CKA_WRAP,&ttrue, sizeof(ttrue)},
            {CKA_SESSKEY_ID, &nSessKeyIDBK, sizeof(nSessKeyID)}
    };

    //find SM4key
    CK_OBJECT_HANDLE hObject[16] = {0};
    CK_ULONG ulObjectCount = 0;
    CK_ATTRIBUTE keyTemplate_find[] =
    {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
            {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
    //        {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
            {CKA_SESSKEY_ID, &nSessKeyID, sizeof(nSessKeyID)}
    };

    TimeStart();
    rv = C_FindObjectsInit(hSession, SM4keyTemplate_tobewrapped, sizeof(SM4keyTemplate_tobewrapped)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit",rv,"",TimeEnd());

    TimeStart();
    rv = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
    sprintf(n,"%ld",ulObjectCount);
    info.clear();
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulObjectCount;i++)
    {
        sprintf(n," 0x%08x",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects",rv,info,TimeEnd());

    TimeStart();
    rv =C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal",rv,"",TimeEnd());

    for(int i=0;i<ulObjectCount;i++)
    {
        TimeStart();
        rv = C_DestroyObject(hSession,hObject[i]);
        Save("C_DestroyObject",rv,"",TimeEnd());
    }

    info.clear();
    TimeStart();
    rv = C_GenerateKey(hSession, &SM4mechanismGen,SM4keyTemplate_tobewrapped, sizeof(SM4keyTemplate_tobewrapped)/sizeof(CK_ATTRIBUTE), &hkeysm4);
//    rv = C_CreateObject(hSession,SM4keyTemplate_tobewrapped,sizeof(SM4keyTemplate_tobewrapped)/sizeof(CK_ATTRIBUTE), &hkeysm4);
    info.append("hkeysm4: ");
    sprintf(n,"0x%08x",hkeysm4);
    info.append(n);
    Save("C_GenerateKey",rv,info,TimeEnd());

    for(int i=0;i<1;i++)
    {
        TimeStart();
        rv = C_FindObjectsInit(hSession, SM4keyTemplate_tobewrapped, sizeof(SM4keyTemplate_tobewrapped)/sizeof(CK_ATTRIBUTE));
        Save("C_FindObjectsInit",rv,"",TimeEnd());

        TimeStart();
        rv = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
        sprintf(n,"%ld",ulObjectCount);
        info.clear();
        info.append("object count = ");
        info.append(n);
        for(int i=0;i<ulObjectCount;i++)
        {
            sprintf(n," 0x%08x",hObject[i]);
            info.append(n);
        }
        Save("C_FindObjects",rv,info,TimeEnd());

        TimeStart();
        rv =C_FindObjectsFinal(hSession);
        Save("C_FindObjectsFinal",rv,"",TimeEnd());
    }

    //find BK
    CK_OBJECT_HANDLE hObjectBK[16] = {0};
    TimeStart();
    rv = C_FindObjectsInit(hSession, SM4keyTemplate_BK, sizeof(SM4keyTemplate_BK)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit,BK",rv,"",TimeEnd());

    TimeStart();
    rv = C_FindObjects(hSession, hObjectBK, 16, &ulObjectCount);
    sprintf(n,"%ld",ulObjectCount);
    info.clear();
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulObjectCount;i++)
    {
        sprintf(n," 0x%08x",hObjectBK[i]);
        info.append(n);
    }
    Save("C_FindObjects,BK",rv,info,TimeEnd());

    TimeStart();
    rv =C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal,BK",rv,"",TimeEnd());


    CK_MECHANISM WrapMechanism = {CKM_SM4_ECB, NULL_PTR, 0};
    CK_BYTE  WrappedKey[128] = {0};
    CK_ULONG     ulWrappedKeyLen = sizeof(WrappedKey);

    TimeStart();
    rv = C_WrapKey(hSession,&WrapMechanism,hObjectBK[0],hObject[0], WrappedKey,&ulWrappedKeyLen);
    Save("C_WrapKey",rv,"",TimeEnd());


    TimeStart();
    rv = C_DestroyObject(hSession,hkeysm4);
    Save("C_DestroyObject",rv,"",TimeEnd());

    return 0;
}



CK_ULONG xtest_SM2_signtest()
{
    CK_RV ret=0;
    int bRtn=0;
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    CK_OBJECT_HANDLE * phPublicKey = &hPublicKey, *phPrivateKey = &hPrivateKey;
    string info;
    char n[1024 * 1024] = {0};

    int i=0,j=0;
    CK_BYTE pData[2048]={0};

    CK_MECHANISM      mechanism = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_BYTE      subject[] = {0x00,0x01,0x02};
    CK_BYTE      idid[] = {0x00,0x01,0x02,0x03};
    CK_BBOOL     ttrue = CK_TRUE, ffalse = CK_FALSE;
    CK_KEY_TYPE  keyType=CKK_SM2;
    CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY,priclass=CKO_PRIVATE_KEY;


    CK_ULONG ulObjectCount = 0;

    CK_BYTE sm2pubvalue[64] = {0};
    CK_ATTRIBUTE SM2GetPubKeyTemplate[] = {
            {CKA_VALUE, sm2pubvalue, sizeof(sm2pubvalue)}
    };

    CK_BYTE sm2privalue[32] = {0};
    CK_ATTRIBUTE SM2GetPriKeyTemplate[] = {
            {CKA_VALUE, sm2privalue, sizeof(sm2privalue)}
    };

    CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_TOKEN, &ttrue, sizeof(ttrue)},
            {CKA_VERIFY, &ttrue, sizeof(ttrue)},
            {CKA_SUBJECT, subject, sizeof(subject)},
            {CKA_ID, idid, sizeof(idid)},
            {CKA_PRIVATE, &ffalse, sizeof(ffalse)},
            {CKA_KEY_TYPE,&keyType,sizeof(keyType)}
    };
    CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_TOKEN, &ttrue, sizeof(ttrue)},
            {CKA_PRIVATE, &ttrue, sizeof(ttrue)},
            {CKA_SUBJECT, subject, sizeof(subject)},
            {CKA_ID, idid, sizeof(idid)},
            {CKA_SENSITIVE, &ttrue, sizeof(ttrue)},
            {CKA_SIGN, &ttrue, sizeof(ttrue)},
            {CKA_KEY_TYPE,&keyType,sizeof(keyType)}
    };

    CK_ATTRIBUTE pubFindKeyTemplate[1] = {
            {CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)}
    };

    CK_ATTRIBUTE prvFindKeyTemplate[1] = {
            {CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)}
    };

    CK_ATTRIBUTE flashFindKeyTemplate[1] = {
            {CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)}
    };


    CK_OBJECT_HANDLE_PTR hObject = NULL_PTR;

    TimeStart();
    ret = C_GenerateKeyPair(hSession, &mechanism,
                            publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
                            privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),
                            phPublicKey, phPrivateKey);
    Save("C_GenerateKeyPair",ret,"",TimeEnd());

    if(ret != 0){
        return 0;
    }

    TimeStart();
    ret = C_GetAttributeValue(hSession, hPublicKey, SM2GetPubKeyTemplate, sizeof(SM2GetPubKeyTemplate)/sizeof(CK_ATTRIBUTE));
    info.clear();
    info.append("pubkey: 0x");
    for(int i=0;i<SM2GetPubKeyTemplate[0].ulValueLen;i++)
    {
        sprintf(n,"%02x",*((CK_BYTE_PTR)(SM2GetPubKeyTemplate[0].pValue)+i));
        info.append(n);
    }
    Save("C_GetAttributeValue ",ret,info,TimeEnd());

    if(ret != 0){
        return 0;
    }

    TimeStart();
    ret = C_GetAttributeValue(hSession, hPrivateKey, SM2GetPriKeyTemplate, sizeof(SM2GetPriKeyTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_GetAttributeValue, prikey should fail",ret,"",TimeEnd());

    //find key
    hObject = NULL_PTR;
    hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16);
    ulObjectCount = 16;

    TimeStart();
    ret = C_FindObjectsInit(hSession, flashFindKeyTemplate, sizeof(flashFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit",ret,"",TimeEnd());

    if(ret != 0){
        free(hObject);
        hObject = NULL;
        return 0;
    }

    TimeStart();
    ret = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
    sprintf(n,"%ld",ulObjectCount);
    info.clear();
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulObjectCount;i++)
    {
        sprintf(n," 0x%08x",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects",ret,info,TimeEnd());

    if(ret != 0)
        return 0;

    TimeStart();
    ret = C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal",ret,"",TimeEnd());

    free(hObject);
    if(ret != 0)
        return 0;


    hObject = NULL_PTR;
    hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16);
    ulObjectCount = 16;

    TimeStart();
    ret = C_FindObjectsInit(hSession, prvFindKeyTemplate, sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit pubkey",ret,"",TimeEnd());

    if(ret != 0)
        return 0;

    TimeStart();
    ret = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
    sprintf(n,"%ld",ulObjectCount);
    info.clear();
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulObjectCount;i++)
    {
        sprintf(n," 0x%08x",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects pubkey",ret,info,TimeEnd());
    if(ret != 0)
        return 0;


    TimeStart();
    ret =C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal pubkey",ret,"",TimeEnd());

    free(hObject);
    if(ret != 0)
        return 0;


    hObject = NULL_PTR;
    hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16);
    ulObjectCount = 16;
    TimeStart();
    ret = C_FindObjectsInit(hSession, pubFindKeyTemplate, sizeof(pubFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit prikey",ret,"",TimeEnd());

    TimeStart();
    ret = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
    sprintf(n,"%ld",ulObjectCount);
    info.clear();
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulObjectCount;i++)
    {
        sprintf(n," 0x%08x",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects prikey",ret,info,TimeEnd());
    if(ret != 0)
        return 0;


    TimeStart();
    ret = C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal prikey",ret,"",TimeEnd());

    free(hObject);
    if(ret != 0)
        return 0;

    int datalen = 32;
    CK_BYTE pOutData[256] = {0};
    CK_ULONG ulOutDataLen = sizeof(pOutData);
    CK_SESSION_HANDLE  session = hSession;
    CK_MECHANISM  mechanismcalc = {CKM_SM2, NULL_PTR, 0};

    srand( (unsigned)time( NULL ) );
    RandomGenerate(pData,datalen);


    TimeStart();
    CK_RV rv=C_SignInit(session,&mechanismcalc,hPrivateKey);
    Save("C_SignInit",rv,"",TimeEnd());

    memset(pOutData,0,ulOutDataLen);

    TimeStart();
    rv=C_Sign(session,pData,datalen,pOutData,&ulOutDataLen);
    info.clear();
    Save("C_Sign",rv,"",TimeEnd());

    TimeStart();
    rv=C_VerifyInit(session,&mechanismcalc,hPublicKey);
    Save("C_VerifyInit",rv,"",TimeEnd());

    TimeStart();
    rv=C_Verify(session,pData,datalen,pOutData,ulOutDataLen);
    info.clear();
    Save("C_Verify",rv,"",TimeEnd());

    //destroy generated keypair
    TimeStart();
    ret = C_DestroyObject(hSession, hPublicKey);
    Save("C_DestroyObject pub",ret,"",TimeEnd());
    if(ret != 0)
        return 0;


    TimeStart();
    ret = C_DestroyObject(hSession, hPrivateKey);
    Save("C_DestroyObject pri",ret,"",TimeEnd());

    return 0;
}

#define LOGEE(tag,...)  __android_log_print(ANDROID_LOG_ERROR, tag, __VA_ARGS__)
static const char *tag = "csm_sm2test";
CK_ULONG p11_mode_crypt_sm2()
{
    CK_RV rv = CKR_OK;
    CK_OBJECT_HANDLE hPrivateKey = 0;
    CK_OBJECT_HANDLE hPublicKey = 0;
    CK_OBJECT_HANDLE hKey = 0;
    CK_OBJECT_HANDLE hKey1 = 0;
    CK_MECHANISM cipher_ecc_mechanism = {CKM_SM2, NULL, 0};
    CK_BYTE srandom[32] = {0};
    CK_ULONG signlen = 64;
    CK_BYTE signbuffer[64] = {0};
    CK_ULONG enclen = 256;
    CK_BYTE encbuffer[256] = {0};

 /*   {
        CK_MECHANISM gen_key_pair_mechanism = {CKM_SM2_KEY_PAIR_GEN, NULL, 0};
        CK_OBJECT_CLASS cclass = CKO_PUBLIC_KEY;
        CK_KEY_TYPE keyType = CKK_SM2;
        CK_UTF8CHAR label[] = "An ECC public key object";
        CK_BBOOL _true = TRUE;
        CK_BBOOL _false = FALSE;
        CK_BYTE params_value[] = "this is sm2  params value";

        CK_ATTRIBUTE publicKeyTemplate[] = {
                {CKA_CLASS, &cclass, sizeof(cclass)},
                {CKA_LOCAL, &_true, sizeof(_true)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_TOKEN, &_false, sizeof(_false)},
                {CKA_LABEL, label, sizeof(label)-1},
                {CKA_VERIFY, &_true, sizeof(_true)},
                {CKA_ECDSA_PARAMS, params_value, sizeof(params_value)}
        };
        int n_pubkey_attr = sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE);

        CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_CLASS, &privkey_class, sizeof(privkey_class)},
                {CKA_LOCAL, &_true, sizeof(_true)},
                {CKA_TOKEN, &_false, sizeof(_false)},
                {CKA_PRIVATE, &_true, sizeof(_true)},
                {CKA_SENSITIVE, &_true, sizeof(_true)},
                {CKA_SIGN, &_true, sizeof(_true)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_ECDSA_PARAMS, params_value, sizeof(params_value)}
        };
        int n_privkey_attr = sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE);;

        rv = C_GenerateKeyPair(hSession, &gen_key_pair_mechanism, publicKeyTemplate, n_pubkey_attr,
                               privateKeyTemplate, n_privkey_attr, &hPublicKey, &hPrivateKey);
        if (rv != CKR_OK)
        {
            LOGEE(tag, "PKCS11 Generate Key Pair Failed:%08x\n", rv);
            return rv;
        }

        rv = C_SignInit(hSession, &cipher_ecc_mechanism, hPrivateKey);
        if (rv != CKR_OK)
        {
            LOGEE(tag, "PKCS11 Sign Initialize Key Failed:%08x\n", rv);
            return rv;
        }

        rv = C_Sign(hSession, srandom, sizeof(srandom), signbuffer, &signlen);
        if (rv != CKR_OK)
        {
            LOGEE(tag, "PKCS11 Sign Failed:%08x\n", rv);
            return rv;
        }

        rv = C_VerifyInit(hSession, &cipher_ecc_mechanism, hPublicKey);
        if (rv != CKR_OK)
        {
            LOGEE(tag, "PKCS11 Verify Initialize Key Failed:%08x\n", rv);
            return rv;
        }

        rv = C_Verify(hSession, srandom, sizeof(srandom), signbuffer, signlen);
        if (rv != CKR_OK)
        {
            LOGEE(tag, "PKCS11 Verify Failed:%08x", rv);
            return rv;
        }
    }
*/
    {
        CK_MECHANISM gen_key_pair_mechanism = {CKM_SM2_KEY_PAIR_GEN, NULL, 0};
        CK_OBJECT_CLASS cclass = CKO_PUBLIC_KEY;
        CK_KEY_TYPE keyType = CKK_SM2;
        CK_UTF8CHAR label[] = "An ECC public key object";
        CK_BBOOL _true = TRUE;
        CK_BBOOL _false = FALSE;
        CK_BYTE params_value[] = "this is sm2  params value";

        CK_ATTRIBUTE publicKeyTemplate[] = {
                {CKA_CLASS, &cclass, sizeof(cclass)},
                {CKA_LOCAL, &_true, sizeof(_true)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_TOKEN, &_false, sizeof(_false)},
                {CKA_LABEL, label, sizeof(label)-1},
                {CKA_ENCRYPT, &_true, sizeof(_true)},
                {CKA_ECDSA_PARAMS, params_value, sizeof(params_value)}
        };
        int n_pubkey_attr = sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE);

        CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_CLASS, &privkey_class, sizeof(privkey_class)},
                {CKA_LOCAL, &_true, sizeof(_true)},
                {CKA_TOKEN, &_false, sizeof(_false)},
                {CKA_PRIVATE, &_true, sizeof(_true)},
                {CKA_SENSITIVE, &_true, sizeof(_true)},
                {CKA_DECRYPT, &_true, sizeof(_true)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_ECDSA_PARAMS, params_value, sizeof(params_value)}
        };
        int n_privkey_attr = sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE);;

        rv = C_GenerateKeyPair(hSession, &gen_key_pair_mechanism, publicKeyTemplate, n_pubkey_attr,
                               privateKeyTemplate, n_privkey_attr, &hPublicKey, &hPrivateKey);
        if (rv != CKR_OK)
        {
            LOGEE(tag,"PKCS11 Generate Key Pair Failed:%08x\n", rv);
            return rv;
        }

        rv = C_EncryptInit(hSession, &cipher_ecc_mechanism, hPublicKey);
        if (rv != CKR_OK)
        {
            LOGEE(tag,"PKCS11 Encrypt Initialize Key Failed:%08x\n", rv);
            return rv;
        }

        rv = C_Encrypt(hSession, srandom, sizeof(srandom), encbuffer, &enclen);
        if (rv != CKR_OK)
        {
            LOGEE(tag,"PKCS11 Encrypt Failed:%08x\n", rv);
            return rv;
        }

        rv = C_DecryptInit(hSession, &cipher_ecc_mechanism, hPrivateKey);
        if (rv != CKR_OK)
        {
            LOGEE(tag,"PKCS11 Decrypt Initialize Key Failed:%08x\n", rv);
            return rv;
        }

        signlen = sizeof(signbuffer);
        rv = C_Decrypt(hSession, encbuffer, enclen, signbuffer, &signlen);
        if (rv != CKR_OK)
        {
            LOGEE(tag,"PKCS11 Decrypt Failed:%08x\n", rv);
            return rv;
        }

        if (0 != memcmp(srandom, signbuffer, sizeof(srandom)))
        {
            LOGEE(tag,"SM2 Crypto Failed\n");
        }
    }

 /*   {
        // Wrap with SM2
        CK_MECHANISM gen_key_pair_mechanism = {CKM_SM2_KEY_PAIR_GEN, NULL, 0};
        CK_OBJECT_CLASS cclass = CKO_PUBLIC_KEY;
        CK_KEY_TYPE keyType = CKK_SM2;
        CK_UTF8CHAR label[] = "An ECC public key object";
        CK_BBOOL _true = TRUE;
        CK_BBOOL _false = FALSE;
        CK_BYTE params_value[] = "this is sm2  params value";

        CK_ATTRIBUTE publicKeyTemplate[] = {
                {CKA_CLASS, &cclass, sizeof(cclass)},
                {CKA_LOCAL, &_true, sizeof(_true)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_TOKEN, &_false, sizeof(_false)},
                {CKA_LABEL, label, sizeof(label)-1},
                {CKA_ENCRYPT, &_true, sizeof(_true)},
                {CKA_WRAP, &_true, sizeof(_true)},
                {CKA_ECDSA_PARAMS, params_value, sizeof(params_value)}
        };
        int n_pubkey_attr = sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE);

        CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE privateKeyTemplate[] = {
                {CKA_CLASS, &privkey_class, sizeof(privkey_class)},
                {CKA_LOCAL, &_true, sizeof(_true)},
                {CKA_TOKEN, &_false, sizeof(_false)},
                {CKA_PRIVATE, &_true, sizeof(_true)},
                {CKA_SENSITIVE, &_true, sizeof(_true)},
                {CKA_DECRYPT, &_true, sizeof(_true)},
                {CKA_UNWRAP, &_true, sizeof(_true)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_ECDSA_PARAMS, params_value, sizeof(params_value)}
        };
        int n_privkey_attr = sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE);

        //  Wrap with SM4
        CK_MECHANISM gen_key_mechanism = {CKM_SM4_KEY_GEN, NULL, 0};
        CK_OBJECT_CLASS sclass = CKO_SECRET_KEY;
        CK_KEY_TYPE skeyType = CKK_SM4;

        CK_ATTRIBUTE key_tmp[] = {
                {CKA_CLASS, &sclass, sizeof(cclass)},
                {CKA_KEY_TYPE, &skeyType, sizeof(keyType)},
                {CKA_EXTRACTABLE, &_true, sizeof(_true)},
                {CKA_ENCRYPT, &_true, sizeof(_true)},
                {CKA_DECRYPT, &_true, sizeof(_true)}
        };
        int n_key_attr = sizeof(key_tmp)/sizeof(CK_ATTRIBUTE);

        //  Wrap mechanism
        CK_MECHANISM wrap_mechanism = {CKM_SM2, NULL, 0};
        CK_BYTE wrappedKey[256] = {0};
        CK_ULONG wrappedLen = 0;

        rv = C_GenerateKeyPair(hSession, &gen_key_pair_mechanism, publicKeyTemplate, n_pubkey_attr,
                               privateKeyTemplate, n_privkey_attr, &hPublicKey, &hPrivateKey);
        if (rv != CKR_OK)
        {
            LOGEE("PKCS11 Generate Key Pair Failed:%08x\n", rv);
            return rv;
        }

        rv = C_GenerateKey(hSession, &gen_key_mechanism, key_tmp, n_key_attr, &hKey);
        if (rv != CKR_OK)
        {
            LOGEE("PKCS11 Generate Key Failed:%08x\n", (CK_UINT)rv);
            return rv;
        }

        rv = C_WrapKey(hSession, &wrap_mechanism, hPublicKey, hKey, wrappedKey, &wrappedLen);
        if (rv != CKR_OK)
        {
            LOGEE("PKCS11 Wrap Key Failed:%08x\n", rv);
            return rv;
        }

        rv = C_UnwrapKey(hSession, &wrap_mechanism, hPrivateKey, wrappedKey, wrappedLen, key_tmp, n_key_attr, &hKey1);
        if (rv != CKR_OK)
        {
            LOGEE("PKCS11 Unwrap Key Failed:%08x\n", rv);
            return rv;
        }
    }
*/
    LOGEE(tag,"PKCS11 sm2 success:%08x", rv);
    return rv;
}
CK_ULONG xtest_SM2_keytest()
{
    CK_RV ret=0;
    int bRtn=0;
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    CK_OBJECT_HANDLE * phPublicKey = &hPublicKey, *phPrivateKey = &hPrivateKey;
    string info;
    char n[1024 * 1024] = {0};

    int i=0,j=0;
    CK_BYTE pData[2048]={0};

    CK_MECHANISM      mechanism = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_BYTE      subject[] = {0x00,0x01,0x02};
    CK_BYTE      idid[] = {0x00,0x01,0x02,0x03};
    CK_BBOOL     ttrue = CK_TRUE, ffalse = CK_FALSE;
    CK_KEY_TYPE  keyType=CKK_SM2;
    CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY,priclass=CKO_PRIVATE_KEY;


    CK_ULONG ulObjectCount = 0;

    CK_BYTE sm2pubvalue[64] = {0};
    CK_ATTRIBUTE SM2GetPubKeyTemplate[] = {
            {CKA_VALUE, sm2pubvalue, sizeof(sm2pubvalue)}
    };

    CK_BYTE sm2privalue[32] = {0};
    CK_ATTRIBUTE SM2GetPriKeyTemplate[] = {
            {CKA_VALUE, sm2privalue, sizeof(sm2privalue)}
    };

    CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_TOKEN, &ttrue, sizeof(ttrue)},
            {CKA_ENCRYPT, &ffalse, sizeof(ttrue)},
            {CKA_VERIFY, &ttrue, sizeof(ttrue)},
            {CKA_SUBJECT, subject, sizeof(subject)},
            {CKA_ID, idid, sizeof(idid)},
            {CKA_PRIVATE, &ffalse, sizeof(ffalse)},
            { CKA_WRAP, &ffalse, sizeof(ffalse) },
            {CKA_EXTRACTABLE, &ttrue, sizeof(ttrue) },
            {CKA_KEY_TYPE,&keyType,sizeof(keyType)}
    };
    CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_TOKEN, &ttrue, sizeof(ttrue)},
            {CKA_PRIVATE, &ttrue, sizeof(ttrue)},
            {CKA_SUBJECT, subject, sizeof(subject)},
            {CKA_ID, idid, sizeof(idid)},
            {CKA_SENSITIVE, &ttrue, sizeof(ttrue)},
            {CKA_DECRYPT, &ffalse, sizeof(ttrue)},
            {CKA_SIGN, &ttrue, sizeof(ttrue)},
            { CKA_UNWRAP, &ffalse, sizeof(ffalse) },
            {CKA_KEY_TYPE,&keyType,sizeof(keyType)}
    };

    CK_ATTRIBUTE pubFindKeyTemplate[1] = {
            {CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)}
    };

    CK_ATTRIBUTE prvFindKeyTemplate[1] = {
            {CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)}
    };

    CK_ATTRIBUTE flashFindKeyTemplate[1] = {
            {CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)}
    };


    CK_OBJECT_HANDLE_PTR hObject = NULL_PTR;

    TimeStart();
    ret = C_GenerateKeyPair(hSession, &mechanism,
                            publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
                            privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),
                            phPublicKey, phPrivateKey);
    Save("C_GenerateKeyPair0",ret,"",TimeEnd());

    TimeStart();
    ret = C_GetAttributeValue(hSession, hPublicKey, SM2GetPubKeyTemplate, sizeof(SM2GetPubKeyTemplate)/sizeof(CK_ATTRIBUTE));
    info.clear();
    info.append("pubkey: 0x");
    for(int i=0;i<SM2GetPubKeyTemplate[0].ulValueLen;i++)
    {
        sprintf(n,"%02x",*((CK_BYTE_PTR)(SM2GetPubKeyTemplate[0].pValue)+i));
        info.append(n);
    }
    Save("C_GetAttributeValue ",ret,info,TimeEnd());

    TimeStart();
    ret = C_GetAttributeValue(hSession, hPrivateKey, SM2GetPriKeyTemplate, sizeof(SM2GetPriKeyTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_GetAttributeValue, prikey should fail",ret,"",TimeEnd());

    //find key
    hObject = NULL_PTR;
    hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16);
    ulObjectCount = 16;

    TimeStart();
    ret = C_FindObjectsInit(hSession, flashFindKeyTemplate, sizeof(flashFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit",ret,"",TimeEnd());

    TimeStart();
    ret = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
    sprintf(n,"%ld",ulObjectCount);
    info.clear();
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulObjectCount;i++)
    {
        sprintf(n," 0x%08x",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects",ret,info,TimeEnd());

    TimeStart();
    ret = C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal",ret,"",TimeEnd());

    free(hObject);

    hObject = NULL_PTR;
    hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16);
    ulObjectCount = 16;

    TimeStart();
    ret = C_FindObjectsInit(hSession, prvFindKeyTemplate, sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit pubkey",ret,"",TimeEnd());

    TimeStart();
    ret = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
    sprintf(n,"%ld",ulObjectCount);
    info.clear();
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulObjectCount;i++)
    {
        sprintf(n," 0x%08x",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects pubkey",ret,info,TimeEnd());

    TimeStart();
    ret =C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal pubkey",ret,"",TimeEnd());

    free(hObject);

    hObject = NULL_PTR;
    hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16);
    ulObjectCount = 16;
    TimeStart();
    ret = C_FindObjectsInit(hSession, pubFindKeyTemplate, sizeof(pubFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
    Save("C_FindObjectsInit prikey",ret,"",TimeEnd());

    TimeStart();
    ret = C_FindObjects(hSession, hObject, 16, &ulObjectCount);
    sprintf(n,"%ld",ulObjectCount);
    info.clear();
    info.append("object count = ");
    info.append(n);
    for(int i=0;i<ulObjectCount;i++)
    {
        sprintf(n," 0x%08x",hObject[i]);
        info.append(n);
    }
    Save("C_FindObjects prikey",ret,info,TimeEnd());

    TimeStart();
    ret = C_FindObjectsFinal(hSession);
    Save("C_FindObjectsFinal prikey",ret,"",TimeEnd());

    free(hObject);

    //destroy generated keypair
    TimeStart();
    ret = C_DestroyObject(hSession, hPublicKey);
    Save("C_DestroyObject pub",ret,"",TimeEnd());

    TimeStart();
    ret = C_DestroyObject(hSession, hPrivateKey);
    Save("C_DestroyObject pri",ret,"",TimeEnd());

    return 0;
}


CK_ULONG xtest_SM2calcimportkey(int looptime, int datalen)
{
    string info;
    char n[1024 * 1024] = {0};
    CK_RV rv=0;
    int bRtn=0;
    bool genkey = FALSE;
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
    CK_OBJECT_HANDLE * phPublicKey = &hPublicKey, *phPrivateKey = &hPrivateKey;

    int i=0,j=0;
    CK_BYTE pData[2048]={0};

    CK_MECHANISM      mechanism = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_BYTE      subject[] = {0x00,0x01,0x02};
    CK_BYTE      id[] = {0x00,0x01,0x02,0x03};
    CK_BBOOL     ttrue = CK_TRUE, ffalse = CK_FALSE;
    CK_KEY_TYPE  keyType=CKK_SM2;
    CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY,priclass=CKO_PRIVATE_KEY;

    CK_MECHANISM  mechanismcalc = {CKM_SM2, NULL_PTR, 0};
    CK_MECHANISM  mechanismcalc2 = {CKM_SM2, NULL_PTR, 0};
    CK_BYTE       pOutData[256];
    CK_ULONG      ulOutDataLen=sizeof(pOutData);
    CK_BYTE       pOutData1[512];
    CK_ULONG      ulOutDataLen1=sizeof(pOutData1);
    CK_SESSION_HANDLE session = hSession;

    CK_BYTE pub_key[64] = {
            0xec,0x91,0x81,0x8d,0xe0,0xb7,0x01,0x21,0x73,0xf5,0x1c,0x33,0x75,0x43,0x6e,0x43,
            0xb6,0xa9,0xa2,0x6a,0xbd,0x6d,0xbc,0xb7,0x9f,0x85,0x1c,0xde,0xaf,0x7a,0x0f,0x6c,
            0xcb,0xf4,0xb5,0xa1,0x5f,0xb8,0x7e,0x60,0xfc,0x0b,0x3a,0x92,0x3d,0x12,0xe8,0x66,
            0x36,0x4a,0x93,0x5f,0xfb,0x30,0x84,0x2b,0xc9,0x13,0x9e,0xbd,0x2d,0xdc,0xe9,0x61
    };
    CK_BYTE     pri_key[32]={
            0xc5,0x6a,0x2b,0x58,0xa0,0x94,0xef,0x24,0x41,0x03,0x79,0x45,0xba,0xb1,0x39,0x8c,
            0xc0,0xdf,0x9f,0xc4,0xf9,0x9e,0x9a,0x60,0x2c,0xd8,0x6f,0xc2,0xc3,0x88,0xad,0x0c
    };

    CK_UINT pub_key_len = 64;
    CK_UINT pri_key_len = 32;

    CK_BYTE sm2pubvalue[64] = {0};
    CK_ATTRIBUTE SM2GetPubKeyTemplate[] = {
            {CKA_VALUE, sm2pubvalue, sizeof(sm2pubvalue)}
    };

    CK_BYTE sm2privalue[32] = {0};
    CK_ATTRIBUTE SM2GetPriKeyTemplate[] = {
            {CKA_VALUE, sm2privalue, sizeof(sm2privalue)}
    };

    CK_BYTE ecdsa[10] = {0};
    CK_UTF8CHAR label[] = "An ECC public key object";
    CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_CLASS, &pubclass, sizeof(pubclass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_TOKEN, &ttrue, sizeof(ttrue)},
   //         {CKA_LABEL, label, sizeof(label)-1},
            {CKA_WRAP, &ttrue, sizeof(ttrue)},
   //         {CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
            {CKA_VERIFY, &ttrue, sizeof(ttrue)},
    //        {CKA_ECDSA_PARAMS, ecdsa, sizeof(ecdsa)},   //for softcard test
            {CKA_VALUE, pub_key, sizeof(pub_key)},
            {CKA_SENSITIVE, &ttrue, sizeof(ttrue)},
            {CKA_ID, id, sizeof(id)}
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_TOKEN, &ttrue, sizeof(ttrue)},
            {CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
            {CKA_PRIVATE, &ttrue, sizeof(ttrue)},
      //      {CKA_DECRYPT, &ttrue, sizeof(ttrue)},
            {CKA_SIGN, &ttrue, sizeof(ttrue)},
            {CKA_KEY_TYPE,&keyType,sizeof(keyType)},
            {CKA_VALUE,pri_key, sizeof(pri_key)},
     //       {CKA_ECDSA_PARAMS, ecdsa, sizeof(ecdsa)},   //for softcard test
            {CKA_ID, id, sizeof(id)}
    };

    info.clear();
    info.append("hPublicKey: ");
    TimeStart();
    rv = C_CreateObject(session,publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),phPublicKey);
    sprintf(n,"0x%08x",hPublicKey);
    info.append(n);
    Save("C_CreateObject pub",rv,info,TimeEnd());

    if(rv !=0)
        goto END;

    info.clear();
    info.append("hPrivateKey: ");
    TimeStart();
    rv = C_CreateObject(session, privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE), phPrivateKey);
    sprintf(n,"0x%08x",hPrivateKey);
    info.append(n);
    Save("C_CreateObject pri",rv,info,TimeEnd());

    if(rv !=0)
        goto END;

    srand( (unsigned)time( NULL ) );

    for(j = 0; j < looptime; j++)
    {
        RandomGenerate(pData,datalen);

#if 0
        TimeStart();
        rv=C_EncryptInit(session,&mechanismcalc,hPublicKey);
        Save("C_EncryptInit",rv,"",TimeEnd());
        if(rv !=0)
            goto END;

        TimeStart();
        rv=C_Encrypt(session,pData,datalen,NULL_PTR,&ulOutDataLen);
        Save("C_Encrypt1",rv,"",TimeEnd());

        memset(pOutData,0,ulOutDataLen);

        TimeStart();
        rv=C_Encrypt(session,pData,datalen,pOutData,&ulOutDataLen);
        info.clear();

        if(rv !=0)
        {
            Save("C_Encrypt2",rv,info,TimeEnd());
            goto END;
        }


        if(looptime == 1)
        {
            if (SM2Init() != SM2_OK)
            {
                info.append("SM2InitB fail\n");
            }

            int r = SM2Decrypt(pOutData, ulOutDataLen, pri_key, sizeof(pri_key), pOutData1, (int*) &ulOutDataLen1);
            if (r!= SM2_OK)
            {
                info.append("SM2Decrypt(soft verify) fail,r = ");
                sprintf(n,"%d",r);
                info.append(n);
                Save("C_Encrypt2",rv,info,TimeEnd());
                goto END;
            }
            if((ulOutDataLen1!=datalen)||(memcmp(pOutData1,pData,datalen)!=0))
            {
                info.append("SM2 Encrypt output Error!!");
                Save("C_Encrypt2",rv,info,TimeEnd());
                goto END;
            }
            else{
                info.append("SM2 enc success!");
                Save("C_Encrypt2",rv,info,TimeEnd());
            }
        }


        TimeStart();
        rv=C_DecryptInit(session,&mechanismcalc,hPrivateKey);
        Save("C_DecryptInit",rv,"",TimeEnd());

        if(rv !=0)
            goto END;

        TimeStart();
        rv=C_Decrypt(session,pOutData,ulOutDataLen,NULL_PTR,&ulOutDataLen1);
        Save("C_Decrypt1",rv,"",TimeEnd());

        if(rv !=0)
            goto END;

        TimeStart();
        rv=C_Decrypt(session,pOutData,ulOutDataLen,pOutData1,&ulOutDataLen1);
        info.clear();

        if(rv !=0)
        {
            info.append("SM2 dec error!");
            Save("C_Decrypt2",rv,info,TimeEnd());
            goto END;
        }


        if((ulOutDataLen1!=datalen)||(memcmp(pOutData1,pData,datalen)!=0))
        {
            info.append("SM2 decrypt Error!");
            Save("C_Decrypt2",rv,info,TimeEnd());
            goto END;
        } else{
            info.append("SM2 dec success!");
            Save("C_Decrypt2",rv,info,TimeEnd());
        }
#endif
        if(datalen==32)
        {
            ulOutDataLen=sizeof(pOutData);
            memset(pOutData,0,ulOutDataLen);

            TimeStart();
            rv=C_SignInit(session,&mechanismcalc2,hPrivateKey);
            Save("C_SignInit",rv,"",TimeEnd());

            TimeStart();
            rv=C_Sign(session,pData,datalen,pOutData,&ulOutDataLen);
            info.clear();

            if(rv !=0)
            {
                info.append("SM2 sign error!");
                Save("C_Sign",rv,info,TimeEnd());
                goto END;
            }

            if(looptime==1)
            {
                if (SM2Init() != SM2_OK)
                {
                    info.append("SM2InitB fail\n");
                    Save("C_Sign",rv,info,TimeEnd());
                    goto END;
                }

                if(SM2VerifyHash(pData,32,pub_key,64,pOutData,ulOutDataLen)!=0)
                {
                    info.append("SM2 verify hash Error!!");
                    Save("C_Sign",rv,info,TimeEnd());
                    goto END;
                } else{
                    info.append("SM2 sign success!");
                    Save("C_Sign",rv,info,TimeEnd());
                }
            }


            TimeStart();
            rv=C_VerifyInit(session,&mechanismcalc2,hPublicKey);
            Save("C_VerifyInit",rv,"",TimeEnd());

            TimeStart();
            rv=C_Verify(session,pData,datalen,pOutData,ulOutDataLen);
            Save("C_Verify",rv,"",TimeEnd());
        }
    }


    END:
    TimeStart();
    rv = C_DestroyObject(session,hPublicKey);
    Save("C_DestroyObject pub",rv,"",TimeEnd());
    TimeStart();
    rv = C_DestroyObject(session,hPrivateKey);
    Save("C_DestroyObject pri",rv,"",TimeEnd());

    return 0;
}


#if 0
CK_ULONG xtest_SM3Encrypt()
{
	CK_ULONG bRtn = 0;
	CK_RV rv = 0;
	int i = 0;
	CK_BYTE srcData[64] = {0};
	for(i = 0;i < sizeof(srcData)/4;i++)
	{
		memcpy(&srcData[i*4],"abcd",4);
	}
	unsigned char pszCorrectResult_SM3[]={0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d, 0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32};
	CK_BYTE digData[100];
	CK_ULONG ulDigLen=sizeof(digData);

	CK_MECHANISM mechanism={CKM_HASH_SM3,NULL_PTR,0};

	//UtilsPrintData(VNAME(srcData),sizeof(srcData),0);
	rv=FunctionPtr->C_DigestInit(session,&mechanism);
	RV_NOT_OK_RETURN_FALSE(pC_DigestInit,rv);

	if(rv != CKR_OK)
	{
		rv = FunctionPtr->C_Login(session,CKU_USER,pusrpin,strlen((char*)pusrpin));
		if (rv != CKR_OK)
		{ 
			   printf("CKU_USER C_Login error with default_usrerr_pin, should be error: rc = 0x%08lx\n", rv); 
		} 
		else
		{
				printf("Login OK\n");
		
		}

		rv=FunctionPtr->C_DigestInit(session,&mechanism);
		RV_NOT_OK_RETURN_FALSE(pC_DigestInit,rv);
	}

	rv=(FunctionPtr->C_DigestInit)(session,&mechanism);
	printf("SECOND init, should fail. rv = 0x%08lx \n", rv);
	RV_NOT_OK_RETURN_TRUE(pC_DigestInit1,rv);
		
	ulDigLen=sizeof(digData);
	rv=FunctionPtr->C_Digest(session,srcData,sizeof(srcData),digData,&ulDigLen);
	RV_NOT_OK_RETURN_FALSE(pC_Digest,rv);

	rv=FunctionPtr->C_Digest(session,srcData,sizeof(srcData),digData,&ulDigLen);
	printf("SECOND digest, should fail. rv = 0x%08lx \n", rv);
	RV_NOT_OK_RETURN_TRUE(pC_Digest2,rv);


//	UtilsPrintData(VNAME(digData),ulDigLen,0);
	
	if (memcmp(pszCorrectResult_SM3, digData, ulDigLen))
	{
		printf("test_digest failed.SM3 Result is wrong1!!! \n");
//		nResultLength += sprintf(Testresult[nItemNumb] + nResultLength, "test_digest failed.SM3 Result is wrong1! <br>");
		bRtn= 1;
		goto END;
	}
	else
	{
		printf("SM3 Digest Result is correct!\n");
	}
	
	rv=FunctionPtr->C_DigestInit(session,&mechanism);
	RV_NOT_OK_RETURN_FALSE(pC_DigestInit,rv);

	rv=FunctionPtr->C_DigestUpdate(session,srcData,sizeof(srcData)/2);
	RV_NOT_OK_RETURN_FALSE(pC_DigestUpdate1,rv);

	rv=FunctionPtr->C_DigestUpdate(session,srcData+sizeof(srcData)/2,sizeof(srcData)-sizeof(srcData)/2);
	RV_NOT_OK_RETURN_FALSE(pC_DigestUpdate2,rv);
		
	ulDigLen=sizeof(digData);
	rv=FunctionPtr->C_DigestFinal(session,digData,&ulDigLen);
	RV_NOT_OK_RETURN_FALSE(pC_DigestFinal,rv);

	rv=FunctionPtr->C_DigestFinal(session,digData,&ulDigLen);
	printf("SECOND final, should fail. rv = 0x%08lx \n", rv);
	RV_NOT_OK_RETURN_TRUE(pC_DigestFinal2,rv);

//	UtilsPrintData(VNAME(digData),ulDigLen,0);
	
	if (memcmp(pszCorrectResult_SM3, digData, ulDigLen))
	{
		printf("test_digest failed.SM3 Result is wrong2!!! \n");
		bRtn= 1;
		goto END;
	}
	else
	{
		printf("SM3 Updated Digest Result is correct!\n");
	}

END:
//	ENTER_LEAVE_FUNCTION(Testresult[nItemNumb],&nResultLength,xTestSM3Encrypt);
	
	return bRtn;
}


CK_ULONG xtest_SM3Performance(int looptime,int datalen)
{
	CK_RV rv=0;
	CK_ULONG bRtn=0;
	int i=0;
	CK_ULONG ulSlotCountXX=0;	

	CK_BYTE digData[100],digData1[100];
	CK_ULONG ulDigLen=sizeof(digData);
	CK_ULONG ulDigLen1=sizeof(digData1);

	CK_MECHANISM mechanism={CKM_HASH_SM3,NULL_PTR,0};	

	CK_BYTE srcData[5000]={0};
	UtilscTime ttc1={0, 0},ttc2={0,0},ttc3={0,0},ttc4={0,0};

	printf("input looptime:\n");
	CK_BYTE ch[10];
	fgets(ch,10,stdin);
   	looptime = atoi(ch);

	printf("input datalen(0-5000):\n");
	fgets(ch,10,stdin);
   	datalen = atoi(ch);

//	ENTER_LEAVE_FUNCTION(Testresult[nItemNumb],&nResultLength,xTestSM3Performance);
	
	printf("Datalen=%d.looptime = %d.\n",datalen,looptime);
//	nResultLength += sprintf(Testresult[nItemNumb]+nResultLength ,"Datalen=%d.<br>",datalen);
	for(i=0;i<looptime;i++)
	{
			srand( (unsigned)time( NULL ) );//??????
			//???????	
			RandomGenerate(srcData,datalen);
			Utilsgettime(&ttc1);
			rv=(FunctionPtr->C_DigestInit)(session,&mechanism);
			RV_NOT_OK_RETURN_FALSE(pC_DigestInit1,rv);
			ulDigLen=sizeof(digData);

			
			rv=(FunctionPtr->C_Digest)(session,srcData,datalen,digData,&ulDigLen);
			RV_NOT_OK_RETURN_FALSE(pC_Digest,rv);
			Utilsgettime(&ttc2);			
			UtilsTimeSubstracted(&ttc2,&ttc1);			
			UtilsTimeAdded(&ttc3,&ttc2);

			Utilsgettime(&ttc1);
			rv=(FunctionPtr->C_DigestInit)(session,&mechanism);
			RV_NOT_OK_RETURN_FALSE(pC_DigestInit2,rv);

			rv=(FunctionPtr->C_DigestUpdate)(session,srcData,datalen/2);
			RV_NOT_OK_RETURN_FALSE(pC_DigestUpdate1,rv);

			rv=(FunctionPtr->C_DigestUpdate)(session,srcData+datalen/2,datalen-datalen/2);
			RV_NOT_OK_RETURN_FALSE(pC_DigestUpdate2,rv);

			rv=(FunctionPtr->C_DigestFinal)(session,digData1,&ulDigLen1);
			RV_NOT_OK_RETURN_FALSE(pC_DigestFinal,rv);
			Utilsgettime(&ttc2);
			UtilsTimeSubstracted(&ttc2,&ttc1);
			UtilsTimeAdded(&ttc4,&ttc2);
			if (ulDigLen!=ulDigLen1)
			{
				printf("test_digest failed.???????\n");
//				nResultLength += sprintf(Testresult[nItemNumb] + nResultLength , "test_digest failed.???????<br>");
				bRtn = 1;
				goto END;
			}
			if (memcmp(digData, digData1, ulDigLen))
			{
				printf("test_digest failed.?????????\n");
//				nResultLength += sprintf(Testresult[nItemNumb]+nResultLength , "test_digest failed.?????????<br>");
				bRtn = 1;
				goto END;
			}	
	}

	Utilsprint(&ttc3,"Digest", looptime);
//	nResultLength += Utilssprint(&ttc3,Testresult[nItemNumb]+ nResultLength,"Digest", looptime);
	Utilsprint(&ttc4,"Digest Update", looptime);
//	nResultLength += Utilssprint(&ttc4,Testresult[nItemNumb]+ nResultLength,"Digest", looptime);
	

	//printf("after pC_DigestFinal ok sleep\n");
	//sleep(30);

	//pC_Proxy_Final();

	//rv=pC_Proxy_Init();
	//RV_NOT_OK_RETURN_FALSE(Testresult[nItemNumb],&nResultLength,pC_Proxy_Init,rv);

	//rv = (*pC_Initialize)(NULL_PTR);
	//RV_NOT_OK_RETURN_FALSE(Testresult[nItemNumb],&nResultLength,pC_Initialize,rv);

	//rv=(*pC_GetSlotList)(CK_TRUE,NULL_PTR,&ulSlotCountXX);
	//RV_NOT_OK_RETURN_FALSE(Testresult[nItemNumb],&nResultLength,pC_GetSlotList,rv);

	//rv=(*pC_GetSlotList)(CK_TRUE,pSlotList,&ulSlotCount);

//	bRtn=true;
END:
//	ENTER_LEAVE_FUNCTION(Testresult[nItemNumb],&nResultLength,xTestSM3Performance);
	return bRtn;
}


#define DESTORYUSELESSKEY
CK_ULONG xtest_FindKeyObjectAndDestroy()
{
	CK_RV rv=0;
	CK_ULONG bRtn=0;
	CK_BYTE IDIDid[]={};//0x00};//,0x01};//,0x02};//,0x03};
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY,priclass=CKO_PRIVATE_KEY,secretclass = CKO_SECRET_KEY;	
	CK_BYTE keyID3 = CK_SESSKEY_ID3;

	CK_ATTRIBUTE pubFindKeyTemplate[] = {
		{CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)}
	};

	CK_ATTRIBUTE prvFindKeyTemplate[] = {
		{CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)}
	};

	CK_ATTRIBUTE secFindKeyTemplate[] = {
		{CKA_CLASS, &secretclass, sizeof(CK_OBJECT_CLASS)}
	};

	CK_ATTRIBUTE flashFindKeyTemplate[] = {
		{CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)}
	};
	CK_ATTRIBUTE ramFindKeyTemplate[] = {
		{CKA_TOKEN, &ffalse, sizeof(CK_BBOOL)}
	};

	CK_ATTRIBUTE SESSKEYFindKeyTemplate[] = {
		{CKA_SESSKEY_ID, &keyID3, sizeof(CK_BYTE)}
	};

	CK_OBJECT_HANDLE_PTR hObject = NULL_PTR;
	CK_OBJECT_HANDLE hObjectDestory = NULL_PTR;
	CK_ULONG ulObjectCount = 0;
	int i;
	bool destroy = FALSE;

	CK_BYTE ch[10];

	printf("Destroy all keys?(Y/N):\n");
	fgets(ch,10,stdin);
   	if(ch[0]=='Y')
   	{
   		destroy = TRUE;
   	}

	//??Flash??
	printf("\n-------??FLASH??--------\n");
	hObject = NULL_PTR;
	hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16); 
	ulObjectCount = 16;

	//UtilsPrintData(VNAME(prvFindKeyTemplate),256,0);
	//printf("count=%d\n",sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	rv = FunctionPtr->C_FindObjectsInit(session, flashFindKeyTemplate, sizeof(flashFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit1,rv);


	rv = FunctionPtr->C_FindObjects(session, hObject, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects1,rv);

	printf("FLASH Key count=%lu.\n", ulObjectCount);
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength ,"Private Key count=%d.<br>", ulObjectCount);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal1,rv);

	
	free(hObject);


	//??RAM??
	printf("\n-------??RAM??--------\n");
	hObject = NULL_PTR;
	hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16); 
	ulObjectCount = 16;

	//UtilsPrintData(VNAME(prvFindKeyTemplate),256,0);
	//printf("count=%d\n",sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	rv = FunctionPtr->C_FindObjectsInit(session, ramFindKeyTemplate, sizeof(ramFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit1,rv);


	rv = FunctionPtr->C_FindObjects(session, hObject, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects1,rv);

	printf("ram Key count=%lu.\n", ulObjectCount);
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength ,"Private Key count=%d.<br>", ulObjectCount);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal1,rv);

	
	free(hObject);

		//??sesskey??
	printf("\n-------??sesskey??--------\n");
	hObject = NULL_PTR;
	hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16); 
	ulObjectCount = 16;

	//UtilsPrintData(VNAME(prvFindKeyTemplate),256,0);
	//printf("count=%d\n",sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	rv = FunctionPtr->C_FindObjectsInit(session, SESSKEYFindKeyTemplate, sizeof(SESSKEYFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit1,rv);


	rv = FunctionPtr->C_FindObjects(session, hObject, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects1,rv);

	printf("ram Key count=%lu.\n", ulObjectCount);
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength ,"Private Key count=%d.<br>", ulObjectCount);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal1,rv);

	
	free(hObject);

	//??????	
	printf("\n-------??????--------\n");
	hObject = NULL_PTR;
	hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16); 
	ulObjectCount = 16;

	//UtilsPrintData(VNAME(prvFindKeyTemplate),256,0);
	//printf("count=%d\n",sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	rv = FunctionPtr->C_FindObjectsInit(session, prvFindKeyTemplate, sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit1,rv);

	rv = FunctionPtr->C_FindObjectsInit(session, prvFindKeyTemplate, sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_TRUE(pC_FindObjectsInit,rv);

	rv = FunctionPtr->C_FindObjects(session, hObject, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects1,rv);

	printf("Private Key count=%lu.\n", ulObjectCount);
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength ,"Private Key count=%d.<br>", ulObjectCount);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal1,rv);

	if(destroy)
	{
		hObjectDestory = NULL_PTR;
		for(i=0;i<ulObjectCount;i++)
		{
			hObjectDestory=hObject[i];
			printf("Private i=%d,KeyObject=0x%08lx.\n",i,hObjectDestory);
			rv = FunctionPtr->C_DestroyObject(session, hObjectDestory);
			RV_NOT_OK_RETURN_FALSE(pC_DestroyObject1,rv);
		}
	}

	free(hObject);

	//??????
	printf("\n-------??????--------\n");
	hObject = NULL_PTR;
	hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16);
	ulObjectCount = 16;
	rv = FunctionPtr->C_FindObjectsInit(session, pubFindKeyTemplate, sizeof(pubFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit2,rv);

	rv = FunctionPtr->C_FindObjects(session, hObject, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects2,rv);
	
	printf("Public Key count=%lu.\n", ulObjectCount);
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength ,"Public Key count=%d.<br>", ulObjectCount);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal2,rv);

	if(destroy)
	{
		hObjectDestory = NULL_PTR;
		for(i=0;i<ulObjectCount;i++)
		{
			hObjectDestory=hObject[i];
			printf("Public i=%d,KeyObject=0x%08lx.\n",i,hObjectDestory);
			rv = (FunctionPtr->C_DestroyObject)(session, hObjectDestory);
			RV_NOT_OK_RETURN_FALSE(pC_DestroyObject2,rv);
		}
	}
	free(hObject);

	//????????
	printf("\n-------??????--------\n");
	hObject = NULL_PTR;
	hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16);
//	ulObjectCount = 16;
	rv = FunctionPtr->C_FindObjectsInit(session, secFindKeyTemplate, sizeof(secFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit3,rv);

	rv = FunctionPtr->C_FindObjects(session, hObject, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects3,rv);
	printf("Secret Key count=%lu.\n", ulObjectCount);
//	nResultLength += sprintf(Testresult[nItemNumb]+nResultLength ,"Secret Key count=%d.<br>", ulObjectCount);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal3,rv);

	if(destroy)
	{
		hObjectDestory = NULL_PTR;
		for(i=0;i<ulObjectCount;i++)
		{
			hObjectDestory=hObject[i];
			printf("Secret i=%d,KeyObject=0x%08lx.\n",i,hObjectDestory);
			rv = FunctionPtr->C_DestroyObject(session, hObjectDestory);
			RV_NOT_OK_RETURN_FALSE(pC_DestroyObject3,rv);
		}
	}
	free(hObject);

END:
	return bRtn;
}



CK_ULONG xtest_SM4ECB_Encrypt()
{
	bool bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE SM4keyType = CKK_SM4;
	
	//????
	unsigned char	SM4keyVal_Enc[]={0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
//	unsigned char	SM4keyVal_Enc[]={0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
//	unsigned char	SM4iv_Enc[16] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
	CK_BYTE SM4plain_Enc[32]={0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
//	CK_BYTE SM4plain_Enc[32]={0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
//							  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
	CK_BYTE SM4cipher_Enc[32]={0x68, 0x6d, 0xb7, 0x66, 0xc9, 0x20, 0x48, 0x22, 0xbb, 0xfa, 0x6b, 0x84, 0x68, 0xc2, 0x86, 0x91, 
							   0x68, 0x6d, 0xb7, 0x66, 0xc9, 0x20, 0x48, 0x22, 0xbb, 0xfa, 0x6b, 0x84, 0x68, 0xc2, 0x86, 0x91};
//	CK_BYTE SM4cipher_Enc[32]={0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46, 
//							   0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};
	CK_ATTRIBUTE SM4keyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ttrue)},//FLASH ,FFLASE RAM
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,SM4keyVal_Enc,sizeof(SM4keyVal_Enc)}
	};
	CK_MECHANISM SM4mechanism_Enc = {CKM_SM4_ECB, NULL, 0};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

	CK_BYTE indata[32] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata0[32] = {0};
	CK_ULONG outdatalen0=sizeof(outdata0);
	CK_BYTE outdata[32] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	//???????
	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate_Enc, sizeof(SM4keyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject,rv);
//	printf("C_CreateObject rv = 0x%08lx\n",rv);

	printf("hkey is 0x%08lx.\n",hKey_Enc);

	CK_BYTE sm4value[16] = {0};
	CK_ATTRIBUTE SM4GetKeyTemplate[] = {
		{CKA_VALUE, sm4value, sizeof(sm4value)}
	};
	
	rv = FunctionPtr->C_GetAttributeValue(session, hKey_Enc, SM4GetKeyTemplate, sizeof(SM4GetKeyTemplate)/sizeof(CK_ATTRIBUTE));	
	printf("C_GetAttributeValue,should fail, rv = 0x%08lx\n",rv);

	UtilsPrintData(VNAME(sm4value),16,0);

	indatalen = sizeof(indata);
	memset(indata, 0, indatalen);
	outdatalen = sizeof(outdata);
	memset(outdata, 0, outdatalen);
	
	//?????
	memcpy(indata, SM4plain_Enc, sizeof(SM4plain_Enc));
	indatalen = sizeof(SM4plain_Enc);

	UtilsPrintData(VNAME(indata),indatalen,0);

	rv = FunctionPtr->C_EncryptInit(session, &SM4mechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);	
//	printf("C_EncryptInit1 rv = 0x%08lx\n",rv);

	rv = FunctionPtr->C_Encrypt(session, indata, indatalen, outdata0, &outdatalen0);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);
//	printf("C_Encrypt rv = 0x%08lx\n",rv);

	if ((outdatalen0 != sizeof(SM4cipher_Enc)) || (memcmp(outdata0, SM4cipher_Enc, sizeof(SM4cipher_Enc))))
	{
		printf("SM4 ECB Encrypt Calc Error: test_SM4Encrypt_ECB.\n");
		bRtn = 1;
	}
	else
	{
		printf("SM4 ECB Encrypt Result is correct!\n");
	}

	rv = FunctionPtr->C_EncryptInit(session, &SM4mechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);	
//	printf("C_EncryptInit rv = 0x%08lx\n",rv);

	//????
//	rv = FunctionPtr->C_EncryptUpdate(session, indata, indatalen, NULL, &outdatalen);
//	printf("outdatalen is %lu\n", outdatalen);
//	printf("C_EncryptUpdate1 rv = 0x%08lx\n",rv);
	
	rv = FunctionPtr->C_EncryptUpdate(session, indata, indatalen, outdata, &outdatalen);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);
	UtilsPrintData(VNAME(outdata),outdatalen,0);
//	printf("C_EncryptUpdate2 rv = 0x%08lx\n",rv);

	if ((outdatalen != sizeof(SM4cipher_Enc)) || (memcmp(outdata, SM4cipher_Enc, sizeof(SM4cipher_Enc))))
	{
		printf("SM4 ECB EncryptUpdated Calc Error: test_SM4Encrypt_ECB.\n"); 
		bRtn = 1;
	}
	else
	{
		printf("SM4 ECB EncryptUpdated Result is correct!\n");
	}
	rv = FunctionPtr->C_EncryptFinal(session, outdata, &outdatalen);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);
//	printf("C_EncryptFinal rv = 0x%08lx\n",rv);

	rv = FunctionPtr->C_DestroyObject(session, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject,rv);
//	printf("C_DestroyObject rv = 0x%08lx\n",rv);

END:
	return bRtn;
}


CK_ULONG xtest_Find_SM2test()
{
	
	CK_RV rv=0;
	int bRtn=0;
	CK_BBOOL     ttrue = CK_TRUE, ffalse = CK_FALSE;
	CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY,priclass=CKO_PRIVATE_KEY;
	CK_ATTRIBUTE pubFindKeyTemplate[] = {
		{CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)}
	};

	CK_ATTRIBUTE prvFindKeyTemplate[] = {
		{CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)}
	};

	CK_ATTRIBUTE flashFindKeyTemplate[] = {
		{CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)}
	};

	
	CK_OBJECT_HANDLE_PTR hObject = NULL_PTR;
	CK_ULONG ulObjectCount = 0;

	//find key
	printf("\n-------??FLASH??--------\n");
	hObject = NULL_PTR;
	hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16); 
	ulObjectCount = 16;

	//UtilsPrintData(VNAME(prvFindKeyTemplate),256,0);
	//printf("count=%d\n",sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	rv = FunctionPtr->C_FindObjectsInit(session, flashFindKeyTemplate, sizeof(flashFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit1,rv);


	rv = FunctionPtr->C_FindObjects(session, hObject, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects1,rv);

	printf("FLASH Key count=%lu.\n", ulObjectCount);
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength ,"Private Key count=%d.<br>", ulObjectCount);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal1,rv);
	
	free(hObject);
	
	//??????	
	printf("\n-------??????--------\n");
	hObject = NULL_PTR;
	hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16); 
	ulObjectCount = 16;

	//UtilsPrintData(VNAME(prvFindKeyTemplate),256,0);
	//printf("count=%d\n",sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	rv = FunctionPtr->C_FindObjectsInit(session, prvFindKeyTemplate, sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit1,rv);

	rv = FunctionPtr->C_FindObjectsInit(session, prvFindKeyTemplate, sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_TRUE(pC_FindObjectsInit,rv);

	rv = FunctionPtr->C_FindObjects(session, hObject, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects1,rv);

	printf("Private Key count=%lu.\n", ulObjectCount);
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength ,"Private Key count=%d.<br>", ulObjectCount);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal1,rv);

	free(hObject);

	//??????
	printf("\n-------??????--------\n");
	hObject = NULL_PTR;
	hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16);
	ulObjectCount = 16;
	rv = FunctionPtr->C_FindObjectsInit(session, pubFindKeyTemplate, sizeof(pubFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit2,rv);

	rv = FunctionPtr->C_FindObjects(session, hObject, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects2,rv);
	
	printf("Public Key count=%lu.\n", ulObjectCount);
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength ,"Public Key count=%d.<br>", ulObjectCount);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal2,rv);
	
	free(hObject);

	
	return bRtn;
}

CK_ULONG test_SM4FLASHValue(CK_MECHANISM_TYPE mAlgType, CK_BYTE *label, CK_ULONG labelsize)
{
	int bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE SM4keyType = CKK_SM4;

	//????
	unsigned char	SM4keyVal_Enc[]={0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
	unsigned char	SM4iv_Enc[16] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
	unsigned char	SM4plain_Enc[192]={0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
	unsigned char	SM4cipher_Enc_OFB[192]={0x73, 0xa3, 0x37, 0x80, 0x40, 0xad, 0x2f, 0x7c, 0x91, 0x81, 0x8e, 0xcd, 0x49, 0x6a, 0xe2, 0x62, 0xb8, 0x83, 0xc1, 0x38, 0x12, 0xfa, 0x3d, 0xb4, 0xfc, 0x2a, 0xf4, 0x97, 0x2b, 0xa9, 0xaf, 0xae, 0xcc, 0x8d, 0x58, 0x49, 0x07, 0x67, 0xd3, 0x76, 0xab, 0xb8, 0x1e, 0xe6, 0x8d, 0x19, 0xfa, 0xfb, 0x18, 0x3d, 0x10, 0xa9, 0x2f, 0xbb, 0xf1, 0x21, 0xa4, 0xd7, 0x2d, 0xb4, 0x1b, 0xf2, 0x42, 0x9e, 0x4b, 0x44, 0xfd, 0x08, 0x89, 0x20, 0x78, 0xf8, 0xd5, 0x7d, 0x48, 0xd1, 0x4e, 0x0a, 0x39, 0xa3, 0x88, 0xec, 0xfa, 0x04, 0x84, 0xa6, 0x24, 0x88, 0xd5, 0x91, 0xea, 0x27, 0xaa, 0x99, 0x9f, 0x29, 0xe4, 0xf0, 0x12, 0xde, 0x35, 0x07, 0x5f, 0xe2, 0x34, 0x96, 0xfb, 0x61, 0xc1, 0xff, 0xa2, 0xc7, 0x00, 0x4a, 0xd1, 0xca, 0x3b, 0xc2, 0xdb, 0x49, 0xc7, 0xd5, 0x7a, 0x04, 0x82, 0x9d, 0xfa, 0xff, 0xd2, 0xd8, 0x6c, 0x77, 0x4f, 0xa8, 0x44, 0x47, 0xdd, 0x84, 0xd4, 0xf1, 0x8e, 0xc6, 0x36, 0xfc, 0xa4, 0xd8, 0x1a, 0xa5, 0x38, 0x30, 0xc3, 0xf6, 0xde, 0xe8, 0x69, 0xb5, 0x37, 0x1b, 0x47, 0x26, 0x41, 0xf7, 0x9f, 0xac, 0x29, 0x69, 0x2e, 0xba, 0xbd, 0x55, 0x8d, 0x28, 0xa6, 0x03, 0x0e, 0xaf, 0xeb, 0x6b, 0xe9, 0xb3, 0x75, 0xe0, 0x81, 0x76, 0xc9, 0x60, 0xaa, 0x8c, 0xab, 0x70, 0x2f, 0x42};
	unsigned char	SM4cipher_Enc_ECB[192]={0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91};
	unsigned char	SM4cipher_Enc_CBC[192]={0x94, 0x0f, 0x58, 0xdf, 0xb5, 0x3e, 0x53, 0x48, 0x70, 0x14, 0xf6, 0x4d, 0x95, 0x9e, 0x12, 0x2e, 0x24, 0xd8, 0x02, 0xa7, 0x69, 0x09, 0x2f, 0xcb, 0xcd, 0xa7, 0xc0, 0x8b, 0xe3, 0x2c, 0xe8, 0x99, 0x94, 0xb3, 0x56, 0xe2, 0x90, 0x75, 0xc9, 0x82, 0x13, 0x53, 0x02, 0xc8, 0xf3, 0xe6, 0xc5, 0x7d, 0xed, 0x17, 0x16, 0x50, 0xed, 0x45, 0x2e, 0xa3, 0xaf, 0x2d, 0xce, 0xf2, 0x85, 0x42, 0x45, 0x17, 0x6c, 0xe7, 0x2e, 0x78, 0x3b, 0xfd, 0x9a, 0x8a, 0x9e, 0x6a, 0x7c, 0xa6, 0xad, 0xfa, 0x7d, 0xec, 0xde, 0xd6, 0x87, 0x3e, 0x45, 0xcd, 0x9a, 0xe9, 0x7f, 0xf5, 0x4a, 0x71, 0xe4, 0x04, 0x2b, 0x14, 0xca, 0xca, 0x43, 0x3a, 0x5a, 0x9d, 0xf3, 0x22, 0xee, 0x78, 0x7d, 0x27, 0xd1, 0x26, 0x15, 0x35, 0x5b, 0xf6, 0x78, 0x08, 0x67, 0xe8, 0xe2, 0xfd, 0xd8, 0x85, 0xbb, 0x2b, 0x41, 0xe7, 0xd3, 0xf7, 0xcb, 0x7c, 0xb3, 0x6c, 0x92, 0xdf, 0x9a, 0x07, 0x09, 0x81, 0x97, 0xec, 0x36, 0x93, 0xab, 0x96, 0xad, 0xb7, 0x61, 0x89, 0xa9, 0xa5, 0x20, 0x82, 0x5f, 0xba, 0x5f, 0xbc, 0x73, 0xdb, 0xba, 0x43, 0xc4, 0x46, 0x6f, 0xbd, 0x1e, 0x71, 0xfd, 0xb1, 0xd3, 0x80, 0xbe, 0x2d, 0xb1, 0x76, 0xbd, 0xb9, 0x3f, 0x5c, 0x58, 0x2a, 0x6d, 0x9a, 0x94, 0xca, 0x7f, 0x92, 0x8f, 0x56, 0x30, 0x9f, 0x06, 0x43};
	unsigned char	*SM4cipher_Enc = NULL;
	
	CK_ATTRIBUTE SM4keyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ffalse, sizeof(ttrue)},
		{CKA_VALUE,SM4keyVal_Enc,sizeof(SM4keyVal_Enc)},
		{CKA_LABEL,label,labelsize}
	};
	CK_MECHANISM SM4mechanism_Enc = {mAlgType, SM4iv_Enc, sizeof(SM4iv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

	//????
	CK_ATTRIBUTE SM4keyTemplate_Dec[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ffalse, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,SM4keyVal_Enc,sizeof(SM4keyVal_Enc)},
		{CKA_LABEL,label,labelsize}
	};
	CK_MECHANISM SM4mechanism_Dec = {mAlgType, SM4iv_Enc, sizeof(SM4iv_Enc)};
	CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

	CK_BYTE indata[256] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[256] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[256] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[256] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);
	int loopTime = 1;
	unsigned int i = 0;
	char  fname[4] = {0x00};
	char* fNameECB = "ECB";
	char* fNameCBC = "CBC";
	char* fNameOFB = "OFB";
	
	if (mAlgType == CKM_SM4_ECB)
	{
		SM4cipher_Enc = SM4cipher_Enc_ECB;
		SM4mechanism_Enc.pParameter = NULL;
		SM4mechanism_Enc.ulParameterLen = 0;
		SM4mechanism_Dec.pParameter = NULL;
		SM4mechanism_Dec.ulParameterLen = 0;
		strcpy(fname, fNameECB);
	}
	else if (mAlgType == CKM_SM4_CBC)
	{
		SM4cipher_Enc = SM4cipher_Enc_CBC;
		strcpy(fname, fNameCBC);
	}
	else if (mAlgType == CKM_SM4_OFB)
	{
		SM4cipher_Enc = SM4cipher_Enc_OFB;
		strcpy(fname, fNameOFB);
	}

	printf("enter %s:%s.\n",__FUNCTION__,fname);

	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate_Enc, sizeof(SM4keyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject,rv);

	hKey_Dec = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate_Dec, sizeof(SM4keyTemplate_Dec)/sizeof(CK_ATTRIBUTE), &hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject,rv);

	rv = (FunctionPtr->C_EncryptInit)(session, &SM4mechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);

	indatalen = sizeof(indata);
	memset(indata, 0, indatalen);
	outdatalen=sizeof(outdata);
	memset(outdata, 0, outdatalen);

	indatalen1 = sizeof(indata1);
	memset(indata1, 0, indatalen1);
	outdatalen1=sizeof(outdata1);
	memset(outdata1, 0, outdatalen1);

	//?????
	memcpy(indata, SM4plain_Enc, sizeof(SM4plain_Enc));
	indatalen = sizeof(SM4plain_Enc);
	
	/*******************????**********************/
	//????
	rv = (FunctionPtr->C_EncryptUpdate)(session, indata, indatalen, outdata, &outdatalen);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);

	rv = (FunctionPtr->C_EncryptFinal)(session, outdata1, &outdatalen1);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);

	if ((/*(outdatalen != sizeof(SM4cipher_Enc)) || */memcmp(outdata, SM4cipher_Enc, outdatalen)) && (i == 0))
	{
		printf("test_SM4FLASHValue failed, memcmp(outdata, SM4cipher_Enc, outdatalen).\n");
//			nResultLength += sprintf(Testresult[nItemNumb] + nResultLength,"SM4 Encrypt Calc Error: test_SM4Encrypt.<br>"); 
		bRtn = 1;
		goto END;
	}

	/******************????***********************/

	rv = (FunctionPtr->C_DecryptInit)(session, &SM4mechanism_Dec, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);
	
	//?????
	memcpy(indata1, outdata, outdatalen);
	indatalen1 = outdatalen;

	//????

	
	rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, NULL, &outdatalen1);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);

	rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, outdata1, &outdatalen1);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);

	rv = (FunctionPtr->C_DecryptFinal)(session, outdata, &outdatalen);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);

	if ((outdatalen1 != sizeof(SM4plain_Enc)) || (memcmp(outdata1, SM4plain_Enc, outdatalen1)))
	{
		printf("Calc Error: test_SM4Encrypt.\n");
		bRtn = 1;
		goto END;
	}
	else
	{
		printf("Calc Correct: test_SM4Encrypt.\n");
	}

	printf("leave %s:%s.\n",__FUNCTION__,fname);
	bRtn = 0;
END:

	
	return bRtn;
}

/*
??????FLASH??
*/
CK_ULONG xtest_SM4FLASHnoValue(CK_MECHANISM_TYPE mAlgType, unsigned char *label, CK_ULONG labelsize, CK_BBOOL bEncrypt, CK_BBOOL bDecrypt)
{
	bool bRtn = false;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE SM4keyType = CKK_SM4;
	
	CK_ULONG ulObjectCount = 0;

	//????
	unsigned char	SM4keyVal_Enc[]={0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
	unsigned char	SM4iv_Enc[16] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
	unsigned char	SM4plain_Enc[192]={0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
	unsigned char	SM4cipher_Enc_OFB[192]={0x73, 0xa3, 0x37, 0x80, 0x40, 0xad, 0x2f, 0x7c, 0x91, 0x81, 0x8e, 0xcd, 0x49, 0x6a, 0xe2, 0x62, 0xb8, 0x83, 0xc1, 0x38, 0x12, 0xfa, 0x3d, 0xb4, 0xfc, 0x2a, 0xf4, 0x97, 0x2b, 0xa9, 0xaf, 0xae, 0xcc, 0x8d, 0x58, 0x49, 0x07, 0x67, 0xd3, 0x76, 0xab, 0xb8, 0x1e, 0xe6, 0x8d, 0x19, 0xfa, 0xfb, 0x18, 0x3d, 0x10, 0xa9, 0x2f, 0xbb, 0xf1, 0x21, 0xa4, 0xd7, 0x2d, 0xb4, 0x1b, 0xf2, 0x42, 0x9e, 0x4b, 0x44, 0xfd, 0x08, 0x89, 0x20, 0x78, 0xf8, 0xd5, 0x7d, 0x48, 0xd1, 0x4e, 0x0a, 0x39, 0xa3, 0x88, 0xec, 0xfa, 0x04, 0x84, 0xa6, 0x24, 0x88, 0xd5, 0x91, 0xea, 0x27, 0xaa, 0x99, 0x9f, 0x29, 0xe4, 0xf0, 0x12, 0xde, 0x35, 0x07, 0x5f, 0xe2, 0x34, 0x96, 0xfb, 0x61, 0xc1, 0xff, 0xa2, 0xc7, 0x00, 0x4a, 0xd1, 0xca, 0x3b, 0xc2, 0xdb, 0x49, 0xc7, 0xd5, 0x7a, 0x04, 0x82, 0x9d, 0xfa, 0xff, 0xd2, 0xd8, 0x6c, 0x77, 0x4f, 0xa8, 0x44, 0x47, 0xdd, 0x84, 0xd4, 0xf1, 0x8e, 0xc6, 0x36, 0xfc, 0xa4, 0xd8, 0x1a, 0xa5, 0x38, 0x30, 0xc3, 0xf6, 0xde, 0xe8, 0x69, 0xb5, 0x37, 0x1b, 0x47, 0x26, 0x41, 0xf7, 0x9f, 0xac, 0x29, 0x69, 0x2e, 0xba, 0xbd, 0x55, 0x8d, 0x28, 0xa6, 0x03, 0x0e, 0xaf, 0xeb, 0x6b, 0xe9, 0xb3, 0x75, 0xe0, 0x81, 0x76, 0xc9, 0x60, 0xaa, 0x8c, 0xab, 0x70, 0x2f, 0x42};
	unsigned char	SM4cipher_Enc_ECB[192]={0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91, 0x68, 0x6D, 0xB7, 0x66, 0xC9, 0x20, 0x48, 0x22, 0xBB, 0xFA, 0x6B, 0x84, 0x68, 0xC2, 0x86, 0x91};
	unsigned char	SM4cipher_Enc_CBC[192]={0x94, 0x0f, 0x58, 0xdf, 0xb5, 0x3e, 0x53, 0x48, 0x70, 0x14, 0xf6, 0x4d, 0x95, 0x9e, 0x12, 0x2e, 0x24, 0xd8, 0x02, 0xa7, 0x69, 0x09, 0x2f, 0xcb, 0xcd, 0xa7, 0xc0, 0x8b, 0xe3, 0x2c, 0xe8, 0x99, 0x94, 0xb3, 0x56, 0xe2, 0x90, 0x75, 0xc9, 0x82, 0x13, 0x53, 0x02, 0xc8, 0xf3, 0xe6, 0xc5, 0x7d, 0xed, 0x17, 0x16, 0x50, 0xed, 0x45, 0x2e, 0xa3, 0xaf, 0x2d, 0xce, 0xf2, 0x85, 0x42, 0x45, 0x17, 0x6c, 0xe7, 0x2e, 0x78, 0x3b, 0xfd, 0x9a, 0x8a, 0x9e, 0x6a, 0x7c, 0xa6, 0xad, 0xfa, 0x7d, 0xec, 0xde, 0xd6, 0x87, 0x3e, 0x45, 0xcd, 0x9a, 0xe9, 0x7f, 0xf5, 0x4a, 0x71, 0xe4, 0x04, 0x2b, 0x14, 0xca, 0xca, 0x43, 0x3a, 0x5a, 0x9d, 0xf3, 0x22, 0xee, 0x78, 0x7d, 0x27, 0xd1, 0x26, 0x15, 0x35, 0x5b, 0xf6, 0x78, 0x08, 0x67, 0xe8, 0xe2, 0xfd, 0xd8, 0x85, 0xbb, 0x2b, 0x41, 0xe7, 0xd3, 0xf7, 0xcb, 0x7c, 0xb3, 0x6c, 0x92, 0xdf, 0x9a, 0x07, 0x09, 0x81, 0x97, 0xec, 0x36, 0x93, 0xab, 0x96, 0xad, 0xb7, 0x61, 0x89, 0xa9, 0xa5, 0x20, 0x82, 0x5f, 0xba, 0x5f, 0xbc, 0x73, 0xdb, 0xba, 0x43, 0xc4, 0x46, 0x6f, 0xbd, 0x1e, 0x71, 0xfd, 0xb1, 0xd3, 0x80, 0xbe, 0x2d, 0xb1, 0x76, 0xbd, 0xb9, 0x3f, 0x5c, 0x58, 0x2a, 0x6d, 0x9a, 0x94, 0xca, 0x7f, 0x92, 0x8f, 0x56, 0x30, 0x9f, 0x06, 0x43};
	unsigned char	*SM4cipher_Enc = NULL;


	CK_ATTRIBUTE SM4keyTemplateFind_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(CK_OBJECT_CLASS)},
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_DECRYPT, &bDecrypt, sizeof(ttrue)},
		{CKA_ENCRYPT, &bEncrypt, sizeof(ttrue)},
		{CKA_LABEL, label, labelsize}
	};
	CK_MECHANISM SM4mechanism_Enc = {mAlgType, SM4iv_Enc, sizeof(SM4iv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;
	CK_OBJECT_HANDLE hKey = NULL_PTR;
	

	//????
		
	CK_ATTRIBUTE SM4keyTemplateFind_Dec[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(CK_OBJECT_CLASS)},
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_DECRYPT, &bEncrypt, sizeof(ttrue)},
		{CKA_ENCRYPT, &bDecrypt, sizeof(ttrue)},
		{CKA_LABEL, label, labelsize}
	};
	CK_MECHANISM SM4mechanism_Dec = {mAlgType, SM4iv_Enc, sizeof(SM4iv_Enc)};
	CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;
	CK_OBJECT_HANDLE hKey1 = NULL_PTR;

	CK_BYTE indata[256] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[256] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[256] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[256] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);
	int loopTime = 1;
	unsigned int i = 0;
	char  fname[4] = {0x00};
	char* fNameECB = "ECB";
	char* fNameCBC = "CBC";
	char* fNameOFB = "OFB";

	if (mAlgType == CKM_SM4_ECB)
	{
		SM4cipher_Enc = SM4cipher_Enc_ECB;
		SM4mechanism_Enc.pParameter = NULL;
		SM4mechanism_Enc.ulParameterLen = 0;
		SM4mechanism_Dec.pParameter = NULL;
		SM4mechanism_Dec.ulParameterLen = 0;
		strcpy(fname, fNameECB);
	}
	else if (mAlgType == CKM_SM4_CBC)
	{
		SM4cipher_Enc = SM4cipher_Enc_CBC;
		strcpy(fname, fNameCBC);
	}
	else if (mAlgType == CKM_SM4_OFB)
	{
		SM4cipher_Enc = SM4cipher_Enc_OFB;
		strcpy(fname, fNameOFB);
	}
	
	printf("enter %s:%s.\n",__FUNCTION__,fname);

	rv = FunctionPtr->C_FindObjectsInit(session, SM4keyTemplateFind_Enc, sizeof(SM4keyTemplateFind_Enc)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit,rv);

	rv = FunctionPtr->C_FindObjects(session, &hKey_Enc, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects,rv);

//	printf("find Key count=%d, hkey_enc=0x%08lx.\n", ulObjectCount,hKey_Enc);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal,rv);

	rv = (FunctionPtr->C_EncryptInit)(session, &SM4mechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);

	//???????
	ulObjectCount = 0;

	rv = FunctionPtr->C_FindObjectsInit(session, SM4keyTemplateFind_Dec, sizeof(SM4keyTemplateFind_Dec)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit,rv);

	rv = FunctionPtr->C_FindObjects(session, &hKey_Dec, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects,rv);

	printf("find Key count=%lu, hkey_dec=0x%08lx.\n", ulObjectCount,hKey_Dec);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal,rv);

	indatalen = sizeof(indata);
	memset(indata, 0, indatalen);
	outdatalen=sizeof(outdata);
	memset(outdata, 0, outdatalen);

	indatalen1 = sizeof(indata1);
	memset(indata1, 0, indatalen1);
	outdatalen1=sizeof(outdata1);
	memset(outdata1, 0, outdatalen1);

	//?????
	memcpy(indata, SM4plain_Enc, sizeof(SM4plain_Enc));
	indatalen = sizeof(SM4plain_Enc);
	

	/*******************????**********************/
	//????
	rv = (FunctionPtr->C_EncryptUpdate)(session, indata, indatalen, outdata, &outdatalen);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);
	
	rv = (FunctionPtr->C_EncryptFinal)(session, outdata1, &outdatalen1);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);
	
	if ((/*(outdatalen != sizeof(SM4cipher_Enc)) || */memcmp(outdata, SM4cipher_Enc, outdatalen)) && (i == 0))
	{
		printf("test_SM4FLASHnoValue failed, memcmp(outdata, SM4cipher_Enc, outdatalen).\n");
//			nResultLength += sprintf(Testresult[nItemNumb] + nResultLength,"SM4 Encrypt Calc Error: test_SM4Encrypt.<br>"); 
		bRtn = 1;
		goto END;
	}

	/******************????***********************/
	rv = (FunctionPtr->C_DecryptInit)(session, &SM4mechanism_Dec, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);

	//?????
	memcpy(indata1, outdata, outdatalen);
	indatalen1 = outdatalen;

	//????
	rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, NULL, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);

	
	rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, outdata1, &outdatalen1);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);

	rv = (FunctionPtr->C_DecryptFinal)(session, outdata, &outdatalen);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);

	if ((outdatalen1 != sizeof(SM4plain_Enc)) || (memcmp(outdata1, SM4plain_Enc, outdatalen1)))
	{
		printf("Calc Error: test_SM4Encrypt.\n");
		bRtn = 1;
		goto END;
//			nResultLength += sprintf(Testresult[nItemNumb] + nResultLength,"Calc Error: test_SM4Encrypt.<br>"); 
	}
	else
	{
		printf("Calc Correct!\n");
	}
	
	/****??????hKey_Enc?hKey_Dec??????*****/
	if(!(bEncrypt&&bDecrypt))
	{
		rv = (FunctionPtr->C_DestroyObject)(session, hKey_Dec);
		RV_NOT_OK_RETURN_FALSE(pC_DestroyObject_hKey_Dec,rv);

		rv = (FunctionPtr->C_DestroyObject)(session, hKey_Enc);
	    RV_NOT_OK_RETURN_FALSE(pC_DestroyObject_hKey_Enc,rv);
	}
	

	printf("leave %s:%s.\n",__FUNCTION__,fname);
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength, "leave %s:%s.<br>",__FUNCTION__,fname);

	bRtn = 0;
END:
	
	return bRtn;
}


	



//p11????ZUC??
CK_ULONG test_ZUCRAM()
{
	int bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE ZUCkeyType = CKK_ZUC;


	///////////////////////////
	unsigned char	ZUCkeyVal_Enc[]={0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};

	unsigned char	ZUCplain_Enc[136] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, 0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, \
		0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03};
	unsigned char	ZUCcipher_Enc[136] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, 0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, \
		0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34, 0x09, 0x73, 0x5b, 0xad, 0x57, 0x5e, 0x9f, 0x91};

//	unsigned char	ZUCiv_Enc[16] = {0x00, 0x05, 0x68, 0x23, 0xC4,0x00,0x00,0x00,0x00, 0x05, 0x68, 0x23, 0xC4,0x00,0x00,0x00};
	unsigned char	ZUCiv_Enc[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Enc,sizeof(ZUCkeyVal_Enc)}
	};
	CK_MECHANISM ZUCmechanism_Enc ;//= {CKM_ZUC_EEA, ZUCiv_Enc, sizeof(ZUCiv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

	//????
	//////////////////////////////////////
	unsigned char	ZUCkeyVal_Dec[]={0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};

	unsigned char	ZUCplain_Dec[136] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, 0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, \
		0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03};
	unsigned char	ZUCcipher_Dec[136] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, 0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, \
		0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34, 0x09, 0x73, 0x5b, 0xad, 0x57, 0x5e, 0x9f, 0x91};

//	unsigned char	ZUCiv_Dec[]={0x00, 0x05, 0x68, 0x23, 0x38};

	unsigned char	ZUCiv_Dec[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};
//	CK_UINT ZUCiv_Dec[4]={0x56823,0x18,0x1,0x0};


	CK_ATTRIBUTE ZUCkeyTemplate_Dec[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Dec,sizeof(ZUCkeyVal_Dec)}
	};
	CK_MECHANISM ZUCmechanism_Dec ;//= {CKM_ZUC_EEA, ZUCiv_Dec, sizeof(ZUCiv_Dec)};
	CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

	CK_BYTE indata[256] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[256] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[256] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[256] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);
	int loopTime = 1;
	unsigned int i = 0;
	
	printf("enter test_ZUCRAM.\n");
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength, "enter test_ZUCRAM.<br>");

	//???????
	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_hKey_Enc,rv);


	//???????
	hKey_Dec = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Dec, sizeof(ZUCkeyTemplate_Dec)/sizeof(CK_ATTRIBUTE), &hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_hKey_Dec,rv);


	for (i=0; i<loopTime; i++)
	{

		indatalen = sizeof(indata);
		memset(indata, 0, indatalen);
		outdatalen=sizeof(outdata);
		memset(outdata, 0, outdatalen);

		indatalen1 = sizeof(indata1);
		memset(indata1, 0, indatalen1);
		outdatalen1=sizeof(outdata1);
		memset(outdata1, 0, outdatalen1);

		memcpy(indata, ZUCplain_Enc, sizeof(ZUCplain_Enc));
		indatalen = sizeof(ZUCplain_Enc);

		memcpy(indata1, ZUCcipher_Dec, sizeof(ZUCcipher_Dec));
		indatalen1 = sizeof(ZUCcipher_Dec);

		/*******************????**********************/
		//????
		rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);
		
		rv = (FunctionPtr->C_Encrypt)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_Encrypt,rv);

		if ((outdatalen != sizeof(ZUCcipher_Enc)) || (memcmp(outdata, ZUCcipher_Enc, outdatalen)))
		{
			printf("Error: ZUC Encrypt(???).\n");
			bRtn = 1;
			goto END;
		}

		memset(outdata,0,sizeof(outdata));
		
		rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);
		
		rv = (FunctionPtr->C_EncryptUpdate)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);


		rv = (FunctionPtr->C_EncryptFinal)(session, outdata1, &outdatalen1);

		RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);

//		UtilsPrintData(VNAME(ZUCkeyVal_Enc),16,0);
//		UtilsPrintData(VNAME(ZUCiv_Enc),16,0);
//		UtilsPrintData(VNAME(indata),indatalen,0);
//		UtilsPrintData(VNAME(outdata),outdatalen,0);

		if ((outdatalen != sizeof(ZUCcipher_Enc)) || (memcmp(outdata, ZUCcipher_Enc, outdatalen)))
		{
			printf("Error: ZUC Encrypt(???).\n");
			bRtn = 1;
			goto END;
		}

		/******************????***********************/
		//????
		rv = (FunctionPtr->C_DecryptInit)(session, &ZUCmechanism_Dec, hKey_Dec);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);

		rv = (FunctionPtr->C_Decrypt)(session, indata1, indatalen1, NULL, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_Decrypt,rv);
		
		rv = (FunctionPtr->C_Decrypt)(session, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_Decrypt,rv);

		if ((outdatalen1 != sizeof(ZUCplain_Dec)) || (memcmp(outdata1, ZUCplain_Dec, outdatalen1)))
		{
			printf("Error: ZUC Decrypt(???).\n");
			bRtn = 1;
			goto END; 
		}

		memset(outdata1,0,sizeof(outdata1));
		
		rv = (FunctionPtr->C_DecryptInit)(session, &ZUCmechanism_Dec, hKey_Dec);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);
		
		rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);

		rv = (FunctionPtr->C_DecryptFinal)(session, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);


		if ((outdatalen1 != sizeof(ZUCplain_Dec)) || (memcmp(outdata1, ZUCplain_Dec, outdatalen1)))
		{
			printf("Error: ZUC Decrypt(???).\n");
			bRtn = 1;
			goto END; 
		}
		printf("Calc Success:ZUC.\n");
	}


	bRtn = 0;
END:

	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject_hKey_Enc,rv);

	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject_hKey_Dec,rv);

	printf("leave test_ZUCRAM.\n");
	return bRtn;
}

//p11????ZUC?????FLASH??
CK_ULONG test_ZUCFLASHValue(CK_BYTE *label)
{
	int bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE ZUCkeyType = CKK_ZUC;
	//????
	///////////////////////////
	unsigned char	ZUCkeyVal_Enc[]={0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Enc[136] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, 0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, \
		0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03};
	unsigned char	ZUCcipher_Enc[136] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, 0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, \
		0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34, 0x09, 0x73, 0x5b, 0xad, 0x57, 0x5e, 0x9f, 0x91};

//	unsigned char	ZUCiv_Enc[] = {0x00, 0x05, 0x68, 0x23, 0x38};
	
//	unsigned char	ZUCiv_Enc[16] = {0x00, 0x05, 0x68, 0x23, 0xC4,0x00,0x00,0x00,0x00, 0x05, 0x68, 0x23, 0xC4,0x00,0x00,0x00};
	unsigned char	ZUCiv_Enc[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};
	CK_BYTE tlabel[] = "ZUCflash";

//	CK_BYTE nSessKeyID_Enc = ucEncID;

	CK_ATTRIBUTE ZUCkeyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ffalse, sizeof(ffalse)},
		{CKA_VALUE,ZUCkeyVal_Enc,sizeof(ZUCkeyVal_Enc)},
		{CKA_LABEL,label,sizeof(label)}
	};
	CK_MECHANISM ZUCmechanism_Enc; //= {CKM_ZUC_EEA, ZUCiv_Enc, sizeof(ZUCiv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

	//????
	//////////////////////////////////////
	unsigned char	ZUCkeyVal_Dec[]={0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Dec[136] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, 0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, \
		0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03};
	unsigned char	ZUCcipher_Dec[136] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, 0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, \
		0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34, 0x09, 0x73, 0x5b, 0xad, 0x57, 0x5e, 0x9f, 0x91};

//	unsigned char	ZUCiv_Dec[]={0x00, 0x05, 0x68, 0x23, 0x38};
	
//	unsigned char	ZUCiv_Dec[16] = {0x00, 0x05, 0x68, 0x23, 0xC4,0x00,0x00,0x00,0x00, 0x05, 0x68, 0x23, 0xC4,0x00,0x00,0x00};
	unsigned char	ZUCiv_Dec[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Dec[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_ENCRYPT, &ffalse, sizeof(ffalse)},
		{CKA_VALUE,ZUCkeyVal_Dec,sizeof(ZUCkeyVal_Dec)},
		{CKA_LABEL,label,sizeof(label)}
	};
	CK_MECHANISM ZUCmechanism_Dec ;//= {CKM_ZUC_EEA, ZUCiv_Dec, sizeof(ZUCiv_Dec)};
	CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

	CK_BYTE indata[256] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[256] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[256] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[256] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);
	int loopTime = 1;
	unsigned int i = 0;

	printf("enter test_ZUCFLASHValue.\n");
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength, "enter test_ZUCFLASHValue.<br>");

	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_hKey_Enc,rv);

	hKey_Dec = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Dec, sizeof(ZUCkeyTemplate_Dec)/sizeof(CK_ATTRIBUTE), &hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_hKey_Dec,rv);

	rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);


	for (i=0; i<loopTime; i++)
	{
		indatalen = sizeof(indata);
		memset(indata, 0, indatalen);
		outdatalen=sizeof(outdata);
		memset(outdata, 0, outdatalen);

		indatalen1 = sizeof(indata1);
		memset(indata1, 0, indatalen1);
		outdatalen1=sizeof(outdata1);
		memset(outdata1, 0, outdatalen1);

		memcpy(indata, ZUCplain_Enc, sizeof(ZUCplain_Enc));
		indatalen = sizeof(ZUCplain_Enc);

		memcpy(indata1, ZUCcipher_Dec, sizeof(ZUCcipher_Dec));
		indatalen1 = sizeof(ZUCcipher_Dec);

		/*******************????**********************/

		//????
		rv = (FunctionPtr->C_EncryptUpdate)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);

		rv = (FunctionPtr->C_EncryptFinal)(session, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);

		rv = (FunctionPtr->C_DecryptInit)(session, &ZUCmechanism_Dec, hKey_Dec);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);

		if ((outdatalen != sizeof(ZUCcipher_Enc)) || (memcmp(outdata, ZUCcipher_Enc, outdatalen)))
		{
			printf("Error: ZUC Encrypt.\n");
			bRtn = 1;
			goto END;
//			nResultLength += sprintf(Testresult[nItemNumb] + nResultLength,"CAL Error: ZUC Encrypt.<br>"); 
		}

		/******************????***********************/
		//????
		rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, NULL, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);

		
		rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);

		rv = (FunctionPtr->C_DecryptFinal)(session, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);
	
		if ((outdatalen1 != sizeof(ZUCplain_Dec)) || (memcmp(outdata1, ZUCplain_Dec, outdatalen1)))
		{
			printf("Error: ZUC Decrypt.\n");
			bRtn = 1;
			goto END;
//			nResultLength += sprintf(Testresult[nItemNumb] + nResultLength,"CAL Error: ZUC Decrypt.<br>"); 
		}
		printf("CLC Success : ZUC.\n");

	}

//	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Enc);
//	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject_hKey_Enc,rv);

//	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Dec);
//	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject_hKey_Dec,rv);

	printf("leave test_ZUCFLASHValue.\n");
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength, "leave test_ZUCFLASHValue.<br>");

	
END:
	
	return bRtn;
}


//p11????ZUC?????FLASH?????????
CK_ULONG test_ZUCFLASHnoValue(CK_BYTE *label)
{
	int bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE ZUCkeyType = CKK_ZUC;
	CK_BYTE tlabel[] = "ZUCflash";
	CK_ULONG ulObjectCount = 0;

	//????
	///////////////////////////
	unsigned char	ZUCkeyVal_Enc[]={0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};

	unsigned char	ZUCplain_Enc[136] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, 0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, \
		0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03};
	unsigned char	ZUCcipher_Enc[136] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, 0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, \
		0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34, 0x09, 0x73, 0x5b, 0xad, 0x57, 0x5e, 0x9f, 0x91};

//	unsigned char	ZUCiv_Enc[] = {0x00, 0x05, 0x68, 0x23, 0x38};
//	unsigned char	ZUCiv_Enc[16] = {0x00, 0x05, 0x68, 0x23, 0xC4,0x00,0x00,0x00,0x00, 0x05, 0x68, 0x23, 0xC4,0x00,0x00,0x00};
	unsigned char	ZUCiv_Enc[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ffalse, sizeof(ffalse)},
		{CKA_LABEL,label,sizeof(label)}
	};
	CK_MECHANISM ZUCmechanism_Enc;// = {CKM_ZUC_EEA, ZUCiv_Enc, sizeof(ZUCiv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = 0;

	//????
	//////////////////////////////////////
	unsigned char	ZUCkeyVal_Dec[]={0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};

	unsigned char	ZUCplain_Dec[136] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, 0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, \
		0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03};
	unsigned char	ZUCcipher_Dec[136] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, 0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, \
		0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34, 0x09, 0x73, 0x5b, 0xad, 0x57, 0x5e, 0x9f, 0x91};

//	unsigned char	ZUCiv_Dec[]={0x00, 0x05, 0x68, 0x23, 0x38};
//	unsigned char	ZUCiv_Dec[16] = {0x00, 0x05, 0x68, 0x23, 0xC4,0x00,0x00,0x00,0x00, 0x05, 0x68, 0x23, 0xC4,0x00,0x00,0x00};
	unsigned char	ZUCiv_Dec[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Dec[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT,&ffalse,sizeof(ffalse)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_LABEL,label,sizeof(label)}
	};
	CK_MECHANISM ZUCmechanism_Dec ;//= {CKM_ZUC_EEA, ZUCiv_Dec, sizeof(ZUCiv_Dec)};
	CK_OBJECT_HANDLE hKey_Dec = 0;

	CK_BYTE indata[256] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[256] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[256] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[256] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);
	int loopTime = 1;
	unsigned int i = 0;

	printf("enter test_ZUCFLASHnoValue.\n");
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength, "enter test_ZUCFLASHnoValue.<br>");

	//??ZUC????
	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_FindObjectsInit(session, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit1,rv);

	rv = FunctionPtr->C_FindObjects(session, &hKey_Enc, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects1,rv);

	printf("ZUC Enc Key count=%lu.\n", ulObjectCount);
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength ,"Private Key count=%d.<br>", ulObjectCount);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal1,rv);

	//??ZUC????
	ulObjectCount = 0;
	
	hKey_Dec = NULL_PTR;

	rv = FunctionPtr->C_FindObjectsInit(session, ZUCkeyTemplate_Dec, sizeof(ZUCkeyTemplate_Dec)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit2,rv);

	rv = FunctionPtr->C_FindObjects(session, &hKey_Dec, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects2,rv);

	printf("ZUC Dec Key count=%lu.\n", ulObjectCount);
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength ,"Private Key count=%d.<br>", ulObjectCount);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal2,rv);


	for (i=0; i<loopTime; i++)
	{
		indatalen = sizeof(indata);
		memset(indata, 0, indatalen);
		outdatalen=sizeof(outdata);
		memset(outdata, 0, outdatalen);

		indatalen1 = sizeof(indata1);
		memset(indata1, 0, indatalen1);
		outdatalen1=sizeof(outdata1);
		memset(outdata1, 0, outdatalen1);
		
		memcpy(indata, ZUCplain_Enc, sizeof(ZUCplain_Enc));
		indatalen = sizeof(ZUCplain_Enc);

		memcpy(indata1, ZUCcipher_Dec, sizeof(ZUCcipher_Dec));
		indatalen1 = sizeof(ZUCcipher_Dec);

		/*******************????**********************/
		rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);
	
		//????
		rv = (FunctionPtr->C_EncryptUpdate)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);
		
		rv = (FunctionPtr->C_EncryptFinal)(session, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);

		if ((outdatalen != sizeof(ZUCcipher_Enc)) || (memcmp(outdata, ZUCcipher_Enc, outdatalen)))
		{
			printf("Error: ZUC Encrypt.\n");
			bRtn=1;
			goto END;
		}

		/******************????***********************/
		
		rv = (FunctionPtr->C_DecryptInit)(session, &ZUCmechanism_Dec, hKey_Dec);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);

		//????
		rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, NULL, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);

		
		rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);

		rv = (FunctionPtr->C_DecryptFinal)(session, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);

		if ((outdatalen1 != sizeof(ZUCplain_Dec)) || (memcmp(outdata1, ZUCplain_Dec, outdatalen1)))
		{
			printf("Error: ZUC Decrypt.\n");
			bRtn=1;
			goto END;
		}

		printf("CLC Success : ZUC.\n");
	}


END:
	
	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject_hKey_Enc,rv);

	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject_hKey_Dec,rv);

	printf("leave test_ZUCFLASHnoValue.\n");
	return bRtn;
}


CK_ULONG xtest_ZUC_KEY()
{
	int xnRtn = 0;
	CK_RV rv = -1;
	CK_BYTE label[] ={0x01, 0x02, 0x03, 0x09};

	xnRtn = test_ZUCRAM();//RAM??
	if(xnRtn == 1)
	{
		return 1;
	}

	xnRtn = test_ZUCFLASHValue(label);//FLASH??
	if(xnRtn == 1)
	{
		return 1;
	}

	xnRtn = test_ZUCFLASHnoValue(label);//FLASH????
	if(xnRtn == 1)
	{
		return 1;
	}
	
	return 0;

}


CK_ULONG xtest_ZUCPerformance(int looptime,int datalen)
{
	const char* pcFile ={ "/sdcard/ZUCperformance.xls"};
	char strtemp[256];
	CK_ULONG bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE ZUCkeyType = CKK_ZUC;
	
	//????
	unsigned char	ZUCkeyVal_Enc[]={0xe5, 0xbd, 0x38, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Enc[5000] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
	 		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char	ZUCcipher_Enc[5000] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
	 		0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};	
//	unsigned char	ZUCiv_Enc[] = {0x00, 0x05, 0x68, 0x23, 0x38};
	unsigned char	ZUCiv_Enc[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Enc,sizeof(ZUCkeyVal_Enc)}
	};
	CK_MECHANISM ZUCmechanism_Enc ;//= {CKM_ZUC_EEA, ZUCiv_Enc, sizeof(ZUCiv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

	//????
	unsigned char	ZUCkeyVal_Dec[]={0xe5, 0xbd, 0x38, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Dec[5000] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
	 		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char	ZUCcipher_Dec[5000] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
			0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};

//	unsigned char	ZUCiv_Dec[]={0x00, 0x05, 0x68, 0x23, 0x38};
	unsigned char	ZUCiv_Dec[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Dec[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Dec,sizeof(ZUCkeyVal_Dec)}
	};
	CK_MECHANISM ZUCmechanism_Dec ;//= {CKM_ZUC_EEA, ZUCiv_Dec, sizeof(ZUCiv_Dec)};
	CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

	CK_BYTE indata[5000] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[5000] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[5000] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[5000] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);

	unsigned int i = 0,j=0;
	UtilscTime ttc1={0, 0},ttc2={0,0},ttc3={0,0},ttc4={0,0};

	
	CK_MECHANISM ZUCmechanismGen = {CKM_ZUC_KEY_GEN, NULL_PTR, 0};

	CK_ATTRIBUTE ZUCkeyTemplate_Gen[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)}
	};

	printf("input looptime:\n");
	CK_BYTE ch[10];
	fgets(ch,10,stdin);
   	looptime = atoi(ch);

	printf("input datalen(0-5000):\n");
	fgets(ch,10,stdin);
   	datalen = atoi(ch);

	//????ZUC key???
/*	hKey = NULL_PTR;
	Utilsgettime(&ttc1);
	rv = FunctionPtr->C_GenerateKey(hSession, &ZUCmechanismGen,ZUCkeyTemplate_Gen, sizeof(ZUCkeyTemplate_Gen)/sizeof(CK_ATTRIBUTE), &hKey);
	RV_NOT_OK_RETURN_FALSE(Testresult[nItemNumb],&nResultLength,pC_GenerateKey,rv);
	Utilsgettime(&ttc2);
	UtilsTimeSubstracted(&ttc2,&ttc1);
	Utilsprint(&ttc2,"ZUC GenerateKey", 1);

	rv = (FunctionPtr->C_DestroyObject)(session, hKey);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject0,rv);*/
	

	srand( (unsigned)time( NULL ) );//??????

	//???????
	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_Enc,rv);

	//???????
	hKey_Dec = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Dec, sizeof(ZUCkeyTemplate_Dec)/sizeof(CK_ATTRIBUTE), &hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_Dec,rv);

	printf("Datalen=%d.\n",datalen);

	for (i=0; i<looptime; i++)
	{
		FILE *_fp;
		_fp=fopen(pcFile,"a");
		if (!_fp)
		{
			printf("ZUC test failed, fopen fail.");
			return 1;
		} 

//		printf("i = %d\n",i);
		
		//???????	
		RandomGenerate(ZUCplain_Enc,datalen);
		//?????????
		RandomGenerate(ZUCiv_Enc,16);
		memcpy(ZUCiv_Dec,ZUCiv_Enc,16);

		BUFFER_REFRESH_ZERO(indata,indatalen,outdata,outdatalen);
		BUFFER_REFRESH_ZERO(indata1,indatalen1,outdata1,outdatalen1);

		memcpy(indata, ZUCplain_Enc, datalen);
		indatalen = datalen;
	

		
		/*******************????**********************/
		rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);
		
		Utilsgettime(&ttc1);
		rv = (FunctionPtr->C_EncryptUpdate)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);
		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc3,&ttc2);
		//tt2.printn("ZUC Encrypt", i);

		sprintf(strtemp, "%.3lf", ttc2.usec/1000.0f); 
		fputs(strtemp, _fp);
		fputs("\t", _fp);

		rv = (FunctionPtr->C_EncryptFinal)(session, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);
		
		memcpy(indata1, outdata, outdatalen);
		indatalen1 = outdatalen;
		outdatalen1=sizeof(outdata1);

		/******************????***********************/
		rv = (FunctionPtr->C_DecryptInit)(session, &ZUCmechanism_Dec, hKey_Dec);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);
		
		Utilsgettime(&ttc1);
		rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);
		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc4,&ttc2);
		//tt2.printn("ZUC Decrypt", i);
		sprintf(strtemp, "%.3lf", ttc2.usec/1000.0f); 
		fputs(strtemp, _fp);
		fputs("\n", _fp);
		fclose(_fp);

		rv = (FunctionPtr->C_DecryptFinal)(session, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);

		if ((outdatalen1 != datalen) || (memcmp(outdata1, ZUCplain_Enc, outdatalen1)))
		{
			printf("Error: ZUCPerformance.\n");
			printf("outdatalen1 = %lu.\n", outdatalen1);		
//			UtilsPrintData(VNAME(ZUCplain_Enc),datalen,0);
//			UtilsPrintData(VNAME(outdata1),outdatalen1,0);
//			nResultLength += sprintf(Testresult[nItemNumb] + nResultLength, "Error: ZUCPerformance.<br>");
			bRtn = 1;
			goto END;
		}
	}


	Utilsprint(&ttc3,"ZUC Encrypt(update)", looptime);
	Utilsprint(&ttc4,"ZUC Decrypt(update)", looptime);
	
END:	
	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject1,rv);

	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject2,rv);
	
	return bRtn;
}

//??ZUC??????
CK_ULONG xtest_ZUCPerformance_two(int looptime,int datalen)
{
	const char* pcFile ={ "/sdcard/ZUCperformance_two.xls"};
	char strtemp[256];
	CK_ULONG bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE ZUCkeyType = CKK_ZUC;
	
	//????
	unsigned char	ZUCkeyVal_Enc[]={0xe5, 0xbd, 0x38, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Enc[5000] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
	 		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char	ZUCcipher_Enc[5000] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
	 		0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};	
	unsigned char	ZUCiv_Enc[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Enc,sizeof(ZUCkeyVal_Enc)}
	};
	CK_MECHANISM ZUCmechanism_Enc;// = {CKM_ZUC_EEA, ZUCiv_Enc, sizeof(ZUCiv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

	//????
	unsigned char	ZUCkeyVal_Dec[]={0xe5, 0xbd, 0x38, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Dec[5000] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
	 		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char	ZUCcipher_Dec[5000] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
			0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};

	unsigned char	ZUCiv_Dec[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Dec[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Dec,sizeof(ZUCkeyVal_Dec)}
	};
	CK_MECHANISM ZUCmechanism_Dec ;//= {CKM_ZUC_EEA, ZUCiv_Dec, sizeof(ZUCiv_Dec)};
	CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

	CK_BYTE indata[5000] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[5000] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[5000] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[5000] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);

	unsigned int i = 0,j=0;
	UtilscTime ttc1={0, 0},ttc2={0,0},ttc3={0,0},ttc4={0,0};

	printf("input looptime:\n");
	CK_BYTE ch[10];
	fgets(ch,10,stdin);
   	looptime = atoi(ch);

	printf("input datalen(0-5000):\n");
	fgets(ch,10,stdin);
   	datalen = atoi(ch);

	srand( (unsigned)time( NULL ) );//??????

	//???????
	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_Enc,rv);

	//???????
	hKey_Dec = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Dec, sizeof(ZUCkeyTemplate_Dec)/sizeof(CK_ATTRIBUTE), &hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_Dec,rv);

	printf("Datalen=%d.\n",datalen);

	for (i=0; i<looptime; i++)
	{
		FILE *_fp;
		_fp=fopen(pcFile,"a");
		if (!_fp)
		{
			printf("ZUC test failed, fopen fail.");
			return false;
		} 

//		printf("i = %d\n",i);
		
		//???????	
		RandomGenerate(ZUCplain_Enc,datalen);
		//?????????
		RandomGenerate(ZUCiv_Enc,16);
		memcpy(ZUCiv_Dec,ZUCiv_Enc,16);

		BUFFER_REFRESH_ZERO(indata,indatalen,outdata,outdatalen);
		BUFFER_REFRESH_ZERO(indata1,indatalen1,outdata1,outdatalen1);

		memcpy(indata, ZUCplain_Enc, datalen);
		indatalen = datalen;
		
		/*******************????**********************/
		Utilsgettime(&ttc1);
		rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);
		
		rv = (FunctionPtr->C_Encrypt)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);

		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc3,&ttc2);
		//tt2.printn("ZUC Encrypt", i);

		sprintf(strtemp, "%.3lf", ttc2.usec/1000.0f); 
		fputs(strtemp, _fp);
		fputs("\t", _fp);

		memcpy(indata1, outdata, outdatalen);
		indatalen1 = outdatalen;

		usleep(10000);

		/******************????***********************/
		Utilsgettime(&ttc1);
		rv = (FunctionPtr->C_DecryptInit)(session, &ZUCmechanism_Dec, hKey_Dec);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);
		
		rv = (FunctionPtr->C_Decrypt)(session, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(C_Decrypt,rv);
		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc4,&ttc2);
		//tt2.printn("ZUC Decrypt", i);
		sprintf(strtemp, "%.3lf", ttc2.usec/1000.0f); 
		fputs(strtemp, _fp);
		fputs("\n", _fp);
		fclose(_fp);

		if ((outdatalen1 != datalen) || (memcmp(outdata1, ZUCplain_Enc, outdatalen1)))
		{
			printf("Error: ZUCPerformance.\n");
			printf("outdatalen = %lu.\n", outdatalen1);		
			bRtn = 1;
			goto END;
		}
		
		usleep(10000);
	}

	Utilsprint(&ttc3,"ZUC Encrypt(init+encrypt)", looptime);
	Utilsprint(&ttc4,"ZUC Decrypt(init+decrypt)", looptime);
	
END:	
	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject1,rv);

	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject2,rv);
	
	return bRtn;
}


CK_ULONG xtest_ZUCHashPerformance_withkey(int looptime,int datalen)
{
	CK_RV rv=0;
	int bRtn=false;
	int i=0;

	CK_BYTE	ZUCkeyVal[]={0xc9, 0xe6, 0xce, 0xc4, 0x60, 0x7c, 0x72, 0xdb, 0x00, 0x0a, 0xef, 0xa8, 0x83, 0x85, 0xab, 0x0a};
//	CK_BYTE	ZUCiv[]={0xa9, 0x40, 0x59, 0xda, 0x2a};
	CK_BYTE ZUCiv[16]={0xa9,0x40,0x59,0xda,0x00,0x00,0x00,0xa,0x00,0x00,0x00,0x1,0x00,0x00,0x00,0x0};
	CK_UINT zuc_hash_ivkey[8]={0x12345678,0xb,0x0,0x0,0x12345678,0x12345678,0x12345678,0x12345678};

	CK_BYTE digData[32],digData1[32];
	CK_ULONG ulDigLen=sizeof(digData);
	CK_ULONG ulDigLen1=sizeof(digData1);

	//CK_MECHANISM mechanism={CKM_HASH_ZUC_CALC,NULL_PTR,0};	
	CK_MECHANISM_PTR pPmechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
	memset(pPmechanism, 0 , sizeof(CK_MECHANISM));
	pPmechanism->mechanism = CKM_ZUC_EIA;

	CK_MECHANISM mechanism_hash = {CKM_ZUC_EIA, &zuc_hash_ivkey[0], 32};
	
	pPmechanism->pParameter = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE)*32);
	memcpy(pPmechanism->pParameter,ZUCkeyVal,sizeof(CK_BYTE)*16);
	memcpy((CK_BYTE_PTR)pPmechanism->pParameter+sizeof(CK_BYTE)*16,ZUCiv,sizeof(CK_BYTE)*16);
	pPmechanism->ulParameterLen = 32;
	UtilsPrintData(VNAME(pPmechanism->pParameter),32,0);

	CK_BYTE srcData[250] ={0x98, 0x3b, 0x41, 0xd4, 0x7d, 0x78, 0x0c, 0x9e, 0x1a, 0xd1, 0x1d, 0x7e, 0xb7, 0x03, 0x91, 0xb1};
	UtilscTime ttc1={0, 0},ttc2={0,0},ttc3={0,0},ttc4={0,0};
	srand( (unsigned)time( NULL ) );//??????

	looptime = 100;
	
	printf("Datalen=%d.looptime = %d.\n",datalen,looptime);

	for(i=0;i<looptime;i++)
	{
		if(looptime >1)
		{
			RandomGenerate(srcData,datalen);
		}
		Utilsgettime(&ttc1);
		rv=(FunctionPtr->C_DigestInit)(session,&mechanism_hash);
		RV_NOT_OK_RETURN_FALSE(pC_DigestInit,rv);

		ulDigLen=sizeof(digData);		
		rv=(FunctionPtr->C_Digest)(session,srcData,datalen,digData,&ulDigLen);
		RV_NOT_OK_RETURN_FALSE(pC_Digest,rv);
		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc3,&ttc2);

//		UtilsPrintData(VNAME(digData),ulDigLen,0);

		Utilsgettime(&ttc1);
		rv=(FunctionPtr->C_DigestInit)(session,&mechanism_hash);
		RV_NOT_OK_RETURN_FALSE(pC_DigestInit,rv);

//		rv=(*pC_DigestInit)(session,pPmechanism);
//	    printf("Second init, rv = 0x%08lx\n",rv);
		
		rv=(FunctionPtr->C_DigestUpdate)(session,srcData,datalen);
		RV_NOT_OK_RETURN_FALSE(pC_DigestUpdate,rv);
		
//		rv=(FunctionPtr->C_DigestUpdate)(session,srcData+datalen/2,datalen-datalen/2);
//		RV_NOT_OK_RETURN_FALSE(pC_DigestUpdate,rv);	
		
		ulDigLen1=sizeof(digData1);
		rv=(FunctionPtr->C_DigestFinal)(session,digData1,&ulDigLen1);
		RV_NOT_OK_RETURN_FALSE(pC_DigestFinal,rv);
		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc4,&ttc2);

		if (ulDigLen!=ulDigLen1)
		{
			printf("test_digest failed.???????\n");
			bRtn=1;
			goto END;
		}
		if (memcmp(digData, digData1, ulDigLen))
		{
			printf("test_digest failed.?????????\n");
			bRtn=1;
			goto END;
		}

		if(looptime == 1)
		{
			UtilsPrintData(VNAME(digData1),ulDigLen1,0);	
		}
	}
	
	Utilsprint(&ttc3,"ZUC Hash Digest", looptime);
//	nResultLength += Utilssprint(&ttc3,Testresult[nItemNumb]+ nResultLength,"ZUC Hash Digest", looptime);
	Utilsprint(&ttc4,"ZUC Hash Update", looptime);
//	nResultLength += Utilssprint(&ttc4,Testresult[nItemNumb]+ nResultLength,"ZUC Hash Update", looptime);
	bRtn=0;
END:
	free(pPmechanism->pParameter);
	free(pPmechanism);
	
	return bRtn;
}

CK_ULONG xtest_SM4ECB_Speed_GenV5(int looptime, int datalen)
{
	int bRtn = false;
	unsigned int i = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE SM4keyType = CKK_SM4;

	//????
	unsigned char	SM4iv[16] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
	CK_BYTE SM4plain_Enc[5000]={0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
	CK_ATTRIBUTE SM4keyTemplate_Gen[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ttrue, sizeof(ffalse)},
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
	};
	CK_MECHANISM SM4mechanism_Gen = {CKM_SM4_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM SM4mechanism = {CKM_SM4_ECB, SM4iv, sizeof(SM4iv)};
	CK_OBJECT_HANDLE hKey = NULL_PTR;

	CK_BYTE randomData[5000] = {0};

	CK_BYTE indata[5000] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[5000] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[5000] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[5000] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);
	UtilscTime ttc1={0, 0},ttc2={0,0},ttc3={0,0},ttc4={0,0};

	printf("input looptime:\n");
	CK_BYTE ch[10];
	fgets(ch,10,stdin);
   	looptime = atoi(ch);

	printf("input datalen(0-5000):\n");
	fgets(ch,10,stdin);
   	datalen = atoi(ch);

	//???????
	hKey = NULL_PTR;
	Utilsgettime(&ttc1);
	rv = FunctionPtr->C_GenerateKey(session, &SM4mechanism_Gen, SM4keyTemplate_Gen, sizeof(SM4keyTemplate_Gen)/sizeof(CK_ATTRIBUTE), &hKey);
	RV_NOT_OK_RETURN_FALSE(pC_GenerateKey,rv);
	Utilsgettime(&ttc2);
	UtilsTimeSubstracted(&ttc2,&ttc1);
	Utilsprint(&ttc2,"SM4ECB GenerateKey", 1);

	printf("Datalen=%d, looptime = %d.\n",datalen,looptime);
	
	for (i=0; i<looptime; i++)
	{
		rv = FunctionPtr->C_GenerateRandom(session, randomData, datalen);
		RV_NOT_OK_RETURN_FALSE(pC_GenerateRandom,rv);

		memcpy(SM4plain_Enc,randomData, datalen);

		BUFFER_REFRESH_ZERO(indata,indatalen,outdata,outdatalen);
		BUFFER_REFRESH_ZERO(indata1,indatalen1,outdata1,outdatalen1);

		rv = (FunctionPtr->C_EncryptInit)(session, &SM4mechanism, hKey);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);

		//?????
		memcpy(indata, SM4plain_Enc,datalen);
		indatalen = datalen;

		Utilsgettime(&ttc1);
		//????
		rv = (FunctionPtr->C_EncryptUpdate)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);
		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc3,&ttc2);

		rv = (FunctionPtr->C_EncryptFinal)(session, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal2,rv);
	
		rv = (FunctionPtr->C_DecryptInit)(session, &SM4mechanism, hKey);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);

		//?????
		memcpy(indata1, outdata, outdatalen);
		indatalen1 = outdatalen;

		Utilsgettime(&ttc1);
		//????
		rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, NULL, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);
		
		rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);
		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc4,&ttc2);

		rv = (FunctionPtr->C_DecryptFinal)(session, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);

		if ((outdatalen1 != datalen) || (memcmp(outdata1, SM4plain_Enc, outdatalen1)))
		{
			printf("Calc Error: test_SM4ECB_Speed.\n");
			bRtn = 1;
			goto END;
		}
	}
END:
	rv = (FunctionPtr->C_DestroyObject)(session, hKey);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject,rv);

	Utilsprint(&ttc3,"ECB Encrypt", looptime);
	Utilsprint(&ttc4,"ECB Decrypt", looptime);
	
	return bRtn;
}

CK_ULONG xtest_SM4CBC_Speed(int looptime,int datalen)
{
	CK_ULONG bRtn = 0;
	unsigned int i = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE SM4keyType = CKK_SM4;
	
	//????
	unsigned char	SM4keyVal_Enc[]={0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
	unsigned char	SM4iv_Enc[16] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
	CK_BYTE SM4plain_Enc[5000]={0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
	CK_ATTRIBUTE SM4keyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ttrue, sizeof(ffalse)},
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,SM4keyVal_Enc,sizeof(SM4keyVal_Enc)}
	};
	CK_MECHANISM SM4mechanism_Enc = {CKM_SM4_CBC, SM4iv_Enc, sizeof(SM4iv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;
	//????
	CK_ATTRIBUTE SM4keyTemplate_Dec[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,SM4keyVal_Enc,sizeof(SM4keyVal_Enc)}
	};
	CK_MECHANISM SM4mechanism_Dec = {CKM_SM4_CBC, SM4iv_Enc, sizeof(SM4iv_Enc)};
	CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

	CK_BYTE randomData[5000] = {0};

	CK_BYTE indata[5000] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[5000] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[5000] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[5000] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);
	UtilscTime ttc1={0, 0},ttc2={0,0},ttc3={0,0},ttc4={0,0};

	printf("input looptime:\n");
	CK_BYTE ch[10];
	fgets(ch,10,stdin);
   	looptime = atoi(ch);

	printf("input datalen(0-5000):\n");
	fgets(ch,10,stdin);
   	datalen = atoi(ch);

	//???????
	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate_Enc, sizeof(SM4keyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject1,rv);

	//???????
	hKey_Dec = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate_Dec, sizeof(SM4keyTemplate_Dec)/sizeof(CK_ATTRIBUTE), &hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject2,rv);

	printf("Datalen=%d, looptime = %d.\n",datalen,looptime);

	for (i=0; i<looptime; i++)
	{
		rv = FunctionPtr->C_GenerateRandom(session, randomData, datalen);
		RV_NOT_OK_RETURN_FALSE(pC_GenerateRandom,rv);

		memcpy(SM4plain_Enc,randomData, datalen);

		BUFFER_REFRESH_ZERO(indata,indatalen,outdata,outdatalen);
		BUFFER_REFRESH_ZERO(indata1,indatalen1,outdata1,outdatalen1);

		rv = (FunctionPtr->C_EncryptInit)(session, &SM4mechanism_Enc, hKey_Enc);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);
	
		//?????
		memcpy(indata, SM4plain_Enc, datalen);
		indatalen = datalen;

		//UtilsPrintData(VNAME(SM4keyVal_Enc),sizeof(SM4keyVal_Enc),0);
		//UtilsPrintData(VNAME(SM4iv_Enc),sizeof(SM4iv_Enc),0);
		//UtilsPrintData(VNAME(indata),indatalen,0);

		Utilsgettime(&ttc1);
		//????
		rv = (FunctionPtr->C_EncryptUpdate)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);
		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc3,&ttc2);

		rv = (FunctionPtr->C_EncryptFinal)(session, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);

		rv = (FunctionPtr->C_DecryptInit)(session, &SM4mechanism_Dec, hKey_Dec);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);
		
		//?????
		memcpy(indata1, outdata, outdatalen);
		indatalen1 = outdatalen;
		outdatalen1=sizeof(outdata1); 

		//UtilsPrintData(VNAME(SM4keyVal_Enc),sizeof(SM4keyVal_Enc),0);
		//UtilsPrintData(VNAME(SM4iv_Enc),sizeof(SM4iv_Enc),0);
		//UtilsPrintData(VNAME(indata1),indatalen1,0);

		Utilsgettime(&ttc1);
		//????
		rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);
		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc4,&ttc2);

		rv = (FunctionPtr->C_DecryptFinal)(session, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);

		//UtilsPrintData(VNAME(outdata1),outdatalen1,0);
		if ((outdatalen1 != datalen) || (memcmp(outdata1, SM4plain_Enc, outdatalen1)))
		{
			printf("Calc Error: test_SM4CBC_Speed.\n");
			bRtn = 1;
			goto END;
		}
	}


	Utilsprint(&ttc3,"CBC Encrypt", looptime);
//	nResultLength += Utilssprint(&ttc3,Testresult[nItemNumb]+ nResultLength,"CBC Encrypt", looptime);
	Utilsprint(&ttc4,"CBC Decrypt", looptime);
//	nResultLength += Utilssprint(&ttc4,Testresult[nItemNumb]+ nResultLength,"CBC Decrypt", looptime);

END:

	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject1,rv);

	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject2,rv);
	
	return bRtn;
}

CK_ULONG xtest_SM4OFB_Speed_GenV5(int looptime, int datalen)
{
	bool bRtn = false;
	unsigned int i = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE SM4keyType = CKK_SM4;
	
	//????
	unsigned char	SM4iv[16] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
	unsigned char	SM4plain_Enc[5000]={0};
	CK_ATTRIBUTE SM4keyTemplate_Gen[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ttrue, sizeof(ffalse)},
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)}
	};
	CK_MECHANISM SM4mechanism_Gen = {CKM_SM4_KEY_GEN, NULL_PTR, 0};
	CK_MECHANISM SM4mechanism = {CKM_SM4_OFB, SM4iv, sizeof(SM4iv)};
	CK_OBJECT_HANDLE hKey = NULL_PTR;


	CK_BYTE randomData[5000] = {0};

	CK_BYTE indata[5000] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[5000] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[5000] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[5000] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);	
	UtilscTime ttc1={0, 0},ttc2={0,0},ttc3={0,0},ttc4={0,0};

	printf("input looptime:\n");
	CK_BYTE ch[10];
	fgets(ch,10,stdin);
   	looptime = atoi(ch);

	printf("input datalen(0-5000):\n");
	fgets(ch,10,stdin);
   	datalen = atoi(ch);

	//???????
	hKey = NULL_PTR;
	Utilsgettime(&ttc1);
	rv = FunctionPtr->C_GenerateKey(session, &SM4mechanism_Gen, SM4keyTemplate_Gen, sizeof(SM4keyTemplate_Gen)/sizeof(CK_ATTRIBUTE), &hKey);
	RV_NOT_OK_RETURN_FALSE(pC_GenerateKey,rv);
	Utilsgettime(&ttc2);
	UtilsTimeSubstracted(&ttc2,&ttc1);
	Utilsprint(&ttc2,"SM4OFB GenerateKey", 1);

	printf("Datalen=%d, looptime = %d.\n",datalen,looptime);

	for (i=0; i<looptime; i++)
	{
		rv = FunctionPtr->C_GenerateRandom(session, randomData, datalen);
		RV_NOT_OK_RETURN_FALSE(pC_GenerateRandom,rv);

		memcpy(SM4plain_Enc, randomData, sizeof(randomData));

		BUFFER_REFRESH_ZERO(indata,indatalen,outdata,outdatalen);
		BUFFER_REFRESH_ZERO(indata1,indatalen1,outdata1,outdatalen1);

		rv = (FunctionPtr->C_EncryptInit)(session, &SM4mechanism, hKey);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);
	
		//?????
		memcpy(indata, SM4plain_Enc, sizeof(SM4plain_Enc));
		indatalen = sizeof(SM4plain_Enc);

		//printf("datalen1=%d,outdatalen1=%d\n",datalen,outdatalen);
		Utilsgettime(&ttc1);
		//????
		//UtilsPrintData(VNAME(indata),datalen,0);
		rv = (FunctionPtr->C_EncryptUpdate)(session, indata, datalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);
		//printf("datalen2=%d,outdatalen2=%d\n",datalen,outdatalen);
		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc3,&ttc2);

		//UtilsPrintData(VNAME(outdata),outdatalen,0);

		rv = (FunctionPtr->C_EncryptFinal)(session, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);
	
		rv = (FunctionPtr->C_DecryptInit)(session, &SM4mechanism, hKey);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);
		
		//?????
		memcpy(indata1, outdata, outdatalen);
		indatalen1 = outdatalen;
		outdatalen1=sizeof(outdata1); 

		Utilsgettime(&ttc1);
		//????
		//UtilsPrintData(VNAME(indata1),indatalen1,0);
		rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);
		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc4,&ttc2);

		rv = (FunctionPtr->C_DecryptFinal)(session, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);

		//UtilsPrintData(VNAME(outdata1),outdatalen1,0);
		if ((outdatalen1 != datalen) || (memcmp(outdata1, SM4plain_Enc, outdatalen1)))
		{
			printf("Calc Error: test_SM4OFB. i=%d, outdatalen = %lu, outdatalen1 = %lu\n",i,outdatalen, outdatalen1);
			UtilsPrintData(VNAME(indata),datalen,0);
			UtilsPrintData(VNAME(outdata1),outdatalen1,0);
			bRtn = 1;
			goto END;
		}
	}

	Utilsprint(&ttc3,"OFB Encrypt", looptime);
	Utilsprint(&ttc4,"OFB Decrypt", looptime);

END:
	rv = (FunctionPtr->C_DestroyObject)(session, hKey);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject,rv);
	
	return bRtn;
}


CK_ULONG xtest_SM2KeyCoordinate_Performace()
{

}

/*??????*/
CK_ULONG test_ImportKeyWithCipher(CK_MECHANISM_TYPE mechUnwrapType, unsigned char *pbIV, unsigned int uiIVLen, CK_OBJECT_HANDLE hUnwrapKey,
				CK_OBJECT_CLASS keyClass, CK_KEY_TYPE keyType, CK_BBOOL bToken, unsigned char *pbCipher, unsigned int uiCipherLen, CK_OBJECT_HANDLE *hgetKey, 
				unsigned char *label_en, CK_ULONG labelsize)
{
	int bRtn = 0;
	int i = 0;
	CK_RV rv = 0;

	CK_BYTE temp_pub[64] = {
		0xec,0x91,0x81,0x8d,0xe0,0xb7,0x01,0x21,0x73,0xf5,0x1c,0x33,0x75,0x43,0x6e,0x43,
		0xb6,0xa9,0xa2,0x6a,0xbd,0x6d,0xbc,0xb7,0x9f,0x85,0x1c,0xde,0xaf,0x7a,0x0f,0x6c,
		0xcb,0xf4,0xb5,0xa1,0x5f,0xb8,0x7e,0x60,0xfc,0x0b,0x3a,0x92,0x3d,0x12,0xe8,0x66,
		0x36,0x4a,0x93,0x5f,0xfb,0x30,0x84,0x2b,0xc9,0x13,0x9e,0xbd,0x2d,0xdc,0xe9,0x61
		};

	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_ATTRIBUTE ImportKeyTemplate[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &bToken, sizeof(bToken)},
		{CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_LABEL, label_en, labelsize}
	};
	CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS priclass=CKO_PRIVATE_KEY;
	CK_UINT     modulusBits = 256;
	CK_BYTE      id[] = {0x01,0x01,0x02,0x03};
	CK_ATTRIBUTE privateKeyTemplate[] = {
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_PRIVATE, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_SIGN, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE,&keyType,sizeof(keyType)},
		{CKA_UNWRAP, &ttrue, sizeof(ttrue)},
		{CKA_ID, id, sizeof(id)}
	};

	CK_ATTRIBUTE publicKeyTemplate[] = {		
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_PRIVATE, &ttrue, sizeof(ttrue)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VERIFY, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE,&keyType,sizeof(keyType)},
		{CKA_VALUE, temp_pub,sizeof(temp_pub)},
		{CKA_ID, id, sizeof(id)}
	};

	CK_MECHANISM  mechanismcalc ;//= {CKM_SM2, NULL_PTR, 0};

	CK_MECHANISM UnwrapMechanism = {mechUnwrapType, pbIV, uiIVLen};
	CK_BYTE_PTR   pData=(CK_BYTE_PTR)"12345678901234567890123456789012";
	CK_ULONG      ulDataLen=strlen((char*)pData);
	CK_BYTE       pOutData[256];   
	CK_ULONG      ulOutDataLen=sizeof(pOutData);

	CK_OBJECT_HANDLE hPubKey = NULL_PTR;
	CK_OBJECT_HANDLE hKey = NULL_PTR;

	if (keyType == 0)//CKK_SM2)
	{
		printf("enter import ECC\n");
		rv = (FunctionPtr->C_UnwrapKey)(session, &UnwrapMechanism, hUnwrapKey, pbCipher, uiCipherLen, privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE), &hKey);
	  	  if (rv != CKR_OK)
		{
			printf("test_ImportKeyWithCipher failed,pC_UnwrapKey. rv=0x%08lx.\n", rv);
			bRtn = 1;
			goto END;
		}

		*hgetKey = hKey;

		rv = (FunctionPtr->C_CreateObject)(session,publicKeyTemplate,sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE), &hPubKey);
		RV_NOT_OK_RETURN_FALSE(pC_CreateObject,rv);

		rv=(FunctionPtr->C_SignInit)(session,&mechanismcalc, hKey);
		RV_NOT_OK_RETURN_FALSE(pC_SignInit,rv);

		rv=(FunctionPtr->C_Sign)(session, pData, ulDataLen, pOutData, &ulOutDataLen);
		RV_NOT_OK_RETURN_FALSE(pC_Sign,rv);


		rv=(FunctionPtr->C_VerifyInit)(session,&mechanismcalc, hPubKey);
		RV_NOT_OK_RETURN_FALSE(pC_VerifyInit,rv);

		rv=(FunctionPtr->C_Verify)(session, pData, ulDataLen, pOutData, ulOutDataLen);
		RV_NOT_OK_RETURN_FALSE(pC_Verify,rv);

	}
	else
	{
		rv = (FunctionPtr->C_UnwrapKey)(session, &UnwrapMechanism, hUnwrapKey, pbCipher, uiCipherLen, ImportKeyTemplate, sizeof(ImportKeyTemplate)/sizeof(CK_ATTRIBUTE), &hKey);

		*hgetKey = hKey;
		
	   	if (rv != CKR_OK)
		{
			printf("test_ImportKeyWithCipher failed,pC_UnwrapKey. rv=0x%08lx.\n", rv);
			bRtn = 1;
			goto END;
		}
		//RV_NOT_OK_RETURN_FALSE(Testresult[nItemNumb],&nResultLength,pC_UnwrapKey,rv);
	}

	bRtn = 0;
END:
	if (hPubKey)
	{
		rv = (FunctionPtr->C_DestroyObject)(session, hPubKey);
		if (rv != CKR_OK)
		{
			printf("test_ImportKeyWithCipher failed,pC_DestroyObject hPubKey. rv=0x%08lx.\n", rv);
			bRtn = false;
		}
	}

	printf("test_ImportKeyWithCipher, return %d.\n", bRtn? 1: 0);

	return bRtn;
}


/*????*/
CK_ULONG test_deleteobject(CK_OBJECT_HANDLE hobj)
{
	CK_RV rv=0;
	CK_ULONG bRtn = 0;

	if(hobj)
	{
		rv = FunctionPtr->C_DestroyObject(session,hobj);
		RV_NOT_OK_RETURN_FALSE(test_deleteobject,rv);
	}
	
	return bRtn;
}


//??????
/*CK_ULONG TestUnwrapAll()
{
	int i = 0;
	CK_RV rv = 0;
	int bRtn = 0;
	CK_USER_TYPE userType = CKU_USER, sotype = CKU_SO;
	CK_OBJECT_HANDLE hPublicKey = NULL_PTR, hPrivateKey = NULL_PTR;
	CK_OBJECT_HANDLE hkey = NULL_PTR, hkey2 = NULL_PTR, hkey3 = NULL_PTR, hkey4 = NULL_PTR;

	CK_MECHANISM  mechanismcalc = {CKM_SM2, NULL_PTR, 0};
	CK_BYTE   pbData[16] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
	CK_ULONG      ulDataLen = sizeof(pbData);
	CK_BYTE   pbPrvData[32] = {0xc5,0x6a,0x2b,0x58,0xa0,0x94,0xef,0x24,0x41,0x03,0x79,0x45,0xba,0xb1,0x39,0x8c,0xc0,0xdf,0x9f,0xc4,0xf9,0x9e,0x9a,0x60,0x2c,0xd8,0x6f,0xc2,0xc3,0x88,0xad,0x0c};
	CK_ULONG  ulPrvDataLen = sizeof(pbPrvData);
	CK_BYTE       pbCipher[256] = {0};
	CK_ULONG      uiCipherLen = sizeof(pbCipher);
	CK_BYTE   key_value[16] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};

	unsigned char   label_en[] = "label_en";
	unsigned char   label_unwrap[] = "label_unwrap";
	unsigned char   label_unwrap2[] = "label_unwrap2";


	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE SM4keyType = CKK_SM4;
	CK_ATTRIBUTE SM4keyTemplate_RAM_en[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_VALUE, key_value, sizeof(key_value)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_UNWRAP, &ttrue, sizeof(ttrue)},
		{CKA_LABEL, &label_en, sizeof(label_en)-1}
	};

	CK_ATTRIBUTE SM4keyTemplate_RAM_unwrap[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_UNWRAP, &ttrue, sizeof(ttrue)},
		{CKA_VALUE, key_value, sizeof(key_value)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_LABEL, &label_unwrap, sizeof(label_unwrap)-1}
	};
	CK_ATTRIBUTE SM4keyTemplate_FLASH[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_UNWRAP, &ttrue, sizeof(ttrue)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE, key_value, sizeof(key_value)},
		{CKA_LABEL, &label_en, sizeof(label_en)-1}
	};
	
	unsigned char	SM4iv_Enc[16] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
	CK_MECHANISM SM4mechanism_ECB = {CKM_SM4_ECB, NULL, 0};
	CK_MECHANISM SM4mechanism_CBC = {CKM_SM4_CBC, SM4iv_Enc, sizeof(SM4iv_Enc)};
	CK_MECHANISM SM4mechanism_OFB = {CKM_SM4_OFB, SM4iv_Enc, sizeof(SM4iv_Enc)};
	
	int prtcnt=0;

   	//???????
//    bRtn=test_ECC_importKeyPair(&hPublicKey,&hPrivateKey); 
	CK_MECHANISM ecc_keygen = {CKM_SM2_KEY_PAIR_GEN,NULL,0};
	CK_MECHANISM mechanism_iea = {CKM_SM2,NULL,0};


	CK_KEY_TYPE  keyType=CKK_SM2;
	CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY,priclass=CKO_PRIVATE_KEY;

	CK_ATTRIBUTE publicKeyTemplate[] = {		
		{CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE,&keyType,sizeof(keyType)},
		{CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)},
		{CKA_PRIVATE, &ttrue, sizeof(CK_BBOOL)},
		{CKA_ENCRYPT, &ttrue, sizeof(CK_BBOOL)},
		{CKA_VERIFY, &ttrue, sizeof(CK_BBOOL)}
	};

	CK_ATTRIBUTE privateKeyTemplate[] = {
		{CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)},
		{CKA_KEY_TYPE,&keyType,sizeof(keyType)},
		{CKA_PRIVATE, &ttrue, sizeof(CK_BBOOL)},
		{CKA_DECRYPT, &ttrue, sizeof(CK_BBOOL)},
		{CKA_UNWRAP, &ttrue, sizeof(ttrue)},
		{CKA_SIGN, &ttrue, sizeof(CK_BBOOL)}
	};
	
	printf("**************import SM4 key with CKM_SM2_IEA**********\n");

	rv = FunctionPtr->C_GenerateKeyPair(session,&ecc_keygen,publicKeyTemplate,sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),privateKeyTemplate,sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),&hPublicKey,&hPrivateKey);
	RV_NOT_OK_RETURN_FALSE(pC_GenerateKeyPair,rv);
	
	rv=(FunctionPtr->C_EncryptInit)(session,&mechanismcalc,hPublicKey);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);

	rv=(FunctionPtr->C_Encrypt)(session, pbData, ulDataLen, pbCipher, &uiCipherLen);
	RV_NOT_OK_RETURN_FALSE(pC_Encrypt,rv);

	//UtilsPrintData(VNAME(pbCipher),uiCipherLen,0);

	//??RAM??
	bRtn = test_ImportKeyWithCipher(CKM_SM2, NULL, 0, hPrivateKey, CKO_SECRET_KEY, CKK_SM4, FALSE, pbCipher, uiCipherLen, &hkey, label_en, sizeof(label_en)-1);
	RV_FALSE_RETURN(bRtn);
	
	//??FLASH??
	bRtn = test_ImportKeyWithCipher(CKM_SM2, NULL, 0, hPrivateKey, CKO_SECRET_KEY, CKK_SM4, TRUE, pbCipher, uiCipherLen, &hkey2, label_en, sizeof(label_en)-1);
	RV_FALSE_RETURN(bRtn);
	
	//SM4???
	bRtn = xtest_SM4RAMnoValue(CKM_SM4_ECB, label_en, sizeof(label_en)-1, ttrue, ttrue);//RAM????
	RV_FALSE_RETURN(bRtn);
	bRtn = xtest_SM4FLASHnoValue(CKM_SM4_ECB, label_en, sizeof(label_en)-1, ttrue, ttrue);//FLASH????
	RV_FALSE_RETURN(bRtn);

	bRtn = xtest_SM4RAMnoValue(CKM_SM4_CBC, label_en, sizeof(label_en)-1, ttrue, ttrue);//RAM????
	RV_FALSE_RETURN(bRtn);
	bRtn = xtest_SM4FLASHnoValue(CKM_SM4_CBC, label_en, sizeof(label_en)-1, ttrue, ttrue);//FLASH????
	RV_FALSE_RETURN(bRtn);

	bRtn = xtest_SM4RAMnoValue(CKM_SM4_OFB, label_en, sizeof(label_en)-1, ttrue, ttrue);//RAM????
	RV_FALSE_RETURN(bRtn);	
	bRtn = xtest_SM4FLASHnoValue(CKM_SM4_OFB, label_en, sizeof(label_en)-1, ttrue, ttrue);//FLASH????
	RV_FALSE_RETURN(bRtn);

#ifdef OPEN_LOGOUT_CLOSESSION
//		bRtn = user_to_so();
//		RV_FALSE_RETURN(bRtn);

//		bRtn = test_ImportKeyWithCipher(CKM_SM2_IEA, NULL, 0, hPrivateKey, CKO_SECRET_KEY, CKK_SM4, TRUE, CK_SESSKEY_PRESET_ID7, pbCipher, uiCipherLen);
//		RV_FALSE_RETURN(bRtn);

//		//bRtn = test_SM4FLASHnoValue(CKM_SM4_ECB, CK_SESSKEY_PRESET_ID7, CK_SESSKEY_PRESET_ID7);//FLASH????
//		//RV_FALSE_RETURN(bRtn);
//		
//		bRtn = test_ImportKeyWithCipher(CKM_SM2_IEA, NULL, 0, hPrivateKey, CKO_SECRET_KEY, CKK_SM4, TRUE, CK_SESSKEY_PRESET_ID7, pbCipher, uiCipherLen);
//		RV_FALSE_RETURN(bRtn);

//		//bRtn = test_SM4FLASHnoValue(CKM_SM4_CBC, CK_SESSKEY_PRESET_ID7, CK_SESSKEY_PRESET_ID7);//FLASH????
//		//RV_FALSE_RETURN(bRtn);
//		
//		bRtn = test_ImportKeyWithCipher(CKM_SM2_IEA, NULL, 0, hPrivateKey, CKO_SECRET_KEY, CKK_ZUC, TRUE, CK_SESSKEY_PRESET_ID7, pbCipher, uiCipherLen);
//		RV_FALSE_RETURN(bRtn);

//		//bRtn = test_SM4FLASHnoValue(CKM_SM4_OFB, CK_SESSKEY_PRESET_ID7, CK_SESSKEY_PRESET_ID7);//FLASH????
//		//RV_FALSE_RETURN(bRtn);

//		bRtn = so_to_user();
//		RV_FALSE_RETURN(bRtn);
#endif

	bRtn=test_deleteobject(hPublicKey);
	RV_FALSE_RETURN(bRtn);

	bRtn=test_deleteobject(hPrivateKey);
	RV_FALSE_RETURN(bRtn);

	bRtn=test_deleteobject(hkey);
	RV_FALSE_RETURN(bRtn);

	bRtn=test_deleteobject(hkey2);
	RV_FALSE_RETURN(bRtn);

  
	//??ECB????
	
	printf("\n\n**************import SM4 key with ECB**********\n");
	rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate_RAM_en, sizeof(SM4keyTemplate_RAM_en)/sizeof(CK_ATTRIBUTE), &hkey);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject1,rv);

	rv = (FunctionPtr->C_EncryptInit)(session, &SM4mechanism_ECB, hkey);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);

	uiCipherLen = sizeof(pbCipher);
	rv=(FunctionPtr->C_Encrypt)(session, pbData, ulDataLen, pbCipher, &uiCipherLen);
	RV_NOT_OK_RETURN_FALSE(pC_Encrypt,rv);

//	rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate_RAM_unwrap, sizeof(SM4keyTemplate_RAM_unwrap)/sizeof(CK_ATTRIBUTE), &hKey_unwrap);
//	RV_NOT_OK_RETURN_FALSE(pC_CreateObject2,rv);

	//??RAM??
	bRtn = test_ImportKeyWithCipher(CKM_SM4_ECB, NULL, 0, hkey, CKO_SECRET_KEY, CKK_SM4, FALSE, pbCipher, uiCipherLen, &hkey3, label_unwrap, sizeof(label_unwrap)-1);
	RV_FALSE_RETURN(bRtn);
	
	//??FLASH??
	bRtn = test_ImportKeyWithCipher(CKM_SM4_ECB, NULL, 0, hkey, CKO_SECRET_KEY, CKK_SM4, TRUE, pbCipher, uiCipherLen, &hkey4, label_unwrap, sizeof(label_unwrap)-1);
	RV_FALSE_RETURN(bRtn);

	//SM4???
	bRtn = xtest_SM4RAMnoValue(CKM_SM4_ECB, label_unwrap, sizeof(label_unwrap)-1, ttrue, ttrue);//RAM????
	RV_FALSE_RETURN(bRtn);

	bRtn = xtest_SM4FLASHnoValue(CKM_SM4_ECB, label_unwrap, sizeof(label_unwrap)-1, ttrue, ttrue);//FLASH????
	RV_FALSE_RETURN(bRtn);


	bRtn = xtest_SM4RAMnoValue(CKM_SM4_CBC, label_unwrap, sizeof(label_unwrap)-1, ttrue, ttrue);//RAM????
	RV_FALSE_RETURN(bRtn);
	
	bRtn = xtest_SM4FLASHnoValue(CKM_SM4_CBC, label_unwrap, sizeof(label_unwrap)-1, ttrue, ttrue);//FLASH????
	RV_FALSE_RETURN(bRtn); 


	bRtn = xtest_SM4RAMnoValue(CKM_SM4_OFB, label_unwrap, sizeof(label_unwrap)-1, ttrue, ttrue);//RAM????
	RV_FALSE_RETURN(bRtn);

	bRtn = xtest_SM4FLASHnoValue(CKM_SM4_OFB, label_unwrap, sizeof(label_unwrap)-1, ttrue, ttrue);//FLASH????
	RV_FALSE_RETURN(bRtn);

#ifdef OPEN_LOGOUT_CLOSESSION
//	bRtn=test_logout();
//	RV_FALSE_RETURN(bRtn);

//	bRtn=test_login(CKU_SO);
//	RV_FALSE_RETURN(bRtn);

//	bRtn = test_ImportKeyWithCipher(CKM_SM4_ECB, NULL, 0, hKey_unwrap, CKO_SECRET_KEY, CKK_SM4, TRUE, CK_SESSKEY_PRESET_ID7, pbCipher, uiCipherLen);
//	RV_FALSE_RETURN(bRtn);

//	//bRtn = test_SM4FLASHnoValue(CKM_SM4_ECB, CK_SESSKEY_PRESET_ID7, CK_SESSKEY_PRESET_ID7);//FLASH????
//	//RV_FALSE_RETURN(bRtn);


//	bRtn = test_ImportKeyWithCipher(CKM_SM4_ECB, NULL, 0, hKey_unwrap, CKO_SECRET_KEY, CKK_SM4, TRUE, CK_SESSKEY_PRESET_ID7, pbCipher, uiCipherLen);
//	RV_FALSE_RETURN(bRtn);

//	//bRtn = test_SM4FLASHnoValue(CKM_SM4_CBC, CK_SESSKEY_PRESET_ID7, CK_SESSKEY_PRESET_ID7);//FLASH????
//	//RV_FALSE_RETURN(bRtn);

//	
//	bRtn = test_ImportKeyWithCipher(CKM_SM4_ECB, NULL, 0, hKey_unwrap, CKO_SECRET_KEY, CKK_ZUC, TRUE, CK_SESSKEY_PRESET_ID7, pbCipher, uiCipherLen);
//	RV_FALSE_RETURN(bRtn);

//	//bRtn = test_SM4FLASHnoValue(CKM_SM4_OFB, CK_SESSKEY_PRESET_ID7, CK_SESSKEY_PRESET_ID7);//FLASH????
//	//RV_FALSE_RETURN(bRtn);

//	bRtn=test_logout();
//	RV_FALSE_RETURN(bRtn);

//	bRtn=test_login(CKU_USER);
//	RV_FALSE_RETURN(bRtn);
#endif

	bRtn=test_deleteobject(hkey);
	RV_FALSE_RETURN(bRtn);

	bRtn=test_deleteobject(hkey3);
	RV_FALSE_RETURN(bRtn);

	bRtn=test_deleteobject(hkey4);
	RV_FALSE_RETURN(bRtn);
	

	printf("\n\n**************import SM4 key with CBC**********\n");	

//	??CBC????
	rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate_FLASH, sizeof(SM4keyTemplate_FLASH)/sizeof(CK_ATTRIBUTE), &hkey);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject11,rv);

	rv = (FunctionPtr->C_EncryptInit)(session, &SM4mechanism_CBC, hkey);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit11,rv);

	uiCipherLen = sizeof(pbCipher);
	rv=(FunctionPtr->C_Encrypt)(session, pbData, ulDataLen, pbCipher, &uiCipherLen);
	RV_NOT_OK_RETURN_FALSE(pC_Encrypt11,rv);
	
	//??RAM??
	bRtn = test_ImportKeyWithCipher(CKM_SM4_CBC, SM4iv_Enc, sizeof(SM4iv_Enc), hkey, CKO_SECRET_KEY, CKK_SM4, FALSE, pbCipher, uiCipherLen, &hkey2,label_unwrap2, sizeof(label_unwrap2)-1);
	RV_FALSE_RETURN(bRtn);
	
	//??FLASH??
	bRtn = test_ImportKeyWithCipher(CKM_SM4_CBC, SM4iv_Enc, sizeof(SM4iv_Enc), hkey, CKO_SECRET_KEY, CKK_SM4, TRUE, pbCipher, uiCipherLen, &hkey3,label_unwrap2, sizeof(label_unwrap2)-1);
	RV_FALSE_RETURN(bRtn);
	
	////SM4???
	bRtn = xtest_SM4RAMnoValue(CKM_SM4_ECB, label_unwrap2, sizeof(label_unwrap2)-1, ttrue, ttrue);//RAM????
	RV_FALSE_RETURN(bRtn);
	
	bRtn = xtest_SM4FLASHnoValue(CKM_SM4_ECB, label_unwrap2, sizeof(label_unwrap2)-1, ttrue, ttrue);//FLASH????
	RV_FALSE_RETURN(bRtn);


	bRtn = xtest_SM4RAMnoValue(CKM_SM4_CBC, label_unwrap2, sizeof(label_unwrap2)-1, ttrue, ttrue);//RAM????
	RV_FALSE_RETURN(bRtn);
	
	bRtn = xtest_SM4FLASHnoValue(CKM_SM4_CBC, label_unwrap2, sizeof(label_unwrap2)-1, ttrue, ttrue);//FLASH????
	RV_FALSE_RETURN(bRtn);


	bRtn = xtest_SM4RAMnoValue(CKM_SM4_OFB, label_unwrap2, sizeof(label_unwrap2)-1, ttrue, ttrue);//RAM????
	RV_FALSE_RETURN(bRtn);

	bRtn = xtest_SM4FLASHnoValue(CKM_SM4_OFB, label_unwrap2, sizeof(label_unwrap2)-1, ttrue, ttrue);//FLASH????
	RV_FALSE_RETURN(bRtn);
#ifdef OPEN_LOGOUT_CLOSESSION
//	bRtn=test_logout();
//	RV_FALSE_RETURN(bRtn);

//	//?????
//	bRtn=test_login(CKU_SO);
//	RV_FALSE_RETURN(bRtn);

//	bRtn = test_ImportKeyWithCipher(CKM_SM4_CBC, SM4iv_Enc, sizeof(SM4iv_Enc), hKey_unwrap, CKO_SECRET_KEY, CKK_SM4, TRUE, CK_SESSKEY_PRESET_ID7, pbCipher, uiCipherLen);
//	RV_FALSE_RETURN(bRtn);
//	
//	//bRtn = test_SM4FLASHnoValue(CKM_SM4_ECB, CK_SESSKEY_PRESET_ID7, CK_SESSKEY_PRESET_ID7);//FLASH????
//	//RV_FALSE_RETURN(bRtn);


//	bRtn = test_ImportKeyWithCipher(CKM_SM4_CBC, SM4iv_Enc, sizeof(SM4iv_Enc), hKey_unwrap, CKO_SECRET_KEY, CKK_SM4, TRUE, CK_SESSKEY_PRESET_ID7, pbCipher, uiCipherLen);
//	RV_FALSE_RETURN(bRtn);

//	//bRtn = test_SM4FLASHnoValue(CKM_SM4_CBC, CK_SESSKEY_PRESET_ID7, CK_SESSKEY_PRESET_ID7);//FLASH????
//	//RV_FALSE_RETURN(bRtn);
//	

//	bRtn = test_ImportKeyWithCipher(CKM_SM4_CBC, SM4iv_Enc, sizeof(SM4iv_Enc), hKey_unwrap, CKO_SECRET_KEY, CKK_ZUC, TRUE, CK_SESSKEY_PRESET_ID7, pbCipher, uiCipherLen);
//	RV_FALSE_RETURN(bRtn);
//	
//	//bRtn = test_SM4FLASHnoValue(CKM_SM4_OFB, CK_SESSKEY_PRESET_ID7, CK_SESSKEY_PRESET_ID7);//FLASH????
//	//RV_FALSE_RETURN(bRtn);

//	bRtn=test_logout();
//	RV_FALSE_RETURN(bRtn);

//	bRtn=test_login(CKU_USER);
//	RV_FALSE_RETURN(bRtn);
#endif

	bRtn=test_deleteobject(hkey);
	RV_FALSE_RETURN(bRtn);

	bRtn=test_deleteobject(hkey2);
	RV_FALSE_RETURN(bRtn);

	bRtn=test_deleteobject(hkey3);
	RV_FALSE_RETURN(bRtn);

	//??CBC?ECB?????
    printf("\n\n**************import SM2 key with CBC**********\n");

	rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate_FLASH, sizeof(SM4keyTemplate_FLASH)/sizeof(CK_ATTRIBUTE), &hkey);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject11,rv);

	rv = (FunctionPtr->C_EncryptInit)(session, &SM4mechanism_CBC, hkey);
	RV_NOT_OK_RETURN_FALSE(C_EncryptInit,rv);

	uiCipherLen = sizeof(pbCipher);
	rv=(FunctionPtr->C_Encrypt)(session, pbPrvData, ulPrvDataLen, pbCipher, &uiCipherLen);
	RV_NOT_OK_RETURN_FALSE(C_Encrypt,rv);

	bRtn = test_ImportKeyWithCipher(CKM_SM4_CBC, SM4iv_Enc, sizeof(SM4iv_Enc), hkey, CKO_PRIVATE_KEY, CKK_SM2, TRUE,pbCipher, uiCipherLen,&hkey2,NULL,0);
	RV_FALSE_RETURN(bRtn);


	printf("\n\n**************import SM2 key with ECB**********\n");
	rv = (FunctionPtr->C_EncryptInit)(session, &SM4mechanism_ECB, hkey);
	RV_NOT_OK_RETURN_FALSE(C_EncryptInit,rv);

	uiCipherLen = sizeof(pbCipher);
	rv=(FunctionPtr->C_Encrypt)(session, pbPrvData, ulPrvDataLen, pbCipher, &uiCipherLen);
	RV_NOT_OK_RETURN_FALSE(C_Encrypt,rv);

	bRtn = test_ImportKeyWithCipher(CKM_SM4_ECB, NULL, 0, hkey, CKO_PRIVATE_KEY, CKK_SM2, TRUE, pbCipher, uiCipherLen, &hkey3,NULL,0);
	RV_FALSE_RETURN(bRtn);

   	bRtn=test_deleteobject(hkey);
	RV_FALSE_RETURN(bRtn);

	bRtn=test_deleteobject(hkey2);
	RV_FALSE_RETURN(bRtn);

	bRtn=test_deleteobject(hkey3);
	RV_FALSE_RETURN(bRtn);
	
END:

	return 0;
}*/

CK_ULONG TestUnwrapAll(){
	return 0;
}

/*??ECC???*/
CK_ULONG test_ECC_importKeyPair(CK_OBJECT_HANDLE *phPublicKey,CK_OBJECT_HANDLE *phPrivateKey)
{
	CK_RV rv=0;

	CK_BYTE     temp_pub[64]={
		0xec,0x91,0x81,0x8d,0xe0,0xb7,0x01,0x21,0x73,0xf5,0x1c,0x33,0x75,0x43,0x6e,0x43,
			0xb6,0xa9,0xa2,0x6a,0xbd,0x6d,0xbc,0xb7,0x9f,0x85,0x1c,0xde,0xaf,0x7a,0x0f,0x6c,
			0xcb,0xf4,0xb5,0xa1,0x5f,0xb8,0x7e,0x60,0xfc,0x0b,0x3a,0x92,0x3d,0x12,0xe8,0x66,
			0x36,0x4a,0x93,0x5f,0xfb,0x30,0x84,0x2b,0xc9,0x13,0x9e,0xbd,0x2d,0xdc,0xe9,0x61
	};
	CK_BYTE     temp_prv[32]={
		0xc5,0x6a,0x2b,0x58,0xa0,0x94,0xef,0x24,0x41,0x03,0x79,0x45,0xba,0xb1,0x39,0x8c,
			0xc0,0xdf,0x9f,0xc4,0xf9,0x9e,0x9a,0x60,0x2c,0xd8,0x6f,0xc2,0xc3,0x88,0xad,0x0c
	};
	
	CK_BBOOL     ttrue = CK_TRUE;
	CK_BBOOL     ffalse = CK_FALSE;
	CK_KEY_TYPE  keyType ;//= CKK_SM2;
	CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY,priclass=CKO_PRIVATE_KEY;
	CK_UINT     modulusBits = 256;

	CK_BYTE      id[] = {0x01,0x01,0x02,0x03};

	CK_ATTRIBUTE publicKeyTemplate[] = {		
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_PRIVATE, &ttrue, sizeof(ttrue)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VERIFY, &ttrue, sizeof(ttrue)},
		{CKA_WRAP, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE,&keyType,sizeof(keyType)},
//		{CKA_ECC_BITS_LEN, &modulusBits, sizeof(CK_UINT)},
//		{CKA_ECC_X_COORDINATE, temp_pub_x, sizeof(temp_pub_x)},
//		{CKA_ECC_Y_COORDINATE, temp_pub_y, sizeof(temp_pub_y)},
		{CKA_VALUE, temp_pub,sizeof(temp_pub)},
		{CKA_ID, id, sizeof(id)}
	};

	CK_ATTRIBUTE privateKeyTemplate[] = {
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_PRIVATE, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_SIGN, &ttrue, sizeof(ttrue)},
		{CKA_UNWRAP, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE,&keyType,sizeof(keyType)},
//		{CKA_ECC_BITS_LEN, &modulusBits, sizeof(CK_UINT)},
//		{CKA_ECC_PRIVATE, temp_prv, sizeof(temp_prv)},
		{CKA_VALUE, temp_prv,sizeof(temp_prv)},
		{CKA_ID, id, sizeof(id)}
	};

	CK_ATTRIBUTE pubFindKeyTemplate[] = {
		{CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE,&keyType,sizeof(keyType)},
		{CKA_ID, id, sizeof(id)}
	};

	CK_ATTRIBUTE prvFindKeyTemplate[] = {
		{CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE,&keyType,sizeof(keyType)},
		{CKA_ID, id, sizeof(id)}
	};

	CK_BYTE get_pub[64] = {0};
	CK_ATTRIBUTE pubGetKeyTemplate[] = {
		{CKA_VALUE, get_pub, sizeof(get_pub)}
	};

	CK_BYTE get_prv[32] = {0};
	CK_ATTRIBUTE prvGetKeyTemplate[] = {
		{CKA_VALUE, get_prv, sizeof(get_prv)}
	};

	CK_OBJECT_HANDLE hObject = NULL_PTR;
	CK_ULONG ulObjectCount = 0;


	printf("enter test_ECC_importKeyPair.\n");
	//nResultLength += sprintf(Testresult[nItemNumb] + nResultLength, "%s","enter test_ECC_importKeyPair.<br>");
	//printf("enter test_ECC_importKeyPairxxxx.\n");

	//??????
	rv = (FunctionPtr->C_CreateObject)(session, 
						  publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
						  phPublicKey);
	if(rv!=CKR_OK)
	{
		printf("test_ECC_importKeyPair failed,pC_CreateObject,0. rv=0x%08lx.\n",rv);
		return 1;
	}

	printf("create publickey success.\n");
	
	//??????
	rv = (FunctionPtr->C_CreateObject)(session, 
						  privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),
						  phPrivateKey);
	if(rv!=CKR_OK)
	{
		printf("test_ECC_importKeyPair failed,pC_CreateObject,1. rv=0x%08lx.\n",rv);
		return 1;
	}

	printf("create privatekey success.\n");

	//??????	
/*	hObject = NULL_PTR;
	ulObjectCount = 0;
	rv = (FunctionPtr->C_FindObjectsInit)(session, prvFindKeyTemplate, sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	if(rv!=CKR_OK)
	{
		printf("test_ECC_importKeyPair failed,pC_FindObjectsInit,1. rv=0x%08lx.\n",rv);
		return 1;
	}

	rv = (FunctionPtr->C_FindObjects)(session, &hObject, 1, &ulObjectCount);
	if(rv!=CKR_OK)
	{
		printf("test_ECC_importKeyPair failed,pC_FindObjects,1. rv=0x%08lx.\n",rv);
		return 1;
	}

	rv = (FunctionPtr->C_FindObjectsFinal)(session);
	if(rv!=CKR_OK)
	{
		printf("test_ECC_importKeyPair failed,pC_FindObjectsFinal,1. rv=0x%08lx.\n",rv);
		return 1;
	}

	//????????????????
	hObject = NULL_PTR;
	ulObjectCount = 0;
	rv = (FunctionPtr->C_FindObjectsInit)(session, pubFindKeyTemplate, sizeof(pubFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	if(rv!=CKR_OK)
	{
		printf("test_ECC_importKeyPair failed,pC_FindObjectsInit,2. rv=0x%08lx.\n",rv);
		return 1;
	}

	rv = (FunctionPtr->C_FindObjects)(session, &hObject, 1, &ulObjectCount);
	if(rv!=CKR_OK)
	{
		printf("test_ECC_importKeyPair failed,pC_FindObjects,2. rv=0x%08lx.\n",rv);
		return 1;
	}

	rv = (FunctionPtr->C_FindObjectsFinal)(session);
	if(rv!=CKR_OK)
	{
		printf("test_ECC_importKeyPair failed,pC_FindObjectsFinal,2. rv=0x%08lx.\n",rv);
		return 1;
	}

	rv = (FunctionPtr->C_GetAttributeValue)(session, hObject, pubGetKeyTemplate, sizeof(pubGetKeyTemplate)/sizeof(CK_ATTRIBUTE));
	if(rv!=CKR_OK)
	{
		printf("test_ECC_importKeyPair failed,pC_GetAttributeValue,2. rv=0x%08lx.\n",rv);
		return 1;
	}*/
	printf("leave test_ECC_importKeyPair.\n");
	//nResultLength += sprintf(Testresult[nItemNumb] + nResultLength, "%s","enter test_ECC_importKeyPair.<br>");
	
	return 0;
}

CK_ULONG Show_Result(char* func_name, int i, const char* run_type, CK_RV rtn)
{
	if((func_name == NULL)||(run_type == NULL))
	{
		printf("Error:Some Input == NULL\n");
		return 1;
	}

	if(i == RUN_CORRECT)
	{
		if(rtn != CKR_OK)
		{
#ifdef USE_PROXY_OPEN
			printf("%s:<%s> Error(rv=0x%08lx:%s)\n", func_name, run_type, rtn, pC_StrErr(rtn));
			*storage_address += sprintf(storage_start + *storage_address, "%s:<%s> Error(rv=0x%08lx:%s)<br>", func_name, run_type, rtn, pC_StrErr(rtn));
#else
			printf("%s:<%s> Error(rv=0x%08lx)\n", func_name, run_type, rtn);
//			*storage_address += sprintf(storage_start + *storage_address, "%s:<%s> Error(rv=0x%08lx)<br>", func_name, run_type, rtn);
#endif
			return 1;
		}
		return 0;
	}

	if(rtn != 0x00000091)
	{
		if((rtn != CKR_OK) && (rtn != 0x90000000))
		{
#ifdef SHOW_ERROR_TEST
#ifdef USE_PROXY_OPEN
			printf("%s:", func_name);
			printf("<%s>should failed",  run_type);
			printf("(rv=0x%08lx",  rtn);
			printf(":%s)\n",  pC_StrErr(rtn));
			*storage_address += sprintf(storage_start + *storage_address, "%s:<%s> should failed(rv=0x%08lx:%s)<br>", func_name, run_type, rtn, pC_StrErr(rtn));
#else
			printf("%s:<%s> should failed(rv=0x%08lx)\n", func_name, run_type, rtn);
//			*storage_address += sprintf(storage_start + *storage_address, "%s:<%s> should failed(rv=0x%08lx)<br>", func_name, run_type, rtn);
#endif
#endif
			return 0;
		}
		else
		{
			printf("%s may succeed <%s>? rv=0x%08lx\n", func_name, run_type, rtn);
//			*storage_address += sprintf(storage_start + *storage_address, "%s may succeed <%s>? rv=0x%08lx<br>", func_name, run_type, rtn);
			return 1;
		}
	}
}


CK_ULONG GenKeyToBeWrapped(CK_KEY_TYPE KeyToBeWrappedType, CK_BBOOL KeyToBeWrappedTokenValue, CK_BBOOL ExtractableValue, CK_BBOOL WrapWithTrustedValue, CK_OBJECT_HANDLE_PTR phKeyToBeWrapped)
{
	CK_ULONG bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;	
	CK_OBJECT_HANDLE hKey = NULL_PTR;
	CK_MECHANISM mechanismGen = {NULL_PTR, NULL_PTR, 0};
	CK_ATTRIBUTE KeyTemplate[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &KeyToBeWrappedTokenValue, sizeof(KeyToBeWrappedTokenValue)},
		{CKA_KEY_TYPE, &KeyToBeWrappedType, sizeof(KeyToBeWrappedType)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_EXTRACTABLE, &ExtractableValue,sizeof(ExtractableValue)},
		{CKA_WRAP_WITH_TRUSTED, &WrapWithTrustedValue,sizeof(WrapWithTrustedValue)}
	};

	int Run_Flag = RUN_CORRECT ;

	//FLASH???extractable?wrapwithtrusted????true
	if((KeyToBeWrappedTokenValue == TRUE)&&((ExtractableValue ==TRUE)||(WrapWithTrustedValue == TRUE)))
	{
		Run_Flag = RUN_INCORRECT;
	}
	
	//RAM???extractable????false?wrapwithtrusted????true?????
	if((KeyToBeWrappedTokenValue == FALSE)&&(ExtractableValue ==FALSE)&&(WrapWithTrustedValue == TRUE))
	{
		Run_Flag = RUN_INCORRECT;
	}

	if(KeyToBeWrappedType == CKK_SM4)
	{
		mechanismGen.mechanism = CKM_SM4_KEY_GEN;
	}
	else if(KeyToBeWrappedType == CKK_ZUC)
	{
		mechanismGen.mechanism = CKM_ZUC_KEY_GEN;
	}
	else
	{
		printf("Error:key type invalid\n");
//		nResultLength += sprintf(Testresult[nItemNumb] + nResultLength,"Error:key type invalid<br>");
		return Free_Memory(FREE_0);
	}
	rv = FunctionPtr->C_GenerateKey(session, &mechanismGen, KeyTemplate, sizeof(KeyTemplate)/sizeof(CK_ATTRIBUTE), phKeyToBeWrapped);
	bRtn = Show_Result("pC_GenerateKey",Run_Flag, __FUNCTION__, rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	return Free_Memory(FREE_0);
}

CK_ULONG user_to_so()
{
	CK_RV rv=0;
	CK_ULONG bRtn = 0;
	int i = 0;

	rv = (FunctionPtr->C_Logout)(session);
	if(rv ==CKR_USER_NOT_LOGGED_IN)
	{
		rv = CKR_OK;
	}
	bRtn = Show_Result("pC_Logout", RUN_CORRECT, "user_to_so", rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));


	rv=(FunctionPtr->C_Login)(session,CKU_SO,default_so_pin,strlen(default_so_pin));
	bRtn = Show_Result("pC_Login", RUN_CORRECT, "user_to_so", rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	printf("user_to_so OK!\n");
	
	return bRtn;
}

CK_ULONG so_to_user()
{
	CK_RV rv=0;
	CK_ULONG bRtn = 0;
	int i = 0;

	rv=(FunctionPtr->C_Logout)(session);
	if(rv ==CKR_USER_NOT_LOGGED_IN)
	{
		rv = CKR_OK;
	}
	bRtn = Show_Result("pC_Logout", RUN_CORRECT, "so_to_user", rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));


	rv=(FunctionPtr->C_Login)(session,CKU_USER,pusrpin,strlen(pusrpin));
	bRtn = Show_Result("pC_Login", RUN_CORRECT, "so_to_user", rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	printf("so_to_user OK!\n");
	
	return bRtn;
}


CK_ULONG GetWrappedKeyValue(CK_OBJECT_HANDLE_PTR phWrappedKey)
{
	CK_ULONG bRtn = 0;
	CK_RV rv=0;
	unsigned char	KeyValGet[16] = {0x00};
	CK_ATTRIBUTE KeyTemplateGet[] = 
	{
		{CKA_VALUE,KeyValGet,sizeof(KeyValGet)}
	};

	rv = FunctionPtr->C_GetAttributeValue(session, *phWrappedKey, KeyTemplateGet,sizeof(KeyTemplateGet)/sizeof(CK_ATTRIBUTE));
	bRtn = Show_Result("pC_GetAttributeValue",RUN_INCORRECT, __FUNCTION__, rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
	
	
	return Free_Memory(FREE_0);
}

CK_ULONG CreateWrappingKeyUser(CK_KEY_TYPE WrappingKeyType, CK_BBOOL WrappingKeyTokenValue, CK_OBJECT_HANDLE_PTR phWrappingKey,CK_OBJECT_HANDLE_PTR phDecryptKey)
{
	CK_RV rv=0;
	CK_ULONG bRtn=0;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;	
	CK_OBJECT_CLASS pubclass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS priclass = CKO_PRIVATE_KEY;
	CK_UINT modulusBits = 256;

	CK_BYTE     temp_pub[64]={
		0xec,0x91,0x81,0x8d,0xe0,0xb7,0x01,0x21,0x73,0xf5,0x1c,0x33,0x75,0x43,0x6e,0x43,
			0xb6,0xa9,0xa2,0x6a,0xbd,0x6d,0xbc,0xb7,0x9f,0x85,0x1c,0xde,0xaf,0x7a,0x0f,0x6c,
			0xcb,0xf4,0xb5,0xa1,0x5f,0xb8,0x7e,0x60,0xfc,0x0b,0x3a,0x92,0x3d,0x12,0xe8,0x66,
			0x36,0x4a,0x93,0x5f,0xfb,0x30,0x84,0x2b,0xc9,0x13,0x9e,0xbd,0x2d,0xdc,0xe9,0x61
	};
	CK_BYTE     temp_prv[32]={
		0xc5,0x6a,0x2b,0x58,0xa0,0x94,0xef,0x24,0x41,0x03,0x79,0x45,0xba,0xb1,0x39,0x8c,
			0xc0,0xdf,0x9f,0xc4,0xf9,0x9e,0x9a,0x60,0x2c,0xd8,0x6f,0xc2,0xc3,0x88,0xad,0x0c
	};

	CK_ATTRIBUTE publicKeyTemplate[] = {		
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_CLASS, &pubclass, sizeof(pubclass)},
		{CKA_PRIVATE, &ttrue, sizeof(ttrue)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VERIFY, &ttrue, sizeof(ttrue)},
		{CKA_WRAP, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE,&WrappingKeyType,sizeof(WrappingKeyType)},
		{CKA_VALUE, temp_pub,sizeof(temp_pub)}
	};

	CK_ATTRIBUTE privateKeyTemplate[] = {
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_CLASS, &priclass, sizeof(priclass)},
		{CKA_PRIVATE, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_SIGN, &ttrue, sizeof(ttrue)},
		{CKA_UNWRAP, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE,&WrappingKeyType,sizeof(WrappingKeyType)},
		{CKA_VALUE, temp_prv, sizeof(temp_prv)}
	};

	CK_BYTE label1[] = {0x04};
	CK_BYTE label2[] = {0x05};
	CK_BYTE     temp_sm4_key[] = { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE SM4keyTemplate1[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &WrappingKeyTokenValue, sizeof(WrappingKeyTokenValue)},
		{CKA_KEY_TYPE, &WrappingKeyType, sizeof(WrappingKeyType)},
		{CKA_WRAP, &ttrue, sizeof(ttrue)},
		//{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE, temp_sm4_key, sizeof(temp_sm4_key)},
		{CKA_LABEL, label1, sizeof(label1)}
	};

	CK_ATTRIBUTE SM4keyTemplate2[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &WrappingKeyTokenValue, sizeof(WrappingKeyTokenValue)},
		{CKA_KEY_TYPE, &WrappingKeyType, sizeof(WrappingKeyType)},
		//{CKA_UNWRAP, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE, temp_sm4_key, sizeof(temp_sm4_key)},
		{CKA_LABEL, label2, sizeof(label2)}
	};

	int Run_Flag = RUN_CORRECT ;

	if(WrappingKeyTokenValue == FALSE)
	{
		Run_Flag = RUN_INCORRECT;
	}

	if(WrappingKeyType == CKK_SM2)
	{
		rv = (FunctionPtr->C_CreateObject)(session, publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE), phWrappingKey);
		bRtn = Show_Result("phWrappingKey",RUN_CORRECT, __FUNCTION__, rv);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

		rv = (FunctionPtr->C_CreateObject)(session, privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE), phDecryptKey);
		bRtn = Show_Result("phDecryptKey",RUN_CORRECT, __FUNCTION__, rv);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
	}
	else
	{
		rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate1, sizeof(SM4keyTemplate1)/sizeof(CK_ATTRIBUTE), phWrappingKey);
		bRtn = Show_Result("phWrappingKey",Run_Flag, __FUNCTION__, rv);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

		rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate2, sizeof(SM4keyTemplate2)/sizeof(CK_ATTRIBUTE), phDecryptKey);
		bRtn = Show_Result("phDecryptKey",RUN_CORRECT, __FUNCTION__, rv);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
	}

	
	return Free_Memory(FREE_0);
}

CK_ULONG CreateWrappingKeySo( CK_KEY_TYPE WrappingKeyType, CK_BBOOL WrappingKeyTokenValue, CK_OBJECT_HANDLE_PTR phWrappingKey,CK_OBJECT_HANDLE_PTR phDecryptKey)
{
	CK_RV rv=0;
	CK_ULONG bRtn=0;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;	
	CK_OBJECT_CLASS pubclass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS priclass = CKO_PRIVATE_KEY;

	CK_BYTE temp_pub[64] = {
		0xec,0x91,0x81,0x8d,0xe0,0xb7,0x01,0x21,0x73,0xf5,0x1c,0x33,0x75,0x43,0x6e,0x43,
		0xb6,0xa9,0xa2,0x6a,0xbd,0x6d,0xbc,0xb7,0x9f,0x85,0x1c,0xde,0xaf,0x7a,0x0f,0x6c,
		0xcb,0xf4,0xb5,0xa1,0x5f,0xb8,0x7e,0x60,0xfc,0x0b,0x3a,0x92,0x3d,0x12,0xe8,0x66,
		0x36,0x4a,0x93,0x5f,0xfb,0x30,0x84,0x2b,0xc9,0x13,0x9e,0xbd,0x2d,0xdc,0xe9,0x61
	};
	
	CK_BYTE     temp_prv[32]={
		0xc5,0x6a,0x2b,0x58,0xa0,0x94,0xef,0x24,0x41,0x03,0x79,0x45,0xba,0xb1,0x39,0x8c,
		0xc0,0xdf,0x9f,0xc4,0xf9,0x9e,0x9a,0x60,0x2c,0xd8,0x6f,0xc2,0xc3,0x88,0xad,0x0c
	};

	CK_ATTRIBUTE publicKeyTemplate[] = {		
		{CKA_TOKEN, &WrappingKeyTokenValue, sizeof(WrappingKeyTokenValue)},
		{CKA_CLASS, &pubclass, sizeof(pubclass)},
		{CKA_PRIVATE, &ttrue, sizeof(ttrue)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VERIFY, &ttrue, sizeof(ttrue)},
		{CKA_WRAP, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE,&WrappingKeyType,sizeof(WrappingKeyType)},
		{CKA_VALUE, temp_pub, sizeof(temp_pub)}
	};

	CK_ATTRIBUTE privateKeyTemplate[] = {
		{CKA_TOKEN, &WrappingKeyTokenValue, sizeof(WrappingKeyTokenValue)},
		{CKA_CLASS, &priclass, sizeof(priclass)},
		{CKA_PRIVATE, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_SIGN, &ttrue, sizeof(ttrue)},
		{CKA_UNWRAP, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE,&WrappingKeyType,sizeof(WrappingKeyType)},
		{CKA_VALUE, temp_prv, sizeof(temp_prv)},
	};

	CK_BYTE     temp_sm4_key[] = { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE SM4keyTemplate1[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &WrappingKeyTokenValue, sizeof(WrappingKeyTokenValue)},
		{CKA_KEY_TYPE, &WrappingKeyType, sizeof(WrappingKeyType)},
		{CKA_WRAP, &ttrue, sizeof(ttrue)},
		//{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE, temp_sm4_key, sizeof(temp_sm4_key)},
		{CKA_TRUSTED, &ttrue, sizeof(ttrue)}
	};

	CK_BYTE tlabel[] ="wrapwithtrusted";
	CK_ATTRIBUTE SM4keyTemplate2[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &WrappingKeyTokenValue, sizeof(WrappingKeyTokenValue)},
		{CKA_KEY_TYPE, &WrappingKeyType, sizeof(WrappingKeyType)},
		//{CKA_UNWRAP, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE, temp_sm4_key, sizeof(temp_sm4_key)},
		{CKA_LABEL, tlabel, sizeof(tlabel)-1}
	};

	int Run_Flag = RUN_CORRECT ;

	if(WrappingKeyTokenValue==FALSE)
	{
		Run_Flag = RUN_INCORRECT;
	}

//	if(WrappingKeyType == CKK_SM2)
//	{
//		rv = (FunctionPtr->C_CreateObject)(session, publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE), phWrappingKey);
//		bRtn = Show_Result("phWrappingKey",RUN_CORRECT, __FUNCTION__, rv);
//		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

//		rv = (FunctionPtr->C_CreateObject)(session, privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE), phDecryptKey);
//		bRtn = Show_Result("phDecryptKey",RUN_CORRECT, __FUNCTION__, rv);
//		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
//	}
//	else
//	{
		bRtn = user_to_so();
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
		rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate1, sizeof(SM4keyTemplate1)/sizeof(CK_ATTRIBUTE), phWrappingKey);
		bRtn = Show_Result("phWrappingKey",Run_Flag, __FUNCTION__, rv);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

		bRtn = so_to_user();
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
		rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate2, sizeof(SM4keyTemplate2)/sizeof(CK_ATTRIBUTE), phDecryptKey);
		bRtn = Show_Result("phDecryptKey",RUN_CORRECT, __FUNCTION__, rv);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
//	}

	
	return Free_Memory(FREE_0);
}


CK_ULONG WrappingTheKeyToBeWrapped(CK_OBJECT_HANDLE_PTR phKeyToBeWrapped, CK_OBJECT_HANDLE_PTR phWrappingKey, unsigned int WrapMechanismType, unsigned char* WrappedKeyValue, unsigned int* pWrappedKeyValueLen, int Run_Flag)
{
	CK_RV rv=0;
	CK_ULONG bRtn=0;
	CK_BYTE SM4_CBC_iv[16] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
	CK_MECHANISM WrapMechanism = {WrapMechanismType, NULL_PTR, 0};
	
	if(WrapMechanismType==CKM_SM4_CBC)
	{
		WrapMechanism.pParameter = SM4_CBC_iv;
		WrapMechanism.ulParameterLen = sizeof(SM4_CBC_iv);
	}

	rv = (FunctionPtr->C_WrapKey)(session, &WrapMechanism, *phWrappingKey, *phKeyToBeWrapped, WrappedKeyValue, (CK_ULONG_PTR) pWrappedKeyValueLen);
	printf("rv = %d\n", rv);
	bRtn = Show_Result("pC_WrapKey",Run_Flag, __FUNCTION__, rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
	return Free_Memory(FREE_0);
}

CK_ULONG Destroy_Useless_KeyPair(CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE PrivateKey)
{
	CK_ULONG bRtn = 0;
	CK_RV rv = 0;

	if(hPublicKey != NULL_PTR)
	{
		rv = FunctionPtr->C_DestroyObject(session, hPublicKey);
		bRtn = Show_Result("DestroyObject",RUN_CORRECT, "hPublicKey", rv);
		RV_FALSE_RETURN(bRtn);
	}

	if(PrivateKey != NULL_PTR)
	{
		rv = FunctionPtr->C_DestroyObject(session, PrivateKey);
		bRtn = Show_Result("DestroyObject",RUN_CORRECT, "PrivateKey", rv);
		RV_FALSE_RETURN(bRtn);
	}

	bRtn = 0;
	
	return bRtn;
}

CK_ULONG DecryptWrappedKey(unsigned char* WrappedKeyValue, unsigned char WrappedKeyValueLen, CK_OBJECT_HANDLE_PTR phDecryptKey, unsigned int DecrptMechanismType, unsigned char* DecryptedKeyValue, unsigned int* pDecryptedKeyValueLen)
{
	CK_RV rv=0;
	CK_ULONG bRtn=0;
	CK_BYTE SM4_CBC_iv[16]= {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
	CK_MECHANISM DecryptMechanism = {DecrptMechanismType, NULL_PTR, 0};
	
	if(DecrptMechanismType==CKM_SM4_CBC)
	{
		DecryptMechanism.pParameter = SM4_CBC_iv;
		DecryptMechanism.ulParameterLen = sizeof(SM4_CBC_iv);
	}

	rv = (FunctionPtr->C_DecryptInit)(session, &DecryptMechanism, *phDecryptKey);
	printf("rv2 = %d\n",rv);
	bRtn = Show_Result("pC_DecryptInit",RUN_CORRECT, __FUNCTION__, rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	rv = (FunctionPtr->C_Decrypt)(session,WrappedKeyValue, WrappedKeyValueLen, DecryptedKeyValue, (CK_ULONG_PTR) pDecryptedKeyValueLen);
	printf("rv3 = %d\n",rv);
	bRtn = Show_Result("pC_Decrypt",RUN_CORRECT, __FUNCTION__, rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	return Free_Memory(FREE_0);
}

CK_ULONG Result_Compare(BYTE* outdata, int outdatalen, BYTE* srcdata, int srcdatalen)
{
	if((outdata == NULL_PTR)||(outdatalen == 0)||(srcdata == NULL_PTR)||(srcdatalen == 0))
	{
		printf("Error:Some Input == NULL\n");
		return 1;
	}

	if(outdatalen != srcdatalen)
	{
		printf("Error: Datalen not Match.\n");
//		*storage_address += sprintf(storage_start + *storage_address, "Error: Datalen not Match.<br>");
		return 1;
	}

	if(memcmp(outdata, srcdata, outdatalen))
	{
		printf("Error: Data not Match.\n");
//		*storage_address += sprintf(storage_start + *storage_address, "Error: Data not Match.<br>");
		return 1;
	}

	return 0;
}

CK_ULONG Check_GenKey_by_KeyValue(CK_KEY_TYPE KeyToBeWrappedType,unsigned char* pBaseKey, unsigned char pBaseKeyLen, CK_OBJECT_HANDLE_PTR phKeyToBeWrapped)
{
	CK_RV bRtn = 0;
	CK_RV rv = 0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	unsigned char	SM4iv[16] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
	unsigned char   ZUCiv[16] = {0x0};

	CK_ATTRIBUTE ZUCkeyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &KeyToBeWrappedType, sizeof(KeyToBeWrappedType)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,pBaseKey,pBaseKeyLen}
	};

	CK_MECHANISM mechanismInit = {CKM_SM4_ECB, NULL_PTR, 0};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

	CK_BYTE indata[256] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[256] = {0};
	CK_ULONG outdatalen=sizeof(outdata);
	CK_BYTE inresultdata[256] = {0};
	CK_ULONG inresultdatalen=sizeof(inresultdata);
	CK_BYTE outresultdata[256] = {0};
	CK_ULONG outresultdatalen=sizeof(outresultdata);

	if(KeyToBeWrappedType == CKK_SM4)
	{
		mechanismInit.mechanism = CKM_SM4_ECB;
	}
	else if(KeyToBeWrappedType == CKK_ZUC)
	{
		mechanismInit.mechanism = CKM_ZUC_EEA;
		mechanismInit.pParameter = ZUCiv;
	}
	else
	{
		printf("Error:key type invalid\n");
		return Free_Memory(FREE_0);
	}

	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	bRtn = Show_Result("pC_CreateObject hKey_Enc", RUN_CORRECT, __FUNCTION__, rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	rv = (FunctionPtr->C_EncryptInit)(session, &mechanismInit, hKey_Enc);
	bRtn = Show_Result("pC_EncryptInit", RUN_CORRECT, __FUNCTION__, rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	indatalen = sizeof(indata);
	memset(indata, 0, indatalen);

	//?IV???????
	if(KeyToBeWrappedType == CKK_SM4 )
	{
		indatalen =  32;
		RandomGenerate(indata, indatalen);
	}
	else if(KeyToBeWrappedType == CKK_ZUC)
	{
		indatalen =  32;
		RandomGenerate(indata, indatalen);
	}
	else
	{
		printf("Error:key type invalid\n");
		return Free_Memory(FREE_0);
	}

	memset(inresultdata, 0, inresultdatalen);
	//????
	rv = (FunctionPtr->C_Encrypt)(session, indata, indatalen, inresultdata, &inresultdatalen);
	bRtn = Show_Result("pC_Encrypt", RUN_CORRECT, __FUNCTION__, rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));


	if(KeyToBeWrappedType == CKK_SM4)
	{
		memcpy(outdata,inresultdata, inresultdatalen);	
		outdatalen = inresultdatalen;
	}
	else if(KeyToBeWrappedType == CKK_ZUC)
	{
		memcpy(outdata,inresultdata, inresultdatalen);	
		outdatalen = inresultdatalen;
	}
	else
	{
		printf("Error:key type invalid\n");
		return Free_Memory(FREE_0);
	}

	rv = (FunctionPtr->C_DecryptInit)(session, &mechanismInit, *phKeyToBeWrapped);
	bRtn = Show_Result("pC_DecryptInit", RUN_CORRECT, __FUNCTION__, rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	rv = (FunctionPtr->C_Decrypt)(session, outdata, outdatalen, outresultdata, &outresultdatalen);
	bRtn = Show_Result("pC_Decrypt", RUN_CORRECT, __FUNCTION__, rv);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	if(KeyToBeWrappedType == CKK_SM4)
	{
		bRtn = Result_Compare(outresultdata, outresultdatalen, indata,indatalen);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
	}
	else if(KeyToBeWrappedType == CKK_ZUC)
	{
		bRtn = Result_Compare(outresultdata, outresultdatalen, indata,indatalen);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
	}
	else
	{
		printf("Error:key type invalid\n");
		return Free_Memory(FREE_0);
	}

	if(hKey_Enc != NULL_PTR)
		{
			rv = FunctionPtr->C_DestroyObject(session, hKey_Enc);
			bRtn = Show_Result("DestroyObject",RUN_CORRECT, "hKey_Enc", rv);
			RV_FALSE_RETURN(bRtn);
		}	

	return Free_Memory(FREE_0);
}

CK_ULONG CheckOneTypeKeyUserGen(CK_KEY_TYPE KeyToBeWrappedType,CK_KEY_TYPE WrappingKeyType,unsigned int WrapMechanismType,CK_BBOOL*TokenValue,CK_BBOOL*ExtractableValue,CK_BBOOL*WrapWithTrustedValue)
{
	CK_ULONG bRtn = 0;
	CK_RV rv=0;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE SM4keyType = CKK_SM4;

	CK_OBJECT_HANDLE hKeyToBeWrapped = NULL_PTR;
	CK_OBJECT_HANDLE hWrappingKey = NULL_PTR;
	CK_OBJECT_HANDLE hDecryptKey = NULL_PTR;

	CK_BYTE WrappedKeyValue[16 + 96] = {0};
	unsigned int WrappedKeyValueLen = sizeof(WrappedKeyValue);

	CK_BYTE DecryptedKeyValue[16] = {0};
	unsigned int DecryptedKeyValueLen = sizeof(DecryptedKeyValue);
	int i = 0;
	int Wrapping_Flag = RUN_CORRECT;

	for(i = 0; i < 8; ++i)
	{
		printf("i = %d\n",i);
		
		//?????????flash?????
		if(TokenValue[i] == TRUE)
		{
			printf("flash key, skip.\n");
			continue;
		}

		//?????????ram?????
		if((TokenValue[i] == FALSE)&&(ExtractableValue[i] ==FALSE)&&(WrapWithTrustedValue[i] == TRUE))
		{
			printf("wrong ram key, skip.\n");
			continue;
		}
		
		Wrapping_Flag = RUN_CORRECT;
		
		if((TokenValue[i] == TRUE)||(WrapWithTrustedValue[i] == TRUE)||(ExtractableValue[i] == FALSE))
		{
			Wrapping_Flag = RUN_INCORRECT;
		}
		
	    //??????????
		bRtn = GenKeyToBeWrapped(KeyToBeWrappedType, TokenValue[i], ExtractableValue[i], WrapWithTrustedValue[i], &hKeyToBeWrapped);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

		//?????????????,????????
   		bRtn = GetWrappedKeyValue(&hKeyToBeWrapped);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));


		//???????????SM4????		
		bRtn = CreateWrappingKeyUser(WrappingKeyType, ttrue, &hWrappingKey, &hDecryptKey);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
		

		//????	
		bRtn = WrappingTheKeyToBeWrapped(&hKeyToBeWrapped, &hWrappingKey, WrapMechanismType, WrappedKeyValue, &WrappedKeyValueLen, Wrapping_Flag);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

		if(Wrapping_Flag = RUN_INCORRECT)
		{
			bRtn = Destroy_Useless_KeyPair(hWrappingKey,hDecryptKey);
			RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

			if(hKeyToBeWrapped != NULL_PTR)
			{
				rv = FunctionPtr->C_DestroyObject(session, hKeyToBeWrapped);
				bRtn = Show_Result("DestroyObject",RUN_CORRECT, "hKeyToBeWrapped", rv);
				RV_FALSE_RETURN(bRtn);
			}	
			
			continue;
		}

		bRtn = DecryptWrappedKey(WrappedKeyValue, WrappedKeyValueLen, &hDecryptKey, WrapMechanismType, DecryptedKeyValue, &DecryptedKeyValueLen);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

		if(WrappingKeyType == CKK_SM2)
		{
			bRtn = Destroy_Useless_KeyPair(hWrappingKey,hDecryptKey);
			RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
		}

		if(WrappingKeyType == CKK_SM4)
		{
			if(hWrappingKey != NULL_PTR)
			{
				rv = FunctionPtr->C_DestroyObject(session, hWrappingKey);
				bRtn = Show_Result("DestroyObject",RUN_CORRECT, "hWrappingKey", rv);
				RV_FALSE_RETURN(bRtn);
			}
			if(hDecryptKey != NULL_PTR)
			{
				rv = FunctionPtr->C_DestroyObject(session, hDecryptKey);
				bRtn = Show_Result("DestroyObject",RUN_CORRECT, "hDecryptKey", rv);
				RV_FALSE_RETURN(bRtn);
			}	
		}

		bRtn = Check_GenKey_by_KeyValue(KeyToBeWrappedType, DecryptedKeyValue, DecryptedKeyValueLen, &hKeyToBeWrapped);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

		printf("Success!\n");

		if(hKeyToBeWrapped != NULL_PTR)
		{
			rv = FunctionPtr->C_DestroyObject(session, hKeyToBeWrapped);
			bRtn = Show_Result("DestroyObject",RUN_CORRECT, "hKeyToBeWrapped", rv);
			RV_FALSE_RETURN(bRtn);
		}	
	}

	return Free_Memory(FREE_0);
}

CK_ULONG CheckOneTypeKeySoGen(CK_KEY_TYPE KeyToBeWrappedType,CK_KEY_TYPE WrappingKeyType,unsigned int WrapMechanismType, CK_BBOOL*TokenValue,CK_BBOOL*ExtractableValue,CK_BBOOL*WrapWithTrustedValue)
{
	CK_ULONG bRtn = 0;
	CK_RV rv=0;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE SM4keyType = CKK_SM4;

	CK_OBJECT_HANDLE hKeyToBeWrapped = NULL_PTR;
	CK_OBJECT_HANDLE hWrappingKey = NULL_PTR;
	CK_OBJECT_HANDLE hDecryptKey = NULL_PTR;

	CK_BYTE WrappedKeyValue[16] = {0};
	unsigned int WrappedKeyValueLen = sizeof(WrappedKeyValue);

	CK_BYTE DecryptedKeyValue[16] = {0};
	unsigned int DecryptedKeyValueLen = sizeof(DecryptedKeyValue);
	int i = 0;
	int Wrapping_Flag = RUN_CORRECT;

	for(i = 0; i < 8; ++i)
	{
		printf("i=%d\n",i);
		
		//?????????flash?????
		if(TokenValue[i] == TRUE)
			continue;

		//?????????ram?????
		if((TokenValue[i] == FALSE)&&(ExtractableValue[i] ==FALSE)&&(WrapWithTrustedValue[i] == TRUE))
		{
			continue;
		}
		
		Wrapping_Flag = RUN_CORRECT;
		if((TokenValue[i] == TRUE)||(ExtractableValue[i] == FALSE))
		{
			Wrapping_Flag = RUN_INCORRECT;
		}

		bRtn = GenKeyToBeWrapped(KeyToBeWrappedType, TokenValue[i], ExtractableValue[i], WrapWithTrustedValue[i], &hKeyToBeWrapped);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

//		bRtn = GetWrappedKeyValue(&hKeyToBeWrapped);
//		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

		bRtn = CreateWrappingKeySo(WrappingKeyType, ttrue, &hWrappingKey, &hDecryptKey);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

		bRtn = WrappingTheKeyToBeWrapped(&hKeyToBeWrapped, &hWrappingKey, WrapMechanismType, WrappedKeyValue, &WrappedKeyValueLen, Wrapping_Flag);
		printf("bRtn1 = %d!\n", bRtn);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
		printf("bRtn2 = %d!\n", bRtn);

		if(Wrapping_Flag = RUN_INCORRECT)
		{
			bRtn = Destroy_Useless_KeyPair(hWrappingKey,hDecryptKey);
			printf("bRtn5555 = %d!\n", bRtn);
			RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

			if(hKeyToBeWrapped != NULL_PTR)
			{
				rv = FunctionPtr->C_DestroyObject(session, hKeyToBeWrapped);
				bRtn = Show_Result("DestroyObject",RUN_CORRECT, "hKeyToBeWrapped", rv);
				RV_FALSE_RETURN(bRtn);
			}	
			
			continue;
		}

		bRtn = DecryptWrappedKey(WrappedKeyValue, WrappedKeyValueLen, &hDecryptKey, WrapMechanismType, DecryptedKeyValue, &DecryptedKeyValueLen);
		printf("bRtn3 = %d!\n", bRtn);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

		if(WrappingKeyType == CKK_SM4)
		{
			if(hWrappingKey != NULL_PTR)
			{
				rv = FunctionPtr->C_DestroyObject(session, hWrappingKey);
				bRtn = Show_Result("DestroyObject",RUN_CORRECT, "hWrappingKey", rv);
			//	RV_FALSE_RETURN(bRtn);
			}
			if(hDecryptKey != NULL_PTR)
			{
				rv = FunctionPtr->C_DestroyObject(session, hDecryptKey);
				bRtn = Show_Result("DestroyObject",RUN_CORRECT, "hDecryptKey", rv);
				//RV_FALSE_RETURN(bRtn);
			}	
		}
		
		bRtn = Check_GenKey_by_KeyValue(KeyToBeWrappedType, DecryptedKeyValue, DecryptedKeyValueLen, &hKeyToBeWrapped);
		RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

		printf("Success!\n");

		if(hKeyToBeWrapped != NULL_PTR)
		{
			rv = FunctionPtr->C_DestroyObject(session, hKeyToBeWrapped);
			bRtn = Show_Result("DestroyObject",RUN_CORRECT, "hKeyToBeWrapped", rv);
			//RV_FALSE_RETURN(bRtn);
		}	

	}

	return Free_Memory(FREE_0);
}

#define OPEN_LOGOUT_CLOSESSION
CK_ULONG test_WrapKeyOut_Gen()
{
	CK_ULONG bRtn = FALSE;
	CK_RV rv=0;

	//78=>45
	CK_BBOOL TokenValue[8] =			{ CK_TRUE, CK_TRUE, CK_TRUE, CK_FALSE, CK_FALSE, CK_TRUE, CK_FALSE, CK_FALSE };
	CK_BBOOL ExtractableValue[8] =		{ CK_TRUE, CK_TRUE, CK_FALSE, CK_FALSE, CK_FALSE, CK_FALSE, CK_TRUE, CK_TRUE };
	CK_BBOOL WrapWithTrustedValue[8] =	{ CK_TRUE, CK_FALSE, CK_TRUE, CK_TRUE, CK_FALSE, CK_FALSE, CK_TRUE, CK_FALSE };


	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	//expect result: i=0,1,2,3:skip; i=4:cannot extract; i=5:skip; i=6: success(so), cannotextract(user); i=7, success

#ifdef OPEN_LOGOUT_CLOSESSION
	printf("\n------SO: wrap SM4 key out with SM4 ECB-------\n");
	bRtn = CheckOneTypeKeySoGen(CKK_SM4, CKK_SM4, CKM_SM4_ECB, TokenValue, ExtractableValue, WrapWithTrustedValue);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	printf("\n------SO: wrap SM4 key out with SM4 CBC-------\n");
	bRtn = CheckOneTypeKeySoGen(CKK_SM4, CKK_SM4, CKM_SM4_CBC, TokenValue, ExtractableValue, WrapWithTrustedValue);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
#endif

	printf("\n------wrap SM4 key out with SM4 ECB-------\n");
	bRtn = CheckOneTypeKeyUserGen(CKK_SM4, CKK_SM4, CKM_SM4_ECB, TokenValue, ExtractableValue, WrapWithTrustedValue);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	printf("\n------wrap SM4 key out with SM4 CBC-------\n");
	bRtn = CheckOneTypeKeyUserGen(CKK_SM4, CKK_SM4, CKM_SM4_CBC, TokenValue, ExtractableValue, WrapWithTrustedValue);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

#ifdef OPEN_LOGOUT_CLOSESSION
	printf("\n------SO: wrap ZUC key out with SM4 ECB-------\n");
	bRtn = CheckOneTypeKeySoGen(CKK_ZUC, CKK_SM4, CKM_SM4_ECB, TokenValue, ExtractableValue, WrapWithTrustedValue);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	printf("\n------SO: wrap ZUC key out with SM4 CBC-------\n");
	bRtn = CheckOneTypeKeySoGen(CKK_ZUC, CKK_SM4, CKM_SM4_CBC, TokenValue, ExtractableValue, WrapWithTrustedValue);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));
#endif

	printf("\n------wrap ZUC key out with SM4 ECB-------\n");
	bRtn = CheckOneTypeKeyUserGen(CKK_ZUC, CKK_SM4, CKM_SM4_ECB, TokenValue, ExtractableValue, WrapWithTrustedValue);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	printf("\n------wrap ZUC key out with SM4 CBC-------\n");
	bRtn = CheckOneTypeKeyUserGen(CKK_ZUC, CKK_SM4, CKM_SM4_CBC, TokenValue, ExtractableValue, WrapWithTrustedValue);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));


	printf("\n------wrap SM4 key out with SM2-------\n");
	bRtn = CheckOneTypeKeyUserGen(CKK_SM4, CKK_SM2, CKM_SM2, TokenValue, ExtractableValue, WrapWithTrustedValue);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	printf("\n------wrap ZUC key out with SM2-------\n");
	bRtn = CheckOneTypeKeyUserGen(CKK_ZUC, CKK_SM2, CKM_SM2, TokenValue, ExtractableValue, WrapWithTrustedValue);
	RV_FALSE_RETURN(Rv_False_Free_Memory(bRtn, FREE_0));

	return Free_Memory(FREE_0);
}

char* my_itoa(unsigned int value, char* result) {
	char* ptr = result, *ptr1 = result, tmp_char;
	unsigned int tmp_value;

	if (value < 10)
	{
		result[0] = 0x30;
		result[1] = 0x30 + value;
		return result;
	}

	do {
		tmp_value = value;
		value /= 10;
		*ptr++ = 0x30 + (tmp_value - value * 10);

	} while ( value );

	*ptr--;

	while(ptr1 < ptr) {
		tmp_char = *ptr;
		*ptr--= *ptr1;
		*ptr1++ = tmp_char;
	}

	return result;
}


CK_RV Get_Date_For_Key_Gen(CK_DATE* start_date, CK_DATE* end_date)
{
	struct tm *localt;
	time_t t;
	t=time(NULL);
	localt=localtime(&t);

	my_itoa(localt->tm_year+1900,start_date->year);
	my_itoa(localt->tm_mon+1,start_date->month);
	my_itoa(localt->tm_mday,start_date->day);

	my_itoa(localt->tm_year+1900+10,end_date->year);
	my_itoa(localt->tm_mon+1,end_date->month);
	my_itoa(localt->tm_mday,end_date->day);

	return CKR_OK;
}

CK_ULONG xtest_GenerateKeyPairAndOperateDate()
{
	CK_DATE start_date;
	CK_DATE end_date;
	CK_ULONG bRtn = 0;
	CK_RV rv = 0;
	unsigned int i = 0;
	CK_BYTE idid[] = {1,2,4,3};
	CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY,priclass=CKO_PRIVATE_KEY;

	CK_BBOOL ttrue = CK_TRUE,ffalse = CK_FALSE;
	CK_MECHANISM      ECCMechanism = {CKM_SM2_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_UINT     ECCModulesBits = 256;
	CK_KEY_TYPE  ECCKeyType = CKK_SM2;
	CK_ATTRIBUTE publicKeyTemplate[] = {
		{CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)},
		{CKA_ENCRYPT, &ffalse, sizeof(CK_BBOOL)},
		{CKA_VERIFY, &ffalse, sizeof(CK_BBOOL)},
		{CKA_WRAP, &ttrue, sizeof(CK_BBOOL)},
		{CKA_ID, idid, sizeof(idid)},
		{CKA_START_DATE, &start_date,sizeof(start_date)},
		{CKA_END_DATE, &end_date,sizeof(end_date)},
		{CKA_KEY_TYPE,&ECCKeyType,sizeof(CK_KEY_TYPE)}
	};

	CK_ATTRIBUTE privateKeyTemplate[] = {
		{CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_TOKEN, &ttrue, sizeof(CK_BBOOL)},
		{CKA_PRIVATE, &ttrue, sizeof(CK_BBOOL)},
		{CKA_SENSITIVE, &ttrue, sizeof(CK_BBOOL)},
		{CKA_DECRYPT, &ffalse, sizeof(CK_BBOOL)},
		{CKA_SIGN, &ffalse, sizeof(CK_BBOOL)},
		{CKA_UNWRAP, &ttrue, sizeof(CK_BBOOL)},
		{CKA_ID, idid, sizeof(idid)},
		{CKA_START_DATE, &start_date,sizeof(start_date)},
		{CKA_END_DATE, &end_date,sizeof(end_date)},
		{CKA_KEY_TYPE,&ECCKeyType,sizeof(CK_KEY_TYPE)}
	};
	CK_OBJECT_HANDLE hPublicKey = NULL_PTR, hPrivateKey = NULL_PTR;	


	CK_DATE get_start_date;
	CK_DATE get_end_date;
	CK_ATTRIBUTE GetDateTemplate[] = {
		{CKA_START_DATE, &get_start_date,sizeof(get_start_date)},
		{CKA_END_DATE, &get_end_date,sizeof(get_end_date)},
	};

	CK_DATE set_date={"9999","04","28"};

	CK_ATTRIBUTE SetDateTemplate[] = {
		{CKA_START_DATE, &set_date,sizeof(set_date)},
		{CKA_END_DATE, &set_date,sizeof(set_date)}	
	};

	rv = Get_Date_For_Key_Gen(&start_date, &end_date);
	RV_NOT_OK_RETURN_FALSE(Get_Date_For_Key_Gen,rv);

	printf("start_date:%.4s-%.2s-%.2s\n",start_date.year,start_date.month,start_date.day);
	printf("end_date:%.4s-%.2s-%.2s\n",end_date.year,end_date.month,end_date.day);

	rv = (FunctionPtr->C_GenerateKeyPair)(session, &ECCMechanism,
		publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
		privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),
		&hPublicKey, &hPrivateKey);
	RV_NOT_OK_RETURN_FALSE(pC_GenerateKeyPair,rv);

	rv = (FunctionPtr->C_GetAttributeValue)(session,hPrivateKey,GetDateTemplate,sizeof(GetDateTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_GetAttributeValue1,rv);

	printf("getpristart_date1:%.4s-%.2s-%.2s\n",get_start_date.year,get_start_date.month,get_start_date.day);
	printf("getpriend_date1:%.4s-%.2s-%.2s\n",get_end_date.year,get_end_date.month,get_end_date.day);

	rv = (FunctionPtr->C_GetAttributeValue)(session,hPublicKey,GetDateTemplate,sizeof(GetDateTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_GetAttributeValue2,rv);

	printf("getpubstart_date1:%.4s-%.2s-%.2s\n",get_start_date.year,get_start_date.month,get_start_date.day);
	printf("getpubend_date1:%.4s-%.2s-%.2s\n",get_end_date.year,get_end_date.month,get_end_date.day);

	//??????
	rv = (FunctionPtr->C_SetAttributeValue)(session,hPublicKey,SetDateTemplate,sizeof(SetDateTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_TRUE(pC_SetAttributeValue2,rv);

	rv = (FunctionPtr->C_GetAttributeValue)(session,hPublicKey,GetDateTemplate,sizeof(GetDateTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_GetAttributeValue2,rv);
	printf("get pubstart_date2:%.4s-%.2s-%.2s\n",get_start_date.year,get_start_date.month,get_start_date.day);
	printf("get pubend_date2:%.4s-%.2s-%.2s\n",get_end_date.year,get_end_date.month,get_end_date.day);

	rv = (FunctionPtr->C_GetAttributeValue)(session,hPrivateKey,GetDateTemplate,sizeof(GetDateTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_GetAttributeValue2,rv);

	printf("getpristart_date2:%.4s-%.2s-%.2s\n",get_start_date.year,get_start_date.month,get_start_date.day);
	printf("getpriend_date2:%.4s-%.2s-%.2s\n",get_end_date.year,get_end_date.month,get_end_date.day);

	if (hPublicKey)
	{
		rv = FunctionPtr->C_DestroyObject(session, hPublicKey);
		RV_NOT_OK_RETURN_FALSE(pC_DestroyObject0,rv);
	}
	if (hPrivateKey)
	{
		rv = FunctionPtr->C_DestroyObject(session, hPrivateKey);
		RV_NOT_OK_RETURN_FALSE(pC_DestroyObject1,rv);
	}

END:
	
	return bRtn;
}



/*??SM3HMAC ??*/
CK_ULONG test_SM3_HMAC()
{
/*	CK_RV rv = 0;
	bool	bRtn = false;
	int i;
	CK_BYTE inputData[32] = {0}; 
	CK_BYTE SM3DigestCorReslut[32] = {0xa4, 0xf5, 0x0a, 0x29, 0xc3, 0x27, 0xe9, 0xac, 0xc4, 0xdd, 0xd4, 0xdb, 0xe3, 0x2b, 0x75, 0xa6, 0xa1, 0xd7, 0x7e, 0x4b, 0xbe, 0x82, 0x3e, 0x3d, 0x71, 0xfd, 0xcc, 0x1a, 0x5f, 0xa5, 0x27, 0x57};

	
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_SM3;
	CK_ATTRIBUTE_TYPE keySize = 64;
	CK_BBOOL _true = TRUE;
    CK_BBOOL _false = FALSE;
	CK_BYTE hmac_key[64]={0};
	int attrcount = 0;
	CK_OBJECT_HANDLE hKey=0;
	CK_OBJECT_HANDLE_PTR pSM3Key =&hKey;

	CK_ATTRIBUTE secretKeyTemplate[] = {
			{ CKA_CLASS, &key_class, sizeof(key_class)},
			{ CKA_TOKEN, &_true, sizeof(_false) },			
			{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
			{ CKA_SIGN, &_true, sizeof(_true) },
			{ CKA_VALUE, &keySize, sizeof(keySize)}
	};

	CK_BYTE_PTR secret_key_data = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * 64);
	memset(secret_key_data,0,sizeof(CK_BYTE) * 64);

	CK_MECHANISM_PTR pPmechanism = (CK_MECHANISM_PTR)malloc(sizeof(CK_MECHANISM));
	memset(pPmechanism, 0 , sizeof(CK_MECHANISM));
	pPmechanism->mechanism = CKM_HMAC_SM3_KEY_GEN;

	rv = FunctionPtr->C_GenerateKey(session,pPmechanism,secretKeyTemplate,5,pSM3Key);
	free(secret_key_data);
	free(pPmechanism);


	
	for(i = 0; i < 1; ++i)
	{	
		
		CK_MECHANISM mechanism_hmac = {CKM_HMAC_SM3, hmac_key, sizeof(hmac_key)};
	
		CK_BYTE SM3DigestFinalData1[sizeof(inputData)] = {0};
		CK_ULONG SM3DigestLen1 = sizeof(inputData);
		
		CK_BYTE SM3DigestFinalData[sizeof(inputData)] = {0};
		CK_ULONG SM3DigestLen = sizeof(inputData);



		rv = FunctionPtr->C_DigestInit(session, &mechanism_hmac);
		if(rv != CKR_OK)
		{
			printf("FunctionPtr->C_DigestInit failed: %0x\n", rv);
			return rv;
		}
		
		rv = FunctionPtr->C_Digest(session,inputData,sizeof(inputData), SM3DigestFinalData1,(CK_ULONG_PTR)(&SM3DigestLen1));
		if(rv != CKR_OK)
		{
			printf("C_Digest error. rv = %d\n", rv);
			return rv;
		}

		if ((SM3DigestLen1 != sizeof(SM3DigestCorReslut)) || (memcmp(SM3DigestFinalData1, SM3DigestCorReslut, SM3DigestLen1)))
		{
			printf("Error: HMAC-SM3 .\n");
		}
		else {
			printf("Success: HMAC-SM3.\n");
		}

		

		rv = FunctionPtr->C_DigestInit(session, &mechanism_hmac);
		if(rv != CKR_OK)
		{
			printf("FunctionPtr->C_DigestInit failed: %0x\n", rv);
			return rv;
		}
		
		rv = FunctionPtr->C_DigestUpdate(session,inputData,sizeof(inputData)/2);
		

		if(rv != CKR_OK)
		{
			printf("FunctionPtr->C_DigestUpdate failed: %0x\n", rv);
			return rv;
		}
		else
		{
			printf("FunctionPtr->C_DigestUpdate success!\n");
		}
		

		rv = FunctionPtr->C_DigestUpdate(session,&inputData[(sizeof(inputData)/2)],sizeof(inputData)/2);
			

			if(rv != CKR_OK)
			{
				printf("FunctionPtr->C_DigestUpdate failed: %0x\n", rv);
				return rv;
			}
			else
			{
				printf("FunctionPtr->C_DigestUpdate success!\n");
			}

//		rv = FunctionPtr->C_DigestFinal(session,NULL, (CK_ULONG_PTR)&SM3DigestLen);

//		if(rv != CKR_OK)
//		{
//			printf("FunctionPtr->C_DigestFinal1 failed: %0x\n", rv);
//			return rv;
//		}


		rv = FunctionPtr->C_DigestFinal(session,SM3DigestFinalData, (CK_ULONG_PTR)&SM3DigestLen);

		if(rv != CKR_OK)
		{
			printf("C_DigestFinal2 failed: %0x\n", rv);
			return rv;
		}


		
		if ((SM3DigestLen != sizeof(SM3DigestCorReslut)) || (memcmp(SM3DigestFinalData, SM3DigestCorReslut, SM3DigestLen)))
		{
			printf("Error: HMAC-SM3 DigestUpdate.\n");
		}
		else {
			printf("Success: HMAC-SM3 DigestUpdate.\n");
		}
	
	}
	
	return rv;
*/
}


//??ZUC??????





CK_ULONG xtest_ZUC_MultiSession(int looptime,int datalen)
{
//	char strtemp[256];
	CK_ULONG bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE ZUCkeyType = CKK_ZUC;
	
	//????
	unsigned char	ZUCkeyVal_Enc[]={0xe5, 0xbd, 0x38, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Enc[5000] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
	 		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char	ZUCcipher_Enc[5000] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
	 		0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};	
//	unsigned char	ZUCiv_Enc[] = {0x00, 0x05, 0x68, 0x23, 0x38};
	unsigned char	ZUCiv_Enc[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Enc,sizeof(ZUCkeyVal_Enc)}
	};
	CK_MECHANISM ZUCmechanism_Enc = {CKM_ZUC_EEA, ZUCiv_Enc, sizeof(ZUCiv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;
	CK_OBJECT_HANDLE hKey_Enc_sess2 = NULL_PTR;

	//????
	unsigned char	ZUCkeyVal_Dec[]={0xe5, 0xbd, 0x38, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Dec[5000] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
	 		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char	ZUCcipher_Dec[5000] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
			0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};

//	unsigned char	ZUCiv_Dec[]={0x00, 0x05, 0x68, 0x23, 0x38};
	unsigned char	ZUCiv_Dec[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Dec[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Dec,sizeof(ZUCkeyVal_Dec)}
	};
	CK_MECHANISM ZUCmechanism_Dec = {CKM_ZUC_EEA, ZUCiv_Dec, sizeof(ZUCiv_Dec)};
	CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

	CK_BYTE indata[5000] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[5000] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[5000] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[5000] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);

	CK_BYTE outdata_ses1[5000] = {0};
	CK_ULONG outdatalen_ses1=sizeof(outdata_ses1);
	CK_BYTE outdata1_ses1[5000] = {0};
	CK_ULONG outdatalen1_ses1=sizeof(outdata1);

	unsigned int i = 0,j=0;
	UtilscTime ttc1={0, 0},ttc2={0,0},ttc3={0,0},ttc4={0,0};
	CK_BYTE ch[10];

//	printf("input looptime:\n");
//	fgets(ch,10,stdin);
//  looptime = atoi(ch);

	looptime = 1;

	printf("input datalen(0-5000):\n");
	fgets(ch,10,stdin);
   	datalen = atoi(ch);

	srand( (unsigned)time( NULL ) );//??????

	//???????
	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	printf("hKey_Enc = 0x%x\n", hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_Enc,rv);

	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc_sess2);
	printf("hKey_Enc_sess2 = 0x%x\n", hKey_Enc_sess2);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_Enc,rv);

	//???????
	hKey_Dec = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Dec, sizeof(ZUCkeyTemplate_Dec)/sizeof(CK_ATTRIBUTE), &hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_Dec,rv);

	printf("Datalen=%d.\n",datalen);

	for (i=0; i<looptime; i++)
	{

//		printf("i = %d\n",i);
		
		//???????	
		RandomGenerate(ZUCplain_Enc,datalen);
		//?????????
		RandomGenerate(ZUCiv_Enc,16);
		memcpy(ZUCiv_Dec,ZUCiv_Enc,16);

		BUFFER_REFRESH_ZERO(indata,indatalen,outdata,outdatalen);
		BUFFER_REFRESH_ZERO(indata1,indatalen1,outdata1,outdatalen1);

		memcpy(indata, ZUCplain_Enc, datalen);
		indatalen = datalen;

		/*******************????**********************/
		rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);

		rv = (FunctionPtr->C_EncryptInit)(session1, &ZUCmechanism_Enc, hKey_Enc_sess2);  
		printf("rv = %x\n",rv);
		//RV_NOT_OK_RETURN_TRUE(pC_EncryptInit_ses1,rv);
		
		rv = (FunctionPtr->C_EncryptUpdate)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);

		rv = (FunctionPtr->C_EncryptUpdate)(session1, indata, indatalen, outdata_ses1, &outdatalen_ses1);
		printf("rv1 = %x\n",rv);

		if ((outdatalen != outdatalen_ses1) || (memcmp(outdata, outdata_ses1, outdatalen)))
		{
			printf("??session???????!(update)\n");
			bRtn = 1;
			goto END;
		}
		//RV_NOT_OK_RETURN_TRUE(pC_EncryptUpdate_ses1,rv);

		/*rv = (FunctionPtr->C_EncryptInit)(session1, &ZUCmechanism_Enc, hKey_Enc);
		printf("rv2 = %x\n",rv2);
		RV_NOT_OK_RETURN_TRUE(pC_EncryptInit_ses1_2,rv);*/

		rv = (FunctionPtr->C_EncryptFinal)(session, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);

		rv = (FunctionPtr->C_EncryptFinal)(session1, outdata_ses1, &outdatalen_ses1);
		RV_NOT_OK_RETURN_TRUE(pC_EncryptFinal_ses1,rv);

		rv = (FunctionPtr->C_EncryptInit)(session1, &ZUCmechanism_Enc, hKey_Enc);   
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit_ses1_3,rv);
	
		rv = (FunctionPtr->C_EncryptUpdate)(session1, indata, indatalen, outdata_ses1, &outdatalen_ses1);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate_ses1_3,rv);

		rv = (FunctionPtr->C_EncryptFinal)(session1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal_ses1_3,rv);

		if ((outdatalen != outdatalen_ses1) || (memcmp(outdata, outdata_ses1, outdatalen)))
		{
			printf("??session???????!(update)\n");
			bRtn = 1;
			goto END;
		}

		
		//???
		rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);   
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);
		
		rv = (FunctionPtr->C_Encrypt)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_Encrypt,rv);

		rv = (FunctionPtr->C_Encrypt)(session1, indata, indatalen, outdata_ses1, &outdatalen_ses1);
		RV_NOT_OK_RETURN_TRUE(pC_Encrypt_ses1_4,rv);

		rv = (FunctionPtr->C_EncryptInit)(session1, &ZUCmechanism_Enc, hKey_Enc);   
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit_ses1_5,rv);
		
		rv = (FunctionPtr->C_Encrypt)(session1, indata, indatalen, outdata_ses1, &outdatalen_ses1);
		RV_NOT_OK_RETURN_FALSE(pC_Encrypt_ses1_5,rv);

		if ((outdatalen != outdatalen_ses1) || (memcmp(outdata, outdata_ses1, outdatalen)))
		{
			printf("??session???????!\n");
			bRtn = 1;
			goto END;
		}
		
		memcpy(indata1, outdata, outdatalen);
		indatalen1 = outdatalen;

		/******************????***********************/
		rv = (FunctionPtr->C_DecryptInit)(session, &ZUCmechanism_Dec, hKey_Dec);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);

		rv = (FunctionPtr->C_DecryptInit)(session1, &ZUCmechanism_Dec, hKey_Dec);
		RV_NOT_OK_RETURN_TRUE(pC_DecryptInit_ses1,rv);
		
		rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);

		rv = (FunctionPtr->C_DecryptUpdate)(session1, indata1, indatalen1, outdata1_ses1, &outdatalen1_ses1);
		RV_NOT_OK_RETURN_TRUE(pC_DecryptUpdate_ses1,rv);

		rv = (FunctionPtr->C_DecryptInit)(session1, &ZUCmechanism_Dec, hKey_Dec);
		RV_NOT_OK_RETURN_TRUE(pC_DecryptInit_ses1_2,rv);

		rv = (FunctionPtr->C_DecryptFinal)(session, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);

		rv = (FunctionPtr->C_DecryptFinal)(session1, outdata1, &outdatalen1_ses1);
		RV_NOT_OK_RETURN_TRUE(pC_DecryptFinal,rv);

		rv = (FunctionPtr->C_DecryptInit)(session1, &ZUCmechanism_Dec, hKey_Dec);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptInit_ses1_3,rv);

		rv = (FunctionPtr->C_DecryptUpdate)(session1, indata1, indatalen1, outdata1_ses1, &outdatalen1_ses1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate_ses1_3,rv);

		rv = (FunctionPtr->C_DecryptFinal)(session1, outdata1, &outdatalen1_ses1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal_3,rv);

		if ((outdatalen1 != datalen) || (memcmp(outdata1, ZUCplain_Enc, outdatalen1)))
		{
			printf("Result Error.\n");
			printf("outdatalen = %lu.\n", outdatalen1);		
			bRtn = 1;
			goto END;
		}

		if ((outdatalen1 != outdatalen1_ses1) || (memcmp(outdata1, outdata1_ses1, outdatalen1)))
		{
			printf("??session???????(update)!\n");
			bRtn = 1;
			goto END;
		}
	}
	
END:	
	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject1,rv);

	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject2,rv);
	
	return bRtn;
}

CK_ULONG xtest_SM4ECB_MultiSession()
{
	bool bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE SM4keyType = CKK_SM4;
	
	//????
	unsigned char	SM4keyVal_Enc[]={0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
	CK_BYTE SM4plain_Enc[32]= {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
							   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
	CK_BYTE SM4cipher_Enc[32]={0x68, 0x6d, 0xb7, 0x66, 0xc9, 0x20, 0x48, 0x22, 0xbb, 0xfa, 0x6b, 0x84, 0x68, 0xc2, 0x86, 0x91, 
							   0x68, 0x6d, 0xb7, 0x66, 0xc9, 0x20, 0x48, 0x22, 0xbb, 0xfa, 0x6b, 0x84, 0x68, 0xc2, 0x86, 0x91};
	CK_ATTRIBUTE SM4keyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ttrue)},//FLASH ,FFLASE RAM
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,SM4keyVal_Enc,sizeof(SM4keyVal_Enc)}
	};
	CK_MECHANISM SM4mechanism_Enc = {CKM_SM4_ECB, NULL, 0};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;
	CK_OBJECT_HANDLE hKey_Enc2 = NULL_PTR;
	
	CK_BYTE indata[32] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata0[32] = {0};
	CK_ULONG outdatalen0=sizeof(outdata0);
	CK_BYTE outdata[32] = {0};
	CK_ULONG outdatalen=sizeof(outdata);
	CK_BYTE outdata1[32] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);

	CK_BYTE outdata2[32] = {0};
	CK_ULONG outdatalen2=sizeof(outdata1);

	//???????
	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate_Enc, sizeof(SM4keyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject,rv);

	rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate_Enc, sizeof(SM4keyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc2);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject,rv);

	indatalen = sizeof(indata);
	memset(indata, 0, indatalen);
	outdatalen = sizeof(outdata);
	memset(outdata, 0, outdatalen);
	
	//??(???)
	memcpy(indata, SM4plain_Enc, sizeof(SM4plain_Enc));
	indatalen = sizeof(SM4plain_Enc);

	rv = FunctionPtr->C_EncryptInit(session, &SM4mechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);	

	rv = FunctionPtr->C_EncryptInit(session1, &SM4mechanism_Enc, hKey_Enc2);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit_ses1_000,rv);	

	rv = FunctionPtr->C_Encrypt(session, indata, indatalen, outdata0, &outdatalen0);
	RV_NOT_OK_RETURN_FALSE(pC_Encrypt,rv);
	
	rv = FunctionPtr->C_Encrypt(session1, indata, indatalen, outdata, &outdatalen);
	RV_NOT_OK_RETURN_FALSE(pC_Encrypt,rv);

	if ((outdatalen0 != sizeof(SM4cipher_Enc)) || (memcmp(outdata0, SM4cipher_Enc, sizeof(SM4cipher_Enc))))
	{
		printf("SM4 ECB Encrypt Calc Error: test_SM4Encrypt_ECB.\n");
		bRtn = 1;
	}
	else
	{
		printf("SM4 ECB Encrypt sess0 Result is correct!\n");
	}

	if ((outdatalen != sizeof(SM4cipher_Enc)) || (memcmp(outdata, SM4cipher_Enc, sizeof(SM4cipher_Enc))))
	{
		printf("SM4 ECB Encrypt Calc Error: test_SM4Encrypt_ECB.\n");
		bRtn = 1;
	}
	else
	{
		printf("SM4 ECB Encrypt sess1 Result is correct!\n");
	}
	//????
	rv = FunctionPtr->C_EncryptInit(session, &SM4mechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);	
	
	rv = FunctionPtr->C_EncryptInit(session1, &SM4mechanism_Enc, hKey_Enc);
	printf("rv = %d \n",rv);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit_ses1,rv);	

//	rv = FunctionPtr->C_EncryptUpdate(session, indata, indatalen, NULL, &outdatalen);
//	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);	

	rv = FunctionPtr->C_EncryptUpdate(session, indata, indatalen, outdata, &outdatalen);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);

	rv = FunctionPtr->C_EncryptUpdate(session1, indata, indatalen, outdata1, &outdatalen1);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate_ses1,rv);

	if ((outdatalen != sizeof(SM4cipher_Enc)) || (memcmp(outdata, SM4cipher_Enc, sizeof(SM4cipher_Enc))))
	{
		printf("SM4 ECB EncryptUpdated Calc Error: test_SM4Encrypt_ECB.\n"); 
		bRtn = 1;
	}
	else
	{
		printf("SM4 ECB EncryptUpdated Sess0 Result is correct!\n");
	}

	if ((outdatalen1 != sizeof(SM4cipher_Enc)) || (memcmp(outdata1, SM4cipher_Enc, sizeof(SM4cipher_Enc))))
	{
		printf("SM4 ECB EncryptUpdated Calc Error: test_SM4Encrypt_ECB.\n"); 
		bRtn = 1;
	}
	else
	{
		printf("SM4 ECB EncryptUpdated Sess1 Result is correct!\n");
	}
	rv = FunctionPtr->C_EncryptFinal(session, outdata2, &outdatalen2);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);

	rv = FunctionPtr->C_EncryptFinal(session1, outdata2, &outdatalen2);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal_ses1,rv);

	
	//????
	memcpy(indata, SM4cipher_Enc, sizeof(SM4cipher_Enc));
	indatalen = sizeof(SM4cipher_Enc);

	memset(outdata, 0, outdatalen);
	memset(outdata1, 0, outdatalen1);

	rv = FunctionPtr->C_DecryptInit(session, &SM4mechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);	
	
	rv = FunctionPtr->C_DecryptInit(session1, &SM4mechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptInit_ses1,rv);	

//	rv = FunctionPtr->C_DecryptUpdate(session, indata, indatalen, NULL, &outdatalen);
//	RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);	

	rv = FunctionPtr->C_DecryptUpdate(session, indata, indatalen, outdata, &outdatalen);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);

/*	rv = FunctionPtr->C_DecryptInit(session1, &SM4mechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_TRUE(pC_DecryptInit_ses1_2,rv);	*/

	rv = FunctionPtr->C_DecryptUpdate(session1, indata, indatalen, outdata1, &outdatalen1);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate_ses1,rv);

	if ((outdatalen != sizeof(SM4plain_Enc)) || (memcmp(outdata, SM4plain_Enc, sizeof(SM4plain_Enc))))
	{
		printf("SM4 ECB DecryptUpdated Calc Error: test_SM4Encrypt_ECB.\n"); 
		bRtn = 1;
	}
	else
	{
		printf("SM4 ECB DecryptUpdated Sess0 Result is correct!\n");
	}

	if ((outdatalen1 != sizeof(SM4plain_Enc)) || (memcmp(outdata1, SM4plain_Enc, sizeof(SM4plain_Enc))))
	{
		printf("SM4 ECB DecryptUpdated Calc Error: test_SM4Encrypt_ECB.\n"); 
		bRtn = 1;
	}
	else
	{
		printf("SM4 ECB DecryptUpdated Sess1 Result is correct!\n");
	}

	rv = FunctionPtr->C_DecryptFinal(session, outdata2, &outdatalen2);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);

	rv = FunctionPtr->C_DecryptFinal(session1, outdata2, &outdatalen2);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal_ses1,rv);

	rv = FunctionPtr->C_DestroyObject(session, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject,rv);

END:
	return bRtn;
}


CK_ULONG xtest_SM4ECB_SM2()
{
	bool bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE SM4keyType = CKK_SM4;
	
	//????
	unsigned char	SM4keyVal_Enc[]={0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
	CK_BYTE SM4plain_Enc[32]= {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
							   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
	CK_BYTE SM4cipher_Enc[32]={0x68, 0x6d, 0xb7, 0x66, 0xc9, 0x20, 0x48, 0x22, 0xbb, 0xfa, 0x6b, 0x84, 0x68, 0xc2, 0x86, 0x91, 
							   0x68, 0x6d, 0xb7, 0x66, 0xc9, 0x20, 0x48, 0x22, 0xbb, 0xfa, 0x6b, 0x84, 0x68, 0xc2, 0x86, 0x91};
	CK_ATTRIBUTE SM4keyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ttrue)},//FLASH ,FFLASE RAM
		{CKA_KEY_TYPE, &SM4keyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,SM4keyVal_Enc,sizeof(SM4keyVal_Enc)}
	};
	CK_MECHANISM SM4mechanism_Enc = {CKM_SM4_ECB, NULL, 0};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

	//???
	CK_BYTE pub_key[64] = {
			0xec,0x91,0x81,0x8d,0xe0,0xb7,0x01,0x21,0x73,0xf5,0x1c,0x33,0x75,0x43,0x6e,0x43,
			0xb6,0xa9,0xa2,0x6a,0xbd,0x6d,0xbc,0xb7,0x9f,0x85,0x1c,0xde,0xaf,0x7a,0x0f,0x6c,
			0xcb,0xf4,0xb5,0xa1,0x5f,0xb8,0x7e,0x60,0xfc,0x0b,0x3a,0x92,0x3d,0x12,0xe8,0x66,
			0x36,0x4a,0x93,0x5f,0xfb,0x30,0x84,0x2b,0xc9,0x13,0x9e,0xbd,0x2d,0xdc,0xe9,0x61
		};
	CK_BYTE     pri_key[32]={
		0xc5,0x6a,0x2b,0x58,0xa0,0x94,0xef,0x24,0x41,0x03,0x79,0x45,0xba,0xb1,0x39,0x8c,
			0xc0,0xdf,0x9f,0xc4,0xf9,0x9e,0x9a,0x60,0x2c,0xd8,0x6f,0xc2,0xc3,0x88,0xad,0x0c
	};

	CK_UINT pub_key_len = 64;
	CK_UINT pri_key_len = 32;
	CK_KEY_TYPE  keyType=CKK_SM2;
	CK_OBJECT_CLASS pubclass=CKO_PUBLIC_KEY,priclass=CKO_PRIVATE_KEY;
	
	CK_MECHANISM  mechanismcalc = {CKM_SM2, NULL_PTR, 0};
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
	CK_OBJECT_HANDLE * phPublicKey = &hPublicKey, *phPrivateKey = &hPrivateKey;
	
	CK_BYTE indata[32] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata0[32] = {0};
	CK_ULONG outdatalen0=sizeof(outdata0);
	CK_BYTE outdata[128] = {0};
	CK_ULONG outdatalen=sizeof(outdata);
	CK_BYTE outdata1[128] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);

	//SM4???????
	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, SM4keyTemplate_Enc, sizeof(SM4keyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject,rv);

	//SM2
	CK_ATTRIBUTE publicKeyTemplate[] = {		
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_CLASS, &pubclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_PRIVATE, &ttrue, sizeof(ttrue)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VERIFY, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE,&keyType,sizeof(keyType)},
		{CKA_VALUE, pub_key, sizeof(pub_key)},
		{CKA_VALUE_LEN, &pub_key_len, sizeof(CK_UINT)}
//		{CKA_ID, id, sizeof(id)}
	};

	CK_ATTRIBUTE privateKeyTemplate[] = {
		{CKA_TOKEN, &ttrue, sizeof(ttrue)},
		{CKA_CLASS, &priclass, sizeof(CK_OBJECT_CLASS)},
		{CKA_PRIVATE, &ttrue, sizeof(ttrue)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_SIGN, &ttrue, sizeof(ttrue)},
		{CKA_KEY_TYPE,&keyType,sizeof(keyType)},
		{CKA_VALUE, pri_key, sizeof(pri_key)},
		{CKA_VALUE_LEN, &pri_key_len, sizeof(CK_UINT)}
//		{CKA_ID, id, sizeof(id)}
	};

	//??????
	rv = (FunctionPtr->C_CreateObject)(session, 
						  publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
						  phPublicKey);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject1,rv);

	//??????
	rv = (FunctionPtr->C_CreateObject)(session, 
						  privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),
						  phPrivateKey);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject2,rv);

	indatalen = sizeof(indata);
	memset(indata, 0, indatalen);
	outdatalen = sizeof(outdata);
	memset(outdata, 0, outdatalen);
	
	//??(???)
	memcpy(indata, SM4plain_Enc, sizeof(SM4plain_Enc));
	indatalen = sizeof(SM4plain_Enc);

	rv = FunctionPtr->C_EncryptInit(session, &SM4mechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);	

	rv = FunctionPtr->C_EncryptInit(session1, &mechanismcalc, hPublicKey);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit_ses1_0,rv);	

	rv = FunctionPtr->C_Encrypt(session, indata, indatalen, outdata0, &outdatalen0);
	RV_NOT_OK_RETURN_FALSE(pC_Encrypt,rv);

	if ((outdatalen0 != sizeof(SM4cipher_Enc)) || (memcmp(outdata0, SM4cipher_Enc, sizeof(SM4cipher_Enc))))
	{
		printf("SM4 ECB Encrypt Calc Error: test_SM4Encrypt_ECB.\n");
		bRtn = 1;
	}
	else
	{
		printf("SM4 ECB Encrypt sess0 Result is correct!\n");
	}

	rv = FunctionPtr->C_Encrypt(session1, indata, indatalen, outdata, &outdatalen);
	RV_NOT_OK_RETURN_FALSE(pC_Encrypt,rv);


	

	memcpy(indata, outdata0, sizeof(outdata0));
	indatalen = sizeof(outdata0);

	rv = FunctionPtr->C_DecryptInit(session, &SM4mechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);	
	
	rv = FunctionPtr->C_DecryptInit(session1, &mechanismcalc, hPrivateKey);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptInit_ses1,rv);		

	rv = FunctionPtr->C_DecryptUpdate(session, indata, indatalen, outdata1, &outdatalen1);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);

	if ((outdatalen1 != sizeof(SM4plain_Enc)) || (memcmp(outdata1, SM4plain_Enc, sizeof(SM4plain_Enc))))
	{
		printf("SM2 Encrypt Calc Error: test_SM4Encrypt_ECB.\n");
		bRtn = 1;
	}
	else
	{
		printf("SM2 Encrypt sess0 Result is correct!\n");
	}

	rv = FunctionPtr->C_DecryptFinal(session, outdata1, &outdatalen1);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);

	rv = FunctionPtr->C_DecryptFinal(session1, outdata1, &outdatalen1);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal_ses1,rv);

	rv = FunctionPtr->C_DestroyObject(session, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject,rv);
	
	rv = FunctionPtr->C_DestroyObject(session, hPublicKey);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject,rv);
	
	rv = FunctionPtr->C_DestroyObject(session, hPrivateKey);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject,rv);

END:
	return bRtn;
}



CK_ULONG xtest_SM3Encrypt_MultiSession()
{
	CK_ULONG bRtn = 0;
	CK_RV rv = 0;
	int i = 0;
	CK_BYTE srcData[64] = {0};
	for(i = 0;i < sizeof(srcData)/4;i++)
	{
		memcpy(&srcData[i*4],"abcd",4);
	}
	unsigned char pszCorrectResult_SM3[]={0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 
										  0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d, 0x6f, 0xdb, 0x70, 0xe5, 
										  0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 
										  0x57, 0x32};
	CK_BYTE digData[100];
	CK_ULONG ulDigLen=sizeof(digData);
	
	CK_BYTE digData_ses1[100];
	CK_ULONG ulDigLen_ses1=sizeof(digData_ses1);

	CK_MECHANISM mechanism={CKM_HASH_SM3,NULL_PTR,0};

	rv=FunctionPtr->C_DigestInit(session,&mechanism);
	RV_NOT_OK_RETURN_FALSE(pC_DigestInit,rv);

	rv=FunctionPtr->C_DigestInit(session1,&mechanism);
	RV_NOT_OK_RETURN_TRUE(pC_DigestInit_ses1,rv);
		
	ulDigLen=sizeof(digData);
	rv=FunctionPtr->C_Digest(session,srcData,sizeof(srcData),digData,&ulDigLen);
	RV_NOT_OK_RETURN_FALSE(pC_Digest,rv);

	rv=FunctionPtr->C_Digest(session1,srcData,sizeof(srcData),digData_ses1,&ulDigLen_ses1);
	RV_NOT_OK_RETURN_TRUE(pC_Digest_ses1,rv);


//	UtilsPrintData(VNAME(digData),ulDigLen,0);
	
	if (memcmp(pszCorrectResult_SM3, digData, ulDigLen))
	{
		printf("test_digest failed.SM3 Result is wrong1!!! \n");
		bRtn= 1;
		goto END;
	}

//	if (memcmp(pszCorrectResult_SM3, digData_ses1, ulDigLen_ses1))
//	{
//		printf("test_digest failed.SM3 Result is wrong1!!! \n");
//		bRtn= 1;
//		goto END;
//	}
	else
	{
		printf("SM3 Digest Result is correct!\n");
	}
	
	rv=FunctionPtr->C_DigestInit(session,&mechanism);
	RV_NOT_OK_RETURN_FALSE(pC_DigestInit,rv);

	rv=FunctionPtr->C_DigestUpdate(session,srcData,sizeof(srcData)/2);
	RV_NOT_OK_RETURN_FALSE(pC_DigestUpdate1,rv);

	rv=FunctionPtr->C_DigestUpdate(session,srcData+sizeof(srcData)/2,sizeof(srcData)-sizeof(srcData)/2);
	RV_NOT_OK_RETURN_FALSE(pC_DigestUpdate2,rv);
		
	ulDigLen=sizeof(digData);
	rv=FunctionPtr->C_DigestFinal(session,digData,&ulDigLen);
	RV_NOT_OK_RETURN_FALSE(pC_DigestFinal,rv);

	rv=FunctionPtr->C_DigestFinal(session,digData,&ulDigLen);
	printf("SECOND final, should fail. rv = 0x%08lx \n", rv);
	RV_NOT_OK_RETURN_TRUE(pC_DigestFinal2,rv);

//	UtilsPrintData(VNAME(digData),ulDigLen,0);
	
	if (memcmp(pszCorrectResult_SM3, digData, ulDigLen))
	{
		printf("test_digest failed.SM3 Result is wrong2!!! \n");
		bRtn= 1;
		goto END;
	}
	else
	{
		printf("SM3 Updated Digest Result is correct!\n");
	}

END:
	
	return bRtn;
}



CK_ULONG xtest_CleanFlags()
{
	CK_ULONG bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE ZUCkeyType = CKK_ZUC;
	int datalen = 32;
	
	//????
	unsigned char	ZUCkeyVal_Enc[]={0xe5, 0xbd, 0x38, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Enc[5000] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
	 		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char	ZUCcipher_Enc[5000] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
	 		0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};	
	unsigned char	ZUCiv_Enc[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Enc,sizeof(ZUCkeyVal_Enc)}
	};
	CK_MECHANISM ZUCmechanism_Enc = {CKM_ZUC_EEA, ZUCiv_Enc, sizeof(ZUCiv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

	//????
	unsigned char	ZUCkeyVal_Dec[]={0xe5, 0xbd, 0x38, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Dec[5000] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
	 		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char	ZUCcipher_Dec[5000] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
			0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};

	unsigned char	ZUCiv_Dec[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Dec[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Dec,sizeof(ZUCkeyVal_Dec)}
	};
	CK_MECHANISM ZUCmechanism_Dec = {CKM_ZUC_EEA, ZUCiv_Dec, sizeof(ZUCiv_Dec)};
	CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

	CK_BYTE indata[5000] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[5000] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[5000] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[5000] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);

	CK_BYTE outdata_ses1[5000] = {0};
	CK_ULONG outdatalen_ses1=sizeof(outdata_ses1);
	CK_BYTE outdata1_ses1[5000] = {0};
	CK_ULONG outdatalen1_ses1=sizeof(outdata1);

	unsigned int i = 0,j=0;
	UtilscTime ttc1={0,0},ttc2={0,0},ttc3={0,0},ttc4={0,0};
	CK_BYTE ch[10];

	srand( (unsigned)time( NULL ) );//??????

	//???????
	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_Enc,rv);

	//???????
	hKey_Dec = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Dec, sizeof(ZUCkeyTemplate_Dec)/sizeof(CK_ATTRIBUTE), &hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_Dec,rv);
		
	//???????	
	RandomGenerate(ZUCplain_Enc,datalen);
	//?????????
	RandomGenerate(ZUCiv_Enc,16);
	memcpy(ZUCiv_Dec,ZUCiv_Enc,16);

	BUFFER_REFRESH_ZERO(indata,indatalen,outdata,outdatalen);
	BUFFER_REFRESH_ZERO(indata1,indatalen1,outdata1,outdatalen1);

	memcpy(indata, ZUCplain_Enc, datalen);
	indatalen = datalen;

	
//	rv = (FunctionPtr->C_CleanFlags)(1);
	RV_NOT_OK_RETURN_FALSE(C_CleanFlags,rv);

	/*******************????**********************/
	rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);

	rv = (FunctionPtr->C_EncryptInit)(session1, &ZUCmechanism_Enc, hKey_Enc);   
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit_ses1,rv);

//	rv = (FunctionPtr->C_CleanFlags)(1);
	RV_NOT_OK_RETURN_FALSE(C_CleanFlags,rv);

	rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);
	
	rv = (FunctionPtr->C_EncryptUpdate)(session, indata, indatalen, outdata, &outdatalen);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);

	rv = (FunctionPtr->C_EncryptUpdate)(session1, indata, indatalen, outdata_ses1, &outdatalen_ses1);
	RV_NOT_OK_RETURN_TRUE(pC_EncryptUpdate_ses1,rv);

	rv = (FunctionPtr->C_EncryptInit)(session1, &ZUCmechanism_Enc, hKey_Enc);   
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit_ses1_2,rv);

	rv = (FunctionPtr->C_EncryptFinal)(session, outdata, &outdata);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);

	rv = (FunctionPtr->C_EncryptUpdate)(session1, indata, indatalen, outdata_ses1, &outdatalen_ses1);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate_ses1_3,rv);

	rv = (FunctionPtr->C_EncryptFinal)(session1, outdata, &outdata);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal_ses1_3,rv);
	
	memcpy(indata1, outdata_ses1, outdatalen_ses1);
	indatalen1 = outdatalen_ses1;

	/******************????***********************/
	rv = (FunctionPtr->C_DecryptInit)(session, &ZUCmechanism_Dec, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);

//	rv = (FunctionPtr->C_CleanFlags)(1);
	RV_NOT_OK_RETURN_FALSE(C_CleanFlags,rv);

	rv = (FunctionPtr->C_DecryptInit)(session1, &ZUCmechanism_Dec, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptInit_ses1,rv);
	
	rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, outdata1, &outdatalen1);
	RV_NOT_OK_RETURN_TRUE(pC_DecryptUpdate,rv);

	printf("outdatalen1_ses1 = %ld, indatalen1 = %ld\n", outdatalen1_ses1,indatalen1);
	rv = (FunctionPtr->C_DecryptUpdate)(session1, indata1, indatalen1, outdata1_ses1, &outdatalen1_ses1);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate_ses1,rv);

	rv = (FunctionPtr->C_DecryptFinal)(session1, outdata1, &outdatalen1);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal_ses1,rv);

	UtilsPrintData(VNAME(outdata1_ses1),outdatalen1_ses1,0);

	if ((outdatalen1_ses1 != datalen) || (memcmp(outdata1_ses1, ZUCplain_Enc, outdatalen1_ses1)))
	{
		printf("Result Error.\n");
		printf("outdatalen = %lu.\n", outdatalen1_ses1);		
		bRtn = 1;
		goto END;
	}
	
END:	
	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject1,rv);

	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject2,rv);
	
	return bRtn;
}

/*
CK_ULONG xtest_ZUCPerformance_Extend(int looptime,int datalen)
{
	const char* pcFile ={ "/sdcard/ZUCperformance_extend.xls"};
	char strtemp[256];
	CK_ULONG bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE ZUCkeyType = CKK_ZUC;
	
	//????
	unsigned char	ZUCkeyVal_Enc[]={0xe5, 0xbd, 0x38, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Enc[5000] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
	 		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char	ZUCcipher_Enc[5000] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
	 		0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};
	unsigned char	ZUCiv_Enc[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Enc,sizeof(ZUCkeyVal_Enc)}
	};
	CK_MECHANISM ZUCmechanism_Enc = {CKM_ZUC_EEA, ZUCiv_Enc, sizeof(ZUCiv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

	//????
	unsigned char	ZUCkeyVal_Dec[]={0xe5, 0xbd, 0x38, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Dec[5000] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
	 		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char	ZUCcipher_Dec[5000] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
			0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};

	unsigned char	ZUCiv_Dec[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Dec[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Dec,sizeof(ZUCkeyVal_Dec)}
	};
	CK_MECHANISM ZUCmechanism_Dec = {CKM_ZUC_EEA, ZUCiv_Dec, sizeof(ZUCiv_Dec)};
	CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

	CK_BYTE indata[5000] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[5000] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[5000] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[5000] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);

	unsigned int i = 0,j=0;
	UtilscTime ttc1={0, 0},ttc2={0,0},ttc3={0,0},ttc4={0,0};

	printf("input looptime:\n");
	CK_BYTE ch[10];
	fgets(ch,10,stdin);
   	looptime = atoi(ch);

	printf("input datalen(0-5000):\n");
	fgets(ch,10,stdin);
   	datalen = atoi(ch);

	srand( (unsigned)time( NULL ) );//??????

	//???????
	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_Enc,rv);

	rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);

	//???????
	hKey_Dec = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Dec, sizeof(ZUCkeyTemplate_Dec)/sizeof(CK_ATTRIBUTE), &hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_Dec,rv);

	rv = (FunctionPtr->C_DecryptInit)(session, &ZUCmechanism_Dec, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);

	printf("Datalen=%d.\n",datalen);

	for (i=0; i<looptime; i++)
	{
		FILE *_fp;
		_fp=fopen(pcFile,"a");
		if (!_fp)
		{
			printf("ZUC test failed, fopen fail.");
			return 1;
		} 

//		printf("i = %d\n",i);
		//?????????
		RandomGenerate(ZUCiv_Enc,16);
		memcpy(ZUCiv_Dec,ZUCiv_Enc,16);

		//???????	
		RandomGenerate(ZUCplain_Enc,datalen);

		BUFFER_REFRESH_ZERO(indata,indatalen,outdata,outdatalen);
		BUFFER_REFRESH_ZERO(indata1,indatalen1,outdata1,outdatalen1);

		//????
		//?IV???????
		memcpy(indata, ZUCiv_Enc, sizeof(ZUCiv_Enc));
		memcpy(indata+sizeof(ZUCiv_Enc), ZUCplain_Enc, datalen);
		indatalen = sizeof(ZUCiv_Enc) + datalen;

		Utilsgettime(&ttc1);
		rv = (FunctionPtr->C_EncryptUpdate_Extend)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(C_EncryptUpdate_Extend,rv);
		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc3,&ttc2);
		//tt2.printn("ZUC Encrypt", i);

		sprintf(strtemp, "%.3lf", ttc2.usec/1000.0f); 
		fputs(strtemp, _fp);
		fputs("\t", _fp);

		//????
		//?IV???????
		memcpy(indata1, ZUCiv_Dec, sizeof(ZUCiv_Dec));
		memcpy(indata1+sizeof(ZUCiv_Dec), outdata, outdatalen);
		indatalen1 = sizeof(ZUCiv_Dec) + outdatalen;
		
		Utilsgettime(&ttc1);
		rv = (FunctionPtr->C_DecryptUpdate_Extend)(session, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(C_DecryptUpdate_Extend,rv);
		Utilsgettime(&ttc2);
		UtilsTimeSubstracted(&ttc2,&ttc1);
		UtilsTimeAdded(&ttc4,&ttc2);
		//tt2.printn("ZUC Decrypt", i);
		sprintf(strtemp, "%.3lf", ttc2.usec/1000.0f); 
		fputs(strtemp, _fp);
		fputs("\n", _fp);
		fclose(_fp);

		
		if ((outdatalen1 != datalen) || (memcmp(outdata1, ZUCplain_Enc, outdatalen1)))
		{
			printf("Error: ZUCPerformance.\n");
			printf("outdatalen1 = %lu.\n", outdatalen1);		
//			UtilsPrintData(VNAME(ZUCplain_Enc),datalen,0);
//			UtilsPrintData(VNAME(outdata1),outdatalen1,0);
//			nResultLength += sprintf(Testresult[nItemNumb] + nResultLength, "Error: ZUCPerformance.<br>");
			bRtn = 1;
			goto END;
		}
	}


	Utilsprint(&ttc3,"ZUC Encrypt(update)", looptime);
	Utilsprint(&ttc4,"ZUC Decrypt(update)", looptime);
	
END:	
	rv = (FunctionPtr->C_EncryptFinal)(session, outdata1, &outdatalen1);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);

	rv = (FunctionPtr->C_DecryptFinal)(session, outdata, &outdatalen);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);
		
	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject1,rv);

	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject2,rv);
	
	return bRtn;
}


CK_ULONG xtest_ZUC_Extend_MultiSession(int looptime,int datalen)
{
	char strtemp[256];
	CK_ULONG bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE ZUCkeyType = CKK_ZUC;
	
	//????
	unsigned char	ZUCkeyVal_Enc[]={0xe5, 0xbd, 0x38, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Enc[5000] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
	 		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char	ZUCcipher_Enc[5000] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
	 		0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};
	unsigned char	ZUCiv_Enc[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Enc,sizeof(ZUCkeyVal_Enc)}
	};
	CK_MECHANISM ZUCmechanism_Enc = {CKM_ZUC_EEA, ZUCiv_Enc, sizeof(ZUCiv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

	//????
	unsigned char	ZUCkeyVal_Dec[]={0xe5, 0xbd, 0x38, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char	ZUCplain_Dec[5000] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
	 		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char	ZUCcipher_Dec[5000] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
			0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};

	unsigned char	ZUCiv_Dec[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Dec[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Dec,sizeof(ZUCkeyVal_Dec)}
	};
	CK_MECHANISM ZUCmechanism_Dec = {CKM_ZUC_EEA, ZUCiv_Dec, sizeof(ZUCiv_Dec)};
	CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

	CK_BYTE indata[5000] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[5000] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[5000] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[5000] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);

	unsigned int i = 0,j=0;
	UtilscTime ttc1={0, 0},ttc2={0,0},ttc3={0,0},ttc4={0,0};

	printf("input looptime:\n");
	CK_BYTE ch[10];
	fgets(ch,10,stdin);
   	looptime = atoi(ch);

	printf("input datalen(0-5000):\n");
	fgets(ch,10,stdin);
   	datalen = atoi(ch);

	srand( (unsigned)time( NULL ) );//??????

	//???????
	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_Enc,rv);

	rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);

	rv = (FunctionPtr->C_EncryptInit)(session1, &ZUCmechanism_Enc, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);

	//???????
	hKey_Dec = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Dec, sizeof(ZUCkeyTemplate_Dec)/sizeof(CK_ATTRIBUTE), &hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_Dec,rv);

	rv = (FunctionPtr->C_DecryptInit)(session, &ZUCmechanism_Dec, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);

	rv = (FunctionPtr->C_DecryptInit)(session1, &ZUCmechanism_Dec, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);

	printf("Datalen=%d.\n",datalen);

	for (i=0; i<looptime; i++)
		{

//		printf("i = %d\n",i);
		//?????????
		RandomGenerate(ZUCiv_Enc,16);
		memcpy(ZUCiv_Dec,ZUCiv_Enc,16);

		//???????	
		RandomGenerate(ZUCplain_Enc,datalen);

		BUFFER_REFRESH_ZERO(indata,indatalen,outdata,outdatalen);
		BUFFER_REFRESH_ZERO(indata1,indatalen1,outdata1,outdatalen1);

		//????
		//?IV???????
		memcpy(indata, ZUCiv_Enc, sizeof(ZUCiv_Enc));
		memcpy(indata+sizeof(ZUCiv_Enc), ZUCplain_Enc, datalen);
		indatalen = sizeof(ZUCiv_Enc) + datalen;

		rv = (FunctionPtr->C_EncryptUpdate_Extend)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(C_EncryptUpdate_Extend,rv);

		rv = (FunctionPtr->C_EncryptUpdate_Extend)(session1, indata, indatalen, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(C_EncryptUpdate_Extend,rv);

		
		if ((outdatalen1 != outdatalen) || (memcmp(outdata, outdata1, sizeof(outdata))))
		{
			printf("ZUC Encrypt Calc Error: test_SM4Encrypt_ECB.\n");
			bRtn = 1;
		}
		else
		{
			printf("ZUC Encrypt sess0 Result is correct!\n");
		}



		//????
		//?IV???????
		memcpy(indata1, ZUCiv_Dec, sizeof(ZUCiv_Dec));
		memcpy(indata1+sizeof(ZUCiv_Dec), outdata, outdatalen);
		indatalen1 = sizeof(ZUCiv_Dec) + outdatalen;
		

		rv = (FunctionPtr->C_DecryptUpdate_Extend)(session, indata1, indatalen1, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(C_DecryptUpdate_Extend,rv);

		rv = (FunctionPtr->C_DecryptUpdate_Extend)(session1, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(C_DecryptUpdate_Extend,rv);


		
		if ((outdatalen != datalen) || (memcmp(outdata, ZUCplain_Enc, outdatalen)))
		{
			printf("Error: ZUCPerformance.\n");
			printf("outdatalen1 = %lu.\n", outdatalen1);		
			bRtn = 1;
			goto END;
		}	
		else
		{
			printf("ZUC Encrypt sess0 Result is correct!\n");
		}

		if ((outdatalen1 != datalen) || (memcmp(outdata1, ZUCplain_Enc, outdatalen1)))
		{
			printf("Error: ZUCPerformance.\n");
			printf("outdatalen1 = %lu.\n", outdatalen1);		
			bRtn = 1;
			goto END;
		}
		else
		{
			printf("ZUC Encrypt sess1 Result is correct!\n");
		}
	}


	
END:	
	rv = (FunctionPtr->C_EncryptFinal)(session, outdata1, &outdatalen1);
	RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);

	rv = (FunctionPtr->C_DecryptFinal)(session, outdata, &outdatalen);
	RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);
		
	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject1,rv);

	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject2,rv);
	
	return bRtn;
}

*/
CK_RV xtest_Poweroff()
{

	int bRtn = 0;
	CK_RV rv=0;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE ZUCkeyType = CKK_ZUC;

	CK_ATTRIBUTE ramFindKeyTemplate[] = {
		{CKA_TOKEN, &ffalse, sizeof(CK_BBOOL)}
	};

	//????
	///////////////////////////
	unsigned char	ZUCkeyVal_Enc[]={0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};

	unsigned char	ZUCplain_Enc[136] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, 0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, \
		0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03};
	unsigned char	ZUCcipher_Enc[136] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, 0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, \
		0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34, 0x09, 0x73, 0x5b, 0xad, 0x57, 0x5e, 0x9f, 0x91};

//	unsigned char	ZUCiv_Enc[16] = {0x00, 0x05, 0x68, 0x23, 0xC4,0x00,0x00,0x00,0x00, 0x05, 0x68, 0x23, 0xC4,0x00,0x00,0x00};
	unsigned char	ZUCiv_Enc[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};

	CK_ATTRIBUTE ZUCkeyTemplate_Enc[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Enc,sizeof(ZUCkeyVal_Enc)}
	};
	CK_MECHANISM ZUCmechanism_Enc = {CKM_ZUC_EEA, ZUCiv_Enc, sizeof(ZUCiv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

	//????
	//////////////////////////////////////
	unsigned char	ZUCkeyVal_Dec[]={0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};

	unsigned char	ZUCplain_Dec[136] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, 0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, \
		0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03};
	unsigned char	ZUCcipher_Dec[136] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, 0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, \
		0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34, 0x09, 0x73, 0x5b, 0xad, 0x57, 0x5e, 0x9f, 0x91};

//	unsigned char	ZUCiv_Dec[]={0x00, 0x05, 0x68, 0x23, 0x38};

	unsigned char	ZUCiv_Dec[16] = {0x00,0x05,0x68,0x23,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00};
//	CK_UINT ZUCiv_Dec[4]={0x56823,0x18,0x1,0x0};


	CK_ATTRIBUTE ZUCkeyTemplate_Dec[] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Dec,sizeof(ZUCkeyVal_Dec)}
	};
	CK_MECHANISM ZUCmechanism_Dec = {CKM_ZUC_EEA, ZUCiv_Dec, sizeof(ZUCiv_Dec)};
	CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

	CK_BYTE indata[256] = {0};
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[256] = {0};
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[256] = {0};
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[256] = {0};
	CK_ULONG outdatalen1=sizeof(outdata1);
	int loopTime = 1;
	unsigned int i = 0;

	CK_OBJECT_HANDLE_PTR hObject;
	int ulObjectCount;
	printf("enter test_ZUCRAM.\n");
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength, "enter test_ZUCRAM.<br>");

	//???????
	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	printf("C_CreateObject error with default_usrerr_pin, should be error: rc = 0x%08lx\n", rv);
	//RV_NOT_OK_RETURN_FALSE(pC_CreateObject_hKey_Enc,rv);

	rv = FunctionPtr->C_Login(session,CKU_USER,pusrpin,strlen((char*)pusrpin));
	if (rv != CKR_OK)
	{ 
		   printf("CKU_USER C_Login error with default_usrerr_pin, should be error: rc = 0x%08lx\n", rv); 
	} 
	else
	{
			printf("Login OK\n");

	}


	hKey_Enc = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_hKey_Enc,rv);

	//???????
	hKey_Dec = NULL_PTR;
	rv = FunctionPtr->C_CreateObject(session, ZUCkeyTemplate_Dec, sizeof(ZUCkeyTemplate_Dec)/sizeof(CK_ATTRIBUTE), &hKey_Dec);
	RV_NOT_OK_RETURN_FALSE(pC_CreateObject_hKey_Dec,rv);

			//??RAM??
	printf("\n-------???????RAM??--------\n");
	hObject = NULL_PTR;
	hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16); 
	ulObjectCount = 16;

	//UtilsPrintData(VNAME(prvFindKeyTemplate),256,0);
	//printf("count=%d\n",sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	rv = FunctionPtr->C_FindObjectsInit(session, ramFindKeyTemplate, sizeof(ramFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit1,rv);


	rv = FunctionPtr->C_FindObjects(session, hObject, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects1,rv);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal1,rv);

	printf("ram Key count=%lu.\n", ulObjectCount);
	free(hObject);


	for (i=0; i<loopTime; i++)
	{

		indatalen = sizeof(indata);
		memset(indata, 0, indatalen);
		outdatalen=sizeof(outdata);
		memset(outdata, 0, outdatalen);

		indatalen1 = sizeof(indata1);
		memset(indata1, 0, indatalen1);
		outdatalen1=sizeof(outdata1);
		memset(outdata1, 0, outdatalen1);

		memcpy(indata, ZUCplain_Enc, sizeof(ZUCplain_Enc));
		indatalen = sizeof(ZUCplain_Enc);

		memcpy(indata1, ZUCcipher_Dec, sizeof(ZUCcipher_Dec));
		indatalen1 = sizeof(ZUCcipher_Dec);

		/*******************????**********************/
		//????
		rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);
		
		rv = (FunctionPtr->C_Encrypt)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_Encrypt,rv);

		if ((outdatalen != sizeof(ZUCcipher_Enc)) || (memcmp(outdata, ZUCcipher_Enc, outdatalen)))
		{
			printf("Error: ZUC Encrypt(???).\n");
			bRtn = 1;
			goto END;
		}

		memset(outdata,0,sizeof(outdata));
		
		rv = (FunctionPtr->C_EncryptInit)(session, &ZUCmechanism_Enc, hKey_Enc);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptInit,rv);
		
		rv = (FunctionPtr->C_EncryptUpdate)(session, indata, indatalen, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_EncryptUpdate,rv);


		rv = (FunctionPtr->C_EncryptFinal)(session, outdata1, &outdatalen1);

		RV_NOT_OK_RETURN_FALSE(pC_EncryptFinal,rv);

//		UtilsPrintData(VNAME(ZUCkeyVal_Enc),16,0);
//		UtilsPrintData(VNAME(ZUCiv_Enc),16,0);
//		UtilsPrintData(VNAME(indata),indatalen,0);
//		UtilsPrintData(VNAME(outdata),outdatalen,0);

		if ((outdatalen != sizeof(ZUCcipher_Enc)) || (memcmp(outdata, ZUCcipher_Enc, outdatalen)))
		{
			printf("Error: ZUC Encrypt(???).\n");
			bRtn = 1;
			goto END;
		}

		/******************????***********************/
		//????
		rv = (FunctionPtr->C_DecryptInit)(session, &ZUCmechanism_Dec, hKey_Dec);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);

		rv = (FunctionPtr->C_Decrypt)(session, indata1, indatalen1, NULL, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_Decrypt,rv);
		
		rv = (FunctionPtr->C_Decrypt)(session, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_Decrypt,rv);

		if ((outdatalen1 != sizeof(ZUCplain_Dec)) || (memcmp(outdata1, ZUCplain_Dec, outdatalen1)))
		{
			printf("Error: ZUC Decrypt(???).\n");
			bRtn = 1;
			goto END; 
		}

		memset(outdata1,0,sizeof(outdata1));
		
		rv = (FunctionPtr->C_DecryptInit)(session, &ZUCmechanism_Dec, hKey_Dec);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptInit,rv);
		
		rv = (FunctionPtr->C_DecryptUpdate)(session, indata1, indatalen1, outdata1, &outdatalen1);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptUpdate,rv);

		rv = (FunctionPtr->C_DecryptFinal)(session, outdata, &outdatalen);
		RV_NOT_OK_RETURN_FALSE(pC_DecryptFinal,rv);


		if ((outdatalen1 != sizeof(ZUCplain_Dec)) || (memcmp(outdata1, ZUCplain_Dec, outdatalen1)))
		{
			printf("Error: ZUC Decrypt(???).\n");
			bRtn = 1;
			goto END; 
		}
		printf("Calc Success:ZUC.\n");
	}


	bRtn = 0;
END:

	getchar();


		//??RAM??
	printf("\n-------?????RAM??--------\n");
	hObject = NULL_PTR;
	hObject= (CK_OBJECT_HANDLE_PTR)malloc(sizeof(int)*16); 
	ulObjectCount = 16;

	//UtilsPrintData(VNAME(prvFindKeyTemplate),256,0);
	//printf("count=%d\n",sizeof(prvFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	rv = FunctionPtr->C_FindObjectsInit(session, ramFindKeyTemplate, sizeof(ramFindKeyTemplate)/sizeof(CK_ATTRIBUTE));
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsInit1,rv);


	rv = FunctionPtr->C_FindObjects(session, hObject, 16, &ulObjectCount);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjects1,rv);

	printf("ram Key count=%lu.\n", ulObjectCount);
//	nResultLength += sprintf(Testresult[nItemNumb] + nResultLength ,"Private Key count=%d.<br>", ulObjectCount);

	rv = FunctionPtr->C_FindObjectsFinal(session);
	RV_NOT_OK_RETURN_FALSE(pC_FindObjectsFinal1,rv);

	

	
	
//	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Enc);
//	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject_hKey_Enc,rv);
//
//	rv = (FunctionPtr->C_DestroyObject)(session, hKey_Dec);
//	RV_NOT_OK_RETURN_FALSE(pC_DestroyObject_hKey_Dec,rv);

	printf("leave test_ZUCRAM.\n");
	return bRtn;



}


#endif

