#ifndef P11FUNCTION_PARSE_H
#define P11FUNCTION_PARSE_H

#include "FunctionParse.h"
#include "cryptoki.h"

class P11FunctionParse : public FunctionParse
{
public:
	P11FunctionParse();
	virtual ~P11FunctionParse();
private:
	int C_Initialize(const string src,string &dst);
	int C_Finalize(const string src,string &dst);
	int C_GetInfo(const string src,string &dst);
	int C_GetFunctionList(const string src,string &dst);
	int C_GetSlotList(const string src,string &dst);
	int C_GetSlotInfo(const string src,string &dst);
	int C_GetTokenInfo(const string src,string &dst);
	int C_GetMechanismList(const string src,string &dst);
	int C_GetMechanismInfo(const string src,string &dst);
	int C_InitToken(const string src,string &dst);
	int C_InitPIN(const string src,string &dst);
	int C_SetPIN(const string src,string &dst);
	int C_OpenSession(const string src,string &dst);
	int C_CloseSession(const string src,string &dst);
	int C_CloseAllSessions(const string src,string &dst);
	int C_GetSessionInfo(const string src,string &dst);
	int C_GetOperationState(const string src,string &dst);
	int C_SetOperationState(const string src,string &dst);
	int C_Login(const string src,string &dst);
	int C_Logout(const string src,string &dst);
	int C_CreateObject(const string src,string &dst);
	int C_CopyObject(const string src,string &dst);
	int C_DestroyObject(const string src,string &dst);
	int C_GetObjectSize(const string src,string &dst);
	int C_GetAttributeValue(const string src,string &dst);
	int C_SetAttributeValue(const string src,string &dst);
	int C_FindObjectsInit(const string src,string &dst);
	int C_FindObjects(const string src,string &dst);
	int C_FindObjectsFinal(const string src,string &dst);
	int C_EncryptInit(const string src,string &dst);
	int C_Encrypt(const string src,string &dst);
	int C_EncryptUpdate(const string src,string &dst);
	int C_EncryptFinal(const string src,string &dst);
	int C_DecryptInit(const string src,string &dst);
	int C_Decrypt(const string src,string &dst);
	int C_DecryptUpdate(const string src,string &dst);
	int C_DecryptFinal(const string src,string &dst);
	int C_DigestInit(const string src,string &dst);
	int C_Digest(const string src,string &dst);
	int C_DigestUpdate(const string src,string &dst);
	int C_DigestKey(const string src,string &dst);
	int C_DigestFinal(const string src,string &dst);
	int C_SignInit(const string src,string &dst);
	int C_Sign(const string src,string &dst);
	int C_SignUpdate(const string src,string &dst);
	int C_SignFinal(const string src,string &dst);
	int C_SignRecoverInit(const string src,string &dst);
	int C_SignRecover(const string src,string &dst);
	int C_VerifyInit(const string src,string &dst);
	int C_Verify(const string src,string &dst);
	int C_VerifyUpdate(const string src,string &dst);
	int C_VerifyFinal(const string src,string &dst);
	int C_VerifyRecoverInit(const string src,string &dst);
	int C_VerifyRecover(const string src,string &dst);
	int C_DigestEncryptUpdate(const string src,string &dst);
	int C_DecryptDigestUpdate(const string src,string &dst);
	int C_SignEncryptUpdate(const string src,string &dst);
	int C_DecryptVerifyUpdate(const string src,string &dst);
	int C_GenerateKey(const string src,string &dst);
	int C_GenerateKeyPair(const string src,string &dst);
	int C_WrapKey(const string src,string &dst);
	int C_UnwrapKey(const string src,string &dst);
	int C_DeriveKey(const string src,string &dst);
	int C_SeedRandom(const string src,string &dst);
	int C_GenerateRandom(const string src,string &dst);
	int C_GetFunctionStatus(const string src,string &dst);
	int C_CancelFunction(const string src,string &dst);
	int C_WaitForSlotEvent(const string src,string &dst);

	int C_Extend_GetPinRemainCount(const string src,string &dst);
	int C_Extend_GetStatus(const string src,string &dst);
	int C_Extend_Register_Status_Callback_Func(const string src,string &dst);
	int C_Extend_Register_Callback(const string src,string &dst);
	int C_Extend_Unregister_Callback(const string src,string &dst);
	int C_Extend_GetExchangeSessionKey(const string src,string &dst);
	int C_Extend_Destroy(const string src,string &dst);
	int C_Extend_Reset_Pin_With_OTP(const string src,string &dst);
	int C_Extend_Reset_OTP(const string src,string &dst);
	int C_Extend_Get_OTP_Unlock_Count(const string src,string &dst);
	int C_Extend_Get_OTP_Remain_Count(const string src,string &dst);
	int C_Extend_DeriveSessionKey(const string src,string &dst);
	int C_Extend_EncryptInit(const string src,string &dst);
	int C_Extend_DecryptInit(const string src,string &dst);
	int C_Extend_EncryptUpdate(const string src,string &dst);
	int C_Extend_DecryptUpdate(const string src,string &dst);
	int C_Extend_EncryptFinalize(const string src,string &dst);
	int C_Extend_DecryptFinalize(const string src,string &dst);
	int C_Extend_PointMultiply(const string src,string &dst);
	int C_Extend_Reset_TT(const string src,string &dst);
	int C_Extend_Reset_BK(const string src,string &dst);
	int C_Extend_Get_Special_Object_Version(const string src,string &dst);
	int C_Extend_DestroyCard(const string src,string &dst);	
	int C_Extend_Get_ExchangePubKey(const string src,string &dst);
	int C_Extend_MonopolizeEnable(const string src,string &dst);
	int C_Extend_MonopolizeDisable(const string src,string &dst);
	int C_Extend_GetDevInfo(const string src,string &dst);
	int C_Extend_DevSign(const string src,string &dst);
	int C_Extend_Set_DestroyKey(const string src,string &dst);	
	int softCreateCipherCard(const string src,string &dst);
	int DestroyCipherCard(const string src,string &dst);

};

void clearmono(string clientname);

#endif// P11FUNCTION_PARSE_H