#include "p11FunctionParse.h"
#include "cryptoki.h"
#include "skf_t.h"

#include <jni.h>

class SkfFunctionParse : public P11FunctionParse
{
public:
	SkfFunctionParse();
	virtual ~SkfFunctionParse();
    void initCard(JavaVM *javaVMIn, jint versionIn, jobject telephonyManager);
private:
	ULONG SKF_WaitForDevEvent(const string src,string &dst);
	ULONG SKF_CancelWaitForDevEvent(const string src,string &dst);
	ULONG SKF_EnumDev(const string src,string &dst);
	ULONG SKF_ConnectDev(const string src,string &dst);
	ULONG SKF_DisConnectDev(const string src,string &dst);
	ULONG SKF_GetDevState(const string src,string &dst);
	ULONG SKF_SetLabel(const string src,string &dst);
	ULONG SKF_GetDevInfo(const string src,string &dst);
	ULONG SKF_LockDev(const string src,string &dst);
	ULONG SKF_UnlockDev(const string src,string &dst);
	ULONG SKF_ChangeDevAuthKey(const string src,string &dst);
	ULONG SKF_DevAuth(const string src,string &dst);
	ULONG SKF_ChangePIN(const string src,string &dst);
	ULONG SKF_GetPINInfo(const string src,string &dst);
	ULONG SKF_VerifyPIN(const string src,string &dst);
	ULONG SKF_UnblockPIN(const string src,string &dst);
	ULONG SKF_ClearSecureState(const string src,string &dst);
	ULONG SKF_CreateApplication(const string src,string &dst);
	ULONG SKF_EnumApplication(const string src,string &dst);
	ULONG SKF_DeleteApplication(const string src,string &dst);
	ULONG SKF_OpenApplication(const string src,string &dst);
	ULONG SKF_CloseApplication(const string src,string &dst);
	ULONG SKF_CreateFile(const string src,string &dst);
	ULONG SKF_DeleteFile(const string src,string &dst);
	ULONG SKF_EnumFiles(const string src,string &dst);
	ULONG SKF_GetFileInfo(const string src,string &dst);
	ULONG SKF_ReadFile(const string src,string &dst);
	ULONG SKF_WriteFile(const string src,string &dst);
	ULONG SKF_CreateContainer(const string src,string &dst);
	ULONG SKF_DeleteContainer(const string src,string &dst);
	ULONG SKF_OpenContainer(const string src,string &dst);
	ULONG SKF_CloseContainer(const string src,string &dst);
	ULONG SKF_EnumContainer(const string src,string &dst);
	ULONG SKF_GetContainerType(const string src,string &dst);
	ULONG SKF_GenRandom(const string src,string &dst);
	ULONG SKF_GenExtRSAKey(const string src,string &dst);
	ULONG SKF_GenRSAKeyPair(const string src,string &dst);
	ULONG SKF_ImportRSAKeyPair(const string src,string &dst);
	ULONG SKF_RSASignData(const string src,string &dst);
	ULONG SKF_RSAVerify(const string src,string &dst);
	ULONG SKF_RSAExportSessionKey(const string src,string &dst);
	ULONG SKF_ExtRSAPubKeyOperation(const string src,string &dst);
	ULONG SKF_ExtRSAPriKeyOperation(const string src,string &dst);
	ULONG SKF_GenECCKeyPair(const string src,string &dst);
	ULONG SKF_ImportECCKeyPair(const string src,string &dst);
	ULONG SKF_ECCSignData(const string src,string &dst);
	ULONG SKF_ECCVerify(const string src,string &dst);
	ULONG SKF_ECCExportSessionKey(const string src,string &dst);
	ULONG SKF_ExtECCEncrypt(const string src,string &dst);
	ULONG SKF_ExtECCDecrypt(const string src,string &dst);
	ULONG SKF_ExtECCSign(const string src,string &dst);
	ULONG SKF_ExtECCVerify(const string src,string &dst);
	ULONG SKF_GenerateAgreementDataWithECC(const string src,string &dst);
	ULONG SKF_GenerateAgreementDataAndKeyWithECC(const string src,string &dst);
	ULONG SKF_GenerateKeyWithECC(const string src,string &dst);
	ULONG SKF_ExportPublicKey(const string src,string &dst);
	ULONG SKF_ImportSessionKey(const string src,string &dst);
	ULONG SKF_SetSymmKey(const string src,string &dst);
	ULONG SKF_EncryptInit(const string src,string &dst);
	ULONG SKF_Encrypt(const string src,string &dst);
	ULONG SKF_EncryptUpdate(const string src,string &dst);
	ULONG SKF_EncryptFinal(const string src,string &dst);
	ULONG SKF_DecryptInit(const string src,string &dst);
	ULONG SKF_Decrypt(const string src,string &dst);
	ULONG SKF_DecryptUpdate(const string src,string &dst);
	ULONG SKF_DecryptFinal(const string src,string &dst);
	ULONG SKF_DigestInit(const string src,string &dst);
	ULONG SKF_Digest(const string src,string &dst);
	ULONG SKF_DigestUpdate(const string src,string &dst);
	ULONG SKF_DigestFinal(const string src,string &dst);
	ULONG SKF_MacInit(const string src,string &dst);
	ULONG SKF_Mac(const string src,string &dst);
	ULONG SKF_MacUpdate(const string src,string &dst);
	ULONG SKF_MacFinal(const string src,string &dst);
	ULONG SKF_CloseHandle(const string src,string &dst);
	ULONG SKF_Transmit(const string src,string &dst);
	ULONG SKF_ImportCertificate(const string src,string &dst);
	ULONG SKF_ExportCertificate(const string src,string &dst);
	ULONG SKF_GetContainerProperty(const string src,string &dst);
};


