//
// Created by wjr on 19-4-18.
//

#include "skfLibLoader.h"
#include <dlfcn.h>

#if 1
#include <android/log.h>
#define DEBUG_SKF_LOAD(...) __android_log_print(ANDROID_LOG_INFO,"skf_wjr",__VA_ARGS__)
#endif

skfLibLoader::skfLibLoader(char *libPath) {
    DEBUG_SKF_LOAD("%s IN,path = [%s]",__FUNCTION__,libPath);
    handle = dlopen(libPath,RTLD_LAZY);
    if(handle != NULL){
        skfFunctionList.SKF_WaitForDevEvent = (SKF_POINTER(SKF_WaitForDevEvent))dlsym(handle,"SKF_WaitForDevEvent");
        skfFunctionList.SKF_CancelWaitForDevEvent = (SKF_POINTER(SKF_CancelWaitForDevEvent))dlsym(handle,"SKF_CancelWaitForDevEvent");
        skfFunctionList.SKF_EnumDev = (SKF_POINTER(SKF_EnumDev))dlsym(handle,"SKF_EnumDev");
        skfFunctionList.SKF_ConnectDev = (SKF_POINTER(SKF_ConnectDev))dlsym(handle,"SKF_ConnectDev");
        skfFunctionList.SKF_DisConnectDev = (SKF_POINTER(SKF_DisConnectDev))dlsym(handle,"SKF_DisConnectDev");
        skfFunctionList.SKF_GetDevState = (SKF_POINTER(SKF_GetDevState))dlsym(handle,"SKF_GetDevState");
        skfFunctionList.SKF_SetLabel = (SKF_POINTER(SKF_SetLabel))dlsym(handle,"SKF_SetLabel");
        skfFunctionList.SKF_GetDevInfo = (SKF_POINTER(SKF_GetDevInfo))dlsym(handle,"SKF_GetDevInfo");
        skfFunctionList.SKF_LockDev = (SKF_POINTER(SKF_LockDev))dlsym(handle,"SKF_LockDev");
        skfFunctionList.SKF_UnlockDev = (SKF_POINTER(SKF_UnlockDev))dlsym(handle,"SKF_UnlockDev");
        skfFunctionList.SKF_ChangeDevAuthKey = (SKF_POINTER(SKF_ChangeDevAuthKey))dlsym(handle,"SKF_ChangeDevAuthKey");
        skfFunctionList.SKF_DevAuth = (SKF_POINTER(SKF_DevAuth))dlsym(handle,"SKF_DevAuth");
        skfFunctionList.SKF_ChangePIN = (SKF_POINTER(SKF_ChangePIN))dlsym(handle,"SKF_ChangePIN");
        skfFunctionList.SKF_GetPINInfo = (SKF_POINTER(SKF_GetPINInfo))dlsym(handle,"SKF_GetPINInfo");
        skfFunctionList.SKF_VerifyPIN = (SKF_POINTER(SKF_VerifyPIN))dlsym(handle,"SKF_VerifyPIN");
        skfFunctionList.SKF_UnblockPIN = (SKF_POINTER(SKF_UnblockPIN))dlsym(handle,"SKF_UnblockPIN");
        skfFunctionList.SKF_ClearSecureState = (SKF_POINTER(SKF_ClearSecureState))dlsym(handle,"SKF_ClearSecureState");
        skfFunctionList.SKF_CreateApplication = (SKF_POINTER(SKF_CreateApplication))dlsym(handle,"SKF_CreateApplication");
        skfFunctionList.SKF_EnumApplication = (SKF_POINTER(SKF_EnumApplication))dlsym(handle,"SKF_EnumApplication");
        skfFunctionList.SKF_DeleteApplication = (SKF_POINTER(SKF_DeleteApplication))dlsym(handle,"SKF_DeleteApplication");
        skfFunctionList.SKF_OpenApplication = (SKF_POINTER(SKF_OpenApplication))dlsym(handle,"SKF_OpenApplication");
        skfFunctionList.SKF_CloseApplication = (SKF_POINTER(SKF_CloseApplication))dlsym(handle,"SKF_CloseApplication");
        skfFunctionList.SKF_CreateFile = (SKF_POINTER(SKF_CreateFile))dlsym(handle,"SKF_CreateFile");
        skfFunctionList.SKF_DeleteFile = (SKF_POINTER(SKF_DeleteFile))dlsym(handle,"SKF_DeleteFile");
        skfFunctionList.SKF_EnumFiles = (SKF_POINTER(SKF_EnumFiles))dlsym(handle,"SKF_EnumFiles");
        skfFunctionList.SKF_GetFileInfo = (SKF_POINTER(SKF_GetFileInfo))dlsym(handle,"SKF_GetFileInfo");
        skfFunctionList.SKF_ReadFile = (SKF_POINTER(SKF_ReadFile))dlsym(handle,"SKF_ReadFile");
        skfFunctionList.SKF_WriteFile = (SKF_POINTER(SKF_WriteFile))dlsym(handle,"SKF_WriteFile");
        skfFunctionList.SKF_CreateContainer = (SKF_POINTER(SKF_CreateContainer))dlsym(handle,"SKF_CreateContainer");
        skfFunctionList.SKF_DeleteContainer = (SKF_POINTER(SKF_DeleteContainer))dlsym(handle,"SKF_DeleteContainer");
        skfFunctionList.SKF_OpenContainer = (SKF_POINTER(SKF_OpenContainer))dlsym(handle,"SKF_OpenContainer");
        skfFunctionList.SKF_CloseContainer = (SKF_POINTER(SKF_CloseContainer))dlsym(handle,"SKF_CloseContainer");
        skfFunctionList.SKF_EnumContainer = (SKF_POINTER(SKF_EnumContainer))dlsym(handle,"SKF_EnumContainer");
        skfFunctionList.SKF_GetContainerType = (SKF_POINTER(SKF_GetContainerType))dlsym(handle,"SKF_GetContainerType");
        skfFunctionList.SKF_GenRandom = (SKF_POINTER(SKF_GenRandom))dlsym(handle,"SKF_GenRandom");
        skfFunctionList.SKF_GenExtRSAKey = (SKF_POINTER(SKF_GenExtRSAKey))dlsym(handle,"SKF_GenExtRSAKey");
        skfFunctionList.SKF_GenRSAKeyPair = (SKF_POINTER(SKF_GenRSAKeyPair))dlsym(handle,"SKF_GenRSAKeyPair");
        skfFunctionList.SKF_ImportRSAKeyPair = (SKF_POINTER(SKF_ImportRSAKeyPair))dlsym(handle,"SKF_ImportRSAKeyPair");
        skfFunctionList.SKF_RSASignData = (SKF_POINTER(SKF_RSASignData))dlsym(handle,"SKF_RSASignData");
        skfFunctionList.SKF_RSAVerify = (SKF_POINTER(SKF_RSAVerify))dlsym(handle,"SKF_RSAVerify");
        skfFunctionList.SKF_RSAExportSessionKey = (SKF_POINTER(SKF_RSAExportSessionKey))dlsym(handle,"SKF_RSAExportSessionKey");
        skfFunctionList.SKF_ExtRSAPubKeyOperation = (SKF_POINTER(SKF_ExtRSAPubKeyOperation))dlsym(handle,"SKF_ExtRSAPubKeyOperation");
        skfFunctionList.SKF_ExtRSAPriKeyOperation = (SKF_POINTER(SKF_ExtRSAPriKeyOperation))dlsym(handle,"SKF_ExtRSAPriKeyOperation");
        skfFunctionList.SKF_GenECCKeyPair = (SKF_POINTER(SKF_GenECCKeyPair))dlsym(handle,"SKF_GenECCKeyPair");
        skfFunctionList.SKF_ImportECCKeyPair = (SKF_POINTER(SKF_ImportECCKeyPair))dlsym(handle,"SKF_ImportECCKeyPair");
        skfFunctionList.SKF_ECCSignData = (SKF_POINTER(SKF_ECCSignData))dlsym(handle,"SKF_ECCSignData");
        skfFunctionList.SKF_ECCVerify = (SKF_POINTER(SKF_ECCVerify))dlsym(handle,"SKF_ECCVerify");
        skfFunctionList.SKF_ECCExportSessionKey = (SKF_POINTER(SKF_ECCExportSessionKey))dlsym(handle,"SKF_ECCExportSessionKey");
        skfFunctionList.SKF_ExtECCEncrypt = (SKF_POINTER(SKF_ExtECCEncrypt))dlsym(handle,"SKF_ExtECCEncrypt");
        skfFunctionList.SKF_ExtECCDecrypt = (SKF_POINTER(SKF_ExtECCDecrypt))dlsym(handle,"SKF_ExtECCDecrypt");
        skfFunctionList.SKF_ExtECCSign = (SKF_POINTER(SKF_ExtECCSign))dlsym(handle,"SKF_ExtECCSign");
        skfFunctionList.SKF_ExtECCVerify = (SKF_POINTER(SKF_ExtECCVerify))dlsym(handle,"SKF_ExtECCVerify");
        skfFunctionList.SKF_GenerateAgreementDataWithECC = (SKF_POINTER(SKF_GenerateAgreementDataWithECC))dlsym(handle,"SKF_GenerateAgreementDataWithECC");
        skfFunctionList.SKF_GenerateAgreementDataAndKeyWithECC = (SKF_POINTER(SKF_GenerateAgreementDataAndKeyWithECC))dlsym(handle,"SKF_GenerateAgreementDataAndKeyWithECC");
        skfFunctionList.SKF_GenerateKeyWithECC = (SKF_POINTER(SKF_GenerateKeyWithECC))dlsym(handle,"SKF_GenerateKeyWithECC");
        skfFunctionList.SKF_ExportPublicKey = (SKF_POINTER(SKF_ExportPublicKey))dlsym(handle,"SKF_ExportPublicKey");
        skfFunctionList.SKF_ImportSessionKey = (SKF_POINTER(SKF_ImportSessionKey))dlsym(handle,"SKF_ImportSessionKey");
        skfFunctionList.SKF_SetSymmKey = (SKF_POINTER(SKF_SetSymmKey))dlsym(handle,"SKF_SetSymmKey");
        skfFunctionList.SKF_EncryptInit = (SKF_POINTER(SKF_EncryptInit))dlsym(handle,"SKF_EncryptInit");
        skfFunctionList.SKF_Encrypt = (SKF_POINTER(SKF_Encrypt))dlsym(handle,"SKF_Encrypt");
        skfFunctionList.SKF_EncryptUpdate = (SKF_POINTER(SKF_EncryptUpdate))dlsym(handle,"SKF_EncryptUpdate");
        skfFunctionList.SKF_EncryptFinal = (SKF_POINTER(SKF_EncryptFinal))dlsym(handle,"SKF_EncryptFinal");
        skfFunctionList.SKF_DecryptInit = (SKF_POINTER(SKF_DecryptInit))dlsym(handle,"SKF_DecryptInit");
        skfFunctionList.SKF_Decrypt = (SKF_POINTER(SKF_Decrypt))dlsym(handle,"SKF_Decrypt");
        skfFunctionList.SKF_DecryptUpdate = (SKF_POINTER(SKF_DecryptUpdate))dlsym(handle,"SKF_DecryptUpdate");
        skfFunctionList.SKF_DecryptFinal = (SKF_POINTER(SKF_DecryptFinal))dlsym(handle,"SKF_DecryptFinal");
        skfFunctionList.SKF_DigestInit = (SKF_POINTER(SKF_DigestInit))dlsym(handle,"SKF_DigestInit");
        skfFunctionList.SKF_Digest = (SKF_POINTER(SKF_Digest))dlsym(handle,"SKF_Digest");
        skfFunctionList.SKF_DigestUpdate = (SKF_POINTER(SKF_DigestUpdate))dlsym(handle,"SKF_DigestUpdate");
        skfFunctionList.SKF_DigestFinal = (SKF_POINTER(SKF_DigestFinal))dlsym(handle,"SKF_DigestFinal");
        skfFunctionList.SKF_MacInit = (SKF_POINTER(SKF_MacInit))dlsym(handle,"SKF_MacInit");
        skfFunctionList.SKF_Mac = (SKF_POINTER(SKF_Mac))dlsym(handle,"SKF_Mac");
        skfFunctionList.SKF_MacUpdate = (SKF_POINTER(SKF_MacUpdate))dlsym(handle,"SKF_MacUpdate");
        skfFunctionList.SKF_MacFinal = (SKF_POINTER(SKF_MacFinal))dlsym(handle,"SKF_MacFinal");
        skfFunctionList.SKF_CloseHandle = (SKF_POINTER(SKF_CloseHandle))dlsym(handle,"SKF_CloseHandle");
        skfFunctionList.SKF_Transmit = (SKF_POINTER(SKF_Transmit))dlsym(handle,"SKF_Transmit");
        skfFunctionList.SKF_ImportCertificate = (SKF_POINTER(SKF_ImportCertificate))dlsym(handle,"SKF_ImportCertificate");
        skfFunctionList.SKF_ExportCertificate = (SKF_POINTER(SKF_ExportCertificate))dlsym(handle,"SKF_ExportCertificate");
        skfFunctionList.SKF_GetContainerProperty = (SKF_POINTER(SKF_GetContainerProperty))dlsym(handle,"SKF_GetContainerProperty");

        DEBUG_SKF_LOAD("%s dlsym END",__FUNCTION__);
        DEBUG_SKF_LOAD("skfFunctionList.SKF_ConnectDev = %p ",skfFunctionList.SKF_ConnectDev);
    }

    DEBUG_SKF_LOAD("%s END,handle = [%p]",__FUNCTION__,handle);
}

skfLibLoader::~skfLibLoader() {
    if(NULL != handle){
        dlclose(handle);
        handle = NULL;
    }
}

void* skfLibLoader::SKF_GetFuncPointer(char *name) {
    void *pointer = NULL;
    if(NULL != handle){
        pointer = dlsym(handle,name);
    }

    return pointer;
}

SKFFunctionList_PTR skfLibLoader::SKF_GetFunctionList() {
    if(NULL != handle){
        return &skfFunctionList;
    }

    return NULL;
}

