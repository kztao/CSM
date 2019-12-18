package com.westone.skflist;

import com.westone.skf.DEVHANDLE;
import com.westone.skf.HANDLE;
import com.westone.skf.HAPPLICATION;
import com.westone.skf.HCONTAINER;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

class SkfFunc {
    public static List<String> list = Arrays.asList(
            "SKF_WaitForDevEvent",
            "SKF_CancelWaitForDevEvent",
            "SKF_EnumDev",
            "SKF_ConnectDev",
            "SKF_DisConnectDev",
            "SKF_GetDevState",
            "SKF_SetLabel",
            "SKF_GetDevInfo",
            "SKF_LockDev",
            "SKF_UnlockDev",
            "SKF_ChangeDevAuthKey",
            "SKF_DevAuth",
            "SKF_ChangePIN",
            "SKF_GetPINInfo",
            "SKF_VerifyPIN",
            "SKF_UnblockPIN",
            "SKF_ClearSecureState",
            "SKF_CreateApplication",
            "SKF_EnumApplication",
            "SKF_DeleteApplication",
            "SKF_OpenApplication",
            "SKF_CloseApplication",
            "SKF_CreateFile",
            "SKF_DeleteFile",
            "SKF_EnumFiles",
            "SKF_GetFileInfo",
            "SKF_ReadFile",
            "SKF_WriteFile",
            "SKF_CreateContainer",
            "SKF_DeleteContainer",
            "SKF_OpenContainer",
            "SKF_CloseContainer",
            "SKF_EnumContainer",
            "SKF_GetContainerType",
            "SKF_GenRandom",
            "SKF_GenExtRSAKey",
            "SKF_GenRSAKeyPair",
            "SKF_ImportRSAKeyPair",
            "SKF_RSASignData",
            "SKF_RSAVerify",
            "SKF_RSAExportSessionKey",
            "SKF_ExtRSAPubKeyOperation",
            "SKF_ExtRSAPriKeyOperation",
            "SKF_GenECCKeyPair",
            "SKF_ImportECCKeyPair",
            "SKF_ECCSignData",
            "SKF_ECCVerify",
            "SKF_ECCExportSessionKey",
            "SKF_ExtECCEncrypt",
            "SKF_ExtECCDecrypt",
            "SKF_ExtECCSign",
            "SKF_ExtECCVerify",
            "SKF_GenerateAgreementDataWithECC",
            "SKF_GenerateAgreementDataAndKeyWithECC",
            "SKF_GenerateKeyWithECC",
            "SKF_ExportPublicKey",
            "SKF_ImportSessionKey",
            "SKF_SetSymmKey",
            "SKF_EncryptInit",
            "SKF_Encrypt",
            "SKF_EncryptUpdate",
            "SKF_EncryptFinal",
            "SKF_DecryptInit",
            "SKF_Decrypt",
            "SKF_DecryptUpdate",
            "SKF_DecryptFinal",
            "SKF_DigestInit",
            "SKF_Digest",
            "SKF_DigestUpdate",
            "SKF_DigestFinal",
            "SKF_MacInit",
            "SKF_Mac",
            "SKF_MacUpdate",
            "SKF_MacFinal",
            "SKF_CloseHandle",
            "SKF_Transmit",
            "SKF_ImportCertificate",
            "SKF_ExportCertificate",
            "SKF_GetContainerProperty"
    );

    public static List<String> handleDesc = Arrays.asList(
            "DevName",
            "AppName",
            "ContainerName",
            "FileName",

            "DevHandle",
            "HApplication",
            "HContainer",
            "HANDLE"
    );

    public static Set<String> devNames = new HashSet<>();
    public static Set<String> appNames = new HashSet<>();
    public static Set<String> containerNames = new HashSet<>();
    public static Set<String> fileNames = new HashSet<>();
    public static Set<DEVHANDLE> devhandles = new HashSet<>();
    public static Set<HAPPLICATION> happlications = new HashSet<>();
    public static Set<HCONTAINER> hcontainers = new HashSet<>();
    public static Set<HANDLE> handles = new HashSet<>();
}
