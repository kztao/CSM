package com.westone.skflist;

import android.content.Context;
import android.widget.TextView;

import com.westone.skf.DEVHANDLE;
import com.westone.skf.DEVINFO;
import com.westone.skf.DevEvent;
import com.westone.skf.DevState;
import com.westone.skf.FILEATTRIBUTE;
import com.westone.skf.HANDLE;
import com.westone.skf.HAPPLICATION;
import com.westone.skf.HCONTAINER;
import com.westone.skf.PinInfo;
import com.westone.skf.PinRetryCount;
import com.westone.skf.SKFException;
import com.westone.skf.SkfWrapper;
import com.westone.testdemo.LogDebug;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

class SKFFuncRun {

    public SKFFuncRun(Context context){
        skfWrapper = null;
        skfWrapper = new SkfWrapper(context);
    }
    static SkfWrapper skfWrapper = new SkfWrapper();

    public static long skf_run(int funcNameIndex, int devNameIndex, int appNameIndex,int containerNameIndex,int fileNameIndex,int devIndex, int appIndex, int containerIndex, int handleIndex, TextView textView){
        long ret = 0x0A000003;

        List<String> devNames = new ArrayList<>(SkfFunc.devNames);
        List<String> appNames = new ArrayList<>(SkfFunc.appNames);
        List<String> containerNames = new ArrayList<>(SkfFunc.containerNames);
        List<String> fileNames = new ArrayList<>(SkfFunc.fileNames);

        List<DEVHANDLE> devhandles = new ArrayList<>(SkfFunc.devhandles);
        List<HAPPLICATION> happlications = new ArrayList<>(SkfFunc.happlications);
        List<HCONTAINER> hcontainers = new ArrayList<>(SkfFunc.hcontainers);
        List<HANDLE> handles = new ArrayList<>(SkfFunc.handles);

        try {
            switch (funcNameIndex){
                case 0:
                    skfWrapper.SKF_WaitForDevEvent(new DevEvent() {
                        @Override
                        public void notifyDevEvent(String s, int i) {

                        }
                    });

                    textView.setText("SKF_WaitForDevEvent OK");
                break;

                case 1:
                    skfWrapper.SKF_CancelWaitForDevEvent();
                    textView.setText("SKF_CancelWaitForDevEvent OK");
                break;

                case 2:
                    List<String>  list_SKF_EnumDev = new ArrayList();
                    skfWrapper.SKF_EnumDev(list_SKF_EnumDev);
                    SkfFunc.devNames.addAll(list_SKF_EnumDev);
                    textView.setText("SKF_EnumDev OK,devNames = " + Arrays.toString(SkfFunc.devNames.toArray()));
                break;

                case 3:

                    DEVHANDLE SKF_ConnectDev_devhandle = new DEVHANDLE();
                    skfWrapper.SKF_ConnectDev(devNames.get(devNameIndex),SKF_ConnectDev_devhandle);
                    SkfFunc.devhandles.add(SKF_ConnectDev_devhandle);
                    textView.setText("SKF_ConnectDev OK,devhandle = " + SKF_ConnectDev_devhandle);
                break;

                case 4:
                    skfWrapper.SKF_DisConnectDev(devhandles.get(devIndex));
                    textView.setText("SKF_DisConnectDev OK,devhandle = " + devhandles.get(devIndex));
                break;

                case 5:
                    DevState SKF_GetDevState_devState = new DevState();
                    skfWrapper.SKF_GetDevState(devNames.get(devNameIndex),SKF_GetDevState_devState);
                    textView.setText("SKF_GetDevState OK,devName = " + devNames.get(devNameIndex) +",status = "+ SKF_GetDevState_devState.getDevState());
                break;

                case 6:
                    skfWrapper.SKF_SetLabel(devhandles.get(devIndex),"Label");
                    textView.setText("SKF_SetLabel OK,devhandle = " + devhandles.get(devIndex));
                break;

                case 7:
                    DEVINFO SKF_GetDevInfo_devinfo = new DEVINFO();
                    skfWrapper.SKF_GetDevInfo(devhandles.get(devIndex),SKF_GetDevInfo_devinfo);
                    textView.setText("SKF_GetDevInfo OK,devhandle = " + devhandles.get(devIndex) + ",getManufacturer = "+SKF_GetDevInfo_devinfo.getManufacturer() + ",getSerialNumber = "+SKF_GetDevInfo_devinfo.getSerialNumber());
                break;

                case 8:
                    skfWrapper.SKF_LockDev(devhandles.get(devIndex),10);
                    textView.setText("SKF_LockDev OK,devhandle = " + devhandles.get(devIndex));
                break;

                case 9:
                    skfWrapper.SKF_UnlockDev(devhandles.get(devIndex));
                    textView.setText("SKF_UnlockDev OK,devhandle = " + devhandles.get(devIndex));
                break;

                case 10:
                    String devKey1 = "1234567812345678";
                    skfWrapper.SKF_ChangeDevAuthKey(devhandles.get(devIndex),devKey1.getBytes());
                    textView.setText("SKF_ChangeDevAuthKey OK,devhandle = " + devhandles.get(devIndex));
                break;

                case 11:
                    String devKey = "1234567812345678";
                    byte[] auth = new byte[16];
                    byte[] rnd = skfWrapper.SKF_GenRandom(devhandles.get(devIndex),8);
                    System.arraycopy(rnd,0,auth,0,8);
                    HANDLE handle = new HANDLE();
                    skfWrapper.SKF_SetSymmKey(devhandles.get(devIndex), devKey.getBytes(), 1025, handle);
                    skfWrapper.SKF_EncryptInit(handle,null,0,16 * 8);
                    byte[] cipher = skfWrapper.SKF_Encrypt(handle,auth);
                    skfWrapper.SKF_CloseHandle(handle);
                    skfWrapper.SKF_DevAuth(devhandles.get(devIndex),cipher);
                    textView.setText("SKF_DevAuth OK,devhandle = " + devhandles.get(devIndex));
                break;

                case 12:
                    PinRetryCount SKF_ChangePIN_pinRetryCount = new PinRetryCount();
                    skfWrapper.SKF_ChangePIN(happlications.get(appIndex),1,"123456","123456",SKF_ChangePIN_pinRetryCount);
                    textView.setText("SKF_ChangePIN OK,happlication = " + happlications.get(appIndex)+ ",pinRetryCount.getRetryCount() = " + SKF_ChangePIN_pinRetryCount.getRetryCount());
                break;

                case 13:
                    PinInfo SKF_GetPINInfo_pinInfo = new PinInfo();
                    skfWrapper.SKF_GetPINInfo(happlications.get(appIndex),1,SKF_GetPINInfo_pinInfo);
                    textView.setText("SKF_GetPINInfo OK,happlication = " + happlications.get(appIndex)+
                            ",getMaxRetryCount = " + SKF_GetPINInfo_pinInfo.getMaxRetryCount() +
                            ",getRemainRetryCount = "+ SKF_GetPINInfo_pinInfo.getRemainRetryCount()+"" +
                            ",isDefaultPin = " + SKF_GetPINInfo_pinInfo.isDefaultPin());
                break;

                case 14:
                    PinRetryCount SKF_VerifyPIN_pinRetryCount = new PinRetryCount();
                    skfWrapper.SKF_VerifyPIN(happlications.get(appIndex),1,"123456",SKF_VerifyPIN_pinRetryCount);
                    textView.setText("SKF_VerifyPIN OK,happlication = " + happlications.get(appIndex)+ ",pinRetryCount.getRetryCount() = " + SKF_VerifyPIN_pinRetryCount.getRetryCount());
                break;

                case 15:
                    PinRetryCount SKF_UnblockPIN_pinRetryCount = new PinRetryCount();
                    skfWrapper.SKF_UnblockPIN(happlications.get(appIndex),"123456","123456",SKF_UnblockPIN_pinRetryCount);
                    textView.setText("SKF_UnblockPIN OK,happlication = " + happlications.get(appIndex)+ ",pinRetryCount.getRetryCount() = " + SKF_UnblockPIN_pinRetryCount.getRetryCount());
                break;

                case 16:
                    skfWrapper.SKF_ClearSecureState(happlications.get(appIndex));
                    textView.setText("SKF_ClearSecureState OK,happlication = " + happlications.get(appIndex));
                break;

                case 17:
                    HAPPLICATION SKF_CreateApplication_happlication = new HAPPLICATION();
                    LogDebug.log("before SKF_CreateApplication");
                    skfWrapper.SKF_CreateApplication(devhandles.get(devIndex),"testApp","123456",6,"123456",6,16,SKF_CreateApplication_happlication);
                    LogDebug.log("end SKF_CreateApplication");
                    textView.setText("SKF_CreateApplication OK,happlication = " + SKF_CreateApplication_happlication);
                    SkfFunc.happlications.add(SKF_CreateApplication_happlication);
                    SkfFunc.appNames.add("testApp");
                break;

                case 18:
                    List<String> SKF_EnumApplication_list = new ArrayList<>();
                    skfWrapper.SKF_EnumApplication(devhandles.get(devIndex),SKF_EnumApplication_list);
                    SkfFunc.appNames.addAll(SKF_EnumApplication_list);
                    textView.setText("SKF_EnumApplication OK,appname = " + Arrays.toString(SKF_EnumApplication_list.toArray()));
                break;

                case 19:
                    skfWrapper.SKF_DeleteApplication(devhandles.get(devIndex),appNames.get(appNameIndex));
                    SkfFunc.appNames.remove(appNames.get(appNameIndex));
                    textView.setText("SKF_DeleteApplication OK,appname = " + appNames.get(appNameIndex));
                break;

                case 20:
                    HAPPLICATION SKF_OpenApplication_happlication = new HAPPLICATION();
                    skfWrapper.SKF_OpenApplication(devhandles.get(devIndex),appNames.get(appNameIndex),SKF_OpenApplication_happlication);
                    SkfFunc.happlications.add(SKF_OpenApplication_happlication);
                    textView.setText("SKF_OpenApplication OK,happlication = " + SKF_OpenApplication_happlication);
                break;

                case 21:
                    skfWrapper.SKF_CloseApplication(happlications.get(appIndex));
                    textView.setText("SKF_CloseApplication OK,happlication = " + happlications.get(appIndex));
                break;

                case 22:
                    skfWrapper.SKF_CreateFile(happlications.get(appIndex),"testFile",10,16,16);
                    textView.setText("SKF_CreateFile testFile OK,happlication = " + happlications.get(appIndex));
                break;

                case 23:
                    skfWrapper.SKF_DeleteFile(happlications.get(appIndex),fileNames.get(fileNameIndex));
                    textView.setText("SKF_DeleteFile " + fileNames.get(fileNameIndex)+" OK,happlication = " + happlications.get(appIndex));
                break;

                case 24:
                    List<String> SKF_EnumFiles_list = new ArrayList<>();
                    skfWrapper.SKF_EnumFiles(happlications.get(appIndex),SKF_EnumFiles_list);
                    textView.setText("SKF_EnumFiles OK,happlication = " + happlications.get(appIndex) + ",file name = " + Arrays.toString(SKF_EnumFiles_list.toArray()));
                break;

                case 25:
                    FILEATTRIBUTE fileattribute = new FILEATTRIBUTE();
                    skfWrapper.SKF_GetFileInfo(happlications.get(appIndex),fileNames.get(fileNameIndex),fileattribute);
                    textView.setText("SKF_GetFileInfo OK,happlication = " + happlications.get(appIndex));
                break;

                case 26:
                    skfWrapper.SKF_ReadFile(happlications.get(appIndex),fileNames.get(fileNameIndex),0,10);
                    textView.setText("SKF_ReadFile OK,happlication = " + happlications.get(appIndex));
                break;

                case 27:
                String s = "01213456789";
                skfWrapper.SKF_WriteFile(happlications.get(appIndex),fileNames.get(fileNameIndex),0,s.getBytes());
                textView.setText("SKF_WriteFile OK,happlication = " + happlications.get(appIndex));
                break;

                case 28:
                    HCONTAINER SKF_CreateContainer_hcontainer = new HCONTAINER();
                    skfWrapper.SKF_CreateContainer(happlications.get(appIndex),"testContainer",SKF_CreateContainer_hcontainer);
                    textView.setText("SKF_CreateContainer OK,hcontainer = " + SKF_CreateContainer_hcontainer);
                break;

                case 29:
                    skfWrapper.SKF_DeleteContainer(happlications.get(appIndex),containerNames.get(containerIndex));
                    textView.setText("SKF_Delete Container "+containerNames.get(containerIndex) +" OK");
                break;

                case 30:
                    HCONTAINER SKF_OpenContainer_h = new HCONTAINER();
                    skfWrapper.SKF_OpenContainer(happlications.get(appIndex),containerNames.get(containerIndex),SKF_OpenContainer_h);
                    textView.setText("SKF_CreateContainer OK,hcontainer = " + SKF_OpenContainer_h);
                break;

                case 31:
                    skfWrapper.SKF_CloseContainer(hcontainers.get(containerIndex));
                    textView.setText("SKF_CloseContainer OK,hcontainer = " + hcontainers.get(containerIndex));
                break;


                case 32:
                    List<String> SKF_EnumContainer_l = new ArrayList<>();
                    skfWrapper.SKF_EnumContainer(happlications.get(appIndex),SKF_EnumContainer_l);
                    textView.setText("SKF_EnumContainer OK,containers = " + Arrays.toString(SKF_EnumContainer_l.toArray()));
                break;

                case 33:
                    long sm2ret = skfWrapper.SKF_GetContainerType(hcontainers.get(containerIndex));
                    textView.setText("SKF_GetContainerType OK,type = " + sm2ret);
                break;

                case 34:
                    byte[] SKF_GenRandom_r = skfWrapper.SKF_GenRandom(devhandles.get(devIndex),4);
                    textView.setText("SKF_GenRandom OK,rnd = " + Arrays.toString(SKF_GenRandom_r));
                break;

                case 35:
                    //skfWrapper.SKF_GenExtRSAKey;
                break;

                case 36:
                    //skfWrapper.SKF_GenRSAKeyPair;
                break;

                case 37:
                //skfWrapper.SKF_ImportRSAKeyPair;
                break;

                case 38:
                //skfWrapper.SKF_RSASignData;
                break;

                case 39:
                //skfWrapper.SKF_RSAVerify;
                break;

                case 40:
                //skfWrapper.SKF_RSAExportSessionKey;
                break;

                case 41:
                //skfWrapper.SKF_ExtRSAPubKeyOperation;
                break;

                case 42:
                //skfWrapper.SKF_ExtRSAPriKeyOperation;
                break;

                case 43:
                    skfWrapper.SKF_GenECCKeyPair(hcontainers.get(containerIndex),0x00020100);
                    textView.setText("SKF_GenECCKeyPair OK,container = " + String.format("0x%08x",hcontainers.get(containerIndex)));
                break;

                case 44:
                    //skfWrapper.SKF_ImportECCKeyPair();
                break;

                case 45:
                    byte[] SKF_ECCSignData_d = new byte[]{
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
                    };

                    byte[]sign = skfWrapper.SKF_ECCSignData(hcontainers.get(containerIndex),SKF_ECCSignData_d);
                    textView.setText("SKF_ECCSignData OK SignData = " +Arrays.toString(sign));
                break;

                case 46:
                    //skfWrapper.SKF_ECCVerify();
                break;

                case 47:
                    //skfWrapper.SKF_ECCExportSessionKey;
                break;

                case 48:
                    //skfWrapper.SKF_ExtECCEncrypt;
                break;

                case 49:
                //skfWrapper.SKF_ExtECCDecrypt;
                break;

                case 50:
                //skfWrapper.SKF_ExtECCSign;
                break;

                case 51:
                //skfWrapper.SKF_ExtECCVerify;
                break;

                case 52:
                //skfWrapper.SKF_GenerateAgreementDataWithECC;
                break;

                case 53:
                //skfWrapper.SKF_GenerateAgreementDataAndKeyWithECC;
                break;

                case 54:
                //skfWrapper.SKF_GenerateKeyWithECC;
                break;

                case 55:
                //skfWrapper.SKF_ExportPublicKey;
                break;

                case 56:
                //skfWrapper.SKF_ImportSessionKey;
                break;

                case 57:
                    String SKF_SetSymmKey_k = "1234567812345678";
                    HANDLE SKF_SetSymmKey_h = new HANDLE();
                    skfWrapper.SKF_SetSymmKey(devhandles.get(devIndex),SKF_SetSymmKey_k.getBytes(),1025,SKF_SetSymmKey_h);
                    textView.setText("SKF_SetSymmKey OK");
                break;

                case 58:
                    skfWrapper.SKF_EncryptInit(handles.get(handleIndex),null,0,16*8);
                    textView.setText("SKF_EncryptInit OK");
                break;

                case 59:
                    byte[] SKF_Encrypt_d = new byte[]{
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
                    };

                    byte[] out = skfWrapper.SKF_Encrypt(handles.get(handleIndex),SKF_Encrypt_d);
                    textView.setText("SKF_Encrypt OK,1-8 1-8 enc result is " + Arrays.toString(out));
                break;

                case 60:
                    byte[] SKF_EncryptUpdate_d = new byte[]{
                            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
                    };

                    byte[] out_eu = skfWrapper.SKF_EncryptUpdate(handles.get(handleIndex),SKF_EncryptUpdate_d);
                    textView.setText("SKF_EncryptUpdate OK,1-8 1-8 enc result is " + Arrays.toString(out_eu));
                break;

                case 61:
                    byte[] out_ef = skfWrapper.SKF_EncryptFinal(handles.get(handleIndex));
                    textView.setText("SKF_EncryptFinal OK");
                break;

                case 62:
                //skfWrapper.SKF_DecryptInit;
                break;

                case 63:
                //skfWrapper.SKF_Decrypt;
                break;

                case 64:
                //skfWrapper.SKF_DecryptUpdate;
                break;

                case 65:
                //skfWrapper.SKF_DecryptFinal;
                break;

                case 66:
                //skfWrapper.SKF_DigestInit;
                break;

                case 67:
                //skfWrapper.SKF_Digest;
                break;

                case 68:
                //skfWrapper.SKF_DigestUpdate;
                break;

                case 69:
                //skfWrapper.SKF_DigestFinal;
                break;

                case 70:
                //skfWrapper.SKF_MacInit;
                break;

                case 71:
                //skfWrapper.SKF_Mac;
                break;

                case 72:
                //skfWrapper.SKF_MacUpdate;
                break;

                case 73:
                //skfWrapper.SKF_MacFinal;
                break;

                case 74:
                //skfWrapper.SKF_CloseHandle;
                break;

                case 75:
                //skfWrapper.SKF_Transmit;
                break;

                case 76:
                //skfWrapper.SKF_ImportCertificate;
                break;

                case 77:
                //skfWrapper.SKF_ExportCertificate;
                break;

                case 78:
                //skfWrapper.SKF_GetContainerProperty;
                break;

                default:
                    break;
            }
        }catch (Exception e){
            ret = SKFException.getLastError();
            textView.setText("error msg = "+e.getMessage() +"\n"+SkfFunc.list.get(funcNameIndex)+"Error = " + String.format("0x%08x",ret));
        }

        return ret;
    }
}
