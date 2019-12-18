package com.westone.skf;

import android.content.Context;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

/**
 * SKF接口封装类
 */
public class SkfWrapper {
    static int mSimStatus = 0;
    static List<String> mDevName = new ArrayList<>();

    /**
     * 构造函数.
     */
    synchronized public static void setSimStatus(int status){

        mSimStatus = status;

            //TODO
            List<String> list = new ArrayList<>();
            try {

                SKF_EnumDev_r(list);

                Log.i("wjr","\n--------------------------\n");
                Log.i("wjr","sim status is " + status + ",new dev size = " + list.size()+",old dev size = " + mDevName.size());
                for (String n : list){
                    Log.i("wjr","new dev is " + n);
                }

                for (String o : mDevName){
                    Log.i("wjr","old dev is " + o);
                }


                if(list.containsAll(mDevName)){
                    //dev insert
                    for (String newDev : list){
                        if(!mDevName.contains(newDev)){
                            if(SKFDevManager.devEvent != null){
                                SKFDevManager.devEvent.notifyDevEvent(newDev,SkfDefines.EVENT_DEVICE_INSERTED);
                            }
                        }
                    }

                }else {
                    //dev remove

                    for (String newDev : list){
                        if(!mDevName.contains(newDev)){
                            if(SKFDevManager.devEvent != null){
                                SKFDevManager.devEvent.notifyDevEvent(newDev,SkfDefines.EVENT_DEVICE_INSERTED);
                            }
                        }
                    }

                    for (String oldDev : mDevName){
                        if(!list.contains(oldDev)){
                            if(SKFDevManager.devEvent != null){
                                SKFDevManager.devEvent.notifyDevEvent(oldDev,SkfDefines.EVENT_DEVICE_REMOVED);
                            }
                        }
                    }

                }
                mDevName.clear();
                mDevName.addAll(list);
                list.clear();
                list = null;
            } catch (SKFException e) {
                e.printStackTrace();
            }

    }

    private static Context mContext;
    private static String mLibName;

    public SkfWrapper(){

    }
    public SkfWrapper(Context context,String libName){
        if(null != context){
            mContext = context.getApplicationContext();
            mLibName = libName;
            SkfNativeFunc.setLibPath(context,libName);
        }
    }

    /**
     * 构造函数,用于支持设备事件通知相关接口.
     * @param context 上下文
     */
    public SkfWrapper(Context context){
        if(context != null){
            mContext = context.getApplicationContext();
            /*BroadcastReceiver broadcastReceiver = new MediaMount();
            IntentFilter intentFilter = new IntentFilter();
            intentFilter.addAction(Intent.ACTION_MEDIA_EJECT);
            intentFilter.addAction(Intent.ACTION_MEDIA_MOUNTED);
            intentFilter.addDataScheme("file");
            context.getApplicationContext().registerReceiver(broadcastReceiver,intentFilter);*/
        }
    }

    /************************************************************************/
    /*   1. 设备管理				                                        */
    /*	 SKF_WaitForDevEvent												*/
    /*	 SKF_CancelWaitForDevEvent											*/
    /*	 SKF_EnumDev												        */
    /*	 SKF_ConnectDev														*/
    /*	 SKF_DisConnectDev													*/
    /*	 SKF_GetDevState													*/
    /*	 SKF_SetLabel														*/
    /*	 SKF_GetDevInfo														*/
    /*	 SKF_LockDev												        */
    /*	 SKF_UnlockDev												        */
    /*	 SKF_UnlockDev												        */
    /*	 SKF_Transmit												        */

    /**
     * 等待设备插拔事件.
     *
     * @param event [IN]设备事件
     * @throws SKFException the skf exception
     */
    public void SKF_WaitForDevEvent(DevEvent event) throws SKFException{
        SKFDevManager.devEvent = event;
    }

    /**
     * 取消等待设备插拔事件.
     *
     * @throws SKFException the skf exception
     */
    public void SKF_CancelWaitForDevEvent() throws SKFException{
        SKFDevManager.devEvent = null;
    }


    /**
     * 获得当前系统中的设备列表.
     *
     * @param szNameList [OUT]设备名称列表。每个设备的名称以单个'\0'结束。
     * @throws SKFException the skf exception
     */
    public void SKF_EnumDev(List<String> szNameList) throws SKFException{
        long ret = SkfNativeFunc.SKF_EnumDev(szNameList);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_EnumDev Failed.", ret);
        }

        mDevName.clear();
        mDevName.addAll(szNameList);
    }

    private static void SKF_EnumDev_r(List<String> szNameList) throws SKFException{
        long ret = SkfNativeFunc.SKF_EnumDev(szNameList);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_EnumDev Failed.", ret);
        }

    }

    /**
     * 通过设备名称连接设备，返回设备的句柄.
     *
     * @param szName [IN]设备名称
     * @param phDev  [OUT]返回设备操作句柄
     * @throws SKFException the skf exception
     */
    public void SKF_ConnectDev(String szName,DEVHANDLE phDev) throws SKFException{
        long ret = SkfNativeFunc.SKF_ConnectDev(szName, phDev);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ConnectDev Failed.", ret);
        }
    }

    /**
     * 断开一个已经连接的设备，并释放句柄.
     *
     * @param hDev [IN]连接设备时返回的设备句柄
     * @throws SKFException the skf exception
     */
    public void SKF_DisConnectDev(DEVHANDLE hDev) throws SKFException{
        long ret = SkfNativeFunc.SKF_DisConnectDev(hDev);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DisConnectDev.", ret);
        }
    }

    /**
     * 获取设备是否存在的状态.
     *
     * @param szDevName   [IN]连接名称
     * @param pulDevState [OUT]返回设备状态
     * @throws SKFException the skf exception
     */
    public void SKF_GetDevState(String  szDevName,DevState pulDevState) throws SKFException{
        long ret = SkfNativeFunc.SKF_GetDevState(szDevName, pulDevState);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_GetDevState Failed.", ret);
        }
    }

    /**
     * 设置设备标签.
     *
     * @param hDev    [IN]连接设备时返回的设备句柄
     * @param szLabel [IN]设备标签字符串。该字符串应小于32字节
     * @throws SKFException the skf exception
     */
    public void SKF_SetLabel(DEVHANDLE hDev,String szLabel) throws SKFException{
        long ret = SkfNativeFunc.SKF_SetLabel(hDev, szLabel);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_SetLabel Failed.", ret);
        }
    }

    /**
     * 获取设备的一些特征信息，包括设备标签、厂商信息、支持的算法等.
     *
     * @param hDev     [IN]连接设备时返回的设备句柄
     * @param pDevInfo [OUT]返回设备信息
     * @throws SKFException the skf exception
     */
    public void SKF_GetDevInfo(DEVHANDLE	hDev,DEVINFO pDevInfo) throws SKFException{
        long ret = SkfNativeFunc.SKF_GetDevInfo(hDev, pDevInfo);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_GetDevInfo Failed.", ret);
        }
    }

    /**
     * 获得设备的独占使用权.
     *
     * @param hDev      [IN]连接设备时返回的设备句柄
     * @param ulTimeOut [IN]超时时间，单位为毫秒。如果为0xFFFFFFFF表示无限等待
     * @throws SKFException the skf exception
     */
    public void SKF_LockDev(DEVHANDLE	hDev,long ulTimeOut) throws SKFException{
        long ret = SkfNativeFunc.SKF_LockDev(hDev, ulTimeOut);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_LockDev Failed.", ret);
        }
    }

    /**
     * 释放对设备的独占使用权.
     *
     * @param hDev [IN]连接设备时返回的设备句柄
     * @throws SKFException the skf exception
     */
    public void SKF_UnlockDev(DEVHANDLE	hDev) throws SKFException{
        long ret = SkfNativeFunc.SKF_UnlockDev(hDev);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_UnlockDev Failed.", ret);
        }
    }

    /**
     * 将命令直接发送给设备，并返回结果.
     *
     * @param hDev       [IN] 设备句柄
     * @param pbCommand  [IN] 设备命令
     * @param pbData     [OUT] 返回结果数据
     * @param pulDataLen [IN,OUT] 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度
     * @throws SKFException the skf exception
     */
    public void SKF_Transmit(DEVHANDLE hDev, byte[] pbCommand, byte[] pbData, long[] pulDataLen) throws SKFException{
        long ret = SkfNativeFunc.SKF_Transmit(hDev, pbCommand, pbData, pulDataLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_Transmit Failed.", ret);
        }
    }

/************************************************************************/
    /*  2. 访问控制				                                            */
    /*	 SKF_ChangeDevAuthKey												*/
    /*	 SKF_DevAuth														*/
    /*	 SKF_ChangePIN														*/
    /*	 SKF_GetPINInfo														*/
    /*	 SKF_VerifyPIN														*/
    /*	 SKF_UnblockPIN														*/
    /*	 SKF_ClearSecureState												*/

    /**
     * 更改设备认证密钥.
     *
     * @param hDev [IN]连接时返回的设备句柄
     * @param pbKeyValue [IN]密钥值
     * @throws SKFException the skf exception
     */
    public void SKF_ChangeDevAuthKey(DEVHANDLE hDev,byte[] pbKeyValue) throws SKFException{
        long ret = SkfNativeFunc.SKF_ChangeDevAuthKey(hDev, pbKeyValue);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ChangeDevAuthKey Failed.", ret);
        }
    }

    /**
     * 设备认证是设备对应用程序的认证.
     *
     * @param hDev       [IN]连接时返回的设备句柄
     * @param pbAuthData [IN]认证数据
     * @throws SKFException the skf exception
     */
    public void SKF_DevAuth(DEVHANDLE hDev,byte[] pbAuthData) throws SKFException{
        long ret = SkfNativeFunc.SKF_DevAuth(hDev, pbAuthData);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DevAuth Failed.", ret);
        }
    }

    /**
     * 修改PIN，可以修改Admin和User的PIN，如果原PIN错误，返回剩余重试次数，当剩余次数为0时，表示PIN已经被锁死.
     *
     * @param hApplication  [IN]应用句柄
     * @param ulPINType     [IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
     * @param szOldPIN      [IN]原PIN值
     * @param szNewPIN      [IN]新PIN值
     * @param pulRetryCount [OUT]出错后重试次数
     * @throws SKFException the skf exception
     */
    public void SKF_ChangePIN(HAPPLICATION hApplication, long ulPINType, String szOldPIN, String szNewPIN, PinRetryCount pulRetryCount) throws SKFException{
        long ret = SkfNativeFunc.SKF_ChangePIN(hApplication, ulPINType, szOldPIN, szNewPIN, pulRetryCount);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ChangePIN Failed.", ret);
        }
    }

    /**
     * 获取PIN码信息，包括最大重试次数、当前剩余重试次数，以及当前PIN码是否为出厂默认PIN码.
     *
     * @param hApplication        [IN]应用句柄
     * @param ulPINType           [IN]PIN类型
     * @param ulPinInfo           [OUT]PIN码信息
     * @throws SKFException the skf exception
     */
    public void SKF_GetPINInfo(HAPPLICATION hApplication, long ulPINType, PinInfo ulPinInfo) throws SKFException{
        long ret = SkfNativeFunc.SKF_GetPINInfo(hApplication, ulPINType, ulPinInfo);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_GetPINInfo Failed.", ret);
        }
    }

    /**
     * 校验PIN码。校验成功后，会获得相应的权限，如果PIN码错误，会返回PIN码的重试次数，当重试次数为0时表示PIN码已经锁死.
     *
     * @param hApplication  [IN]应用句柄
     * @param ulPINType     [IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
     * @param szPIN         [IN]PIN值
     * @param pulRetryCount [OUT]出错后返回的重试次数
     * @throws SKFException the skf exception
     */
    public void SKF_VerifyPIN(HAPPLICATION hApplication, long ulPINType, String szPIN, PinRetryCount pulRetryCount) throws SKFException{
        long ret = SkfNativeFunc.SKF_VerifyPIN(hApplication, ulPINType, szPIN, pulRetryCount);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_VerifyPIN Failed.", ret);
        }
    }

    /**
     * 当用户的PIN码锁死后，通过调用该函数来解锁用户PIN码.
     * 解锁后，用户PIN码被设置成新值，用户PIN码的重试次数也恢复到原值
     *
     * @param hApplication  [IN]应用句柄
     * @param szAdminPIN    [IN]管理员PIN码
     * @param szNewUserPIN  [IN]新的用户PIN码
     * @param pulRetryCount [OUT]管理员PIN码错误时，返回剩余重试次数
     * @throws SKFException the skf exception
     */
    public void SKF_UnblockPIN(HAPPLICATION hApplication, String szAdminPIN, String szNewUserPIN, PinRetryCount pulRetryCount) throws SKFException{
        long ret = SkfNativeFunc.SKF_UnblockPIN(hApplication, szAdminPIN, szNewUserPIN, pulRetryCount);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_UnblockPIN Failed.", ret);
        }
    }

    /**
     * 清除应用当前的安全状态.
     *
     * @param hApplication [IN]应用句柄
     * @throws SKFException the skf exception
     */
    public void SKF_ClearSecureState(HAPPLICATION hApplication) throws SKFException{
        long ret = SkfNativeFunc.SKF_ClearSecureState(hApplication);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ClearSecureState Failed.", ret);
        }
    }

    /************************************************************************/
    /*  3. 应用管理				                                            */
    /*	 SKF_CreateApplication												*/
    /*	 SKF_EnumApplication												*/
    /*	 SKF_DeleteApplication												*/
    /*	 SKF_OpenApplication												*/
    /*	 SKF_CloseApplication												*/

    /**
     * 创建一个应用.
     *
     * @param hDev                 [IN]连接设备时返回的设备句柄
     * @param szAppName            [IN]应用名称
     * @param szAdminPIN           [IN]管理员PIN
     * @param dwAdminPinRetryCount [IN]管理员PIN最大重试次数
     * @param szUserPIN            [IN]用户PIN
     * @param dwUserPinRetryCount  [IN]用户PIN最大重试次数
     * @param dwCreateFileRights   [IN]在该应用下创建文件和容器的权限
     * @param phApplication        [OUT]应用的句柄
     * @throws SKFException the skf exception
     */
    public void SKF_CreateApplication(DEVHANDLE hDev, String szAppName, String szAdminPIN, long dwAdminPinRetryCount, String szUserPIN, long dwUserPinRetryCount, long dwCreateFileRights, HAPPLICATION phApplication) throws SKFException{
        long ret = SkfNativeFunc.SKF_CreateApplication(hDev, szAppName, szAdminPIN, dwAdminPinRetryCount, szUserPIN, dwUserPinRetryCount, dwCreateFileRights, phApplication);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_CreateApplication Failed.", ret);
        }
    }

    /**
     * 枚举设备中所存在的所有应用.
     *
     * @param hDev      [IN]连接设备时返回的设备句柄
     * @param szAppName [OUT]返回应用名称列表。每个应用的名称以单个'\0'结束。
     * @throws SKFException the skf exception
     */
    public void SKF_EnumApplication(DEVHANDLE hDev, List<String> szAppName) throws SKFException{
        long ret = SkfNativeFunc.SKF_EnumApplication(hDev, szAppName);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_EnumApplication Failed.", ret);
        }
    }

    /**
     * 删除指定的应用.
     *
     * @param hDev      [IN]连接设备时返回的设备句柄
     * @param szAppName [IN]应用名称
     * @throws SKFException the skf exception
     */
    public void SKF_DeleteApplication(DEVHANDLE hDev, String szAppName) throws SKFException{
        long ret = SkfNativeFunc.SKF_DeleteApplication(hDev, szAppName);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DeleteApplication Failed.", ret);
        }
    }

    /**
     * 打开指定的应用.
     *
     * @param hDev          [IN]连接设备时返回的设备句柄
     * @param szAppName     [IN]应用名称
     * @param phApplication [OUT]应用的句柄
     * @throws SKFException the skf exception
     */
    public void SKF_OpenApplication(DEVHANDLE hDev, String szAppName, HAPPLICATION phApplication) throws SKFException{
        long ret = SkfNativeFunc.SKF_OpenApplication(hDev, szAppName, phApplication);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_OpenApplication Failed.", ret);
        }
    }

    /**
     * 关闭应用并释放应用句柄.
     *
     * @param hApplication [IN]应用的句柄
     * @throws SKFException the skf exception
     */
    public void SKF_CloseApplication(HAPPLICATION hApplication) throws SKFException{
        long ret = SkfNativeFunc.SKF_CloseApplication(hApplication);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_CloseApplication Failed.", ret);
        }
    }

    /************************************************************************/
    /*  4. 文件管理				                                            */
    /*	 SKF_CreateFile														*/
    /*	 SKF_DeleteFile														*/
    /*	 SKF_EnumFiles														*/
    /*	 SKF_GetFileInfo													*/
    /*	 SKF_ReadFile														*/
    /*	 SKF_WriteFile														*/

    /**
     * 创建一个文件。创建文件时要指定文件的名称，大小，以及文件的读写权限.
     *
     * @param hApplication  [IN]应用句柄
     * @param szFileName    [IN]文件名称，长度不得大于32个字节
     * @param ulFileSize    [IN]文件大小
     * @param ulReadRights  [IN]文件读权限
     * @param ulWriteRights [IN]文件写权限
     * @throws SKFException the skf exception
     */
    public void SKF_CreateFile(HAPPLICATION hApplication, String szFileName, long ulFileSize, long ulReadRights, long ulWriteRights) throws SKFException{
        long ret = SkfNativeFunc.SKF_CreateFile(hApplication, szFileName, ulFileSize,ulReadRights, ulWriteRights);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_CreateFile Failed.", ret);
        }
    }

    /**
     * 删除指定文件，文件删除后，文件中写入的所有信息将丢失。文件在设备中的占用的空间将被释放.
     *
     * @param hApplication [IN]要删除文件所在的应用句柄
     * @param szFileName   [IN]要删除文件的名称
     * @throws SKFException the skf exception
     */
    public void SKF_DeleteFile(HAPPLICATION hApplication, String szFileName) throws SKFException{
        long ret = SkfNativeFunc.SKF_DeleteFile(hApplication, szFileName);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DeleteFile Failed.", ret);
        }
    }

    /**
     * 枚举一个应用下存在的所有文件.
     *
     * @param hApplication [IN]应用的句柄
     * @param szFileList   [OUT]返回文件名称列表，该参数为空，由pulSize返回文件信息所需要的空间大小。每个文件名称以单个'\0'结束，以双'\0'表示列表的结束
     * @throws SKFException the skf exception
     */
    public void SKF_EnumFiles(HAPPLICATION hApplication, List<String> szFileList) throws SKFException{
        long ret = SkfNativeFunc.SKF_EnumFiles(hApplication, szFileList);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_EnumFiles Failed.", ret);
        }
    }

    /**
     * 获取应用文件的属性信息，例如文件的大小、权限等.
     *
     * @param hApplication [IN]文件所在应用的句柄
     * @param szFileName   [IN]文件名称
     * @param pFileInfo    [OUT]文件信息，指向文件属性结构的指针
     * @throws SKFException the skf exception
     */
    public void SKF_GetFileInfo(HAPPLICATION hApplication, String szFileName, FILEATTRIBUTE pFileInfo) throws SKFException{
        long ret = SkfNativeFunc.SKF_GetFileInfo(hApplication, szFileName, pFileInfo);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_GetFileInfo Failed.", ret);
        }
    }

    /**
     * 读取文件内容.
     *
     * @param hApplication [IN]文件所在的应用句柄
     * @param szFileName   [IN]文件名
     * @param ulOffset     [IN]文件读取偏移位置
     * @param ulSize       [IN]要读取的长度
     * @return [OUT]返回数据的缓冲区
     * @throws SKFException the skf exception
     */
    public byte[] SKF_ReadFile(HAPPLICATION	hApplication, String szFileName, long ulOffset, long ulSize) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulOutLen = new long[1];

        ret = SkfNativeFunc.SKF_ReadFile(hApplication, szFileName, ulOffset, ulSize, null, pulOutLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ReadFile Failed.", ret);
        }

        if(pulOutLen[0] <= 0){
            return null;
        }

        byte[] pbOutData = new byte[(int)pulOutLen[0]];
        ret = SkfNativeFunc.SKF_ReadFile(hApplication, szFileName, ulOffset, ulSize, pbOutData, pulOutLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ReadFile Failed.", ret);
        }

        return pbOutData;
    }

    /**
     * 写数据到文件中.
     *
     * @param hApplication [IN]文件所在的应用句柄
     * @param szFileName   [IN]文件名
     * @param ulOffset     [IN]写入文件的偏移量
     * @param pbData       [IN]写入数据缓冲区
     * @throws SKFException the skf exception
     */
    public void SKF_WriteFile(HAPPLICATION hApplication, String szFileName, long ulOffset, byte[] pbData) throws SKFException{
        long ret = SkfNativeFunc.SKF_WriteFile(hApplication, szFileName, ulOffset, pbData);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_WriteFile Failed.", ret);
        }
    }

    /************************************************************************/
    /*  5. 容器管理				                                            */
    /*	 SKF_CreateContainer												*/
    /*	 SKF_DeleteContainer												*/
    /*	 SKF_OpenContainer													*/
    /*	 SKF_CloseContainer													*/
    /*	 SKF_EnumContainer													*/
    /*	 SKF_GetContainerType												*/
    /*	 SKF_ImportCertificate												*/
    /*	 SKF_ExportCertificate												*/

    /**
     * 在应用下建立指定名称的容器并返回容器句柄.
     *
     * @param hApplication    [IN]应用句柄
     * @param szContainerName [IN]ASCII字符串，表示所建立容器的名称，容器名称的最大长度不能超过64字节
     * @param phContainer     [OUT]返回所建立容器的容器句柄
     * @throws SKFException the skf exception
     */
    public void SKF_CreateContainer(HAPPLICATION hApplication, String szContainerName, HCONTAINER phContainer) throws SKFException{
        long ret = SkfNativeFunc.SKF_CreateContainer(hApplication, szContainerName, phContainer);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_CreateContainer Failed.", ret);
        }
    }

    /**
     * 在应用下删除指定名称的容器并释放容器相关的资源.
     *
     * @param hApplication    [IN]应用句柄
     * @param szContainerName [IN]指向删除容器的名称
     * @throws SKFException the skf exception
     */
    public void SKF_DeleteContainer(HAPPLICATION hApplication, String szContainerName) throws SKFException{
        long ret = SkfNativeFunc.SKF_DeleteContainer(hApplication, szContainerName);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DeleteContainer Failed.", ret);
        }
    }

    /**
     * 获取容器句柄.
     *
     * @param hApplication    [IN]应用句柄
     * @param szContainerName [IN]容器名称
     * @param phContainer     [OUT]返回所打开容器的句柄
     * @throws SKFException the skf exception
     */
    public void SKF_OpenContainer(HAPPLICATION hApplication, String szContainerName, HCONTAINER phContainer) throws SKFException{
        long ret = SkfNativeFunc.SKF_OpenContainer(hApplication, szContainerName, phContainer);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_OpenContainer Failed.", ret);
        }
    }

    /**
     * 关闭容器句柄，并释放容器句柄相关资源.
     *
     * @param hContainer [IN]容器句柄
     * @throws SKFException the skf exception
     */
    public void SKF_CloseContainer(HCONTAINER hContainer) throws SKFException{
        long ret = SkfNativeFunc.SKF_CloseContainer(hContainer);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_CloseContainer Failed.", ret);
        }
    }

    /**
     * 枚举应用下的所有容器并返回容器名称列表.
     *
     * @param hApplication    [IN]应用句柄
     * @param szContainerName [OUT]指向容器名称列表缓冲区，如果此参数为NULL时，pulSize表示返回数据所需要缓冲区的长度，如果此参数不为NULL时，返回容器名称列表，每个容器名以单个'\0'为结束，列表以双'\0'结束
     * @throws SKFException the skf exception
     */
    public void SKF_EnumContainer(HAPPLICATION hApplication, List<String> szContainerName) throws SKFException{
        long ret = SkfNativeFunc.SKF_EnumContainer(hApplication, szContainerName);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_EnumContainer Failed.", ret);
        }
    }

    /**
     * 获取容器的类型.
     *
     * @param hContainer [IN]容器句柄
     * @return [OUT] 获得的容器类型。指针指向的值为0表示未定、尚未分配类型或者为空容器，为1表示为RSA容器，为2表示为SM2容器
     * @throws SKFException the skf exception
     */
    public long SKF_GetContainerType(HCONTAINER hContainer) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulContainerType = new long[1];

        ret = SkfNativeFunc.SKF_GetContainerType(hContainer, pulContainerType);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_GetContainerType Failed.", ret);
        }

        return pulContainerType[0];
    }

    /**
     * 往容器中导入签名证书或者加密证书.
     *
     * @param hContainer [IN] 容器句柄
     * @param bSignFlag  [IN] TRUE表示导入签名证书，FALSE表示导入加密证书
     * @param pbCert     [IN] 指向证书数据的缓冲区
     * @throws SKFException the skf exception
     */
    public void SKF_ImportCertificate(HCONTAINER hContainer, boolean bSignFlag, byte[] pbCert) throws SKFException{
        long ret = SkfNativeFunc.SKF_ImportCertificate(hContainer, bSignFlag, pbCert);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ImportCertificate Failed.", ret);
        }
    }

    /**
     * 导出容器中的签名证书或者加密证书.
     *
     * @param hContainer [IN] 容器句柄
     * @param bSignFlag  [IN] TRUE表示导出签名证书，FALSE表示导出加密证书
     * @return [OUT] 指向证书数据的缓冲区
     * @throws SKFException the skf exception
     */
    public byte[] SKF_ExportCertificate(HCONTAINER hContainer, boolean bSignFlag) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulCertLen = new long[1];

        ret = SkfNativeFunc.SKF_ExportCertificate(hContainer, bSignFlag, null, pulCertLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ExportCertificate Failed.", ret);
        }

        if(pulCertLen[0] <= 0){
            return null;
        }

        byte[] pbCert = new byte[(int)pulCertLen[0]];
        ret = SkfNativeFunc.SKF_ExportCertificate(hContainer, bSignFlag, pbCert, pulCertLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ExportCertificate Failed.", ret);
        }

        return pbCert;
    }

/************************************************************************/
    /*  6. 密码服务				                                            */
    /*	 SKF_GenRandom														*/
    /*	 SKF_GenExtRSAKey													*/
    /*	 SKF_GenRSAKeyPair													*/
    /*	 SKF_ImportRSAKeyPair												*/
    /*	 SKF_RSASignData													*/
    /*	 SKF_RSAVerify														*/
    /*	 SKF_RSAExportSessionKey											*/
    /*	 SKF_ExtRSAPubKeyOperation											*/
    /*	 SKF_ExtRSAPriKeyOperation											*/
    /*	 SKF_GenECCKeyPair													*/
    /*	 SKF_ImportECCKeyPair												*/
    /*	 SKF_ECCSignData													*/
    /*	 SKF_ECCVerify														*/
    /*	 SKF_ECCExportSessionKey											*/
    /*	 SKF_ExtECCEncrypt													*/
    /*	 SKF_ExtECCDecrypt													*/
    /*	 SKF_ExtECCSign														*/
    /*	 SKF_ExtECCVerify													*/
    /*	 SKF_GenerateAgreementDataWithECC									*/
    /*	 SKF_GenerateAgreementDataAndKeyWithECC								*/
    /*	 SKF_GenerateKeyWithECC												*/
    /*	 SKF_ExportPublicKey												*/
    /*	 SKF_ImportSessionKey												*/
    /*	 SKF_SetSymmKey														*/
    /*	 SKF_EncryptInit													*/
    /*	 SKF_Encrypt														*/
    /*	 SKF_EncryptUpdate													*/
    /*	 SKF_EncryptFinal													*/
    /*	 SKF_DecryptInit													*/
    /*	 SKF_Decrypt														*/
    /*	 SKF_DecryptUpdate													*/
    /*	 SKF_DecryptFinal													*/
    /*	 SKF_DigestInit														*/
    /*	 SKF_Digest															*/
    /*	 SKF_DigestUpdate													*/
    /*	 SKF_DigestFinal													*/
    /*	 SKF_MACInit														*/
    /*	 SKF_MAC															*/
    /*	 SKF_MACUpdate														*/
    /*	 SKF_MACFinal														*/
    /*	 SKF_CloseHandle													*/

    /**
     * 产生指定长度的随机数.
     *
     * @param hDev        [IN] 设备句柄
     * @param ulRandomLen [IN] 随机数长度
     * @return [OUT] 返回的随机数
     * @throws SKFException the skf exception
     */
    public byte[] SKF_GenRandom(DEVHANDLE hDev,long ulRandomLen) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        byte[] pbRandom = new byte[(int)ulRandomLen];

        ret = SkfNativeFunc.SKF_GenRandom(hDev, pbRandom, ulRandomLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_GenRandom Failed.", ret);
        }

        return pbRandom;
    }

    /**
     * 由设备生成RSA密钥对并明文输出.
     *
     * @param hDev      [IN] 设备句柄
     * @param ulBitsLen [IN] 密钥模长
     * @return [OUT] 返回的私钥数据结构
     * @throws SKFException the skf exception
     */
    public RSAPRIVATEKEYBLOB SKF_GenExtRSAKey(DEVHANDLE hDev, long ulBitsLen) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        RSAPRIVATEKEYBLOB pBlob = new RSAPRIVATEKEYBLOB();

        ret = SkfNativeFunc.SKF_GenExtRSAKey(hDev, ulBitsLen, pBlob);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_GenExtRSAKey Failed.", ret);
        }

        return pBlob;
    }

    /**
     * 生成RSA签名密钥对并输出签名公钥.
     *
     * @param hContainer [IN] 容器句柄
     * @param ulBitsLen  [IN] 密钥模长
     * @return [OUT] 返回的RSA公钥数据结构
     * @throws SKFException the skf exception
     */
    public RSAPUBLICKEYBLOB SKF_GenRSAKeyPair(HCONTAINER hContainer, long ulBitsLen) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        RSAPUBLICKEYBLOB pBlob = new RSAPUBLICKEYBLOB();

        ret = SkfNativeFunc.SKF_GenRSAKeyPair(hContainer, ulBitsLen, pBlob);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_GenRSAKeyPair Failed.", ret);
        }

        return pBlob;
    }

    /**
     * 导入RSA加密公私钥对.
     *
     * @param hContainer      [IN] 容器句柄
     * @param ulSymAlgId      [IN] 对称算法密钥标识
     * @param pbWrappedKey    [IN] 使用该容器内签名公钥保护的对称算法密钥
     * @param pbEncryptedData [IN] 对称算法密钥保护的RSA加密私钥。私钥的格式遵循PKCS #1 v2.1: RSA Cryptography Standard中的私钥格式定义
     * @throws SKFException the skf exception
     */
    public void SKF_ImportRSAKeyPair(HCONTAINER hContainer, long ulSymAlgId, byte[] pbWrappedKey, byte[] pbEncryptedData) throws SKFException{
        long ret = SkfNativeFunc.SKF_ImportRSAKeyPair(hContainer, ulSymAlgId, pbWrappedKey, pbEncryptedData);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ImportRSAKeyPair Failed.", ret);
        }
    }

    /**
     * 使用hContainer指定容器的签名私钥，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名的长度.
     *
     * @param hContainer [IN] 用来签名的私钥所在容器句柄
     * @param pbData     [IN] 被签名的数据
     * @return [OUT] 存放签名结果的缓冲区指针，如果值为NULL，用于取得签名结果长度
     * @throws SKFException the skf exception
     */
    public byte[] SKF_RSASignData(HANDLE hContainer, byte[] pbData) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulSigLen = new long[1];

        ret = SkfNativeFunc.SKF_RSASignData(hContainer, pbData, null, pulSigLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_RSASignData Failed.", ret);
        }

        if(pulSigLen[0] <= 0){
            return null;
        }

        byte[] pbSignature = new byte[(int)pulSigLen[0]];
        ret = SkfNativeFunc.SKF_RSASignData(hContainer, pbData, pbSignature, pulSigLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_RSASignData Failed.", ret);
        }

        return pbSignature;
    }

    /**
     * 验证RSA签名。用pRSAPubKeyBlob内的公钥值对待验签数据进行验签.
     *
     * @param hDev           [IN] 连接设备时返回的设备句柄
     * @param pRSAPubKeyBlob [IN] RSA公钥数据结构
     * @param pbData         [IN] 待验证签名的数据
     * @param pbSignature    [IN] 待验证的签名值
     * @throws SKFException the skf exception
     */
    public void SKF_RSAVerify(DEVHANDLE hDev, RSAPUBLICKEYBLOB pRSAPubKeyBlob, byte[] pbData, byte[] pbSignature) throws SKFException{
        long ret = SkfNativeFunc.SKF_RSAVerify(hDev, pRSAPubKeyBlob, pbData, pbSignature);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_RSAVerify Failed.", ret);
        }
    }

    /**
     * 生成会话密钥并用外部公钥加密输出.
     *
     * @param hContainer   [IN] 容器句柄
     * @param ulAlgID      [IN] 会话密钥的算法标识
     * @param pPubKey      [IN] 加密会话密钥的RSA公钥数据结构
     * @param phSessionKey [OUT] 导出的密钥句柄
     * @return [OUT] 导出的加密会话密钥密文，按照PKCS#1v1.5的要求封装
     * @throws SKFException the skf exception
     */
    public byte[] SKF_RSAExportSessionKey(HCONTAINER hContainer, long ulAlgID, RSAPUBLICKEYBLOB pPubKey,HANDLE phSessionKey) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulDataLen = new long[1];

        ret = SkfNativeFunc.SKF_RSAExportSessionKey(hContainer, ulAlgID, pPubKey, null, pulDataLen, phSessionKey);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_RSAExportSessionKey Failed.", ret);
        }

        if(pulDataLen[0] <= 0){
            return null;
        }

        byte[] pbData = new byte[(int)pulDataLen[0]];
        ret = SkfNativeFunc.SKF_RSAExportSessionKey(hContainer, ulAlgID, pPubKey, pbData, pulDataLen, phSessionKey);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_RSAExportSessionKey Failed.", ret);
        }

        return pbData;
    }

    /**
     * 使用外部传入的RSA公钥对输入数据做公钥运算并输出结果.
     *
     * @param hDev           [IN] 设备句柄
     * @param pRSAPubKeyBlob [IN] RSA公钥数据结构
     * @param pbInput        [IN] 指向待运算的原始数据缓冲区
     * @return [OUT] 指向RSA公钥运算结果缓冲区，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
     * @throws SKFException the skf exception
     */
    public byte[] SKF_ExtRSAPubKeyOperation(DEVHANDLE hDev, RSAPUBLICKEYBLOB pRSAPubKeyBlob, byte[] pbInput) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulOutputLen = new long[1];

        ret = SkfNativeFunc.SKF_ExtRSAPubKeyOperation(hDev, pRSAPubKeyBlob, pbInput, null, pulOutputLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ExtRSAPubKeyOperation Failed.", ret);
        }

        if(pulOutputLen[0] <= 0){
            return null;
        }

        byte[] pbOutput = new byte[(int)pulOutputLen[0]];
        ret = SkfNativeFunc.SKF_ExtRSAPubKeyOperation(hDev, pRSAPubKeyBlob, pbInput, pbOutput, pulOutputLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ExtRSAPubKeyOperation Failed.", ret);
        }

        return pbOutput;
    }

    /**
     * 直接使用外部传入的RSA私钥对输入数据做私钥运算并输出结果.
     *
     * @param hDev           [IN] 设备句柄
     * @param pRSAPriKeyBlob [IN] RSA私钥数据结构
     * @param pbInput        [IN] 指向待运算数据缓冲区
     * @return [OUT] RSA私钥运算结果，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
     * @throws SKFException the skf exception
     */
    public byte[] SKF_ExtRSAPriKeyOperation(DEVHANDLE hDev, RSAPRIVATEKEYBLOB pRSAPriKeyBlob, byte[] pbInput) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulOutputLen = new long[1];

        ret = SkfNativeFunc.SKF_ExtRSAPriKeyOperation(hDev, pRSAPriKeyBlob, pbInput, null, pulOutputLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ExtRSAPriKeyOperation Failed.", ret);
        }

        if(pulOutputLen[0] <= 0){
            return null;
        }

        byte[] pbOutput = new byte[(int)pulOutputLen[0]];
        ret = SkfNativeFunc.SKF_ExtRSAPriKeyOperation(hDev, pRSAPriKeyBlob, pbInput, pbOutput, pulOutputLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ExtRSAPriKeyOperation Failed.", ret);
        }

        return pbOutput;
    }

    /**
     * 生成ECC签名密钥对并输出签名公钥.
     *
     * @param hContainer [IN] 容器句柄
     * @param ulAlgId    [IN] 算法标识，只支持 SGD_SM2_1 算法
     * @return [OUT] 返回ECC公钥内容(X+Y)
     * @throws SKFException the skf exception
     */
    public byte[] SKF_GenECCKeyPair(HCONTAINER hContainer, long ulAlgId) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        ECCPUBLICKEYBLOB pBlob = new ECCPUBLICKEYBLOB();

        ret = SkfNativeFunc.SKF_GenECCKeyPair(hContainer, ulAlgId, pBlob);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_GenECCKeyPair Failed.", ret);
        }

        /* compose byte[] x+y */
        byte[] pub = new byte[64];
        System.arraycopy(pBlob.getXCoordinate(),32,pub,0,32);
        System.arraycopy(pBlob.getYCoordinate(),32,pub,32,32);

        return pub;
    }

    /**
     * 导入ECC公私钥对.
     *
     * @param hContainer        [IN] 容器句柄
     * @param cbEncryptedPriKey [IN] 加密密钥对私钥的密文
     * @param pECCPubKey [IN] 加密密钥对的公钥
     * @param ecccipherblob [IN] 用保护公钥加密的对称密钥密文
     * @throws SKFException the skf exception
     */
    public void SKF_ImportECCKeyPair(HCONTAINER hContainer, byte[] cbEncryptedPriKey, byte [] pECCPubKey, ECCCIPHERBLOB ecccipherblob) throws SKFException{
        long ret = SkfDefines.SAR_INVALIDPARAMERR;

        if(cbEncryptedPriKey == null || cbEncryptedPriKey.length != 32 || pECCPubKey == null || pECCPubKey.length != 64 ||
        null == ecccipherblob || ecccipherblob.getCipherLen() == 0){
            throw new SKFException("SKF_ImportECCKeyPair Failed.", ret);
        }
        /* compose private key */
        byte [] pri = new byte[64];
        System.arraycopy(cbEncryptedPriKey,0,pri,32,32);

        /* compose public key blob */
        ECCPUBLICKEYBLOB ECCPubKeyBlob = new ECCPUBLICKEYBLOB();
        ECCPubKeyBlob.setBitLen(32 * 8);
        byte [] pub = new byte[64];
        System.arraycopy(pECCPubKey,0,pub,32,32);
        ECCPubKeyBlob.setXCoordinate(pub);
        System.arraycopy(pECCPubKey,32,pub,32,32);
        ECCPubKeyBlob.setYCoordinate(pub);

        /* compose ciphertext blob */
        /*ECCCIPHERBLOB ecccipherblob = new ECCCIPHERBLOB();
        byte[] x = new byte[64];
        byte[] y = new byte[64];

        Arrays.fill(x,(byte)0);
        Arrays.fill(y,(byte)0);

        System.arraycopy(xy,0,x,32,32);
        System.arraycopy(xy,32,y,32,32);

        ecccipherblob.setXCoordinate(x);
        ecccipherblob.setYCoordinate(y);
        ecccipherblob.setCipherLen(pbCipherText.length);

        byte[] cipherText = new byte[pbCipherText.length];
        Arrays.fill(cipherText,(byte)0);
        System.arraycopy(pbCipherText,0,cipherText,0,pbCipherText.length);
        ecccipherblob.setCipher(cipherText);*/

        /* compose env blob */
        ENVELOPEDKEYBLOB pEnvelopedKeyBlob = new ENVELOPEDKEYBLOB();
        pEnvelopedKeyBlob.setVersion(1);
        pEnvelopedKeyBlob.setUlSymmAlgID(SkfDefines.SGD_SMS4_ECB);
        pEnvelopedKeyBlob.setUlBits(16 * 8);

        pEnvelopedKeyBlob.setCbEncryptedPriKey(pri);
        pEnvelopedKeyBlob.setPubKey(ECCPubKeyBlob);
        pEnvelopedKeyBlob.setECCCipherBlob(ecccipherblob);

        ret = SkfNativeFunc.SKF_ImportECCKeyPair(hContainer, pEnvelopedKeyBlob);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ImportECCKeyPair Failed.", ret);
        }
    }

    /**
     * ECC数字签名。采用ECC算法和指定私钥hKey，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名值的长度.
     *
     * @param hContainer [IN] 用来签名的私钥所在容器句柄
     * @param pbData     [IN] 被签名的数据
     * @return [OUT] 签名值(R+S)
     * @throws SKFException the skf exception
     */
    public byte[] SKF_ECCSignData(HCONTAINER hContainer, byte[] pbData) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        ECCSIGNATUREBLOB pSignature = new ECCSIGNATUREBLOB();

        ret = SkfNativeFunc.SKF_ECCSignData(hContainer, pbData, pSignature);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ECCSignData Failed.", ret);
        }

        /* compose byte[] r+s */
        byte[] sig = new byte[64];
        System.arraycopy(pSignature.getR(),32,sig,0,32);
        System.arraycopy(pSignature.getS(),32,sig,32,32);

        return sig;
    }

    /**
     * 用ECC公钥对数据进行验签.
     *
     * @param hDev           [IN] 设备句柄
     * @param pECCPubKey [IN] ECC公钥数据
     * @param pbData         [IN] 待验证签名的数据
     * @param pSignature     [IN] 待验证的签名值
     * @throws SKFException the skf exception
     */
    public void SKF_ECCVerify(DEVHANDLE hDev, byte[] pECCPubKey, byte[] pbData, byte[] pSignature) throws SKFException{
        long ret = SkfDefines.SAR_OK;

        /* compose public key blob */
        ECCPUBLICKEYBLOB pECCPubKeyBlob = new ECCPUBLICKEYBLOB();
        pECCPubKeyBlob.setBitLen(32 * 8);
        byte [] pub = new byte[64];
        System.arraycopy(pECCPubKey,0,pub,32,32);
        pECCPubKeyBlob.setXCoordinate(pub);
        System.arraycopy(pECCPubKey,32,pub,32,32);
        pECCPubKeyBlob.setYCoordinate(pub);

        /* compose signature blob */
        ECCSIGNATUREBLOB pSignatureBlob = new ECCSIGNATUREBLOB();
        byte [] sig = new byte[64];
        System.arraycopy(pSignature,0,sig,32,32);
        pSignatureBlob.setR(sig);
        System.arraycopy(pSignature,32,sig,32,32);
        pSignatureBlob.setS(sig);

        ret =SkfNativeFunc.SKF_ECCVerify(hDev, pECCPubKeyBlob, pbData, pSignatureBlob);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ECCVerify Failed.", ret);
        }
    }

    /**
     * 生成会话密钥并用外部公钥加密输出.
     *
     * @param hContainer   [IN] 容器句柄
     * @param ulAlgID      [IN] 会话密钥的算法标识
     * @param pPubKey      [IN] 外部输入的公钥
     * @param phSessionKey [OUT] 会话密钥句柄
     * @return [OUT] 导出的加密会话密钥密文
     * @throws SKFException the skf exception
     */
    public ECCCIPHERBLOB SKF_ECCExportSessionKey(HCONTAINER hContainer, long ulAlgID, byte[] pPubKey, HANDLE phSessionKey) throws SKFException{
        long ret = SkfDefines.SAR_INVALIDPARAMERR;

        ECCCIPHERBLOB pData = new ECCCIPHERBLOB();
        /* compose public key blob */
        ECCPUBLICKEYBLOB pPubKeyBlob = new ECCPUBLICKEYBLOB();
        pPubKeyBlob.setBitLen(32 * 8);
        byte [] pub = new byte[64];
        System.arraycopy(pPubKey,0,pub,32,32);
        pPubKeyBlob.setXCoordinate(pub);
        System.arraycopy(pPubKey,32,pub,32,32);
        pPubKeyBlob.setYCoordinate(pub);

        ret = SkfNativeFunc.SKF_ECCExportSessionKey(hContainer, ulAlgID, pPubKeyBlob, pData, phSessionKey);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ECCExportSessionKey Failed.", ret);
        }

        /* compose ciphertext */
        /*byte [] ciphertext = new byte[32+32+32+(int)pData.getCipherLen()];
        System.arraycopy(pData.getXCoordinate(),32,ciphertext,0,32);
        System.arraycopy(pData.getYCoordinate(),32,ciphertext,32,32);
        System.arraycopy(pData.getHASH(),0,ciphertext,32+32,32);
        System.arraycopy(pData.getCipher(),0,ciphertext,32+32+32,(int)pData.getCipherLen());*/

        return pData;
    }

    /**
     * 使用外部传入的ECC公钥对输入数据做加密运算并输出结果.
     *
     * @param hDev           [IN] 设备句柄
     * @param pECCPubKey [IN] ECC公钥数据
     * @param pbPlainText    [IN] 待加密的明文数据
     * @return [OUT] 指向密文数据缓冲区，如果该参数为NULL，则由pulCipherTextLen返回密文数据的实际长度
     * @throws SKFException the skf exception
     */
    public ECCCIPHERBLOB SKF_ExtECCEncrypt(DEVHANDLE hDev, byte[] pECCPubKey, byte[] pbPlainText) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        ECCCIPHERBLOB pbCipherText = new ECCCIPHERBLOB();

        /* compose public key blob */
        ECCPUBLICKEYBLOB pECCPubKeyBlob = new ECCPUBLICKEYBLOB();
        pECCPubKeyBlob.setBitLen(32 * 8);
        byte [] pub = new byte[64];
        System.arraycopy(pECCPubKey,0,pub,32,32);
        pECCPubKeyBlob.setXCoordinate(pub);
        System.arraycopy(pECCPubKey,32,pub,32,32);
        pECCPubKeyBlob.setYCoordinate(pub);

        ret = SkfNativeFunc.SKF_ExtECCEncrypt(hDev, pECCPubKeyBlob, pbPlainText, pbCipherText);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ExtECCEncrypt Failed.", ret);
        }

        /* compose ciphertext *//*
        byte [] ciphertext = new byte[32+32+32+(int)pbCipherText.getCipherLen()];
        System.arraycopy(pbCipherText.getXCoordinate(),32,ciphertext,0,32);
        System.arraycopy(pbCipherText.getYCoordinate(),32,ciphertext,32,32);
        System.arraycopy(pbCipherText.getHASH(),0,ciphertext,32+32,32);
        System.arraycopy(pbCipherText.getCipher(),0,ciphertext,32+32+32,(int)pbCipherText.getCipherLen());*/

        return pbCipherText;
    }

    /**
     * 使用外部传入的ECC私钥对输入数据做解密运算并输出结果.
     *
     * @param hDev           [IN] 设备句柄
     * @param pECCPriKey [IN] ECC私钥数据
     * @param ecccipherblob   [IN] 待解密的密文数据
     * @return [OUT] 返回明文数据，如果该参数为NULL，则由pulPlainTextLen返回明文数据的实际长度
     * @throws SKFException the skf exception
     */
    public byte[] SKF_ExtECCDecrypt(DEVHANDLE hDev, byte[] pECCPriKey, ECCCIPHERBLOB ecccipherblob) throws SKFException{
        long ret = SkfDefines.SAR_INVALIDPARAMERR;
        if(pECCPriKey == null || pECCPriKey.length != 32 ||
                ecccipherblob == null || ecccipherblob.getCipherLen() == 0){
            throw new SKFException("SKF_ImportECCKeyPair Failed.", ret);
        }

        long[] pulOutputLen = new long[1];
        /* compose private key blob */
        ECCPRIVATEKEYBLOB pECCPriKeyBlob = new ECCPRIVATEKEYBLOB();
        pECCPriKeyBlob.setBitLen(32 * 8);
        byte [] pri = new byte[64];
        System.arraycopy(pECCPriKey,0,pri,32,32);
        pECCPriKeyBlob.setPrivateKey(pri);

        /* compose ciphertext blob */
        /*ECCCIPHERBLOB ecccipherblob = new ECCCIPHERBLOB();
        byte[] x = new byte[64];
        byte[] y = new byte[64];

        Arrays.fill(x,(byte)0);
        Arrays.fill(y,(byte)0);

        System.arraycopy(xy,0,x,32,32);
        System.arraycopy(xy,32,y,32,32);

        ecccipherblob.setXCoordinate(x);
        ecccipherblob.setYCoordinate(y);
        ecccipherblob.setCipherLen(pbCipherText.length);

        byte[] cipherText = new byte[pbCipherText.length];
        Arrays.fill(cipherText,(byte)0);
        System.arraycopy(pbCipherText,0,cipherText,0,pbCipherText.length);
        ecccipherblob.setCipher(cipherText);*/

        /*byte [] xy = new byte[64];
        System.arraycopy(pbCipherText, 0, xy, 32, 32);
        pbCipherTextBlob.setXCoordinate(xy);
        System.arraycopy(pbCipherText, 32, xy, 32, 32);
        pbCipherTextBlob.setYCoordinate(xy);
        byte [] hash = new byte[32];
        System.arraycopy(pbCipherText, 32+32, hash, 0, 32);
        pbCipherTextBlob.setHASH(hash);
        byte [] cipher = new byte [(int)pbCipherTextBlob.getCipherLen()];
        System.arraycopy(pbCipherText, 32+32+32, cipher, 0, (int)pbCipherTextBlob.getCipherLen());
        pbCipherTextBlob.setCipher(cipher);*/

        ret = SkfNativeFunc.SKF_ExtECCDecrypt(hDev, pECCPriKeyBlob, ecccipherblob, null, pulOutputLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ExtECCDecrypt Failed.", ret);
        }

        if(pulOutputLen[0] <= 0){
            return null;
        }

        byte[] pbPlainText = new byte[(int)pulOutputLen[0]];
        ret = SkfNativeFunc.SKF_ExtECCDecrypt(hDev, pECCPriKeyBlob, ecccipherblob, pbPlainText, pulOutputLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ExtECCDecrypt Failed.", ret);
        }

        return pbPlainText;
    }

    /**
     * 使用外部传入的ECC私钥对输入数据做签名运算并输出结果.
     *
     * @param hDev           [IN] 设备句柄
     * @param pECCPriKey [IN] ECC私钥数据
     * @param pbData         [IN] 待签名数据
     * @return [OUT] 签名值(R+S)
     * @throws SKFException the skf exception
     */
    public byte[] SKF_ExtECCSign(DEVHANDLE hDev, byte[] pECCPriKey, byte[] pbData) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        ECCSIGNATUREBLOB pSignature = new ECCSIGNATUREBLOB();

        /* compose private key blob */
        ECCPRIVATEKEYBLOB pECCPriKeyBlob = new ECCPRIVATEKEYBLOB();
        pECCPriKeyBlob.setBitLen(32 * 8);
        byte [] pri = new byte[64];
        System.arraycopy(pECCPriKey,0,pri,32,32);
        pECCPriKeyBlob.setPrivateKey(pri);

        ret = SkfNativeFunc.SKF_ExtECCSign(hDev, pECCPriKeyBlob, pbData, pSignature);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ExtECCSign Failed.", ret);
        }

        /* compose byte[] r+s */
        byte[] sig = new byte[64];
        System.arraycopy(pSignature.getR(),32,sig,0,32);
        System.arraycopy(pSignature.getS(),32,sig,32,32);

        return sig;
    }

    /**
     * 外部使用传入的ECC公钥做签名验证.
     *
     * @param hDev           [IN] 设备句柄
     * @param pECCPubKey [IN] ECC公钥数据
     * @param pbData         [IN] 待验证数据
     * @param pSignature     [IN] 签名值
     * @throws SKFException the skf exception
     */
    public void SKF_ExtECCVerify(DEVHANDLE hDev, byte[] pECCPubKey, byte[] pbData, byte[] pSignature) throws SKFException{
        long ret = SkfDefines.SAR_OK;

        /* compose public key blob */
        ECCPUBLICKEYBLOB pECCPubKeyBlob = new ECCPUBLICKEYBLOB();
        pECCPubKeyBlob.setBitLen(32 * 8);
        byte [] pub = new byte[64];
        System.arraycopy(pECCPubKey,0,pub,32,32);
        pECCPubKeyBlob.setXCoordinate(pub);
        System.arraycopy(pECCPubKey,32,pub,32,32);
        pECCPubKeyBlob.setYCoordinate(pub);

        /* compose signature blob */
        ECCSIGNATUREBLOB pSignatureBlob = new ECCSIGNATUREBLOB();
        byte [] sig = new byte[64];
        System.arraycopy(pSignature,0,sig,32,32);
        pSignatureBlob.setR(sig);
        System.arraycopy(pSignature,32,sig,32,32);
        pSignatureBlob.setS(sig);

        ret = SkfNativeFunc.SKF_ExtECCVerify(hDev, pECCPubKeyBlob, pbData, pSignatureBlob);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ExtECCVerify Failed.", ret);
        }
    }

    /**
     * 使用ECC密钥协商算法，为计算会话密钥而产生协商参数，返回临时ECC密钥对的公钥及协商句柄.
     *
     * @param hContainer        [IN] 容器句柄
     * @param ulAlgId           [IN] 会话密钥算法标识
     * @param pbID              [IN] 发起方的ID
     * @param phAgreementHandle [OUT] 返回的密钥协商句柄
     * @return [OUT] 发起方临时ECC公钥
     * @throws SKFException the skf exception
     */
    public ECCPUBLICKEYBLOB SKF_GenerateAgreementDataWithECC(HCONTAINER hContainer, long ulAlgId, byte[] pbID, HANDLE phAgreementHandle) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        ECCPUBLICKEYBLOB pTempECCPubKeyBlob = new ECCPUBLICKEYBLOB();

        ret = SkfNativeFunc.SKF_GenerateAgreementDataWithECC(hContainer, ulAlgId, pTempECCPubKeyBlob, pbID, phAgreementHandle);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_GenerateAgreementDataWithECC Failed.", ret);
        }

        return pTempECCPubKeyBlob;
    }

    /**
     * 使用ECC密钥协商算法，产生协商参数并计算会话密钥，输出临时ECC密钥对公钥，并返回产生的密钥句柄.
     *
     * @param hContainer                [IN] 容器句柄
     * @param ulAlgId                   [IN] 会话密钥算法标识
     * @param pSponsorECCPubKeyBlob     [IN] 发起方的ECC公钥
     * @param pSponsorTempECCPubKeyBlob [IN] 发起方的临时ECC公钥
     * @param pbID                      [IN] 响应方的ID
     * @param pbSponsorID               [IN] 发起方的ID
     * @param phKeyHandle               [OUT] 返回的对称算法密钥句柄
     * @return [OUT] 响应方的临时ECC公钥
     * @throws SKFException the skf exception
     */
    public ECCPUBLICKEYBLOB SKF_GenerateAgreementDataAndKeyWithECC(HANDLE hContainer, long ulAlgId, ECCPUBLICKEYBLOB pSponsorECCPubKeyBlob, ECCPUBLICKEYBLOB pSponsorTempECCPubKeyBlob, byte[] pbID, byte[] pbSponsorID, HANDLE phKeyHandle) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        ECCPUBLICKEYBLOB pTempECCPubKeyBlob = new ECCPUBLICKEYBLOB();

        ret = SkfNativeFunc.SKF_GenerateAgreementDataAndKeyWithECC(hContainer, ulAlgId, pSponsorECCPubKeyBlob, pSponsorTempECCPubKeyBlob, pTempECCPubKeyBlob, pbID, pbSponsorID, phKeyHandle);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_GenerateAgreementDataAndKeyWithECC Failed.", ret);
        }

        return pTempECCPubKeyBlob;
    }

    /**
     * 使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥，同时返回会话密钥句柄.
     *
     * @param hAgreementHandle   [IN] 密钥协商句柄
     * @param pECCPubKeyBlob     [IN] 外部输入的响应方ECC公钥
     * @param pTempECCPubKeyBlob [IN] 外部输入的响应方临时ECC公钥
     * @param pbID               [IN] 响应方的ID
     * @param phKeyHandle        [OUT] 返回的密钥句柄
     * @throws SKFException the skf exception
     */
    public void SKF_GenerateKeyWithECC(HANDLE hAgreementHandle, ECCPUBLICKEYBLOB pECCPubKeyBlob, ECCPUBLICKEYBLOB pTempECCPubKeyBlob, byte[] pbID, HANDLE phKeyHandle) throws SKFException{
        long ret = SkfNativeFunc.SKF_GenerateKeyWithECC(hAgreementHandle, pECCPubKeyBlob, pTempECCPubKeyBlob, pbID, phKeyHandle);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_GenerateKeyWithECC Failed.", ret);
        }
    }

    /**
     * 导出容器中的签名公钥或者加密公钥.
     *
     * @param hContainer [IN] 容器句柄
     * @param bSignFlag  [IN] TRUE表示导出签名公钥，FALSE表示导出加密公钥
     * @return [OUT] 指向RSA公钥结构（RSAPUBLICKEYBLOB）或者ECC公钥结构（ECCPUBLICKEYBLOB），如果此参数为NULL时，由pulBlobLen返回pbBlob的长度
     * @throws SKFException the skf exception
     */
    public byte[] SKF_ExportPublicKey(HCONTAINER hContainer, boolean bSignFlag) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        /* get container type */
        long[] pulContainerType = new long[1];
        ret = SkfNativeFunc.SKF_GetContainerType(hContainer, pulContainerType);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ExportPublicKey Failed.", ret);
        }
        /* container type unknown */
        if(1 != pulContainerType[0] && 2 != pulContainerType[0]){
            return null;
        }

        if(1 == pulContainerType[0]){
            throw new SKFException("SKF_ExportPublicKey Failed.", SkfDefines.SAR_NOTSUPPORTYETERR);
        }else{
            /* container type:ecc */
            ECCPUBLICKEYBLOB pBlob = new ECCPUBLICKEYBLOB();
            ret = SkfNativeFunc.SKF_ExportPublicKey(hContainer,bSignFlag,pBlob);
            if(ret != SkfDefines.SAR_OK){
                throw new SKFException("SKF_ExportPublicKey Failed.", ret);
            }

            /* compose byte[] x+y */
            byte []pub = new byte[64];
            System.arraycopy(pBlob.getXCoordinate(),32,pub,0,32);
            System.arraycopy(pBlob.getYCoordinate(),32,pub,32,32);

            return pub;
        }
    }

    /**
     * 导入会话密钥.
     *
     * @param hContainer   [IN] 容器句柄
     * @param ulAlgID      [IN] 会话密钥的算法标识
     * @param pbWrapedData [IN] 要导入的数据
     * @param phKey        [OUT] 返回会话密钥句柄
     * @throws SKFException the skf exception
     */
    public void SKF_ImportSessionKey(HCONTAINER hContainer, long ulAlgID, ECCCIPHERBLOB pbWrapedData, HANDLE phKey) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        Object pbWrapedDataObj = null;

        /* get container type */
        long[] pulContainerType = new long[1];
        ret = SkfNativeFunc.SKF_GetContainerType(hContainer, pulContainerType);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ImportSessionKey Failed.", ret);
        }

        /* container type unknown */
        if(1 != pulContainerType[0] && 2 != pulContainerType[0]){
            throw new SKFException("SKF_ImportSessionKey Failed.", SkfDefines.SAR_INVALIDHANDLEERR);
        }

        if(1 == pulContainerType[0]){
            throw new SKFException("SKF_ImportSessionKey Failed.", SkfDefines.SAR_NOTSUPPORTYETERR);
        }else{
            /* container type:ecc */

            /* compose ciphertext blob */
            /*pbWrapedDataObj = new ECCCIPHERBLOB();
            ((ECCCIPHERBLOB) pbWrapedDataObj).setCipherLen(pbWrapedData.length-32-32-32);
            byte [] xy = new byte[64];
            System.arraycopy(pbWrapedData, 0, xy, 32, 32);
            ((ECCCIPHERBLOB) pbWrapedDataObj).setXCoordinate(xy);
            System.arraycopy(pbWrapedData, 32, xy, 32, 32);
            ((ECCCIPHERBLOB) pbWrapedDataObj).setYCoordinate(xy);
            byte [] hash = new byte[32];
            System.arraycopy(pbWrapedData, 32+32, hash, 0, 32);
            ((ECCCIPHERBLOB) pbWrapedDataObj).setHASH(hash);
            byte [] cipher = new byte [(int)((ECCCIPHERBLOB) pbWrapedDataObj).getCipherLen()];
            System.arraycopy(pbWrapedData, 32+32+32, cipher, 0, (int)((ECCCIPHERBLOB) pbWrapedDataObj).getCipherLen());
            ((ECCCIPHERBLOB) pbWrapedDataObj).setCipher(cipher);*/
        }

        ret = SkfNativeFunc.SKF_ImportSessionKey(hContainer, ulAlgID, pbWrapedData, phKey);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_ImportSessionKey Failed.", ret);
        }
    }

    /**
     * 设置明文对称密钥，返回密钥句柄.
     *
     * @param hDev    [IN] 容器句柄
     * @param pbKey   [IN] 指向会话密钥值的缓冲区
     * @param ulAlgID [IN] 会话密钥的算法标识
     * @param phKey   t[OUT] 返回会话密钥句柄
     * @throws SKFException the skf exception
     */
    public void SKF_SetSymmKey(DEVHANDLE hDev, byte[] pbKey, long ulAlgID, HANDLE phKey) throws SKFException{
        long ret = SkfNativeFunc.SKF_SetSymmKey(hDev, pbKey, ulAlgID, phKey);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_SetSymmKey Failed.", ret);
        }
    }

    /**
     * 数据加密初始化。设置数据加密的算法相关参数.
     *
     * @param hKey         [IN] 加密密钥句柄
     * @param iv [IN] 初始化向量
     * @param PaddingType [IN] 填充方式
     * @param FeedBitLen [IN] 反馈值的位长度
     * @throws SKFException the skf exception
     */
    public void SKF_EncryptInit(HANDLE hKey, byte [] iv, long PaddingType, long FeedBitLen) throws SKFException{
        long ret = SkfDefines.SAR_OK;

        /* compose block cipher param */
        BLOCKCIPHERPARAM EncryptParam = new BLOCKCIPHERPARAM();
        if(null != iv){
            EncryptParam.setIVLen(iv.length);
            EncryptParam.setIV(iv);
        }
        EncryptParam.setPaddingType(PaddingType);
        EncryptParam.setFeedBitLen(FeedBitLen);

        ret = SkfNativeFunc.SKF_EncryptInit(hKey, EncryptParam);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_EncryptInit Failed.", ret);
        }
    }

    /**
     * 单一分组数据的加密操作.
     * 用指定加密密钥对指定数据进行加密，被加密的数据只包含一个分组，加密后的密文保存到指定的缓冲区中
     * SKF_Encrypt只对单个分组数据进行加密，在调用 SKF_Encrypt之前，必须调用 SKF_EncryptInit初始化加密操作
     * SKF_Encypt等价于先调用 SKF_EncryptUpdate再调用 SKF_EncryptFinal
     *
     * @param hKey   [IN] 加密密钥句柄
     * @param pbData [IN] 待加密数据
     * @return [OUT] 加密后的数据缓冲区指针
     * @throws SKFException the skf exception
     */
    public byte[] SKF_Encrypt(HANDLE hKey, byte[] pbData) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulEncryptedLen = new long[1];

        ret = SkfNativeFunc.SKF_Encrypt(hKey, pbData, null, pulEncryptedLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_Encrypt Failed.", ret);
        }

        if(pulEncryptedLen[0] <= 0){
            return null;
        }

        byte[] pbEncryptedData = new byte[(int)pulEncryptedLen[0]];
        ret = SkfNativeFunc.SKF_Encrypt(hKey, pbData, pbEncryptedData, pulEncryptedLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_Encrypt Failed.", ret);
        }

        return pbEncryptedData;
    }

    /**
     * 多个分组数据的加密操作.
     * 用指定加密密钥对指定数据进行加密，被加密的数据包含多个分组，加密后的密文保存到指定的缓冲区中
     * SKF_EncryptUpdate对多个分组数据进行加密，在调用 SKF_EncryptUpdate之前，必须调用 SKF_EncryptInit初始化加密操作
     * 在调用 SKF_EncryptUpdate之后，必须调用 SKF_EncryptFinal结束加密操作
     *
     * @param hKey   [IN] 加密密钥句柄
     * @param pbData [IN] 待加密数据
     * @return [OUT] 加密后的数据缓冲区指针
     * @throws SKFException the skf exception
     */
    public byte[] SKF_EncryptUpdate(HANDLE hKey, byte[] pbData) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulEncryptedLen = new long[1];

        ret = SkfNativeFunc.SKF_EncryptUpdate(hKey, pbData, null, pulEncryptedLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_EncryptUpdate Failed.", ret);
        }

        if(pulEncryptedLen[0] <= 0){
            return null;
        }

        byte[] pbEncryptedData = new byte[(int)pulEncryptedLen[0]];
        ret = SkfNativeFunc.SKF_EncryptUpdate(hKey, pbData, pbEncryptedData, pulEncryptedLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_EncryptUpdate Failed.", ret);
        }

        return pbEncryptedData;
    }

    /**
     * 结束多个分组数据的加密，返回剩余加密结果.
     * 先调用 SKF_EncryptInit初始化加密操作
     * 再调用 SKF_EncryptUpdate对多个分组数据进行加密
     * 最后调用 SKF_EncryptFinal结束多个分组数据的加密
     *
     * @param hKey [IN] 加密密钥句柄
     * @return [OUT] 加密结果的缓冲区
     * @throws SKFException the skf exception
     */
    public byte[] SKF_EncryptFinal(HANDLE hKey) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulEncryptedLen = new long[1];

        ret = SkfNativeFunc.SKF_EncryptFinal(hKey, null, pulEncryptedLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_EncryptFinal Failed.", ret);
        }

        if(pulEncryptedLen[0] <= 0){
            return null;
        }

        byte[] pbEncryptedData = new byte[(int)pulEncryptedLen[0]];
        ret = SkfNativeFunc.SKF_EncryptFinal(hKey, pbEncryptedData, pulEncryptedLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_EncryptFinal Failed.", ret);
        }

        return pbEncryptedData;
    }

    /**
     * 数据解密初始化，设置解密密钥相关参数.
     * 调用 SKF_DecryptInit之后，可以调用 SKF_Decrypt对单个分组数据进行解密
     * 也可以多次调用 SKF_DecryptUpdate之后再调用 SKF_DecryptFinal完成对多个分组数据的解密
     *
     * @param hKey         [IN] 解密密钥句柄
     * @param iv [IN] 初始化向量
     * @param PaddingType [IN] 填充方式
     * @param FeedBitLen [IN] 反馈值的位长度
     * @throws SKFException the skf exception
     */
    public void SKF_DecryptInit(HANDLE hKey, byte [] iv, long PaddingType, long FeedBitLen) throws SKFException{
        long ret = SkfDefines.SAR_OK;

        /* compose block cipher param */
        BLOCKCIPHERPARAM DecryptParam = new BLOCKCIPHERPARAM();
        if(null != iv){
            DecryptParam.setIVLen(iv.length);
            DecryptParam.setIV(iv);
        }
        DecryptParam.setPaddingType(PaddingType);
        DecryptParam.setFeedBitLen(FeedBitLen);

        ret = SkfNativeFunc.SKF_DecryptInit(hKey, DecryptParam);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DecryptInit Failed.", ret);
        }
    }

    /**
     * 单个分组数据的解密操作.
     * 用指定解密密钥对指定数据进行解密，被解密的数据只包含一个分组，解密后的明文保存到指定的缓冲区中
     * SKF_Decrypt只对单个分组数据进行解密，在调用 SKF_Decrypt之前，必须调用 SKF_DecryptInit初始化解密操作
     * SKF_Decypt等价于先调用 SKF_DecryptUpdate再调用 SKF_DecryptFinal
     *
     * @param hKey            [IN] 解密密钥句柄
     * @param pbEncryptedData [IN] 待解密数据
     * @return [OUT] 指向解密后的数据缓冲区指针，当为NULL时可获得解密后的数据长度
     * @throws SKFException the skf exception
     */
    public byte[] SKF_Decrypt(HANDLE hKey, byte[] pbEncryptedData) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulDataLen = new long[1];

        ret = SkfNativeFunc.SKF_Decrypt(hKey, pbEncryptedData, null, pulDataLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_Decrypt Failed.", ret);
        }

        if(pulDataLen[0] <= 0){
            return null;
        }

        byte[] pbData = new byte[(int)pulDataLen[0]];
        ret = SkfNativeFunc.SKF_Decrypt(hKey, pbEncryptedData, pbData, pulDataLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_Decrypt Failed.", ret);
        }

        return pbData;
    }

    /**
     * 多个分组数据的解密操作.
     * 用指定解密密钥对指定数据进行解密，被解密的数据包含多个分组，解密后的明文保存到指定的缓冲区中
     * SKF_DecryptUpdate对多个分组数据进行解密，在调用 SKF_DecryptUpdate之前，必须调用 SKF_DecryptInit初始化解密操作
     * 在调用 SKF_DecryptUpdate之后，必须调用 SKF_DecryptFinal结束解密操作
     *
     * @param hKey            [IN] 解密密钥句柄
     * @param pbEncryptedData [IN] 待解密数据
     * @return [OUT] 指向解密后的数据缓冲区指针
     * @throws SKFException the skf exception
     */
    public byte[] SKF_DecryptUpdate(HANDLE hKey, byte[] pbEncryptedData) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulDataLen = new long[1];

        ret = SkfNativeFunc.SKF_DecryptUpdate(hKey, pbEncryptedData, null, pulDataLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DecryptUpdate Failed.", ret);
        }

        if(pulDataLen[0] <= 0){
            return null;
        }

        byte[] pbData = new byte[(int)pulDataLen[0]];
        ret = SkfNativeFunc.SKF_DecryptUpdate(hKey, pbEncryptedData, pbData, pulDataLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DecryptUpdate Failed.", ret);
        }

        return pbData;
    }

    /**
     * 结束多个分组数据的解密.
     *
     * @param hKey [IN] 解密密钥句柄
     * @return [OUT] 指向解密结果的缓冲区，如果此参数为NULL时，由pulPlainTextLen返回解密结果的长度
     * @throws SKFException the skf exception
     */
    public byte[] SKF_DecryptFinal(HANDLE hKey) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulDecyptedDataLen = new long[1];

        ret = SkfNativeFunc.SKF_DecryptFinal(hKey, null, pulDecyptedDataLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DecryptFinal Failed.", ret);
        }

        if(pulDecyptedDataLen[0] <= 0){
            return null;
        }

        byte[] pbPlainText = new byte[(int)pulDecyptedDataLen[0]];
        ret = SkfNativeFunc.SKF_DecryptFinal(hKey, pbPlainText, pulDecyptedDataLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DecryptFinal Failed.", ret);
        }

        return pbPlainText;
    }

    /**
     * 初始化消息杂凑计算操作，指定计算消息杂凑的算法.
     *
     * @param hDev    [IN] 连接设备时返回的设备句柄
     * @param ulAlgID [IN] 杂凑算法标识
     * @param pPubKey [IN] 签名者公钥。当 alAlgID 为 SGD_SM3 时有效
     * @param pucID   [IN] 签名者的 ID 值，当 alAlgID 为 SGD_SM3 时有效。
     * @param phHash  [OUT] 密码杂凑对象句柄
     * @throws SKFException the skf exception
     */
    public void SKF_DigestInit(DEVHANDLE hDev, long ulAlgID, byte[] pPubKey, byte[] pucID, HANDLE phHash) throws SKFException{
        long ret = SkfDefines.SAR_OK;

        /* compose public key blob */
        ECCPUBLICKEYBLOB pPubKeyBlob = null;
        if(null != pPubKey){
            pPubKeyBlob = new ECCPUBLICKEYBLOB();
            pPubKeyBlob.setBitLen(32 * 8);
            byte [] pub = new byte[64];
            System.arraycopy(pPubKey,0,pub,32,32);
            pPubKeyBlob.setXCoordinate(pub);
            System.arraycopy(pPubKey,32,pub,32,32);
            pPubKeyBlob.setYCoordinate(pub);
        }

        ret = SkfNativeFunc.SKF_DigestInit(hDev, ulAlgID, pPubKeyBlob, pucID, phHash);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DigestInit Failed.", ret);
        }
    }

    /**
     * 对单一分组的消息进行杂凑计算.
     *
     * @param hHash  [IN] 杂凑对象句柄
     * @param pbData [IN] 指向消息数据的缓冲区
     * @return [OUT] 杂凑数据缓冲区指针，当此参数为NULL时，由pulHashLen返回杂凑结果的长度
     * @throws SKFException the skf exception
     */
    public byte[] SKF_Digest(HANDLE hHash, byte[] pbData) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulHashLen = new long[1];

        ret = SkfNativeFunc.SKF_Digest(hHash, pbData, null, pulHashLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_Digest Failed.", ret);
        }

        if(pulHashLen[0] <= 0){
            return null;
        }

        byte[] pbHashData = new byte[(int)pulHashLen[0]];
        ret = SkfNativeFunc.SKF_Digest(hHash, pbData, pbHashData, pulHashLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_Digest Failed.", ret);
        }

        return pbHashData;
    }

    /**
     * 对多个分组的消息进行杂凑计算.
     *
     * @param hHash  [IN] 杂凑对象句柄
     * @param pbData [IN] 指向消息数据的缓冲区
     * @throws SKFException the skf exception
     */
    public void SKF_DigestUpdate(HANDLE hHash, byte[] pbData) throws SKFException{
        long ret = SkfNativeFunc.SKF_DigestUpdate(hHash, pbData);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DigestUpdate Failed.", ret);
        }
    }

    /**
     * 结束多个分组消息的杂凑计算操作，将杂凑保存到指定的缓冲区.
     *
     * @param hHash [IN] 杂凑对象句柄
     * @return [OUT] 返回的杂凑数据缓冲区指针，如果此参数NULL时，由pulHashLen返回杂凑结果的长度
     * @throws SKFException the skf exception
     */
    public byte[] SKF_DigestFinal(HANDLE hHash) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulHashLen = new long[1];

        ret = SkfNativeFunc.SKF_DigestFinal(hHash, null, pulHashLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DigestFinal Failed.", ret);
        }

        if(pulHashLen[0] <= 0){
            return null;
        }

        byte[] pHashData = new byte[(int)pulHashLen[0]];
        ret = SkfNativeFunc.SKF_DigestFinal(hHash, pHashData, pulHashLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_DigestFinal Failed.", ret);
        }

        return pHashData;
    }

    /**
     * 初始化消息认证码计算操作，设置计算消息认证码的密钥参数，并返回消息认证码句柄.
     *
     * @param hKey     [IN] 计算消息认证码的密钥句柄
     * @param MacParam [IN] 消息认证计算相关参数，包括初始向量、初始向量长度、填充方法等
     * @param phMac    [OUT] 消息认证码对象句柄
     * @throws SKFException the skf exception
     */
    public void SKF_MacInit(HANDLE hKey, BLOCKCIPHERPARAM MacParam, HANDLE phMac) throws SKFException{
        long ret = SkfNativeFunc.SKF_MacInit(hKey, MacParam, phMac);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_MacInit Failed.", ret);
        }
    }

    /**
     * SKF_Mac计算单一分组数据的消息认证码.
     *
     * @param hMac   [IN] 消息认证码句柄
     * @param pbData [IN] 指向待计算数据的缓冲区
     * @return [OUT] 指向计算后的Mac结果，如果此参数为NULL时，由pulMacLen返回计算后Mac结果的长度
     * @throws SKFException the skf exception
     */
    public byte[] SKF_Mac(HANDLE hMac, byte[] pbData) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulMacLen = new long[1];

        ret = SkfNativeFunc.SKF_Mac(hMac, pbData, null, pulMacLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_Mac Failed.", ret);
        }

        if(pulMacLen[0] <= 0){
            return null;
        }

        byte[] pbMacData = new byte[(int)pulMacLen[0]];
        ret = SkfNativeFunc.SKF_Mac(hMac, pbData, pbMacData, pulMacLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_Mac Failed.", ret);
        }

        return pbMacData;
    }

    /**
     * 计算多个分组数据的消息认证码.
     *
     * @param hMac   [IN] 消息认证码句柄
     * @param pbData [IN] 指向待计算数据的缓冲区
     * @throws SKFException the skf exception
     */
    public void SKF_MacUpdate(HANDLE hMac, byte[] pbData) throws SKFException{
        long ret = SkfNativeFunc.SKF_MacUpdate(hMac, pbData);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_MacUpdate Failed.", ret);
        }
    }

    /**
     * 结束多个分组数据的消息认证码计算操作.
     *
     * @param hMac [IN] 消息认证码句柄
     * @return [OUT] 指向消息认证码的缓冲区，当此参数为NULL时，由pulMacDataLen返回消息认证码返回的长度
     * @throws SKFException the skf exception
     */
    public byte[] SKF_MacFinal(HANDLE hMac) throws SKFException{
        long ret = SkfDefines.SAR_OK;
        long[] pulMacDataLen = new long[1];

        ret = SkfNativeFunc.SKF_MacFinal(hMac, null, pulMacDataLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_MacFinal Failed.", ret);
        }

        if(pulMacDataLen[0] <= 0){
            return null;
        }

        byte[] pbMacData = new byte[(int)pulMacDataLen[0]];
        ret = SkfNativeFunc.SKF_MacFinal(hMac, pbMacData, pulMacDataLen);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_MacFinal Failed.", ret);
        }

        return pbMacData;
    }

    /**
     * 关闭会话密钥、杂凑、消息认证码句柄.
     *
     * @param hHandle [IN] 要关闭的对象句柄
     * @throws SKFException the skf exception
     */
    public void SKF_CloseHandle(HANDLE hHandle) throws SKFException{
        long ret = SkfNativeFunc.SKF_CloseHandle(hHandle);
        if(ret != SkfDefines.SAR_OK){
            throw new SKFException("SKF_CloseHandle Failed.", ret);
        }
    }

}
