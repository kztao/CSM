package com.westone.skf;

import java.util.List;

class SkfNativeFunc {
        static {
            System.loadLibrary("SKF_JNI");
        }

        public static native void regCallback(SkfCallback callback);
        public static native void setLibPath(Object obj,String libPath);
        /*
         *	获得当前系统中的设备列表
         *	szNameList		[OUT]设备名称列表。如果该参数为NULL，将由pulSize返回所需要的内存空间大小。每个设备的名称以单个'\0'结束，以双'\0'表示列表的结束
         *	pulSize			[IN,OUT]输入参数，输入设备名称列表的缓冲区长度，输出参数，返回szNameList所需要的空间大小
         */
        public static native long SKF_EnumDev(List<String> szNameList);

        /*
         *	通过设备名称连接设备，返回设备的句柄
         *	szName		[IN]设备名称
         *	phDev		[OUT]返回设备操作句柄
         */
        public static native long SKF_ConnectDev(String szName,DEVHANDLE phDev);

        /*
         *	断开一个已经连接的设备，并释放句柄。
         *	hDev		[IN]连接设备时返回的设备句柄
         */
        public static native long SKF_DisConnectDev(DEVHANDLE hDev);

        /*
         *	获取设备是否存在的状态
         *	szDevName	[IN]连接名称
         *	pulDevState	[OUT]返回设备状态
         */
        public static native long SKF_GetDevState(String  szDevName,DevState pulDevState);

        /*
         *	设置设备标签
         *	hDev		[IN]连接设备时返回的设备句柄
         *	szLabel		[OUT]设备标签字符串。该字符串应小于32字节
         */
        public static native long SKF_SetLabel(DEVHANDLE hDev,String szLabel);

        /*
         *	获取设备的一些特征信息，包括设备标签、厂商信息、支持的算法等
         *	hDev		[IN]连接设备时返回的设备句柄
         *	pDevInfo	[OUT]返回设备信息
         */
        public static native long SKF_GetDevInfo(DEVHANDLE	hDev,DEVINFO pDevInfo);

        /*
         *	获得设备的独占使用权
         *	hDev		[IN]连接设备时返回的设备句柄
         *	ulTimeOut	[IN]超时时间，单位为毫秒。如果为0xFFFFFFFF表示无限等待
         */
        public static native long SKF_LockDev(DEVHANDLE	hDev,long ulTimeOut);

        /*
         *	释放对设备的独占使用权
         *	hDev		[IN]连接设备时返回的设备句柄
         */
        public static native long SKF_UnlockDev(DEVHANDLE	hDev);


        /************************************************************************/
        /*  2. 访问控制				                                            */
        /*	 SKF_ChangeDevAuthKey												*/
        /*	 SKF_DevAuth															*/
        /*	 SKF_ChangePIN														*/
        /*	 SKF_GetPINInfo														*/
        /*	 SKF_VerifyPIN														*/
        /*	 SKF_UnblockPIN														*/
        /*	 SKF_ClearSecureState												*/
        /************************************************************************/

        /*
         *	更改设备认证密钥
         *	hDev		[IN]连接时返回的设备句柄
         *	pbKeyValue	[IN]密钥值
         *	ulKeyLen	[IN]密钥长度
         */
        public static native long SKF_ChangeDevAuthKey(DEVHANDLE hDev,byte[] pbKeyValue);

        /*
         *	设备认证是设备对应用程序的认证
         *	hDev			[IN]连接时返回的设备句柄
         *	pbAuthData		[IN]认证数据
         *	ulLen			[IN]认证数据的长度
         */
        public static native long SKF_DevAuth(DEVHANDLE	hDev,byte[] pbAuthData);

        /*
         *	修改PIN，可以修改Admin和User的PIN，如果原PIN错误，返回剩余重试次数，当剩余次数为0时，表示PIN已经被锁死
         *	hApplication	[IN]应用句柄
         *	ulPINType		[IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
         *	szOldPIN		[IN]原PIN值
         *	szNewPIN		[IN]新PIN值
         *	pulRetryCount	[OUT]出错后重试次数
         */
        public static native long SKF_ChangePIN(HAPPLICATION	hApplication,long	ulPINType,String szOldPIN,
            String	szNewPIN,PinRetryCount pulRetryCount);

        /*
         *	获取PIN码信息，包括最大重试次数、当前剩余重试次数，以及当前PIN码是否为出厂默认PIN码
         *	hApplication		[IN]应用句柄
         *	ulPINType			[IN]PIN类型
         *	pulMaxRetryCount	[OUT]最大重试次数
         *	pulRemainRetryCount	[OUT]当前剩余重试次数，当为0时表示已锁死
         *	pbDefaultPin		[OUT]是否为出厂默认PIN码
         */
        public static native long SKF_GetPINInfo(HAPPLICATION	hApplication, long	ulPINType, PinInfo ulPinInfo);

        /*
         *	校验PIN码。校验成功后，会获得相应的权限，如果PIN码错误，会返回PIN码的重试次数，当重试次数为0时表示PIN码已经锁死
         *	hApplication	[IN]应用句柄
         *	ulPINType		[IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
         *	szPIN			[IN]PIN值
         *	pulRetryCount	[OUT]出错后返回的重试次数
         */
        public static native long SKF_VerifyPIN(HAPPLICATION	hApplication,
            long	ulPINType,
            String	szPIN,
            PinRetryCount pulRetryCount
    );

        /*
         *	当用户的PIN码锁死后，通过调用该函数来解锁用户PIN码。
         *	解锁后，用户PIN码被设置成新值，用户PIN码的重试次数也恢复到原值。
         *	hApplication	[IN]应用句柄
         *	szAdminPIN		[IN]管理员PIN码
         *	szNewUserPIN	[IN]新的用户PIN码
         *	pulRetryCount	[OUT]管理员PIN码错误时，返回剩余重试次数
         */
        public static native long SKF_UnblockPIN(
            HAPPLICATION	hApplication,
            String			szAdminPIN,
            String			szNewUserPIN,
            PinRetryCount pulRetryCount
    );

        /*
         *	清除应用当前的安全状态
         *	hApplication	[IN]应用句柄
         */
        public static native long SKF_ClearSecureState(
            HAPPLICATION	hApplication
    );

        /************************************************************************/
        /*  3. 应用管理				                                            */
        /*	 SKF_CreateApplication												*/
        /*	 SKF_EnumApplication													*/
        /*	 SKF_DeleteApplication												*/
        /*	 SKF_OpenApplication													*/
        /*	 SKF_CloseApplication												*/
        /************************************************************************/

        /*
         *	创建一个应用
         *	hDev					[IN]连接设备时返回的设备句柄
         *	szAppName				[IN]应用名称
         *	szAdminPIN				[IN]管理员PIN
         *	dwAdminPinRetryCount	[IN]管理员PIN最大重试次数
         *	szUserPIN				[IN]用户PIN
         *	dwAdminPinRetryCount	[IN]用户PIN最大重试次数
         *	dwCreateFileRights		[IN]在该应用下创建文件和容器的权限
         *	phApplication			[OUT]应用的句柄
         */
        public static native long SKF_CreateApplication(
            DEVHANDLE		hDev,
            String			szAppName,
            String			szAdminPIN,
            long			dwAdminPinRetryCount,
            String			szUserPIN,
            long			dwUserPinRetryCount,
            long			dwCreateFileRights,
            HAPPLICATION	phApplication
    );

        /*
         *	枚举设备中所存在的所有应用
         *	hDev			[IN]连接设备时返回的设备句柄
         *	szAppName		[OUT]返回应用名称列表, 如果该参数为空，将由pulSize返回所需要的内存空间大小。
         *						 每个应用的名称以单个'\0'结束，以双'\0'表示列表的结束。
         *	pulSize			[IN,OUT]输入参数，输入应用名称的缓冲区长度，输出参数，返回szAppName所占用的的空间大小
         */
        public static native long SKF_EnumApplication(
            DEVHANDLE		hDev,
            List<String>	szAppName);

        /*
         *	删除指定的应用
         *	hDev			[IN]连接设备时返回的设备句柄
         *	szAppName		[IN]应用名称
         */
        public static native long SKF_DeleteApplication(
            DEVHANDLE		hDev,
            String			szAppName
    );

        /*
         *	打开指定的应用
         *	hDev			[IN]连接设备时返回的设备句柄
         *	szAppName		[IN]应用名称
         *	phApplication	[OUT]应用的句柄
         */
        public static native long SKF_OpenApplication(
            DEVHANDLE		hDev,
            String			szAppName,
            HAPPLICATION	phApplication
    );

        /*
         *	关闭应用并释放应用句柄
         *	hApplication	[IN]应用的句柄
         */
        public static native long SKF_CloseApplication(
            HAPPLICATION	hApplication
    );


        /************************************************************************/
        /*  4. 文件管理				                                            */
        /*	 SKF_CreateFile														*/
        /*	 SKF_DeleteFile														*/
        /*	 SKF_EnumFiles														*/
        /*	 SKF_GetFileInfo														*/
        /*	 SKF_ReadFile														*/
        /*	 SKF_WriteFile														*/
        /************************************************************************/

        /*
         *	创建一个文件。创建文件时要指定文件的名称，大小，以及文件的读写权限
         *	hApplication		[IN]应用句柄
         *	szFileName			[IN]文件名称，长度不得大于32个字节
         *	ulFileSize			[IN]文件大小
         *	ulReadRights		[IN]文件读权限
         *	ulWriteRights		[IN]文件写权限
         */
        public static native long SKF_CreateFile(
            HAPPLICATION	hApplication,
            String			szFileName,
            long			ulFileSize,
            long			ulReadRights,
            long			ulWriteRights
    );

        /*
         *	删除指定文件，文件删除后，文件中写入的所有信息将丢失。文件在设备中的占用的空间将被释放。
         *	hApplication		[IN]要删除文件所在的应用句柄
         *	szFileName			[IN]要删除文件的名称
         */
        public static native long SKF_DeleteFile(
            HAPPLICATION	hApplication,
            String			szFileName
    );

        /*
         *	枚举一个应用下存在的所有文件
         *	hApplication		[IN]应用的句柄
         *	szFileList			[OUT]返回文件名称列表，该参数为空，由pulSize返回文件信息所需要的空间大小。每个文件名称以单个'\0'结束，以双'\0'表示列表的结束。
         *	pulSize				[OUT]输入为数据缓冲区的大小，输出为实际文件名称的大小
         */
        public static native long SKF_EnumFiles(
            HAPPLICATION	hApplication,
            List<String>	szFileList);

        /*
         *	获取应用文件的属性信息，例如文件的大小、权限等
         *	hApplication		[IN]文件所在应用的句柄
         *	szFileName			[IN]文件名称
         *	pFileInfo			[OUT]文件信息，指向文件属性结构的指针
         */
        public static native long SKF_GetFileInfo(
            HAPPLICATION		hApplication,
            String				szFileName,
            FILEATTRIBUTE	pFileInfo
    );

        /*
         *	读取文件内容
         *	hApplication		[IN]文件所在的应用句柄
         *	szFileName			[IN]文件名
         *	ulOffset			[IN]文件读取偏移位置
         *	ulSize				[IN]要读取的长度
         *	pbOutData			[OUT]返回数据的缓冲区
         *	pulOutLen			[OUT]输入表示给出的缓冲区大小；输出表示实际读取返回的数据大小
         */
        public static native long SKF_ReadFile(
            HAPPLICATION	hApplication,
            String			szFileName,
            long			ulOffset,
            long			ulSize,
            byte[] pbOutData,
            long[] pulOutLen);

        /*
         *	写数据到文件中
         *	hApplication		[IN]文件所在的应用句柄
         *	szFileName			[IN]文件名
         *	ulOffset			[IN]写入文件的偏移量
         *	pbData				[IN]写入数据缓冲区
         *	ulSize				[IN]写入数据的大小
         */
        public static native long SKF_WriteFile(
            HAPPLICATION	hApplication,
            String			szFileName,
            long			ulOffset,
            byte[] pbData);


        /************************************************************************/
        /*  5. 容器管理				                                            */
        /*	 SKF_CreateContainer													*/
        /*	 SKF_DeleteContainer													*/
        /*	 SKF_OpenContainer													*/
        /*	 SKF_CloseContainer													*/
        /*	 SKF_EnumContainer													*/
        /************************************************************************/

        /*
         *	在应用下建立指定名称的容器并返回容器句柄
         *	hApplication		[IN]应用句柄
         *	szContainerName		[IN]ASCII字符串，表示所建立容器的名称，容器名称的最大长度不能超过64字节
         *	phContainer			[OUT]返回所建立容器的容器句柄
         */
        public static native long SKF_CreateContainer(
            HAPPLICATION	hApplication,
            String			szContainerName,
            HCONTAINER	phContainer
    );

        /*
         *	在应用下删除指定名称的容器并释放容器相关的资源
         *	hApplication		[IN]应用句柄
         *	szContainerName		[IN]指向删除容器的名称
         */
        public static native long SKF_DeleteContainer(
            HAPPLICATION	hApplication,
            String			szContainerName
    );

        /*
         *	获取容器句柄
         *	hApplication		[IN]应用句柄
         *	szContainerName		[IN]容器名称
         *	phContainer			[OUT]返回所打开容器的句柄
         */
        public static native long SKF_OpenContainer(
            HAPPLICATION	hApplication,
            String			szContainerName,
            HCONTAINER	phContainer
    );

        /*
         *	关闭容器句柄，并释放容器句柄相关资源
         *	hContainer			[OUT]容器句柄
         */
        public static native long SKF_CloseContainer(
            HCONTAINER hContainer
    );

        /*
         *	枚举应用下的所有容器并返回容器名称列表
         *	hApplication		[IN]应用句柄
         *	szContainerName		[OUT]指向容器名称列表缓冲区，如果此参数为NULL时，pulSize表示返回数据所需要缓冲区的长度，如果此参数不为NULL时，返回容器名称列表，每个容器名以单个'\0'为结束，列表以双'\0'结束
         *	pulSize				[OUT]调用前表示szContainerName缓冲区的长度，返回容器名称列表的长度
         */
        public static native long SKF_EnumContainer(
            HAPPLICATION	hApplication,
           List<String>	szContainerName);

        /*
         *	功能描述	获取容器的类型
         *	hContainer	[IN]容器句柄。
         *	pulContainerType	[OUT] 获得的容器类型。指针指向的值为0表示未定、尚未分配类型或者为空容器，为1表示为RSA容器，为2表示为SM2容器。
         *
         */
        public static native long SKF_GetContainerType(
                HCONTAINER hContainer,
            long[] pulContainerType);
        /************************************************************************/
        /*  6. 密码服务				                                            */
        /*	 SKF_GetRandom														*/
        /*	 SKF_GenExtRSAKey													*/
        /*	 SKF_GenRSAKeyPair													*/
        /*	 SKF_ImportRSAKeyPair												*/
        /*	 SKF_RSASignData														*/
        /*	 SKF_RSAVerify														*/
        /*	 SKF_RSAExportSessionKey												*/
        /*	 SKF_ExtRSAPubKeyOperation											*/
        /*	 SKF_ExtRSAPriKeyOperation											*/
        /*	 SKF_GenECCKeyPair													*/
        /*	 SKF_ImportECCKeyPair												*/
        /*	 SKF_ECCSignData														*/
        /*	 SKF_ECCVerify														*/
        /*	 SKF_ECCExportSessionKey												*/
        /*	 SKF_ExtECCEncrypt													*/
        /*	 SKF_ExtECCDecrypt													*/
        /*	 SKF_ExtECCSign														*/
        /*	 SKF_ExtECCVerify													*/
        /*	 SKF_ExportPublicKey													*/
        /*	 SKF_ImportSessionKey												*/
        /*	 SKF_SetSymmKey														*/
        /*	 SKF_EncryptInit														*/
        /*	 SKF_Encrypt															*/
        /*	 SKF_EncryptUpdate													*/
        /*	 SKF_EncryptFinal													*/
        /*	 SKF_DecryptInit														*/
        /*	 SKF_Decrypt															*/
        /*	 SKF_DecryptUpdate													*/
        /*	 SKF_DecryptFinal													*/
        /*	 SKF_DegistInit														*/
        /*	 SKF_Degist															*/
        /*	 SKF_DegistUpdate													*/
        /*	 SKF_DegistFinal														*/
        /*	 SKF_MACInit															*/
        /*	 SKF_MAC																*/
        /*	 SKF_MACUpdate														*/
        /*	 SKF_MACFinal														*/
        /************************************************************************/

        /*
         *	产生指定长度的随机数
         *	hDev			[IN] 设备句柄
         *	pbRandom		[OUT] 返回的随机数
         *	ulRandomLen		[IN] 随机数长度
         */
        public static native long SKF_GenRandom(
            DEVHANDLE hDev,
            byte[] pbRandom,
            long ulRandomLen
    );

        /*
         *	由设备生成RSA密钥对并明文输出
         *	hDev			[IN] 设备句柄
         *	ulBitsLen		[IN] 密钥模长
         *	pBlob			[OUT] 返回的私钥数据结构
         */
        public static native long SKF_GenExtRSAKey(
            DEVHANDLE hDev,
            long ulBitsLen,
            RSAPRIVATEKEYBLOB pBlob
    );

        /*
         *	生成RSA签名密钥对并输出签名公钥
         *	hContainer		[IN] 容器句柄
         *	ulBitsLen		[IN] 密钥模长
         *	pBlob			[OUT] 返回的RSA公钥数据结构
         */
        public static native long SKF_GenRSAKeyPair(
            HCONTAINER hContainer,
            long ulBitsLen,
            RSAPUBLICKEYBLOB pBlob
    );

        /*
         *	导入RSA加密公私钥对
         *	hContainer		[IN] 容器句柄
         *	ulSymAlgId		[IN] 对称算法密钥标识
         *	pbWrappedKey	[IN] 使用该容器内签名公钥保护的对称算法密钥
         *	ulWrappedKeyLen	[IN] 保护的对称算法密钥长度
         *	pbEncryptedData	[IN] 对称算法密钥保护的RSA加密私钥。私钥的格式遵循PKCS #1 v2.1: RSA Cryptography Standard中的私钥格式定义
         *	ulEncryptedDataLen	[IN] 对称算法密钥保护的RSA加密公私钥对长度
         */
        public static native long SKF_ImportRSAKeyPair(
            HCONTAINER hContainer,
            long ulSymAlgId,
            byte[] pbWrappedKey,
            byte[] pbEncryptedData);

        /*
         *	使用hContainer指定容器的签名私钥，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名的长度
         *	hContainer		[IN] 用来签名的私钥所在容器句柄
         *	pbData			[IN] 被签名的数据
         *	ulDataLen		[IN] 签名数据长度，应不大于RSA密钥模长-11
         *	pbSignature		[OUT] 存放签名结果的缓冲区指针，如果值为NULL，用于取得签名结果长度
         *	pulSigLen		[IN,OUT] 输入为签名结果缓冲区大小，输出为签名结果长度
         */
        public static native long SKF_RSASignData(
            HANDLE hContainer,
            byte[] pbData,
            byte[] pbSignature,
            long[] pulSigLen
    );

        /*
         *	验证RSA签名。用pRSAPubKeyBlob内的公钥值对待验签数据进行验签。
         *	hDev			[IN] 连接设备时返回的设备句柄
         *	pRSAPubKeyBlob	[IN] RSA公钥数据结构
         *	pbData			[IN] 待验证签名的数据
         *	ulDataLen		[IN] 数据长度，应不大于公钥模长-11
         *	pbSignature		[IN] 待验证的签名值
         *	ulSigLen		[IN] 签名值长度，必须为公钥模长
         */
        public static native long SKF_RSAVerify(
            DEVHANDLE			hDev,
            RSAPUBLICKEYBLOB	pRSAPubKeyBlob,
            byte[]	pbData,
            byte[] pbSignature);

        /*
         *	生成会话密钥并用外部公钥加密输出。
         *	hContainer		[IN] 容器句柄
         *	ulAlgID			[IN] 会话密钥的算法标识
         *	pPubKey			[IN] 加密会话密钥的RSA公钥数据结构
         *	pbData			[OUT] 导出的加密会话密钥密文，按照PKCS#1v1.5的要求封装
         *	pulDataLen		[OUT] 返回导出数据长度
         *	phSessionKey	[OUT] 导出的密钥句柄
         */
        public static native long SKF_RSAExportSessionKey(
            HCONTAINER hContainer,
            long ulAlgID,
            RSAPUBLICKEYBLOB pPubKey,
            byte[] pbData,
            long[] pulDataLen,
            HANDLE phSessionKey
    );

        /*
         *	使用外部传入的RSA公钥对输入数据做公钥运算并输出结果
         *	hDev			[IN] 设备句柄
         *	pRSAPubKeyBlob	[IN] RSA公钥数据结构
         *	pbInput			[IN] 指向待运算的原始数据缓冲区
         *	ulInputLen		[IN] 待运算原始数据的长度，必须为公钥模长
         *	pbOutput		[OUT] 指向RSA公钥运算结果缓冲区，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
         *	pulOutputLen	[OUT] 调用前表示pbOutput缓冲区的长度，返回RSA公钥运算结果的实际长度
         */
        public static native long SKF_ExtRSAPubKeyOperation(
            DEVHANDLE hDev,
            RSAPUBLICKEYBLOB pRSAPubKeyBlob,
            byte[] pbInput,
            byte[] pbOutput,
            long[] pulOutputLen);

        /*
         *	直接使用外部传入的RSA私钥对输入数据做私钥运算并输出结果
         *	hDev			[IN] 设备句柄
         *	pRSAPriKeyBlob	[IN] RSA私钥数据结构
         *	pbInput			[IN] 指向待运算数据缓冲区
         *	ulInputLen		[IN] 待运算数据的长度，必须为公钥模长
         *	pbOutput		[OUT] RSA私钥运算结果，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
         *	pulOutputLen	[OUT] 调用前表示pbOutput缓冲区的长度，返回RSA私钥运算结果的实际长度
         */
        public static native long SKF_ExtRSAPriKeyOperation(
            DEVHANDLE hDev,
            RSAPRIVATEKEYBLOB pRSAPriKeyBlob,
            byte[] pbInput,
            byte[] pbOutput,
            long[] pulOutputLen);

        /*
         *	生成ECC签名密钥对并输出签名公钥。
         *	hContainer		[IN] 容器句柄
         *	ulBitsLen		[IN] 密钥模长
         *	pBlob			[OUT] 返回ECC公钥数据结构
         */
        public static native long SKF_GenECCKeyPair(
            HCONTAINER hContainer,
            long ulAlgId,
            ECCPUBLICKEYBLOB pBlob
    );

        /*
         *	导入ECC公私钥对
         *	hContainer		[IN] 容器句柄
         *	pbWrapedData	[IN] 加密保护的ECC加密公私钥对密文
         *	ulWrapedLen		[IN] 数据长度
         */
        public static native long SKF_ImportECCKeyPair(
            HCONTAINER hContainer,
            ENVELOPEDKEYBLOB pEnvelopedKeyBlob
    );

        /*
         *	ECC数字签名。采用ECC算法和指定私钥hKey，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名值的长度
         *	hContainer		[IN] 用来签名的私钥所在容器句柄
         *	pbData			[IN] 被签名的数据
         *	ulDataLen		[IN] 待签名数据长度，必须小于密钥模长
         *	pbSignature		[OUT] 签名值，为NULL时用于获得签名值的长度
         */
        public static native long SKF_ECCSignData(
            HCONTAINER hContainer,
            byte[] pbData,
            ECCSIGNATUREBLOB pSignature);

        /*
         *	用ECC公钥对数据进行验签
         *	hDev			[IN] 设备句柄
         *	pECCPubKeyBlob	[IN] ECC公钥数据结构
         *	pbData			[IN] 待验证签名的数据
         *	ulDataLen		[IN] 数据长度
         *	pbSignature		[IN] 待验证的签名值
         *	ulSigLen		[IN] 签名值长度
         */
        public static native long SKF_ECCVerify(
            DEVHANDLE			hDev,
            ECCPUBLICKEYBLOB	pECCPubKeyBlob,
            byte[]	pbData,
            ECCSIGNATUREBLOB pSignature
    );

        /*
         *	生成会话密钥并用外部公钥加密输出。
         *	hContainer		[IN] 容器句柄
         *	ulAlgID			[IN] 会话密钥的算法标识
         *	pPubKey			[IN] 外部输入的公钥结构
         *	pbData			[OUT] 导出的加密会话密钥密文
         *	phSessionKey	[OUT] 会话密钥句柄
         */
        public static native long SKF_ECCExportSessionKey(
            HCONTAINER hContainer,
            long ulAlgID,
            ECCPUBLICKEYBLOB pPubKey,
            ECCCIPHERBLOB  pData,
            HANDLE phSessionKey
    );

        /*
         *	使用外部传入的ECC公钥对输入数据做加密运算并输出结果
         *	hDev			[IN] 设备句柄
         *	pECCPubKeyBlob	[IN] ECC公钥数据结构
         *	pbPlainText		[IN] 待加密的明文数据
         *	ulPlainTextLen	[IN] 待加密明文数据的长度
         *	pbCipherText	[OUT] 指向密文数据缓冲区，如果该参数为NULL，则由pulCipherTextLen返回密文数据的实际长度

         */
        public static native long SKF_ExtECCEncrypt(
            DEVHANDLE hDev,
            ECCPUBLICKEYBLOB pECCPubKeyBlob,
            byte[] pbPlainText,
            ECCCIPHERBLOB pbCipherText
    );

        /*
         *	使用外部传入的ECC私钥对输入数据做解密运算并输出结果
         *	hDev			[IN] 设备句柄
         *	pRSAPriKeyBlob	[IN] ECC私钥数据结构
         *	pbInput			[IN] 待解密的密文数据
         *	ulInputLen		[IN] 待解密密文数据的长度
         *	pbOutput		[OUT] 返回明文数据，如果该参数为NULL，则由pulPlainTextLen返回明文数据的实际长度
         *	pulOutputLen	[OUT] 调用前表示pbPlainText缓冲区的长度，返回明文数据的实际长度
         */
        public static native long SKF_ExtECCDecrypt(
            DEVHANDLE hDev,
            ECCPRIVATEKEYBLOB pECCPriKeyBlob,
            ECCCIPHERBLOB pbCipherText,
            byte[] pbPlainText,
            long[] pulOutputLen
    );

        /*
         *	使用外部传入的ECC私钥对输入数据做签名运算并输出结果。
         *	hDev			[IN] 设备句柄
         *	pRSAPriKeyBlob	[IN] ECC私钥数据结构
         *	pbData			[IN] 待签名数据
         *	ulDataLen		[IN] 待签名数据的长度
         *	pbSignature		[OUT] 签名值，如果该参数为NULL，则由pulSignatureLen返回签名结果的实际长度
         *	pulSignatureLen	[OUT] 调用前表示pbSignature缓冲区的长度，返回签名结果的实际长度
         */
        public static native long SKF_ExtECCSign(
            DEVHANDLE hDev,
            ECCPRIVATEKEYBLOB pECCPriKeyBlob,
            byte[] pbData,
            ECCSIGNATUREBLOB pSignature
    );

        /*
         *	外部使用传入的ECC公钥做签名验证
         *	hDev			[IN] 设备句柄
         *	pECCPubKeyBlob	[IN] ECC公钥数据结构
         *	pbData			[IN] 待验证数据
         *	ulDataLen		[IN] 待验证数据的长度
         *	pbSignature		[OUT] 签名值
         *	ulSignLen		[OUT] 签名值的长度
         */
        public static native long SKF_ExtECCVerify(
            DEVHANDLE hDev,
            ECCPUBLICKEYBLOB pECCPubKeyBlob,
            byte[] pbData,
            ECCSIGNATUREBLOB pSignature
    );

        /*
         *	使用ECC密钥协商算法，为计算会话密钥而产生协商参数，返回临时ECC密钥对的公钥及协商句柄
         *	hContainer		[IN] 容器句柄
         *	ulAlgId			[IN] 会话密钥算法标识
         *	pTempECCPubKeyBlob	[OUT] 发起方临时ECC公钥
         *	pbID			[IN] 发起方的ID
         *	ulIDLen			[IN] 发起方ID的长度，不大于32
         *	phAgreementHandle	[OUT] 返回的密钥协商句柄
         */
        public static native long SKF_GenerateAgreementDataWithECC(
            HCONTAINER hContainer,
            long ulAlgId,
            ECCPUBLICKEYBLOB pTempECCPubKeyBlob,
            byte[] pbID,
            HANDLE phAgreementHandle
    );

        /*
         *	使用ECC密钥协商算法，产生协商参数并计算会话密钥，输出临时ECC密钥对公钥，并返回产生的密钥句柄
         *	hContainer					[IN] 容器句柄
         *	ulAlgId						[IN] 会话密钥算法标识
         *	pSponsorECCPubKeyBlob		[IN] 发起方的ECC公钥
         *	pSponsorTempECCPubKeyBlob	[IN] 发起方的临时ECC公钥
         *	pTempECCPubKeyBlob			[OUT] 响应方的临时ECC公钥
         *	pbID						[IN] 响应方的ID
         *	ulIDLen						[IN] 响应方ID的长度，不大于32
         *	pbSponsorID					[IN] 发起方的ID
         *	ulSponsorIDLen				[IN] 发起方ID的长度，不大于32
         *	phKeyHandle					[OUT] 返回的对称算法密钥句柄
         */
        public static native long SKF_GenerateAgreementDataAndKeyWithECC(
            HANDLE hContainer,
            long ulAlgId,
            ECCPUBLICKEYBLOB pSponsorECCPubKeyBlob,
            ECCPUBLICKEYBLOB pSponsorTempECCPubKeyBlob,
            ECCPUBLICKEYBLOB pTempECCPubKeyBlob,
            byte[] pbID,
            byte[] pbSponsorID,
            HANDLE phKeyHandle
    );

        /*
         *	使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥，同时返回会话密钥句柄
         *	hAgreementHandle			[IN] 密钥协商句柄
         *	pECCPubKeyBlob				[IN] 外部输入的响应方ECC公钥
         *	pTempECCPubKeyBlob			[IN] 外部输入的响应方临时ECC公钥
         *	pbID						[IN] 响应方的ID
         *	ulIDLen						[IN] 响应方ID的长度，不大于32
         *	phKeyHandle					[OUT] 返回的密钥句柄
         */
        public static native long SKF_GenerateKeyWithECC(
            HANDLE hAgreementHandle,
            ECCPUBLICKEYBLOB pECCPubKeyBlob,
            ECCPUBLICKEYBLOB pTempECCPubKeyBlob,
            byte[] pbID,
            HANDLE phKeyHandle
    );

        /*
         *	导出容器中的签名公钥或者加密公钥
         *	hContainer		[IN] 容器句柄
         *	bSignFlag		[IN] TRUE表示导出签名公钥，FALSE表示导出加密公钥
         *	pbBlob			[OUT] 指向RSA公钥结构（RSAPUBLICKEYBLOB）或者ECC公钥结构（ECCPUBLICKEYBLOB），如果此参数为NULL时，由pulBlobLen返回pbBlob的长度
         *	pulBlobLen		[IN,OUT] 调用时表示pbBlob的长度，返回导出公钥结构的大小
         */
        public static native long SKF_ExportPublicKey(
            HCONTAINER hContainer,
            boolean bSignFlag,
            Object pubKey);

        /*
         *	导入会话密钥
         *	hContainer		[IN] 容器句柄
         *	ulAlgID			[IN] 会话密钥的算法标识
         *	pbWrapedData	[IN] 要导入的数据
         *	ulWrapedLen		[IN] 数据长度
         *	phKey			[OUT] 返回会话密钥句柄
         */
        public static native long SKF_ImportSessionKey(
            HCONTAINER hContainer,
            long ulAlgID,
            Object pbWrapedData,
            HANDLE phKey
    );

        /*
         *	设置明文对称密钥，返回密钥句柄
         *	hContainer		[IN] 容器句柄
         *	pbKey			[IN] 指向会话密钥值的缓冲区
         *	ulAlgID			[IN] 会话密钥的算法标识
         *	phKey			[OUT] 返回会话密钥句柄
         */
        public static native long SKF_SetSymmKey(
            DEVHANDLE hDev,
            byte[] pbKey,
            long ulAlgID,
            HANDLE phKey
    );

        /*
         *	数据加密初始化。设置数据加密的算法相关参数。
         *	hKey			[IN] 加密密钥句柄
         *	EncryptParam	[IN] 分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
         */
        public static native long SKF_EncryptInit(
            HANDLE hKey,
            BLOCKCIPHERPARAM EncryptParam
    );

	/*
	 *	单一分组数据的加密操作。
		用指定加密密钥对指定数据进行加密，被加密的数据只包含一个分组，加密后的密文保存到指定的缓冲区中。
		 SKF_Encrypt只对单个分组数据进行加密，在调用 SKF_Encrypt之前，必须调用 SKF_EncryptInit初始化加密操作。
		 SKF_Encypt等价于先调用 SKF_EncryptUpdate再调用 SKF_EncryptFinal。
	 *	hKey			[IN] 加密密钥句柄
	 *	pbData			[IN] 待加密数据
	 *	ulDataLen		[IN] 待加密数据长度
	 *	pbEncryptedData [OUT] 加密后的数据缓冲区指针
	 *	pulEncryptedLen [IN,OUT] 输入，给出的缓冲区大小；输出，返回加密后的数据
	长度
	 *	成功: SAR_OK
	 *	失败: SAR_FAIL SAR_MEMORYERR SAR_UNKNOWNERR  SAR_INVALIDPARAMERR SAR_BUFFER_TOO_SMALL
	 */
        public static native long SKF_Encrypt(
            HANDLE	hKey,
            byte[] pbData,
            byte[] pbEncryptedData,
            long[] pulEncryptedLen
    );

	/*
	 *	多个分组数据的加密操作。
		用指定加密密钥对指定数据进行加密，被加密的数据包含多个分组，加密后的密文保存到指定的缓冲区中。
		 SKF_EncryptUpdate对多个分组数据进行加密，在调用 SKF_EncryptUpdate之前，必须调用 SKF_EncryptInit初始化加密操作；
		在调用 SKF_EncryptUpdate之后，必须调用 SKF_EncryptFinal结束加密操作。
	 *	hKey			[IN] 加密密钥句柄
	 *	pbData			[IN] 待加密数据
	 *	ulDataLen		[IN] 待加密数据长度
	 *	pbEncryptedData [OUT] 加密后的数据缓冲区指针
	 *	pulEncryptedLen [OUT] 返回加密后的数据长度
	 */
        public static native long SKF_EncryptUpdate(
            HANDLE		hKey,
            byte[]	pbData,
            byte[] pbEncryptedData,
            long[] pulEncryptedLen);

	/*
	 *	结束多个分组数据的加密，返回剩余加密结果。
		先调用 SKF_EncryptInit初始化加密操作，
		再调用 SKF_EncryptUpdate对多个分组数据进行加密，
		最后调用 SKF_EncryptFinal结束多个分组数据的加密。
	 *	hKey			[IN] 加密密钥句柄
	 *	pbEncryptedData [OUT] 加密结果的缓冲区
	 *	pulEncryptedLen [OUT] 加密结果的长度
	 */
        public static native long SKF_EncryptFinal(
            HANDLE hKey,
            byte[] pbEncryptedData,
            long[] pulEncryptedLen
    );

	/*
	 *	数据解密初始化，设置解密密钥相关参数。
		调用 SKF_DecryptInit之后，可以调用 SKF_Decrypt对单个分组数据进行解密，
		也可以多次调用 SKF_DecryptUpdate之后再调用 SKF_DecryptFinal完成对多个分组数据的解密。
	 *	hKey [IN] 解密密钥句柄
	 *	DecryptParam [IN] 分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
	 */
        public static native long SKF_DecryptInit(
            HANDLE hKey,
            BLOCKCIPHERPARAM DecryptParam
    );

	/*
	 *	单个分组数据的解密操作
		用指定解密密钥对指定数据进行解密，被解密的数据只包含一个分组，解密后的明文保存到指定的缓冲区中
		 SKF_Decrypt只对单个分组数据进行解密，在调用 SKF_Decrypt之前，必须调用 SKF_DecryptInit初始化解密操作
		 SKF_Decypt等价于先调用 SKF_DecryptUpdate再调用 SKF_DecryptFinal
	 *	hKey			[IN] 解密密钥句柄
	 *	pbEncryptedData [IN] 待解密数据
	 *	ulEncryptedLen	[IN] 待解密数据长度
	 *	pbData			[OUT] 指向解密后的数据缓冲区指针，当为NULL时可获得解密后的数据长度
	 *	pulDataLen		[IN，OUT] 返回解密后的数据长度
	 */
        public static native long SKF_Decrypt(
            HANDLE hKey,
            byte[] pbEncryptedData,
            byte[] pbData,
            long[] pulDataLen
    );

	/*
	*	多个分组数据的解密操作。
		用指定解密密钥对指定数据进行解密，被解密的数据包含多个分组，解密后的明文保存到指定的缓冲区中。
		 SKF_DecryptUpdate对多个分组数据进行解密，在调用 SKF_DecryptUpdate之前，必须调用 SKF_DecryptInit初始化解密操作；
		在调用 SKF_DecryptUpdate之后，必须调用 SKF_DecryptFinal结束解密操作。
	 *	hKey			[IN] 解密密钥句柄
	 *	pbEncryptedData [IN] 待解密数据
	 *	ulEncryptedLen	[IN] 待解密数据长度
	 *	pbData			[OUT] 指向解密后的数据缓冲区指针
	 *	pulDataLen		[IN，OUT] 返回解密后的数据长度
	 */
        public static native long SKF_DecryptUpdate(
            HANDLE hKey,
            byte[]	pbEncryptedData,
            byte[]  pbData,
            long[] pulDataLen
    );

        /*
         *	结束多个分组数据的解密。
         *	hKey				[IN] 解密密钥句柄
         *	pbPlainText			[OUT] 指向解密结果的缓冲区，如果此参数为NULL时，由pulPlainTextLen返回解密结果的长度
         *	pulDecyptedDataLen	[IN，OUT] 调用时表示pbPlainText缓冲区的长度，返回解密结果的长度
         */
        public static native long SKF_DecryptFinal(
            HANDLE hKey,
            byte[] pbPlainText,
            long[] pulDecyptedDataLen
    );

        /*
         *	初始化消息杂凑计算操作，指定计算消息杂凑的算法。
         *	hDev			[IN] 连接设备时返回的设备句柄
         *	ulAlgID			[IN] 杂凑算法标识
         *	phHash			[OUT] 杂凑对象句柄
         */
        public static native long SKF_DigestInit(
            DEVHANDLE	hDev,
            long		ulAlgID,
            ECCPUBLICKEYBLOB pPubKey,
            byte[] pucID,
            HANDLE	phHash
	);
        /*
         *	对单一分组的消息进行杂凑计算。
         *	hHash			[IN] 杂凑对象句柄
         *	pbData			[IN] 指向消息数据的缓冲区
         *	ulDataLen		[IN] 消息数据的长度
         *	pbHashData		[OUT] 杂凑数据缓冲区指针，当此参数为NULL时，由pulHashLen返回杂凑结果的长度
         *	pulHashLen		[IN，OUT] 调用时表示pbHashData缓冲区的长度，返回杂凑结果的长度
         */
        public static native long SKF_Digest(
            HANDLE hHash,
            byte[] pbData,
            byte[] pbHashData,
            long[] pulHashLen
    );

        /*
         *	对多个分组的消息进行杂凑计算。
         *	hHash			[IN] 杂凑对象句柄
         *	pbPart			[IN] 指向消息数据的缓冲区
         *	ulPartLen		[IN] 消息数据的长度
         */
        public static native long SKF_DigestUpdate(
            HANDLE hHash,
            byte[] pbData
    );

        /*
         *	结束多个分组消息的杂凑计算操作，将杂凑保存到指定的缓冲区。
         *	hHash			[IN] 哈希对象句柄
         *	pHashData		[OUT] 返回的杂凑数据缓冲区指针，如果此参数NULL时，由pulHashLen返回杂凑结果的长度
         *	pulHashLen		[IN，OUT] 调用时表示杂凑结果的长度，返回杂凑数据的长度
         */
        public static native long SKF_DigestFinal(
            HANDLE hHash,
            byte[] pHashData,
            long[] pulHashLen
    );

        /*
         *	初始化消息认证码计算操作，设置计算消息认证码的密钥参数，并返回消息认证码句柄。
         *	hKey			[IN] 计算消息认证码的密钥句柄
         *	MacParam		[IN] 消息认证计算相关参数，包括初始向量、初始向量长度、填充方法等
         *	phMac			[OUT] 消息认证码对象句柄
         */
        public static native long SKF_MacInit(
            HANDLE hKey,
            BLOCKCIPHERPARAM MacParam,
            HANDLE phMac
    );

        /*
         *	 SKF_Mac计算单一分组数据的消息认证码。
         *	hMac			[IN] 消息认证码句柄
         *	pbData			[IN] 指向待计算数据的缓冲区
         *	ulDataLen		[IN] 待计算数据的长度
         *	pbMacData		[OUT] 指向计算后的Mac结果，如果此参数为NULL时，由pulMacLen返回计算后Mac结果的长度
         *	pulMacLen		[IN，OUT] 调用时表示pbMacData缓冲区的长度，返回计算Mac结果的长度
         */
        public static native long SKF_Mac(
            HANDLE hMac,
            byte[] pbData,
            byte[] pbMacData,
            long[] pulMacLen
    );

        /*
         *	计算多个分组数据的消息认证码。
         *	hMac			[IN] 消息认证码句柄
         *	pbData			[IN] 指向待计算数据的缓冲区
         *	plDataLen		[IN] 待计算数据的长度
         */
        public static native long SKF_MacUpdate(
            HANDLE hMac,
            byte[] pbData
    );

        /*
         *	结束多个分组数据的消息认证码计算操作
         *	hMac			[IN] 消息认证码句柄
         *	pbMacData		[OUT] 指向消息认证码的缓冲区，当此参数为NULL时，由pulMacDataLen返回消息认证码返回的长度
         *	pulMacDataLen	[OUT] 调用时表示消息认证码缓冲区的最大长度，返回消息认证码的长度
         */
        public static native long SKF_MacFinal(
            HANDLE hMac,
            byte[] pbMacData,
            long[] pulMacDataLen
    );

        /*
         *	关闭会话密钥、杂凑、消息认证码句柄。
         *	hHandle			[IN] 要关闭的对象句柄
         */
        public static native long SKF_CloseHandle(
            HANDLE hHandle
    );

        /*
         *	将命令直接发送给设备，并返回结果
         *	hDev			[IN] 设备句柄
         *	pbCommand		[IN] 设备命令
         *	ulCommandLen	[IN] 命令长度
         *	pbData			[OUT] 返回结果数据
         *	pulDataLen		[OUT] 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度
         */
        public static native long SKF_Transmit(
            DEVHANDLE hDev,
            byte[] pbCommand,
            byte[] pbData,
            long[] pulDataLen
    );

        /*
         *	往容器中导入签名证书或者加密证书
         *	hContainer		[IN] 容器句柄
         *	bSignFlag		[IN] TRUE表示导入签名证书，FALSE表示导入加密证书
         *	pbCert			[IN] 指向证书数据的缓冲区
         *	ulCertLen		[IN] 证书数据的长度
         */
        public static native long SKF_ImportCertificate(
            HCONTAINER hContainer,
            boolean bSignFlag,
            byte[] pbCert
    );

        /*
         *	导出容器中的签名证书或者加密证书
         *	hContainer		[IN] 容器句柄
         *	bSignFlag		[IN] TRUE表示导出签名证书，FALSE表示导出加密证书
         *	pbCert			[OUT] 指向证书数据的缓冲区
         *	pulCertLen		[IN,OUT] 调用时表示pbCert的长度，返回导出证书的大小
         */
        public static native long SKF_ExportCertificate(
            HCONTAINER hContainer,
            boolean bSignFlag,
            byte[] pbCert,
            long[] pulCertLen
    );

        /*
         *	获取容器的属性
         *	hContainer		[IN] 容器句柄
         *	pulConProperty	[OUT] 获得的容器属性。指针指向的值为0表示未知、尚未分配属性或者为空容器，为1表示为RSA容器，为2表示为ECC容器。
         */
        public static native long SKF_GetContainerProperty(
            HCONTAINER hContainer,
            long[] pulConProperty
    );

    public static native long SKF_CreateSoftCard();

    public static native long SKF_DeleteSoftCard();

}
