//
// Created by wjr on 19-4-18.
//

SKF_FUNCTION(ULONG,SKF_WaitForDevEvent)
#ifdef SKF_NEED_ARGS
(
        OUT LPSTR szDevName,
        OUT ULONG *pulDevNameLen,
        OUT ULONG *pulEvent
);
#endif

/*
 *	取消等待设备的插拔事件
 */
SKF_FUNCTION(ULONG,SKF_CancelWaitForDevEvent)
#ifdef SKF_NEED_ARGS
();
#endif

/*
 *	获得当前系统中的设备列表
 *	bPresent		[IN]为TRUE表示取当前设备状态为存在的设备列表。为FALSE表示取当前驱动支持的设备列表
 *	szNameList		[OUT]设备名称列表。如果该参数为NULL，将由pulSize返回所需要的内存空间大小。每个设备的名称以单个'\0'结束，以双'\0'表示列表的结束
 *	pulSize			[IN,OUT]输入参数，输入设备名称列表的缓冲区长度，输出参数，返回szNameList所需要的空间大小
 */
SKF_FUNCTION(ULONG,SKF_EnumDev)
#ifdef SKF_NEED_ARGS
(
        IN BOOL bPresent,
        OUT LPSTR szNameList,
        OUT ULONG* pulSize
);
#endif

/*
 *	通过设备名称连接设备，返回设备的句柄
 *	szName		[IN]设备名称
 *	phDev		[OUT]返回设备操作句柄
 */
SKF_FUNCTION(ULONG,SKF_ConnectDev)
#ifdef SKF_NEED_ARGS
(
        IN LPSTR szName,
        OUT DEVHANDLE* phDev
);
#endif

/*
 *	断开一个已经连接的设备，并释放句柄。
 *	hDev		[IN]连接设备时返回的设备句柄
 */
SKF_FUNCTION(ULONG,SKF_DisConnectDev)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE hDev
);

#endif
/*
 *	获取设备是否存在的状态
 *	szDevName	[IN]连接名称
 *	pulDevState	[OUT]返回设备状态
 */
SKF_FUNCTION(ULONG,SKF_GetDevState)
#ifdef SKF_NEED_ARGS
(
        IN  LPSTR	 szDevName,
        OUT ULONG* pulDevState
);

#endif

/*
 *	设置设备标签
 *	hDev		[IN]连接设备时返回的设备句柄
 *	szLabel		[OUT]设备标签字符串。该字符串应小于32字节
 */
SKF_FUNCTION(ULONG,SKF_SetLabel)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE hDev,
        IN LPSTR szLabel
);

#endif

/*
 *	获取设备的一些特征信息，包括设备标签、厂商信息、支持的算法等
 *	hDev		[IN]连接设备时返回的设备句柄
 *	pDevInfo	[OUT]返回设备信息
 */
SKF_FUNCTION(ULONG,SKF_GetDevInfo)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE	hDev,
        OUT PDEVINFO	pDevInfo
);

#endif
/*
 *	获得设备的独占使用权
 *	hDev		[IN]连接设备时返回的设备句柄
 *	ulTimeOut	[IN]超时时间，单位为毫秒。如果为0xFFFFFFFF表示无限等待
 */
SKF_FUNCTION(ULONG,SKF_LockDev)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE	hDev,
        IN ULONG ulTimeOut
);

#endif
/*
 *	释放对设备的独占使用权
 *	hDev		[IN]连接设备时返回的设备句柄
 */
SKF_FUNCTION(ULONG,SKF_UnlockDev)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE	hDev
);

#endif


/************************************************************************/
/*  2. 访问控制				                                            */
/*	SKF_ChangeDevAuthKey												*/
/*	SKF_DevAuth															*/
/*	SKF_ChangePIN														*/
/*	SKF_GetPINInfo														*/
/*	SKF_VerifyPIN														*/
/*	SKF_UnblockPIN														*/
/*	SKF_ClearSecureState												*/
/************************************************************************/

/*
 *	更改设备认证密钥
 *	hDev		[IN]连接时返回的设备句柄
 *	pbKeyValue	[IN]密钥值
 *	ulKeyLen	[IN]密钥长度
 */
SKF_FUNCTION(ULONG,SKF_ChangeDevAuthKey)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE	hDev,
        IN BYTE		*pbKeyValue,
        IN ULONG		ulKeyLen
);

#endif
/*
 *	设备认证是设备对应用程序的认证
 *	hDev			[IN]连接时返回的设备句柄
 *	pbAuthData		[IN]认证数据
 *	ulLen			[IN]认证数据的长度
 */
SKF_FUNCTION(ULONG,SKF_DevAuth)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE	hDev,
        IN BYTE*		pbAuthData,
        IN ULONG		ulLen
);

#endif
/*
 *	修改PIN，可以修改Admin和User的PIN，如果原PIN错误，返回剩余重试次数，当剩余次数为0时，表示PIN已经被锁死
 *	hApplication	[IN]应用句柄
 *	ulPINType		[IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
 *	szOldPIN		[IN]原PIN值
 *	szNewPIN		[IN]新PIN值
 *	pulRetryCount	[OUT]出错后重试次数
 */
SKF_FUNCTION(ULONG,SKF_ChangePIN)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication,
        IN ULONG			ulPINType,
        IN LPSTR			szOldPIN,
        IN LPSTR			szNewPIN,
        OUT ULONG*		pulRetryCount
);

#endif
/*
 *	获取PIN码信息，包括最大重试次数、当前剩余重试次数，以及当前PIN码是否为出厂默认PIN码
 *	hApplication		[IN]应用句柄
 *	ulPINType			[IN]PIN类型
 *	pulMaxRetryCount	[OUT]最大重试次数
 *	pulRemainRetryCount	[OUT]当前剩余重试次数，当为0时表示已锁死
 *	pbDefaultPin		[OUT]是否为出厂默认PIN码
 */
SKF_FUNCTION(ULONG,SKF_GetPINInfo)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication,
        IN ULONG			ulPINType,
        OUT ULONG*		pulMaxRetryCount,
        OUT ULONG*		pulRemainRetryCount,
        OUT BOOL*			pbDefaultPin
);

#endif
/*
 *	校验PIN码。校验成功后，会获得相应的权限，如果PIN码错误，会返回PIN码的重试次数，当重试次数为0时表示PIN码已经锁死
 *	hApplication	[IN]应用句柄
 *	ulPINType		[IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
 *	szPIN			[IN]PIN值
 *	pulRetryCount	[OUT]出错后返回的重试次数
 */
SKF_FUNCTION(ULONG,SKF_VerifyPIN)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication,
        IN ULONG			ulPINType,
        IN LPSTR			szPIN,
        OUT ULONG*		pulRetryCount
);

#endif
/*
 *	当用户的PIN码锁死后，通过调用该函数来解锁用户PIN码。
 *	解锁后，用户PIN码被设置成新值，用户PIN码的重试次数也恢复到原值。
 *	hApplication	[IN]应用句柄
 *	szAdminPIN		[IN]管理员PIN码
 *	szNewUserPIN	[IN]新的用户PIN码
 *	pulRetryCount	[OUT]管理员PIN码错误时，返回剩余重试次数
 */
SKF_FUNCTION(ULONG,SKF_UnblockPIN)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szAdminPIN,
        IN LPSTR			szNewUserPIN,
        OUT ULONG*		pulRetryCount
);

#endif
/*
 *	清除应用当前的安全状态
 *	hApplication	[IN]应用句柄
 */
SKF_FUNCTION(ULONG,SKF_ClearSecureState)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication
);

#endif
/************************************************************************/
/*  3. 应用管理				                                            */
/*	SKF_CreateApplication												*/
/*	SKF_EnumApplication													*/
/*	SKF_DeleteApplication												*/
/*	SKF_OpenApplication													*/
/*	SKF_CloseApplication												*/
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
SKF_FUNCTION(ULONG,SKF_CreateApplication)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE		hDev,
        IN LPSTR			szAppName,
        IN LPSTR			szAdminPIN,
        IN DWORD			dwAdminPinRetryCount,
        IN LPSTR			szUserPIN,
        IN DWORD			dwUserPinRetryCount,
        IN DWORD			dwCreateFileRights,
        OUT HAPPLICATION*	phApplication
);

#endif
/*
 *	枚举设备中所存在的所有应用
 *	hDev			[IN]连接设备时返回的设备句柄
 *	szAppName		[OUT]返回应用名称列表, 如果该参数为空，将由pulSize返回所需要的内存空间大小。
 *						 每个应用的名称以单个'\0'结束，以双'\0'表示列表的结束。
 *	pulSize			[IN,OUT]输入参数，输入应用名称的缓冲区长度，输出参数，返回szAppName所占用的的空间大小
 */
SKF_FUNCTION(ULONG,SKF_EnumApplication)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE		hDev,
        OUT LPSTR			szAppName,
        OUT ULONG*		pulSize
);

#endif
/*
 *	删除指定的应用
 *	hDev			[IN]连接设备时返回的设备句柄
 *	szAppName		[IN]应用名称
 */
SKF_FUNCTION(ULONG,SKF_DeleteApplication)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE		hDev,
        IN LPSTR			szAppName
);

#endif
/*
 *	打开指定的应用
 *	hDev			[IN]连接设备时返回的设备句柄
 *	szAppName		[IN]应用名称
 *	phApplication	[OUT]应用的句柄
 */
SKF_FUNCTION(ULONG,SKF_OpenApplication)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE		hDev,
        IN LPSTR			szAppName,
        OUT HAPPLICATION*	phApplication
);

#endif

/*
 *	关闭应用并释放应用句柄
 *	hApplication	[IN]应用的句柄
 */
SKF_FUNCTION(ULONG,SKF_CloseApplication)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication
);

#endif


/************************************************************************/
/*  4. 文件管理				                                            */
/*	SKF_CreateFile														*/
/*	SKF_DeleteFile														*/
/*	SKF_EnumFiles														*/
/*	SKF_GetFileInfo														*/
/*	SKF_ReadFile														*/
/*	SKF_WriteFile														*/
/************************************************************************/

/*
 *	创建一个文件。创建文件时要指定文件的名称，大小，以及文件的读写权限
 *	hApplication		[IN]应用句柄
 *	szFileName			[IN]文件名称，长度不得大于32个字节
 *	ulFileSize			[IN]文件大小
 *	ulReadRights		[IN]文件读权限
 *	ulWriteRights		[IN]文件写权限
 */
SKF_FUNCTION(ULONG,SKF_CreateFile)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szFileName,
        IN ULONG			ulFileSize,
        IN ULONG			ulReadRights,
        IN ULONG			ulWriteRights
);

#endif
/*
 *	删除指定文件，文件删除后，文件中写入的所有信息将丢失。文件在设备中的占用的空间将被释放。
 *	hApplication		[IN]要删除文件所在的应用句柄
 *	szFileName			[IN]要删除文件的名称
 */
SKF_FUNCTION(ULONG,SKF_DeleteFile)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szFileName
);

#endif
/*
 *	枚举一个应用下存在的所有文件
 *	hApplication		[IN]应用的句柄
 *	szFileList			[OUT]返回文件名称列表，该参数为空，由pulSize返回文件信息所需要的空间大小。每个文件名称以单个'\0'结束，以双'\0'表示列表的结束。
 *	pulSize				[OUT]输入为数据缓冲区的大小，输出为实际文件名称的大小
 */
SKF_FUNCTION(ULONG,SKF_EnumFiles)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication,
        OUT LPSTR			szFileList,
        OUT ULONG*		pulSize
);

#endif
/*
 *	获取应用文件的属性信息，例如文件的大小、权限等
 *	hApplication		[IN]文件所在应用的句柄
 *	szFileName			[IN]文件名称
 *	pFileInfo			[OUT]文件信息，指向文件属性结构的指针
 */
SKF_FUNCTION(ULONG,SKF_GetFileInfo)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION		hApplication,
        IN LPSTR				szFileName,
        OUT FILEATTRIBUTE*	pFileInfo
);

#endif
/*
 *	读取文件内容
 *	hApplication		[IN]文件所在的应用句柄
 *	szFileName			[IN]文件名
 *	ulOffset			[IN]文件读取偏移位置
 *	ulSize				[IN]要读取的长度
 *	pbOutData			[OUT]返回数据的缓冲区
 *	pulOutLen			[OUT]输入表示给出的缓冲区大小；输出表示实际读取返回的数据大小
 */
SKF_FUNCTION(ULONG,SKF_ReadFile)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szFileName,
        IN ULONG			ulOffset,
        IN ULONG			ulSize,
        OUT BYTE*			pbOutData,
        OUT ULONG*		pulOutLen
);

#endif
/*
 *	写数据到文件中
 *	hApplication		[IN]文件所在的应用句柄
 *	szFileName			[IN]文件名
 *	ulOffset			[IN]写入文件的偏移量
 *	pbData				[IN]写入数据缓冲区
 *	ulSize				[IN]写入数据的大小
 */
SKF_FUNCTION(ULONG,SKF_WriteFile)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szFileName,
        IN ULONG			ulOffset,
        IN BYTE*			pbData,
        IN ULONG			ulSize
);

#endif

/************************************************************************/
/*  5. 容器管理				                                            */
/*	SKF_CreateContainer													*/
/*	SKF_DeleteContainer													*/
/*	SKF_OpenContainer													*/
/*	SKF_CloseContainer													*/
/*	SKF_EnumContainer													*/
/************************************************************************/

/*
 *	在应用下建立指定名称的容器并返回容器句柄
 *	hApplication		[IN]应用句柄
 *	szContainerName		[IN]ASCII字符串，表示所建立容器的名称，容器名称的最大长度不能超过64字节
 *	phContainer			[OUT]返回所建立容器的容器句柄
 */
SKF_FUNCTION(ULONG,SKF_CreateContainer)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szContainerName,
        OUT HCONTAINER*	phContainer
);

#endif
/*
 *	在应用下删除指定名称的容器并释放容器相关的资源
 *	hApplication		[IN]应用句柄
 *	szContainerName		[IN]指向删除容器的名称
 */
SKF_FUNCTION(ULONG,SKF_DeleteContainer)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szContainerName
);

#endif

/*
 *	获取容器句柄
 *	hApplication		[IN]应用句柄
 *	szContainerName		[IN]容器名称
 *	phContainer			[OUT]返回所打开容器的句柄
 */
SKF_FUNCTION(ULONG,SKF_OpenContainer)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szContainerName,
        OUT HCONTAINER*	phContainer
);

#endif
/*
 *	关闭容器句柄，并释放容器句柄相关资源
 *	hContainer			[OUT]容器句柄
 */
SKF_FUNCTION(ULONG,SKF_CloseContainer)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer
);

#endif
/*
 *	枚举应用下的所有容器并返回容器名称列表
 *	hApplication		[IN]应用句柄
 *	szContainerName		[OUT]指向容器名称列表缓冲区，如果此参数为NULL时，pulSize表示返回数据所需要缓冲区的长度，如果此参数不为NULL时，返回容器名称列表，每个容器名以单个'\0'为结束，列表以双'\0'结束
 *	pulSize				[OUT]调用前表示szContainerName缓冲区的长度，返回容器名称列表的长度
 */
SKF_FUNCTION(ULONG,SKF_EnumContainer)
#ifdef SKF_NEED_ARGS
(
        IN HAPPLICATION	hApplication,
        OUT LPSTR			szContainerName,
        OUT ULONG*		pulSize
);

#endif
/*
 *	功能描述	获取容器的类型
 *	hContainer	[IN]容器句柄。
 *	pulContainerType	[OUT] 获得的容器类型。指针指向的值为0表示未定、尚未分配类型或者为空容器，为1表示为RSA容器，为2表示为SM2容器。
 *
 */
SKF_FUNCTION(ULONG,SKF_GetContainerType)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer,
        OUT ULONG *pulContainerType
);

#endif
/************************************************************************/
/*  6. 密码服务				                                            */
/*	SKF_GetRandom														*/
/*	SKF_GenExtRSAKey													*/
/*	SKF_GenRSAKeyPair													*/
/*	SKF_ImportRSAKeyPair												*/
/*	SKF_RSASignData														*/
/*	SKF_RSAVerify														*/
/*	SKF_RSAExportSessionKey												*/
/*	SKF_ExtRSAPubKeyOperation											*/
/*	SKF_ExtRSAPriKeyOperation											*/
/*	SKF_GenECCKeyPair													*/
/*	SKF_ImportECCKeyPair												*/
/*	SKF_ECCSignData														*/
/*	SKF_ECCVerify														*/
/*	SKF_ECCExportSessionKey												*/
/*	SKF_ExtECCEncrypt													*/
/*	SKF_ExtECCDecrypt													*/
/*	SKF_ExtECCSign														*/
/*	SKF_ExtECCVerify													*/
/*	SKF_ExportPublicKey													*/
/*	SKF_ImportSessionKey												*/
/*	SKF_SetSymmKey														*/
/*	SKF_EncryptInit														*/
/*	SKF_Encrypt															*/
/*	SKF_EncryptUpdate													*/
/*	SKF_EncryptFinal													*/
/*	SKF_DecryptInit														*/
/*	SKF_Decrypt															*/
/*	SKF_DecryptUpdate													*/
/*	SKF_DecryptFinal													*/
/*	SKF_DegistInit														*/
/*	SKF_Degist															*/
/*	SKF_DegistUpdate													*/
/*	SKF_DegistFinal														*/
/*	SKF_MACInit															*/
/*	SKF_MAC																*/
/*	SKF_MACUpdate														*/
/*	SKF_MACFinal														*/
/************************************************************************/

/*
 *	产生指定长度的随机数
 *	hDev			[IN] 设备句柄
 *	pbRandom		[OUT] 返回的随机数
 *	ulRandomLen		[IN] 随机数长度
 */
SKF_FUNCTION(ULONG,SKF_GenRandom)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE hDev,
        OUT BYTE *pbRandom,
        IN ULONG ulRandomLen
);

#endif

/*
 *	由设备生成RSA密钥对并明文输出
 *	hDev			[IN] 设备句柄
 *	ulBitsLen		[IN] 密钥模长
 *	pBlob			[OUT] 返回的私钥数据结构
 */
SKF_FUNCTION(ULONG,SKF_GenExtRSAKey)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE hDev,
        IN ULONG ulBitsLen,
        OUT RSAPRIVATEKEYBLOB* pBlob
);

#endif
/*
 *	生成RSA签名密钥对并输出签名公钥
 *	hContainer		[IN] 容器句柄
 *	ulBitsLen		[IN] 密钥模长
 *	pBlob			[OUT] 返回的RSA公钥数据结构
 */
SKF_FUNCTION(ULONG,SKF_GenRSAKeyPair)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer,
        IN ULONG ulBitsLen,
        OUT RSAPUBLICKEYBLOB *pBlob
);

#endif

/*
 *	导入RSA加密公私钥对
 *	hContainer		[IN] 容器句柄
 *	ulSymAlgId		[IN] 对称算法密钥标识
 *	pbWrappedKey	[IN] 使用该容器内签名公钥保护的对称算法密钥
 *	ulWrappedKeyLen	[IN] 保护的对称算法密钥长度
 *	pbEncryptedData	[IN] 对称算法密钥保护的RSA加密私钥。私钥的格式遵循PKCS #1 v2.1: RSA Cryptography Standard中的私钥格式定义
 *	ulEncryptedDataLen	[IN] 对称算法密钥保护的RSA加密公私钥对长度
 */
SKF_FUNCTION(ULONG,SKF_ImportRSAKeyPair)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer,
        IN ULONG ulSymAlgId,
        IN BYTE *pbWrappedKey,
        IN ULONG ulWrappedKeyLen,
        IN BYTE *pbEncryptedData,
        IN ULONG ulEncryptedDataLen
);

#endif
/*
 *	使用hContainer指定容器的签名私钥，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名的长度
 *	hContainer		[IN] 用来签名的私钥所在容器句柄
 *	pbData			[IN] 被签名的数据
 *	ulDataLen		[IN] 签名数据长度，应不大于RSA密钥模长-11
 *	pbSignature		[OUT] 存放签名结果的缓冲区指针，如果值为NULL，用于取得签名结果长度
 *	pulSigLen		[IN,OUT] 输入为签名结果缓冲区大小，输出为签名结果长度
 */
SKF_FUNCTION(ULONG,SKF_RSASignData)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hContainer,
        IN BYTE *pbData,
        IN ULONG ulDataLen,
        OUT BYTE *pbSignature,
        OUT ULONG *pulSigLen
);

#endif
/*
 *	验证RSA签名。用pRSAPubKeyBlob内的公钥值对待验签数据进行验签。
 *	hDev			[IN] 连接设备时返回的设备句柄
 *	pRSAPubKeyBlob	[IN] RSA公钥数据结构
 *	pbData			[IN] 待验证签名的数据
 *	ulDataLen		[IN] 数据长度，应不大于公钥模长-11
 *	pbSignature		[IN] 待验证的签名值
 *	ulSigLen		[IN] 签名值长度，必须为公钥模长
 */
SKF_FUNCTION(ULONG,SKF_RSAVerify)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE			hDev,
        IN RSAPUBLICKEYBLOB*	pRSAPubKeyBlob,
        IN BYTE*				pbData,
        IN ULONG				ulDataLen,
        IN BYTE*				pbSignature,
        IN ULONG				ulSigLen
);

#endif

/*
 *	生成会话密钥并用外部公钥加密输出。
 *	hContainer		[IN] 容器句柄
 *	ulAlgID			[IN] 会话密钥的算法标识
 *	pPubKey			[IN] 加密会话密钥的RSA公钥数据结构
 *	pbData			[OUT] 导出的加密会话密钥密文，按照PKCS#1v1.5的要求封装
 *	pulDataLen		[OUT] 返回导出数据长度
 *	phSessionKey	[OUT] 导出的密钥句柄
 */
SKF_FUNCTION(ULONG,SKF_RSAExportSessionKey)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer,
        IN ULONG ulAlgID,
        IN RSAPUBLICKEYBLOB* pPubKey,
        OUT BYTE* pbData,
        OUT ULONG* pulDataLen,
        OUT HANDLE* phSessionKey
);

#endif

/*
 *	使用外部传入的RSA公钥对输入数据做公钥运算并输出结果
 *	hDev			[IN] 设备句柄
 *	pRSAPubKeyBlob	[IN] RSA公钥数据结构
 *	pbInput			[IN] 指向待运算的原始数据缓冲区
 *	ulInputLen		[IN] 待运算原始数据的长度，必须为公钥模长
 *	pbOutput		[OUT] 指向RSA公钥运算结果缓冲区，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
 *	pulOutputLen	[OUT] 调用前表示pbOutput缓冲区的长度，返回RSA公钥运算结果的实际长度
 */
SKF_FUNCTION(ULONG,SKF_ExtRSAPubKeyOperation)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE hDev,
        IN RSAPUBLICKEYBLOB* pRSAPubKeyBlob,
        IN BYTE* pbInput,
        IN ULONG ulInputLen,
        OUT BYTE* pbOutput,
        OUT ULONG* pulOutputLen
);

#endif
/*
 *	直接使用外部传入的RSA私钥对输入数据做私钥运算并输出结果
 *	hDev			[IN] 设备句柄
 *	pRSAPriKeyBlob	[IN] RSA私钥数据结构
 *	pbInput			[IN] 指向待运算数据缓冲区
 *	ulInputLen		[IN] 待运算数据的长度，必须为公钥模长
 *	pbOutput		[OUT] RSA私钥运算结果，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
 *	pulOutputLen	[OUT] 调用前表示pbOutput缓冲区的长度，返回RSA私钥运算结果的实际长度
 */
SKF_FUNCTION(ULONG,SKF_ExtRSAPriKeyOperation)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE hDev,
        IN RSAPRIVATEKEYBLOB* pRSAPriKeyBlob,
        IN BYTE* pbInput,
        IN ULONG ulInputLen,
        OUT BYTE* pbOutput,
        OUT ULONG* pulOutputLen
);

#endif
/*
 *	生成ECC签名密钥对并输出签名公钥。
 *	hContainer		[IN] 容器句柄
 *	ulBitsLen		[IN] 密钥模长
 *	pBlob			[OUT] 返回ECC公钥数据结构
 */
SKF_FUNCTION(ULONG,SKF_GenECCKeyPair)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer,
        IN ULONG ulAlgId,
        OUT ECCPUBLICKEYBLOB *pBlob
);

#endif
/*
 *	导入ECC公私钥对
 *	hContainer		[IN] 容器句柄
 *	pbWrapedData	[IN] 加密保护的ECC加密公私钥对密文
 *	ulWrapedLen		[IN] 数据长度
 */
SKF_FUNCTION(ULONG,SKF_ImportECCKeyPair)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer,
        IN PENVELOPEDKEYBLOB pEnvelopedKeyBlob
);

#endif
/*
 *	ECC数字签名。采用ECC算法和指定私钥hKey，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名值的长度
 *	hContainer		[IN] 用来签名的私钥所在容器句柄
 *	pbData			[IN] 被签名的数据
 *	ulDataLen		[IN] 待签名数据长度，必须小于密钥模长
 *	pbSignature		[OUT] 签名值，为NULL时用于获得签名值的长度
 *	pulSigLen		[IN,OUT] 返回签名值长度的指针
 */
SKF_FUNCTION(ULONG,SKF_ECCSignData)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hContainer,
        IN BYTE *pbData,
        IN ULONG ulDataLen,
        OUT PECCSIGNATUREBLOB pSignature
);

#endif

/*
 *	用ECC公钥对数据进行验签
 *	hDev			[IN] 设备句柄
 *	pECCPubKeyBlob	[IN] ECC公钥数据结构
 *	pbData			[IN] 待验证签名的数据
 *	ulDataLen		[IN] 数据长度
 *	pbSignature		[IN] 待验证的签名值
 *	ulSigLen		[IN] 签名值长度
 */
SKF_FUNCTION(ULONG,SKF_ECCVerify)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE			hDev,
        IN ECCPUBLICKEYBLOB*	pECCPubKeyBlob,
        IN BYTE*				pbData,
        IN ULONG				ulDataLen,
        IN PECCSIGNATUREBLOB pSignature
);

#endif
/*
 *	生成会话密钥并用外部公钥加密输出。
 *	hContainer		[IN] 容器句柄
 *	ulAlgID			[IN] 会话密钥的算法标识
 *	pPubKey			[IN] 外部输入的公钥结构
 *	pbData			[OUT] 导出的加密会话密钥密文
 *	phSessionKey	[OUT] 会话密钥句柄
 */
SKF_FUNCTION(ULONG,SKF_ECCExportSessionKey)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer,
        IN ULONG ulAlgID,
        IN ECCPUBLICKEYBLOB* pPubKey,
        OUT PECCCIPHERBLOB pData,
        OUT HANDLE* phSessionKey
);

#endif
/*
 *	使用外部传入的ECC公钥对输入数据做加密运算并输出结果
 *	hDev			[IN] 设备句柄
 *	pECCPubKeyBlob	[IN] ECC公钥数据结构
 *	pbPlainText		[IN] 待加密的明文数据
 *	ulPlainTextLen	[IN] 待加密明文数据的长度
 *	pbCipherText	[OUT] 指向密文数据缓冲区，如果该参数为NULL，则由pulCipherTextLen返回密文数据的实际长度
 *	pulCipherTextLen[OUT] 调用前表示pbCipherText缓冲区的长度，返回密文数据的实际长度
 */
SKF_FUNCTION(ULONG,SKF_ExtECCEncrypt)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE hDev,
        IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
        IN BYTE* pbPlainText,
        IN ULONG ulPlainTextLen,
        OUT PECCCIPHERBLOB pbCipherText
);

#endif
/*
 *	使用外部传入的ECC私钥对输入数据做解密运算并输出结果
 *	hDev			[IN] 设备句柄
 *	pRSAPriKeyBlob	[IN] ECC私钥数据结构
 *	pbInput			[IN] 待解密的密文数据
 *	ulInputLen		[IN] 待解密密文数据的长度
 *	pbOutput		[OUT] 返回明文数据，如果该参数为NULL，则由pulPlainTextLen返回明文数据的实际长度
 *	pulOutputLen	[OUT] 调用前表示pbPlainText缓冲区的长度，返回明文数据的实际长度
 */
SKF_FUNCTION(ULONG,SKF_ExtECCDecrypt)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE hDev,
        IN ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
        IN PECCCIPHERBLOB pbCipherText,
        OUT BYTE* pbPlainText,
        OUT ULONG* pulPlainTextLen
);

#endif

/*
 *	使用外部传入的ECC私钥对输入数据做签名运算并输出结果。
 *	hDev			[IN] 设备句柄
 *	pRSAPriKeyBlob	[IN] ECC私钥数据结构
 *	pbData			[IN] 待签名数据
 *	ulDataLen		[IN] 待签名数据的长度
 *	pbSignature		[OUT] 签名值，如果该参数为NULL，则由pulSignatureLen返回签名结果的实际长度
 *	pulSignatureLen	[OUT] 调用前表示pbSignature缓冲区的长度，返回签名结果的实际长度
 */
SKF_FUNCTION(ULONG,SKF_ExtECCSign)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE hDev,
        IN ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
        IN BYTE* pbData,
        IN ULONG ulDataLen,
        OUT PECCSIGNATUREBLOB pSignature
);

#endif
/*
 *	外部使用传入的ECC公钥做签名验证
 *	hDev			[IN] 设备句柄
 *	pECCPubKeyBlob	[IN] ECC公钥数据结构
 *	pbData			[IN] 待验证数据
 *	ulDataLen		[IN] 待验证数据的长度
 *	pbSignature		[OUT] 签名值
 *	ulSignLen		[OUT] 签名值的长度
 */
SKF_FUNCTION(ULONG,SKF_ExtECCVerify)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE hDev,
        IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
        IN BYTE* pbData,
        IN ULONG ulDataLen,
        IN PECCSIGNATUREBLOB pSignature
);

#endif
/*
 *	使用ECC密钥协商算法，为计算会话密钥而产生协商参数，返回临时ECC密钥对的公钥及协商句柄
 *	hContainer		[IN] 容器句柄
 *	ulAlgId			[IN] 会话密钥算法标识
 *	pTempECCPubKeyBlob	[OUT] 发起方临时ECC公钥
 *	pbID			[IN] 发起方的ID
 *	ulIDLen			[IN] 发起方ID的长度，不大于32
 *	phAgreementHandle	[OUT] 返回的密钥协商句柄
 */
SKF_FUNCTION(ULONG,SKF_GenerateAgreementDataWithECC)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer,
        IN ULONG ulAlgId,
        OUT ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
        IN BYTE* pbID,
        IN ULONG ulIDLen,
        OUT HANDLE *phAgreementHandle
);

#endif
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
SKF_FUNCTION(ULONG,SKF_GenerateAgreementDataAndKeyWithECC)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hContainer,
        IN ULONG ulAlgId,
        IN ECCPUBLICKEYBLOB* pSponsorECCPubKeyBlob,
        IN ECCPUBLICKEYBLOB* pSponsorTempECCPubKeyBlob,
        OUT ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
        IN BYTE* pbID,
        IN ULONG ulIDLen,
        IN BYTE *pbSponsorID,
        IN ULONG ulSponsorIDLen,
        OUT HANDLE *phKeyHandle
);

#endif
/*
 *	使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥，同时返回会话密钥句柄
 *	hAgreementHandle			[IN] 密钥协商句柄
 *	pECCPubKeyBlob				[IN] 外部输入的响应方ECC公钥
 *	pTempECCPubKeyBlob			[IN] 外部输入的响应方临时ECC公钥
 *	pbID						[IN] 响应方的ID
 *	ulIDLen						[IN] 响应方ID的长度，不大于32
 *	phKeyHandle					[OUT] 返回的密钥句柄
 */
SKF_FUNCTION(ULONG,SKF_GenerateKeyWithECC)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hAgreementHandle,
        IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
        IN ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
        IN BYTE* pbID,
        IN ULONG ulIDLen,
        OUT HANDLE *phKeyHandle
);

#endif
/*
 *	导出容器中的签名公钥或者加密公钥
 *	hContainer		[IN] 容器句柄
 *	bSignFlag		[IN] TRUE表示导出签名公钥，FALSE表示导出加密公钥
 *	pbBlob			[OUT] 指向RSA公钥结构（RSAPUBLICKEYBLOB）或者ECC公钥结构（ECCPUBLICKEYBLOB），如果此参数为NULL时，由pulBlobLen返回pbBlob的长度
 *	pulBlobLen		[IN,OUT] 调用时表示pbBlob的长度，返回导出公钥结构的大小
 */
SKF_FUNCTION(ULONG,SKF_ExportPublicKey)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer,
        IN BOOL bSignFlag,
        OUT BYTE* pbBlob,
        OUT ULONG* pulBlobLen
);

#endif
/*
 *	导入会话密钥
 *	hContainer		[IN] 容器句柄
 *	ulAlgID			[IN] 会话密钥的算法标识
 *	pbWrapedData	[IN] 要导入的数据
 *	ulWrapedLen		[IN] 数据长度
 *	phKey			[OUT] 返回会话密钥句柄
 */
SKF_FUNCTION(ULONG,SKF_ImportSessionKey)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer,
        IN ULONG ulAlgID,
        IN BYTE *pbWrapedData,
        IN ULONG ulWrapedLen,
        OUT HANDLE* phKey
);

#endif
/*
 *	设置明文对称密钥，返回密钥句柄
 *	hContainer		[IN] 容器句柄
 *	pbKey			[IN] 指向会话密钥值的缓冲区
 *	ulAlgID			[IN] 会话密钥的算法标识
 *	phKey			[OUT] 返回会话密钥句柄
 */
SKF_FUNCTION(ULONG,SKF_SetSymmKey)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE hDev,
        IN BYTE* pbKey,
        IN ULONG ulAlgID,
        OUT HANDLE* phKey
);

#endif
/*
 *	数据加密初始化。设置数据加密的算法相关参数。
 *	hKey			[IN] 加密密钥句柄
 *	EncryptParam	[IN] 分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
 */
SKF_FUNCTION(ULONG,SKF_EncryptInit)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hKey,
        IN BLOCKCIPHERPARAM EncryptParam
);

#endif
/*
 *	单一分组数据的加密操作。
    用指定加密密钥对指定数据进行加密，被加密的数据只包含一个分组，加密后的密文保存到指定的缓冲区中。
    SKF_Encrypt只对单个分组数据进行加密，在调用SKF_Encrypt之前，必须调用SKF_EncryptInit初始化加密操作。
    SKF_Encypt等价于先调用SKF_EncryptUpdate再调用SKF_EncryptFinal。
 *	hKey			[IN] 加密密钥句柄
 *	pbData			[IN] 待加密数据
 *	ulDataLen		[IN] 待加密数据长度
 *	pbEncryptedData [OUT] 加密后的数据缓冲区指针
 *	pulEncryptedLen [IN,OUT] 输入，给出的缓冲区大小；输出，返回加密后的数据
长度
 *	成功: SAR_OK
 *	失败: SAR_FAIL SAR_MEMORYERR SAR_UNKNOWNERR  SAR_INVALIDPARAMERR SAR_BUFFER_TOO_SMALL
 */
SKF_FUNCTION(ULONG,SKF_Encrypt)
#ifdef SKF_NEED_ARGS
(
        HANDLE	hKey,
        BYTE*		pbData,
        ULONG		ulDataLen,
        BYTE*		pbEncryptedData,
        ULONG*	pulEncryptedLen
);

#endif

/*
 *	多个分组数据的加密操作。
    用指定加密密钥对指定数据进行加密，被加密的数据包含多个分组，加密后的密文保存到指定的缓冲区中。
    SKF_EncryptUpdate对多个分组数据进行加密，在调用SKF_EncryptUpdate之前，必须调用SKF_EncryptInit初始化加密操作；
    在调用SKF_EncryptUpdate之后，必须调用SKF_EncryptFinal结束加密操作。
 *	hKey			[IN] 加密密钥句柄
 *	pbData			[IN] 待加密数据
 *	ulDataLen		[IN] 待加密数据长度
 *	pbEncryptedData [OUT] 加密后的数据缓冲区指针
 *	pulEncryptedLen [OUT] 返回加密后的数据长度
 */
SKF_FUNCTION(ULONG,SKF_EncryptUpdate)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE		hKey,
        IN BYTE*		pbData,
        IN ULONG		ulDataLen,
        OUT BYTE*		pbEncryptedData,
        OUT ULONG*	pulEncryptedLen
);

#endif
/*
 *	结束多个分组数据的加密，返回剩余加密结果。
    先调用SKF_EncryptInit初始化加密操作，
    再调用SKF_EncryptUpdate对多个分组数据进行加密，
    最后调用SKF_EncryptFinal结束多个分组数据的加密。
 *	hKey			[IN] 加密密钥句柄
 *	pbEncryptedData [OUT] 加密结果的缓冲区
 *	pulEncryptedLen [OUT] 加密结果的长度
 */
SKF_FUNCTION(ULONG,SKF_EncryptFinal)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hKey,
        OUT BYTE *pbEncryptedData,
        OUT ULONG *pulEncryptedDataLen
);

#endif
/*
 *	数据解密初始化，设置解密密钥相关参数。
    调用SKF_DecryptInit之后，可以调用SKF_Decrypt对单个分组数据进行解密，
    也可以多次调用SKF_DecryptUpdate之后再调用SKF_DecryptFinal完成对多个分组数据的解密。
 *	hKey [IN] 解密密钥句柄
 *	DecryptParam [IN] 分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
 */
SKF_FUNCTION(ULONG,SKF_DecryptInit)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hKey,
        IN BLOCKCIPHERPARAM DecryptParam
);

#endif
/*
 *	单个分组数据的解密操作
    用指定解密密钥对指定数据进行解密，被解密的数据只包含一个分组，解密后的明文保存到指定的缓冲区中
    SKF_Decrypt只对单个分组数据进行解密，在调用SKF_Decrypt之前，必须调用SKF_DecryptInit初始化解密操作
    SKF_Decypt等价于先调用SKF_DecryptUpdate再调用SKF_DecryptFinal
 *	hKey			[IN] 解密密钥句柄
 *	pbEncryptedData [IN] 待解密数据
 *	ulEncryptedLen	[IN] 待解密数据长度
 *	pbData			[OUT] 指向解密后的数据缓冲区指针，当为NULL时可获得解密后的数据长度
 *	pulDataLen		[IN，OUT] 返回解密后的数据长度
 */
SKF_FUNCTION(ULONG,SKF_Decrypt)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hKey,
        IN BYTE*	pbEncryptedData,
        IN ULONG	ulEncryptedLen,
        OUT BYTE* pbData,
        OUT ULONG* pulDataLen
);

#endif
/*
*	多个分组数据的解密操作。
    用指定解密密钥对指定数据进行解密，被解密的数据包含多个分组，解密后的明文保存到指定的缓冲区中。
    SKF_DecryptUpdate对多个分组数据进行解密，在调用SKF_DecryptUpdate之前，必须调用SKF_DecryptInit初始化解密操作；
    在调用SKF_DecryptUpdate之后，必须调用SKF_DecryptFinal结束解密操作。
 *	hKey			[IN] 解密密钥句柄
 *	pbEncryptedData [IN] 待解密数据
 *	ulEncryptedLen	[IN] 待解密数据长度
 *	pbData			[OUT] 指向解密后的数据缓冲区指针
 *	pulDataLen		[IN，OUT] 返回解密后的数据长度
 */
SKF_FUNCTION(ULONG,SKF_DecryptUpdate)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hKey,
        IN BYTE*	pbEncryptedData,
        IN ULONG	ulEncryptedLen,
        OUT BYTE* pbData,
        OUT ULONG* pulDataLen
);

#endif
/*
 *	结束多个分组数据的解密。
 *	hKey				[IN] 解密密钥句柄
 *	pbPlainText			[OUT] 指向解密结果的缓冲区，如果此参数为NULL时，由pulPlainTextLen返回解密结果的长度
 *	pulDecyptedDataLen	[IN，OUT] 调用时表示pbPlainText缓冲区的长度，返回解密结果的长度
 */
SKF_FUNCTION(ULONG,SKF_DecryptFinal)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hKey,
        OUT BYTE *pbPlainText,
        OUT ULONG *pulPlainTextLen
);

#endif
/*
 *	初始化消息杂凑计算操作，指定计算消息杂凑的算法。
 *	hDev			[IN] 连接设备时返回的设备句柄
 *	ulAlgID			[IN] 杂凑算法标识
 *	phHash			[OUT] 杂凑对象句柄
 */
SKF_FUNCTION(ULONG,SKF_DigestInit)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE	hDev,
        IN ULONG		ulAlgID,
        IN ECCPUBLICKEYBLOB *pPubKey,
        IN unsigned char *pucID,
        IN ULONG ulIDLen,
        OUT HANDLE*	phHash
);

#endif
/*
 *	对单一分组的消息进行杂凑计算。
 *	hHash			[IN] 杂凑对象句柄
 *	pbData			[IN] 指向消息数据的缓冲区
 *	ulDataLen		[IN] 消息数据的长度
 *	pbHashData		[OUT] 杂凑数据缓冲区指针，当此参数为NULL时，由pulHashLen返回杂凑结果的长度
 *	pulHashLen		[IN，OUT] 调用时表示pbHashData缓冲区的长度，返回杂凑结果的长度
 */
SKF_FUNCTION(ULONG,SKF_Digest)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hHash,
        IN BYTE *pbData,
        IN ULONG ulDataLen,
        OUT BYTE *pbHashData,
        OUT ULONG *pulHashLen
);

#endif
/*
 *	对多个分组的消息进行杂凑计算。
 *	hHash			[IN] 杂凑对象句柄
 *	pbPart			[IN] 指向消息数据的缓冲区
 *	ulPartLen		[IN] 消息数据的长度
 */
SKF_FUNCTION(ULONG,SKF_DigestUpdate)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hHash,
        IN BYTE *pbData,
        IN ULONG ulDataLen
);

#endif
/*
 *	结束多个分组消息的杂凑计算操作，将杂凑保存到指定的缓冲区。
 *	hHash			[IN] 哈希对象句柄
 *	pHashData		[OUT] 返回的杂凑数据缓冲区指针，如果此参数NULL时，由pulHashLen返回杂凑结果的长度
 *	pulHashLen		[IN，OUT] 调用时表示杂凑结果的长度，返回杂凑数据的长度
 */
SKF_FUNCTION(ULONG,SKF_DigestFinal)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hHash,
        OUT BYTE *pHashData,
        OUT ULONG *pulHashLen
);

#endif
/*
 *	初始化消息认证码计算操作，设置计算消息认证码的密钥参数，并返回消息认证码句柄。
 *	hKey			[IN] 计算消息认证码的密钥句柄
 *	MacParam		[IN] 消息认证计算相关参数，包括初始向量、初始向量长度、填充方法等
 *	phMac			[OUT] 消息认证码对象句柄
 */
SKF_FUNCTION(ULONG,SKF_MacInit)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hKey,
        IN BLOCKCIPHERPARAM* MacParam,
        OUT HANDLE *phMac
);

#endif
/*
 *	SKF_Mac计算单一分组数据的消息认证码。
 *	hMac			[IN] 消息认证码句柄
 *	pbData			[IN] 指向待计算数据的缓冲区
 *	ulDataLen		[IN] 待计算数据的长度
 *	pbMacData		[OUT] 指向计算后的Mac结果，如果此参数为NULL时，由pulMacLen返回计算后Mac结果的长度
 *	pulMacLen		[IN，OUT] 调用时表示pbMacData缓冲区的长度，返回计算Mac结果的长度
 */
SKF_FUNCTION(ULONG,SKF_Mac)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hMac,
        IN BYTE * pbData,
        IN ULONG ulDataLen,
        OUT BYTE *pbMacData,
        OUT ULONG *pulMacLen
);

#endif
/*
 *	计算多个分组数据的消息认证码。
 *	hMac			[IN] 消息认证码句柄
 *	pbData			[IN] 指向待计算数据的缓冲区
 *	plDataLen		[IN] 待计算数据的长度
 */
SKF_FUNCTION(ULONG,SKF_MacUpdate)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hMac,
        IN BYTE*	pbData,
        IN ULONG	ulDataLen
);

#endif
/*
 *	结束多个分组数据的消息认证码计算操作
 *	hMac			[IN] 消息认证码句柄
 *	pbMacData		[OUT] 指向消息认证码的缓冲区，当此参数为NULL时，由pulMacDataLen返回消息认证码返回的长度
 *	pulMacDataLen	[OUT] 调用时表示消息认证码缓冲区的最大长度，返回消息认证码的长度
 */
SKF_FUNCTION(ULONG,SKF_MacFinal)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hMac,
        OUT BYTE*	pbMacData,
        OUT ULONG* pulMacDataLen
);

#endif
/*
 *	关闭会话密钥、杂凑、消息认证码句柄。
 *	hHandle			[IN] 要关闭的对象句柄
 */
SKF_FUNCTION(ULONG,SKF_CloseHandle)
#ifdef SKF_NEED_ARGS
(
        IN HANDLE hHandle
);

#endif
/*
 *	将命令直接发送给设备，并返回结果
 *	hDev			[IN] 设备句柄
 *	pbCommand		[IN] 设备命令
 *	ulCommandLen	[IN] 命令长度
 *	pbData			[OUT] 返回结果数据
 *	pulDataLen		[OUT] 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度
 */
SKF_FUNCTION(ULONG,SKF_Transmit)
#ifdef SKF_NEED_ARGS
(
        IN DEVHANDLE hDev,
        IN BYTE* pbCommand,
        IN ULONG ulCommandLen,
        OUT BYTE* pbData,
        OUT ULONG* pulDataLen
);

#endif
/*
 *	往容器中导入签名证书或者加密证书
 *	hContainer		[IN] 容器句柄
 *	bSignFlag		[IN] TRUE表示导入签名证书，FALSE表示导入加密证书
 *	pbCert			[IN] 指向证书数据的缓冲区
 *	ulCertLen		[IN] 证书数据的长度
 */
SKF_FUNCTION(ULONG,SKF_ImportCertificate)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer,
        IN BOOL bSignFlag,
        IN BYTE* pbCert,
        IN ULONG ulCertLen
);

#endif
/*
 *	导出容器中的签名证书或者加密证书
 *	hContainer		[IN] 容器句柄
 *	bSignFlag		[IN] TRUE表示导出签名证书，FALSE表示导出加密证书
 *	pbCert			[OUT] 指向证书数据的缓冲区
 *	pulCertLen		[IN,OUT] 调用时表示pbCert的长度，返回导出证书的大小
 */
SKF_FUNCTION(ULONG,SKF_ExportCertificate)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer,
        IN BOOL bSignFlag,
        OUT BYTE* pbCert,
        IN OUT ULONG* pulCertLen
);

#endif
/*
 *	获取容器的属性
 *	hContainer		[IN] 容器句柄
 *	pulConProperty	[OUT] 获得的容器属性。指针指向的值为0表示未知、尚未分配属性或者为空容器，为1表示为RSA容器，为2表示为ECC容器。
 */
SKF_FUNCTION(ULONG,SKF_GetContainerProperty)
#ifdef SKF_NEED_ARGS
(
        IN HCONTAINER hContainer,
        OUT ULONG *pulConProperty
);

#endif