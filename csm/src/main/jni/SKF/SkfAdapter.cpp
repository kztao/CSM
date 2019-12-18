#include "SkfAdapter.h"
#include "skfLibLoader.h"
#include "skf_info_cache.h"
#include "skf_soft_util.h"
#include <dlfcn.h>

/********************************************************
 *
 *
 *skf 映射表管理
 *
 *
 * *********************************************************/
#if 1
#include <android/log.h>
#define SKF_DEBUG(...) __android_log_print(ANDROID_LOG_INFO,"skf_adapter",__VA_ARGS__)
void SKF_DEBUG_DATA(char *data,int len){
    string s;
    char num[3] = {0};
    for(int i = 0;i < len;i++){
        sprintf(num,"%02x",(data[i] & 0xFF));
        s.append(num);
        if((i + 1) % 16 == 0){
            s.append("\n");
            continue;
        }

        if((i + 1) % 4 == 0){
            s.append(" ");
        }

    }

    SKF_DEBUG("data[%d]",len);
    SKF_DEBUG("%s",s.c_str());
}

#endif

static auto skfLibLoaderp11 = new skfLibLoader((char*)"libServer.so");
static auto skfLibLoaderxindun = new skfLibLoader((char*)"libSafetyCardLib.so");


static unsigned int devNameSq = 1;
static unsigned long devHandleSq = 1;
static unsigned long appHandleSq = 1;
static unsigned long containerHandleSq = 1;
static unsigned long handleSq = 1;

static map<string,skf_info_cache_devname*> mapDevName;
static map<DEVHANDLE ,skf_info_cache_devhandle*> mapDevHandle;
static map<HAPPLICATION ,skf_info_cache_apphandle*> mapAppHandle;
static map<HCONTAINER ,skf_info_cache_containerhandle*> mapContainerHandle;
static map<HANDLE,skf_info_cache_handle*> mapHandle;

//
static multimap<string,SkfAdapterStatusDevName*> adapterStatusDevName;
static multimap<string,SkfAdapterStatusDevHandle*> adapterStatusDevHandle;
static multimap<string,SkfAdapterStatusAppHandle*> adapterStatusAppHandle;
static multimap<string,SkfAdapterStatusContainerHandle*> adapterStatusContainerHandle;

//
static string callerName;
void setCallerName(string name){
    callerName = std::move(name);
}


bool checkDevExist(SKFFunctionList_PTR ptr,LPSTR lpstr){
    auto itMapDevName = mapDevName.begin();
    for(;itMapDevName != mapDevName.end();itMapDevName++){
        if(itMapDevName->second->m_skfFunctionList_ptr == ptr && itMapDevName->second->name == lpstr){
            return true;
        }
    }

    return false;
}


static bool devEnumFlg = false;

static void devEnum(){

    LPSTR szNameList_p11 = NULL;
    ULONG ulSize_p11 = 0;

    LPSTR szNameList_soft = NULL;
    ULONG ulSize_soft = 0;

    LPSTR szNameList_xindun = NULL;
    ULONG ulSize_xindun = 0;

    ULONG ret = 0;
    char sqStr[100] = {0};


    string outStr;
    const char pad[1] = {0};

    ret = skfLibLoaderxindun->SKF_GetFunctionList()->SKF_EnumDev(true,szNameList_xindun,&ulSize_xindun);
    if(ret == 0 && ulSize_xindun > 0){
        szNameList_xindun = new char[ulSize_xindun];
        ret = skfLibLoaderxindun->SKF_GetFunctionList()->SKF_EnumDev(true,szNameList_xindun,&ulSize_xindun);
        SKF_DEBUG("skfFunctionList_ptr_xindun->SKF_EnumDev----------");
        SKF_DEBUG_DATA(szNameList_xindun,ulSize_xindun);
        char *tmp = szNameList_xindun;

        while(tmp[0] != 0){
            if(!checkDevExist(skfLibLoaderxindun->SKF_GetFunctionList(),tmp)){
                skf_info_cache_devname *skfInfoCacheDevname = new skf_info_cache_devname();
                skfInfoCacheDevname->m_skfFunctionList_ptr = skfLibLoaderxindun->SKF_GetFunctionList();
                skfInfoCacheDevname->name = tmp;
                char num[100] = {0};
                sprintf(num,"%08x",devNameSq++);
                mapDevName.insert(make_pair(num,skfInfoCacheDevname));
            }

            tmp += strlen(tmp) + 1;
        }
    }

    ret = skfLibLoaderp11->SKF_GetFunctionList()->SKF_EnumDev(true,szNameList_p11,&ulSize_p11);
    if(ret == 0 && ulSize_p11 > 0){
        szNameList_p11 = new char[ulSize_p11];
        ret = skfLibLoaderp11->SKF_GetFunctionList()->SKF_EnumDev(true,szNameList_p11,&ulSize_p11);
        SKF_DEBUG("skfFunctionList_ptr_p11->SKF_EnumDev----------");
        SKF_DEBUG_DATA(szNameList_p11,ulSize_p11);
        char *tmp = szNameList_p11;

        while(tmp[0] != 0){
            if(!checkDevExist(skfLibLoaderp11->SKF_GetFunctionList(),tmp)){
                skf_info_cache_devname *skfInfoCacheDevname = new skf_info_cache_devname();
                skfInfoCacheDevname->m_skfFunctionList_ptr = skfLibLoaderp11->SKF_GetFunctionList();
                skfInfoCacheDevname->name = tmp;
                char num[100] = {0};
                sprintf(num,"%08x",devNameSq++);
                mapDevName.insert(make_pair(num,skfInfoCacheDevname));
            }

            tmp += strlen(tmp) + 1;
        }
    }

    SKF_DEBUG("%s ,dev size = %d END",__FUNCTION__,mapDevName.size());
}

static void devUninit(){

    devEnumFlg = false;
    for(auto it = mapDevName.begin();it != mapDevName.end();){
        delete it->second;
        it->second = NULL;
        mapDevName.erase(it);

        devNameSq = 1;
        devHandleSq = 1;
        appHandleSq = 1;
        containerHandleSq = 1;
        handleSq = 1;
    }
}


/********************************************************
 *
 *
 *skf 映射表管理
 *
 *
 * *********************************************************/

ULONG Adapter_SKF_WaitForDevEvent(LPSTR szDevName,ULONG *pulDevNameLen,ULONG *pulEvent)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }
    return 0;
}
/*
 *	取消等待设备的插拔事件
 */
ULONG Adapter_SKF_CancelWaitForDevEvent()
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }
    return 0;
}
/*
 *	获得当前系统中的设备列表
 *	bPresent		[IN]为TRUE表示取当前设备状态为存在的设备列表。为FALSE表示取当前驱动支持的设备列表
 *	szNameList		[OUT]设备名称列表。如果该参数为NULL，将由pulSize返回所需要的内存空间大小。每个设备的名称以单个'\0'结束，以双'\0'表示列表的结束
 *	pulSize			[IN,OUT]输入参数，输入设备名称列表的缓冲区长度，输出参数，返回szNameList所需要的空间大小
 */
ULONG Adapter_SKF_EnumDev(BOOL bPresent,LPSTR szNameList,ULONG* pulSize)
{
    SKF_DEBUG("%s IN,mapDevName size = %d",__FUNCTION__,mapDevName.size());
    if(NULL == pulSize){
        return SAR_INVALIDPARAMERR;
    }

    devEnum();

    string s;
    char pad[1] = {0};

    for(auto & it : mapDevName){
        s.append(it.first);
        s.append(pad,1);
    }

    if(!mapDevName.empty()){
        s.append(pad,1);
    }

    *pulSize = s.size();
    if(szNameList){
        memcpy(szNameList,s.data(),s.size());
    }

    auto itAdapterStatusDevName = adapterStatusDevName.find(callerName);
    if(itAdapterStatusDevName == adapterStatusDevName.end()){
        for(auto itn = mapDevName.begin();itn != mapDevName.end();itn++){
            SkfAdapterStatusDevName *statusDevName = new SkfAdapterStatusDevName();
            statusDevName->devName = itn->first;
            statusDevName->status = SKF_STATUS_DEV_DISCONNECT;
            adapterStatusDevName.insert(make_pair(callerName,statusDevName));
        }
    }

    devEnumFlg = true;
    SKF_DEBUG("%s END",__FUNCTION__);
    return 0;
}

/*
 *	通过设备名称连接设备，返回设备的句柄
 *	szName		[IN]设备名称
 *	phDev		[OUT]返回设备操作句柄
 */
ULONG Adapter_SKF_ConnectDev(LPSTR szName,DEVHANDLE* phDev)
{
    SKF_DEBUG("%s IN",__FUNCTION__);

    if(NULL == szName || NULL == phDev){
        return SAR_INVALIDPARAMERR;
    }

    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    auto itAdapterStatusDevName = adapterStatusDevName.find(callerName);
    for(;itAdapterStatusDevName != adapterStatusDevName.end();itAdapterStatusDevName++){
        if(itAdapterStatusDevName->first != callerName){
            break;
        }

        if(itAdapterStatusDevName->second->devName == szName){
            break;
        }
    }

    if(itAdapterStatusDevName == adapterStatusDevName.end() || itAdapterStatusDevName->first != callerName){
        SKF_DEBUG("%s IN,not find dev name",__FUNCTION__);
        return SAR_INVALIDPARAMERR;
    }

    auto itMapDevName = mapDevName.find(szName);
    if(itMapDevName == mapDevName.end()){
        SKF_DEBUG("%s IN,not find dev name2",__FUNCTION__);
        return SAR_INVALIDPARAMERR;
    }

    DEVHANDLE devhandle;
    ULONG ret = itMapDevName->second->m_skfFunctionList_ptr->SKF_ConnectDev((LPSTR)itMapDevName->second->name.c_str(),&devhandle);
    if(ret != SAR_OK){
        SKF_DEBUG("%s IN,SKF_ConnectDev ret = 0x%08x",__FUNCTION__,ret);
        return ret;
    }

    auto itMapDevHandle = mapDevHandle.begin();

    for(;itMapDevHandle != mapDevHandle.end();itMapDevHandle++){
        if(itMapDevHandle->second->devhandle == devhandle && itMapDevHandle->second->skfInfoCacheDevname == itMapDevName->second){
            break;
        }
    }

    if(itMapDevHandle == mapDevHandle.end()){
        skf_info_cache_devhandle *cacheDevhandle = new skf_info_cache_devhandle();
        cacheDevhandle->skfInfoCacheDevname = itMapDevName->second;
        cacheDevhandle->devhandle = devhandle;
        *phDev = (DEVHANDLE)devHandleSq++;
        mapDevHandle.insert(make_pair(*phDev,cacheDevhandle));
    } else{
        *phDev = itMapDevHandle->first;
    }


    auto itAdapterStatusDevHandle = adapterStatusDevHandle.find(callerName);
    for(;itAdapterStatusDevHandle != adapterStatusDevHandle.end();itAdapterStatusDevHandle++){
        if(itAdapterStatusDevHandle->first != callerName){
            break;
        }

        if(itAdapterStatusDevHandle->second->devhandle == *phDev){
            itAdapterStatusDevHandle->second->devName->status |= SKF_STATUS_DEV_CONNECT;
            return SAR_OK;
        }
    }

    if(itAdapterStatusDevHandle == adapterStatusDevHandle.end() || itAdapterStatusDevHandle->first != callerName){
        SkfAdapterStatusDevHandle *statusDevHandle = new SkfAdapterStatusDevHandle();
        statusDevHandle->devhandle = *phDev;
        statusDevHandle->devName = itAdapterStatusDevName->second;
        statusDevHandle->devName->status |= SKF_STATUS_DEV_CONNECT;
        adapterStatusDevHandle.insert(make_pair(callerName,statusDevHandle));
    }

    SKF_DEBUG("%s OUT OK",__FUNCTION__);
    return SAR_OK;
}

/*
 *	断开一个已经连接的设备，并释放句柄。
 *	hDev		[IN]连接设备时返回的设备句柄
 */
ULONG Adapter_SKF_DisConnectDev(DEVHANDLE hDev)
{
    SKF_DEBUG("%s IN,hDev = %p,mapDevHandle size = %d",__FUNCTION__,hDev,mapDevHandle.size());

    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusDevHandle = adapterStatusDevHandle.find(callerName);
    for(;itAdapterStatusDevHandle != adapterStatusDevHandle.end();itAdapterStatusDevHandle++){
        if(itAdapterStatusDevHandle->first != callerName){
            break;
        }

        if(itAdapterStatusDevHandle->second->devhandle == hDev && itAdapterStatusDevHandle->second->devName->status >= SKF_STATUS_DEV_CONNECT){
            break;
        }
    }

    if(itAdapterStatusDevHandle == adapterStatusDevHandle.end() || itAdapterStatusDevHandle->first != callerName){
        SKF_DEBUG("%s IN,dev handle invalid",__FUNCTION__);
        return SAR_INVALIDPARAMERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();){
        if(itAdapterStatusContainerHandle->first != callerName){
            break;
        }

        if(itAdapterStatusContainerHandle->second->appHandle->devHandle == itAdapterStatusDevHandle->second){
            delete itAdapterStatusContainerHandle->second;
            adapterStatusContainerHandle.erase(itAdapterStatusContainerHandle++);
        } else{
            itAdapterStatusContainerHandle++;
        }
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);
    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();){
        if(itAdapterStatusAppHandle->first != callerName){
            break;
        }

        if(itAdapterStatusAppHandle->second->devHandle == itAdapterStatusDevHandle->second){
            //删除应用缓存
            delete itAdapterStatusAppHandle->second;
            adapterStatusAppHandle.erase(itAdapterStatusAppHandle++);
        } else{
            itAdapterStatusAppHandle++;
        }
    }

    itAdapterStatusDevHandle->second->devName->status = SKF_STATUS_DEV_DISCONNECT;
    delete itAdapterStatusDevHandle->second;
    adapterStatusDevHandle.erase(itAdapterStatusDevHandle);

    auto itFindAdapterStatusDevHandle = adapterStatusDevHandle.begin();
    for(;itFindAdapterStatusDevHandle != adapterStatusDevHandle.end();itFindAdapterStatusDevHandle++){
        if(itFindAdapterStatusDevHandle->first != callerName && itFindAdapterStatusDevHandle->second->devhandle == hDev){
            return SAR_OK;
        }
    }

    auto itMapDevHandle = mapDevHandle.find(hDev);
    if(itMapDevHandle == mapDevHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    ULONG ret = itMapDevHandle->second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_DisConnectDev(itMapDevHandle->second->devhandle);
    if(ret != SAR_OK){
        return ret;
    }

    for(auto itMapContainerHandle = mapContainerHandle.begin();itMapContainerHandle!= mapContainerHandle.end();){
        if(itMapContainerHandle->second->skfInfoCacheApphandle->skfInfoCacheDevhandle == itMapDevHandle->second){
            delete itMapContainerHandle->second;
            mapContainerHandle.erase(itMapContainerHandle++);
        } else{
            itMapContainerHandle++;
        }
    }

    for(auto itMapAppHandle = mapAppHandle.begin();itMapAppHandle!= mapAppHandle.end();){
        if(itMapAppHandle->second->skfInfoCacheDevhandle == itMapDevHandle->second){
            delete itMapAppHandle->second;
            mapAppHandle.erase(itMapAppHandle++);
        } else{
            itMapAppHandle++;
        }
    }

    delete itMapDevHandle->second;
    mapDevHandle.erase(itMapDevHandle);

    return SAR_OK;
}

/*
 *	获取设备是否存在的状态
 *	szDevName	[IN]连接名称
 *	pulDevState	[OUT]返回设备状态
 */
ULONG Adapter_SKF_GetDevState(LPSTR	 szDevName,ULONG* pulDevState)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == szDevName || NULL == pulDevState){
        return SAR_INVALIDPARAMERR;
    }

    auto mapIterator = adapterStatusDevName.find(callerName);
    for(;mapIterator != adapterStatusDevName.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devName == szDevName){
            break;
        }
    }

    if(mapIterator == adapterStatusDevName.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevName){
        if(it.first == szDevName){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_GetDevState((LPSTR)it.second->name.c_str(),pulDevState);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDPARAMERR;
}

/*
 *	设置设备标签
 *	hDev		[IN]连接设备时返回的设备句柄
 *	szLabel		[OUT]设备标签字符串。该字符串应小于32字节
 */
ULONG Adapter_SKF_SetLabel(DEVHANDLE hDev,LPSTR szLabel)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev || NULL == szLabel){
        return SAR_INVALIDPARAMERR;
    }

    auto itAdapterStatusDevHandle = adapterStatusDevHandle.find(callerName);
    for(;itAdapterStatusDevHandle != adapterStatusDevHandle.end();itAdapterStatusDevHandle++){
        if(itAdapterStatusDevHandle->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(itAdapterStatusDevHandle->second->devhandle == hDev){
            break;
        }
    }

    if(itAdapterStatusDevHandle == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto it = mapDevHandle.begin();it != mapDevHandle.end();it++){
        if(it->first == hDev){
            ULONG ret = it->second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_SetLabel(it->second->devhandle,szLabel);
            if(ret != SAR_OK){
                return ret;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	获取设备的一些特征信息，包括设备标签、厂商信息、支持的算法等
 *	hDev		[IN]连接设备时返回的设备句柄
 *	pDevInfo	[ ]返回设备信息
 */
ULONG Adapter_SKF_GetDevInfo(DEVHANDLE	hDev,PDEVINFO	pDevInfo)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev || NULL == pDevInfo){
        return SAR_INVALIDPARAMERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_GetDevInfo(it.second->devhandle,pDevInfo);
            if(ret != SAR_OK){
                return ret;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	获得设备的独占使用权
 *	hDev		[IN]连接设备时返回的设备句柄
 *	ulTimeOut	[IN]超时时间，单位为毫秒。如果为0xFFFFFFFF表示无限等待
 */
ULONG Adapter_SKF_LockDev(DEVHANDLE	hDev,ULONG ulTimeOut)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDPARAMERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            SKF_DEBUG("%s IN,not find dev handle!!",__FUNCTION__);
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        SKF_DEBUG("%s IN,not find dev handle!!",__FUNCTION__);
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_LockDev(it.second->devhandle,ulTimeOut);
            if(ret != SAR_OK){
                return ret;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	释放对设备的独占使用权
 *	hDev		[IN]连接设备时返回的设备句柄
 */
ULONG Adapter_SKF_UnlockDev(DEVHANDLE hDev)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }
    if(NULL == hDev){
        return SAR_INVALIDPARAMERR;
    }

    auto itdh = adapterStatusDevHandle.find(callerName);
    for(;itdh != adapterStatusDevHandle.end();itdh++){
        if(itdh->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(itdh->second->devhandle == hDev){
            break;
        }
    }

    if(itdh == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_UnlockDev(it.second->devhandle);
            if(ret != SAR_OK){
                return ret;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}


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
ULONG Adapter_SKF_ChangeDevAuthKey(DEVHANDLE hDev,BYTE* pbKeyValue,ULONG ulKeyLen)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev || NULL == pbKeyValue || ulKeyLen != 16){
        return SAR_INVALIDHANDLEERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ChangeDevAuthKey(it.second->devhandle,pbKeyValue,ulKeyLen);
            if(ret != SAR_OK){
                return ret;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	设备认证是设备对应用程序的认证
 *	hDev			[IN]连接时返回的设备句柄
 *	pbAuthData		[IN]认证数据
 *	ulLen			[IN]认证数据的长度
 */
ULONG Adapter_SKF_DevAuth(DEVHANDLE	hDev,BYTE *pbAuthData,ULONG ulLen)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev || NULL == pbAuthData || ulLen != 16){
        return SAR_INVALIDHANDLEERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_DevAuth(it.second->devhandle,pbAuthData,ulLen);
            if(ret != SAR_OK){
                return ret;
            }

            mapIterator->second->devName->status |= SKF_STATUS_DEV_AUTH;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	修改PIN，可以修改Admin和User的PIN，如果原PIN错误，返回剩余重试次数，当剩余次数为0时，表示PIN已经被锁死
 *	hApplication	[IN]应用句柄
 *	ulPINType		[IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
 *	szOldPIN		[IN]原PIN值
 *	szNewPIN		[IN]新PIN值
 *	pulRetryCount	[OUT]出错后重试次数
 */
ULONG Adapter_SKF_ChangePIN(
        HAPPLICATION	hApplication,
        ULONG			ulPINType,
        LPSTR			szOldPIN,
        LPSTR			szNewPIN,
        ULONG*		pulRetryCount
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapAppHandle){
        if(it.first == hApplication){
            ULONG ret = it.second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ChangePIN(it.second->happlication,ulPINType,szOldPIN,szNewPIN,pulRetryCount);
            if(ret != SAR_OK){
                return ret;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	获取PIN码信息，包括最大重试次数、当前剩余重试次数，以及当前PIN码是否为出厂默认PIN码
 *	hApplication		[IN]应用句柄
 *	ulPINType			[IN]PIN类型
 *	pulMaxRetryCount	[OUT]最大重试次数
 *	pulRemainRetryCount	[OUT]当前剩余重试次数，当为0时表示已锁死
 *	pbDefaultPin		[OUT]是否为出厂默认PIN码
 */
ULONG Adapter_SKF_GetPINInfo(HAPPLICATION hApplication,ULONG ulPINType,ULONG *pulMaxRetryCount,
        ULONG *pulRemainRetryCount,BOOL *pbDefaultPin)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);

    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status >= SKF_STATUS_APP_OPEN){
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto it = mapAppHandle.begin();it != mapAppHandle.end();it++){
        if(it->first == hApplication){
            ULONG ret = it->second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_GetPINInfo(it->second->happlication,ulPINType,pulMaxRetryCount,pulRemainRetryCount,pbDefaultPin);
            if(ret != SAR_OK){
                return ret;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	校验PIN码。校验成功后，会获得相应的权限，如果PIN码错误，会返回PIN码的重试次数，当重试次数为0时表示PIN码已经锁死
 *	hApplication	[IN]应用句柄
 *	ulPINType		[IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
 *	szPIN			[IN]PIN值
 *	pulRetryCount	[OUT]出错后返回的重试次数
 */
ULONG Adapter_SKF_VerifyPIN(HAPPLICATION	hApplication,
        ULONG			ulPINType,
        LPSTR			szPIN,
        ULONG*		pulRetryCount
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);

    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status >= SKF_STATUS_APP_OPEN){
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto it = mapAppHandle.begin();it != mapAppHandle.end();it++){
        if(it->first == hApplication){
            ULONG ret = it->second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_VerifyPIN(it->second->happlication,ulPINType,szPIN,pulRetryCount);
            if(ret != SAR_OK){
                return ret;
            }

            if(ulPINType == ADMIN_TYPE){
                itAdapterStatusAppHandle->second->status |= SKF_STATUS_APP_LOGGIN_ADMIN;
            }

            if(ulPINType == USER_TYPE){
                itAdapterStatusAppHandle->second->status |= SKF_STATUS_APP_LOGGIN_USR;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	当用户的PIN码锁死后，通过调用该函数来解锁用户PIN码。
 *	解锁后，用户PIN码被设置成新值，用户PIN码的重试次数也恢复到原值。
 *	hApplication	[IN]应用句柄
 *	szAdminPIN		[IN]管理员PIN码
 *	szNewUserPIN	[IN]新的用户PIN码
 *	pulRetryCount	[OUT]管理员PIN码错误时，返回剩余重试次数
 */
ULONG Adapter_SKF_UnblockPIN(HAPPLICATION	hApplication,
        LPSTR			szAdminPIN,
        LPSTR			szNewUserPIN,
        ULONG*		pulRetryCount
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);

    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status >= SKF_STATUS_APP_OPEN){
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto it = mapAppHandle.begin();it != mapAppHandle.end();it++){
        if(it->first == hApplication){
            ULONG ret = it->second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_UnblockPIN(it->second->happlication,szAdminPIN,szNewUserPIN,pulRetryCount);
            if(ret != SAR_OK){
                return ret;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	清除应用当前的安全状态
 *	hApplication	[IN]应用句柄
 */
ULONG Adapter_SKF_ClearSecureState(
        HAPPLICATION	hApplication
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);
    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status >= SKF_STATUS_APP_LOGGIN_ADMIN){
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_UNKNOWNERR;
    }

    itAdapterStatusAppHandle->second->status = SKF_STATUS_APP_OPEN;

    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status >= SKF_STATUS_APP_LOGGIN_ADMIN){
            return SAR_OK;
        }
    }

    for(auto it = mapAppHandle.begin();it != mapAppHandle.end();it++){
        if(it->first == hApplication){
            ULONG ret = it->second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ClearSecureState(it->second->happlication);
            if(ret != SAR_OK){
                return ret;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

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
ULONG Adapter_SKF_CreateApplication(
        DEVHANDLE		hDev,
        LPSTR			szAppName,
        LPSTR			szAdminPIN,
        DWORD			dwAdminPinRetryCount,
        LPSTR			szUserPIN,
        DWORD			dwUserPinRetryCount,
        DWORD			dwCreateFileRights,
        HAPPLICATION*	phApplication
)
{
    SKF_DEBUG("%s IN,Adapter_SKF_CreateApplication hDev = %p",__FUNCTION__,hDev);
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == szAppName || NULL == szAdminPIN || NULL == szUserPIN || NULL == phApplication){
        return SAR_INVALIDPARAMERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusDevHandle = adapterStatusDevHandle.find(callerName);
    for(;itAdapterStatusDevHandle != adapterStatusDevHandle.end();itAdapterStatusDevHandle++){
        if(itAdapterStatusDevHandle->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(itAdapterStatusDevHandle->second->devhandle == hDev && itAdapterStatusDevHandle->second->devName->status >= SKF_STATUS_DEV_AUTH){
            break;
        }
    }

    if(itAdapterStatusDevHandle == adapterStatusDevHandle.end()){
        return SAR_UNKNOWNERR;
    }

    for(auto itMapDevHandle = mapDevHandle.begin();itMapDevHandle != mapDevHandle.end();itMapDevHandle++){
        if(itMapDevHandle->first == hDev){

            HAPPLICATION happlication = NULL;
            ULONG ret = itMapDevHandle->second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_CreateApplication(itMapDevHandle->second->devhandle,szAppName,szAdminPIN,dwAdminPinRetryCount,szUserPIN,dwUserPinRetryCount,dwCreateFileRights,&happlication);
            if(ret != SAR_OK){
                return ret;
            }

            skf_info_cache_apphandle *skfInfoCacheApphandle = new skf_info_cache_apphandle();
            skfInfoCacheApphandle->happlication = happlication;
            skfInfoCacheApphandle->appName = szAppName;
            skfInfoCacheApphandle->skfInfoCacheDevhandle = itMapDevHandle->second;
            *phApplication = (HAPPLICATION)appHandleSq;
            mapAppHandle.insert(make_pair((HAPPLICATION)appHandleSq,skfInfoCacheApphandle));
            appHandleSq++;

            SkfAdapterStatusAppHandle *appHandle = new SkfAdapterStatusAppHandle();
            appHandle->appName = szAppName;
            appHandle->status = SKF_STATUS_APP_OPEN;
            appHandle->devHandle = itAdapterStatusDevHandle->second;
            appHandle->happlication = *phApplication;
            adapterStatusAppHandle.insert(make_pair(callerName,appHandle));
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	枚举设备中所存在的所有应用
 *	hDev			[IN]连接设备时返回的设备句柄
 *	szAppName		[OUT]返回应用名称列表, 如果该参数为空，将由pulSize返回所需要的内存空间大小。
 *						 每个应用的名称以单个'\0'结束，以双'\0'表示列表的结束。
 *	pulSize			[IN,OUT]输入参数，输入应用名称的缓冲区长度，输出参数，返回szAppName所占用的的空间大小
 */
ULONG Adapter_SKF_EnumApplication(DEVHANDLE		hDev,
        LPSTR			szAppName,
        ULONG*		pulSize
)
{
    SKF_DEBUG("%s IN",__FUNCTION__);
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto itdh = adapterStatusDevHandle.find(callerName);
    for(;itdh != adapterStatusDevHandle.end();itdh++){
        if(itdh->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(itdh->second->devhandle == hDev){
            break;
        }
    }

    if(itdh == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto it = mapDevHandle.begin();it != mapDevHandle.end();it++){
        if(it->first == hDev){
            ULONG ret = it->second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_EnumApplication(it->second->devhandle,szAppName,pulSize);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	删除指定的应用
 *	hDev			[IN]连接设备时返回的设备句柄
 *	szAppName		[IN]应用名称
 */
ULONG Adapter_SKF_DeleteApplication(
        DEVHANDLE		hDev,
        LPSTR			szAppName
)
{
    SKF_DEBUG("%s %s IN",callerName.c_str(),__FUNCTION__);
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusDevHandle = adapterStatusDevHandle.find(callerName);
    for(;itAdapterStatusDevHandle != adapterStatusDevHandle.end();itAdapterStatusDevHandle++){
        if(itAdapterStatusDevHandle->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(itAdapterStatusDevHandle->second->devhandle == hDev && itAdapterStatusDevHandle->second->devName->status >= SKF_STATUS_DEV_AUTH){
            break;
        }
    }

    if(itAdapterStatusDevHandle == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto itAdapterStatusAppHandle = adapterStatusAppHandle.begin();itAdapterStatusAppHandle != adapterStatusAppHandle.end();){
        if(itAdapterStatusAppHandle->second->devHandle == itAdapterStatusDevHandle->second){

            for(auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.begin();itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();){
                if(itAdapterStatusContainerHandle->second->appHandle == itAdapterStatusAppHandle->second){
                    delete itAdapterStatusContainerHandle->second;
                    adapterStatusContainerHandle.erase(itAdapterStatusContainerHandle++);
                } else{
                    itAdapterStatusContainerHandle++;
                }
            }

            delete itAdapterStatusAppHandle->second;
            adapterStatusAppHandle.erase(itAdapterStatusAppHandle++);
        } else{
            itAdapterStatusAppHandle++;
        }
    }


    for(auto it = mapDevHandle.begin();it != mapDevHandle.end();it++){
        if(it->first == hDev){
            ULONG ret = it->second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_DeleteApplication(it->second->devhandle,szAppName);
            if(ret != SAR_OK){
                return ret;
            }

            for(auto ita = mapAppHandle.begin();ita != mapAppHandle.end();){
                if(ita->second->skfInfoCacheDevhandle == it->second && ita->second->appName == szAppName){

                    for(auto itc = mapContainerHandle.begin();itc != mapContainerHandle.end();){
                        if(itc->second->skfInfoCacheApphandle == ita->second){
                            delete (itc->second);
                            mapContainerHandle.erase(itc++);
                        } else{
                            itc++;
                        }
                    }

                    delete (ita->second);
                    ita->second = NULL;
                    mapAppHandle.erase(ita++);
                } else{
                    ita++;
                }
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	打开指定的应用
 *	hDev			[IN]连接设备时返回的设备句柄
 *	szAppName		[IN]应用名称
 *	phApplication	[OUT]应用的句柄
 */
ULONG Adapter_SKF_OpenApplication(DEVHANDLE	hDev,
        LPSTR			szAppName,
        HAPPLICATION*	phApplication
)
{
    SKF_DEBUG("%s IN",__FUNCTION__);
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev || NULL == phApplication){
        return SAR_INVALIDPARAMERR;
    }

    auto itAdapterStatusDevHandle = adapterStatusDevHandle.find(callerName);
    for(;itAdapterStatusDevHandle != adapterStatusDevHandle.end();itAdapterStatusDevHandle++){
        if(itAdapterStatusDevHandle->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(itAdapterStatusDevHandle->second->devhandle == hDev){
            break;
        }
    }

    if(itAdapterStatusDevHandle == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto itMapDevHandle = mapDevHandle.begin();itMapDevHandle != mapDevHandle.end();itMapDevHandle++){
        if(itMapDevHandle->first == hDev){
            for(auto item = mapAppHandle.begin();item != mapAppHandle.end();item++){
                if(item->second->skfInfoCacheDevhandle == itMapDevHandle->second && item->second->appName == szAppName){
                    *phApplication = item->first;

                    auto itAdapterStatusAppHandle = adapterStatusAppHandle.begin();
                    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
                        if(itAdapterStatusAppHandle->first == callerName && itAdapterStatusAppHandle->second->happlication == *phApplication &&
                                itAdapterStatusAppHandle->second->appName == szAppName &&
                                itAdapterStatusAppHandle->second->devHandle == itAdapterStatusDevHandle->second){
                                    itAdapterStatusAppHandle->second->status |= SKF_STATUS_APP_OPEN;
                                break;
                        }
                    }

                    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
                        SkfAdapterStatusAppHandle *appHandle = new SkfAdapterStatusAppHandle();
                        appHandle->appName = szAppName;
                        appHandle->happlication = *phApplication;
                        appHandle->devHandle = itAdapterStatusDevHandle->second;
                        appHandle->status |= SKF_STATUS_APP_OPEN;
                        adapterStatusAppHandle.insert(make_pair(callerName,appHandle));
                    }

                    return SAR_OK;
                }
            }
            HAPPLICATION happlication = NULL;
            ULONG ret = itMapDevHandle->second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_OpenApplication(itMapDevHandle->second->devhandle,szAppName,&happlication);
            if(ret != SAR_OK){
                return ret;
            }

            skf_info_cache_apphandle* skfInfoCacheApphandle = new skf_info_cache_apphandle();
            skfInfoCacheApphandle->skfInfoCacheDevhandle = itMapDevHandle->second;
            skfInfoCacheApphandle->appName = szAppName;
            skfInfoCacheApphandle->happlication = happlication;
            *phApplication = (HAPPLICATION)appHandleSq;
            mapAppHandle.insert(make_pair(*phApplication,skfInfoCacheApphandle));
            appHandleSq++;

            SkfAdapterStatusAppHandle *appHandle = new SkfAdapterStatusAppHandle();
            appHandle->appName = szAppName;
            appHandle->happlication = *phApplication;
            appHandle->devHandle = itAdapterStatusDevHandle->second;
            appHandle->status |= SKF_STATUS_APP_OPEN;
            adapterStatusAppHandle.insert(make_pair(callerName,appHandle));
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	关闭应用并释放应用句柄
 *	hApplication	[IN]应用的句柄
 */
ULONG Adapter_SKF_CloseApplication(
        HAPPLICATION	hApplication
)
{
    SKF_DEBUG("%s IN,Adapter_SKF_CloseApplication hApplication = %p",__FUNCTION__,hApplication);
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);
    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication){
            itAdapterStatusAppHandle->second->status = SKF_STATUS_APP_CLOSE;
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();){
        if(itAdapterStatusContainerHandle->first != callerName){
            break;
        }

        if(itAdapterStatusContainerHandle->second->appHandle == itAdapterStatusAppHandle->second){
            delete itAdapterStatusContainerHandle->second;
            adapterStatusContainerHandle.erase(itAdapterStatusContainerHandle++);
        } else{
            itAdapterStatusContainerHandle++;
        }
    }

    delete itAdapterStatusAppHandle->second;
    adapterStatusAppHandle.erase(itAdapterStatusAppHandle);


    for(itAdapterStatusAppHandle = adapterStatusAppHandle.begin();itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->second->status != SKF_STATUS_APP_CLOSE && itAdapterStatusAppHandle->second->happlication == hApplication){
            SKF_DEBUG("%s has not close app",itAdapterStatusAppHandle->first.c_str());
            return SAR_OK;
        }
    }

    for(auto itMapAppHandle = mapAppHandle.begin();itMapAppHandle != mapAppHandle.end();){
        if(itMapAppHandle->first == hApplication){
            ULONG ret = itMapAppHandle->second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_CloseApplication(itMapAppHandle->second->happlication);
            if(ret != SAR_OK){
                return ret;
            }

            for(auto itc = mapContainerHandle.begin();itc != mapContainerHandle.end();){
                if(itc->second->skfInfoCacheApphandle == itMapAppHandle->second){
                    delete itc->second;
                    mapContainerHandle.erase(itc++);
                } else{
                    itc++;
                }
            }

            delete itMapAppHandle->second;
            mapAppHandle.erase(itMapAppHandle++);

            return SAR_OK;
        }else{
            itMapAppHandle++;
        }
    }

    return SAR_INVALIDHANDLEERR;
}


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
ULONG Adapter_SKF_CreateFile(HAPPLICATION	hApplication,
        LPSTR			szFileName,
        ULONG			ulFileSize,
        ULONG			ulReadRights,
        ULONG			ulWriteRights
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);
    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status > SKF_STATUS_APP_CLOSE){
            break;
        }
    }


    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }


    for(auto itMapAppHandle = mapAppHandle.begin();itMapAppHandle != mapAppHandle.end();itMapAppHandle++){
        if(itMapAppHandle->first == hApplication){
            ULONG ret = itMapAppHandle->second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_CreateFile(itMapAppHandle->second->happlication,szFileName,ulFileSize,ulReadRights,ulWriteRights);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	删除指定文件，文件删除后，文件中写入的所有信息将丢失。文件在设备中的占用的空间将被释放。
 *	hApplication		[IN]要删除文件所在的应用句柄
 *	szFileName			[IN]要删除文件的名称
 */
ULONG Adapter_SKF_DeleteFile(HAPPLICATION hApplication,LPSTR szFileName)
{
    SKF_DEBUG("%s %s IN",callerName.c_str(),__FUNCTION__);
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);

    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status > SKF_STATUS_APP_CLOSE){
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }


    for(auto it = mapAppHandle.begin();it != mapAppHandle.end();it++){
        if(it->first == hApplication){
            ULONG ret = it->second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_DeleteFile(it->second->happlication,szFileName);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	枚举一个应用下存在的所有文件
 *	hApplication		[IN]应用的句柄
 *	szFileList			[OUT]返回文件名称列表，该参数为空，由pulSize返回文件信息所需要的空间大小。每个文件名称以单个'\0'结束，以双'\0'表示列表的结束。
 *	pulSize				[OUT]输入为数据缓冲区的大小，输出为实际文件名称的大小
 */
ULONG Adapter_SKF_EnumFiles(HAPPLICATION	hApplication,
        LPSTR			szFileList,
        ULONG*		pulSize
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);

    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status > SKF_STATUS_APP_CLOSE){
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }


    for(auto it = mapAppHandle.begin();it != mapAppHandle.end();it++){
        if(it->first == hApplication){
            ULONG ret = it->second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_EnumFiles(it->second->happlication,szFileList,pulSize);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	获取应用文件的属性信息，例如文件的大小、权限等
 *	hApplication		[IN]文件所在应用的句柄
 *	szFileName			[IN]文件名称
 *	pFileInfo			[OUT]文件信息，指向文件属性结构的指针
 */
ULONG Adapter_SKF_GetFileInfo(HAPPLICATION hApplication,
        LPSTR				szFileName,
        FILEATTRIBUTE*	pFileInfo
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);

    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status > SKF_STATUS_APP_CLOSE){
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto it = mapAppHandle.begin();it != mapAppHandle.end();it++){
        if(it->first == hApplication){
            ULONG ret = it->second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_GetFileInfo(it->second->happlication,szFileName,pFileInfo);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	读取文件内容
 *	hApplication		[IN]文件所在的应用句柄
 *	szFileName			[IN]文件名
 *	ulOffset			[IN]文件读取偏移位置
 *	ulSize				[IN]要读取的长度
 *	pbOutData			[OUT]返回数据的缓冲区
 *	pulOutLen			[OUT]输入表示给出的缓冲区大小；输出表示实际读取返回的数据大小
 */
ULONG Adapter_SKF_ReadFile(
        HAPPLICATION	hApplication,
        LPSTR			szFileName,
        ULONG			ulOffset,
        ULONG			ulSize,
        BYTE*			pbOutData,
        ULONG*		pulOutLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);

    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status > SKF_STATUS_APP_CLOSE){
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto it = mapAppHandle.begin();it != mapAppHandle.end();it++){
        if(it->first == hApplication){
            ULONG ret = it->second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ReadFile(it->second->happlication,szFileName,ulOffset,ulSize,pbOutData,pulOutLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	写数据到文件中
 *	hApplication		[IN]文件所在的应用句柄
 *	szFileName			[IN]文件名
 *	ulOffset			[IN]写入文件的偏移量
 *	pbData				[IN]写入数据缓冲区
 *	ulSize				[IN]写入数据的大小
 */
ULONG Adapter_SKF_WriteFile(
        HAPPLICATION	hApplication,
        LPSTR			szFileName,
        ULONG			ulOffset,
        BYTE*			pbData,
        ULONG			ulSize
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);

    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status > SKF_STATUS_APP_CLOSE){
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }


    for(auto it = mapAppHandle.begin();it != mapAppHandle.end();it++){
        if(it->first == hApplication){
            ULONG ret = it->second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_WriteFile(it->second->happlication,szFileName,ulOffset,pbData,ulSize);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}


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
ULONG Adapter_SKF_CreateContainer(HAPPLICATION	hApplication,
        LPSTR			szContainerName,
        HCONTAINER*	phContainer
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication || NULL == phContainer){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);
    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status > SKF_STATUS_APP_CLOSE){
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    if(itAdapterStatusAppHandle->second->status < SKF_STATUS_APP_LOGGIN_USR){
        return SAR_USER_NOT_LOGGED_IN;
    }

   for(auto it = mapAppHandle.begin();it != mapAppHandle.end();it++){
        if(it->first == hApplication){
            HCONTAINER hcontainer = NULL;
            ULONG ret = it->second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_CreateContainer(it->second->happlication,szContainerName,&hcontainer);
            if(ret != SAR_OK){
                return ret;
            }

            skf_info_cache_containerhandle *pCacheContainerhandle = new skf_info_cache_containerhandle();
            pCacheContainerhandle->hcontainer = hcontainer;
            pCacheContainerhandle->skfInfoCacheApphandle = it->second;
            pCacheContainerhandle->containerName = szContainerName;
            *phContainer = (HCONTAINER)containerHandleSq;
            mapContainerHandle.insert(make_pair((HCONTAINER)containerHandleSq,pCacheContainerhandle));
            containerHandleSq++;

            auto containerHandle = new SkfAdapterStatusContainerHandle();
            containerHandle->hcontainer = *phContainer;
            containerHandle->appHandle = itAdapterStatusAppHandle->second;
            containerHandle->containerName = szContainerName;
            containerHandle->status = SKF_STATUS_CONTAINER_OPEN;
            adapterStatusContainerHandle.insert(make_pair(callerName,containerHandle));
            return SAR_OK;
        }
   }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	在应用下删除指定名称的容器并释放容器相关的资源
 *	hApplication		[IN]应用句柄
 *	szContainerName		[IN]指向删除容器的名称
 */
ULONG Adapter_SKF_DeleteContainer(HAPPLICATION	hApplication,
        LPSTR			szContainerName
)
{
    SKF_DEBUG("%s %s IN",callerName.c_str(),__FUNCTION__);

    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);
    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status >= SKF_STATUS_APP_OPEN){
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    if(itAdapterStatusAppHandle->second->status < SKF_STATUS_APP_LOGGIN_USR){
        return SAR_USER_NOT_LOGGED_IN;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();){
        if(itAdapterStatusContainerHandle->second->appHandle->happlication == hApplication && itAdapterStatusContainerHandle->second->containerName == szContainerName){
            delete itAdapterStatusContainerHandle->second;
            adapterStatusContainerHandle.erase(itAdapterStatusContainerHandle++);
        } else{
            itAdapterStatusContainerHandle++;
        }
    }


    for(auto & it : mapAppHandle){
        if(it.first == hApplication){
            ULONG ret = it.second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_DeleteContainer(it.second->happlication,szContainerName);
            if(ret != SAR_OK){
                return ret;
            }

            for(auto item = mapContainerHandle.begin();item != mapContainerHandle.end();){
                if(it.second == item->second->skfInfoCacheApphandle){
                    delete (item->second);
                    mapContainerHandle.erase(item++);
                }else{
                    item++;
                }
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	获取容器句柄
 *	hApplication		[IN]应用句柄
 *	szContainerName		[IN]容器名称
 *	phContainer			[OUT]返回所打开容器的句柄
 */
ULONG Adapter_SKF_OpenContainer(
        HAPPLICATION	hApplication,
        LPSTR			szContainerName,
        HCONTAINER*	phContainer
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication || NULL == phContainer){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);
    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication && itAdapterStatusAppHandle->second->status >= SKF_STATUS_APP_OPEN){
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }


    for(auto & it : mapAppHandle){
        if(it.first == hApplication){
            for(auto item = mapContainerHandle.begin();item != mapContainerHandle.end();item++){
                if(item->second->skfInfoCacheApphandle == it.second && item->second->containerName == szContainerName){
                    *phContainer = item->first;

                    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.begin();
                    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
                        if(itAdapterStatusContainerHandle->first == callerName && itAdapterStatusContainerHandle->second->appHandle == itAdapterStatusAppHandle->second &&
                                itAdapterStatusContainerHandle->second->containerName == szContainerName && itAdapterStatusContainerHandle->second->hcontainer == *phContainer){
                            itAdapterStatusContainerHandle->second->status |= SKF_STATUS_CONTAINER_OPEN;
                            break;
                        }
                    }

                    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
                        auto containerHandle = new SkfAdapterStatusContainerHandle();
                        containerHandle->status = SKF_STATUS_CONTAINER_OPEN;
                        containerHandle->containerName = szContainerName;
                        containerHandle->appHandle = itAdapterStatusAppHandle->second;
                        containerHandle->hcontainer = *phContainer;
                        adapterStatusContainerHandle.insert(make_pair(callerName,containerHandle));
                    }

                    return SAR_OK;
                }
            }
            HCONTAINER hcontainer = NULL;
            ULONG ret = it.second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_OpenContainer(it.second->happlication,szContainerName,&hcontainer);
            if(ret != SAR_OK){
                return ret;
            }

            skf_info_cache_containerhandle *pCacheContainerhandle = new skf_info_cache_containerhandle();
            pCacheContainerhandle->hcontainer = hcontainer;
            pCacheContainerhandle->skfInfoCacheApphandle = it.second;
            pCacheContainerhandle->containerName = szContainerName;
            *phContainer = (HCONTAINER)containerHandleSq;
            mapContainerHandle.insert(make_pair((HCONTAINER)containerHandleSq,pCacheContainerhandle));
            containerHandleSq++;

            auto containerHandle = new SkfAdapterStatusContainerHandle();
            containerHandle->status = SKF_STATUS_CONTAINER_OPEN;
            containerHandle->containerName = szContainerName;
            containerHandle->appHandle = itAdapterStatusAppHandle->second;
            containerHandle->hcontainer = *phContainer;
            adapterStatusContainerHandle.insert(make_pair(callerName,containerHandle));

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	关闭容器句柄，并释放容器句柄相关资源
 *	hContainer			[OUT]容器句柄
 */
ULONG Adapter_SKF_CloseContainer(HCONTAINER hContainer)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer && itAdapterStatusContainerHandle->second->status > SKF_STATUS_CONTAINER_CLOSE){
            itAdapterStatusContainerHandle->second->status = SKF_STATUS_CONTAINER_CLOSE;
            break;
        }
    }

    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    delete itAdapterStatusContainerHandle->second;
    adapterStatusContainerHandle.erase(itAdapterStatusContainerHandle);

    for(itAdapterStatusContainerHandle = adapterStatusContainerHandle.begin();itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer && itAdapterStatusContainerHandle->second->status > SKF_STATUS_CONTAINER_CLOSE){
            SKF_DEBUG("%s has not close container %s",itAdapterStatusContainerHandle->first.c_str(),itAdapterStatusContainerHandle->second->containerName.c_str());
            return SAR_OK;
        }
    }

    for(auto it = mapContainerHandle.begin();it != mapContainerHandle.end();){
        if(it->first == hContainer){
            ULONG ret = it->second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_CloseContainer(it->second->hcontainer);
            if(ret != SAR_OK){
                return ret;
            }
            delete (it->second);
            mapContainerHandle.erase(it++);
            return SAR_OK;
        }else{
            it++;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	枚举应用下的所有容器并返回容器名称列表
 *	hApplication		[IN]应用句柄
 *	szContainerName		[OUT]指向容器名称列表缓冲区，如果此参数为NULL时，pulSize表示返回数据所需要缓冲区的长度，如果此参数不为NULL时，返回容器名称列表，每个容器名以单个'\0'为结束，列表以双'\0'结束
 *	pulSize				[OUT]调用前表示szContainerName缓冲区的长度，返回容器名称列表的长度
 */
ULONG Adapter_SKF_EnumContainer(
        HAPPLICATION	hApplication,
        LPSTR			szContainerName,
        ULONG*		pulSize
)
{
    SKF_DEBUG("Adapter_SKF_EnumContainer IN");
    if(!devEnumFlg){
        SKF_DEBUG("Adapter_SKF_EnumContainer OUT1");
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hApplication){
        SKF_DEBUG("Adapter_SKF_EnumContainer OUT2");
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusAppHandle = adapterStatusAppHandle.find(callerName);
    for(;itAdapterStatusAppHandle != adapterStatusAppHandle.end();itAdapterStatusAppHandle++){
        if(itAdapterStatusAppHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusAppHandle->second->happlication == hApplication){
            break;
        }
    }

    if(itAdapterStatusAppHandle == adapterStatusAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapAppHandle){
        if(it.first == hApplication){
            ULONG ret = it.second->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_EnumContainer(it.second->happlication,szContainerName,pulSize);
            if(ret != SAR_OK){
                return ret;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	功能描述	获取容器的类型
 *	hContainer	[IN]容器句柄。
 *	pulContainerType	[OUT] 获得的容器类型。指针指向的值为0表示未定、尚未分配类型或者为空容器，为1表示为RSA容器，为2表示为SM2容器。
 *
 */
ULONG Adapter_SKF_GetContainerType(HCONTAINER hContainer,ULONG *pulContainerType)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer){
            break;
        }
    }

    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_GetContainerType(it.second->hcontainer,pulContainerType);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}
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
ULONG Adapter_SKF_GenRandom(
        DEVHANDLE hDev,
        BYTE *pbRandom,
        ULONG ulRandomLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_GenRandom(it.second->devhandle,pbRandom,ulRandomLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	由设备生成RSA密钥对并明文输出
 *	hDev			[IN] 设备句柄
 *	ulBitsLen		[IN] 密钥模长
 *	pBlob			[OUT] 返回的私钥数据结构
 */
ULONG Adapter_SKF_GenExtRSAKey(
        DEVHANDLE hDev,
        ULONG ulBitsLen,
        RSAPRIVATEKEYBLOB* pBlob
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto itdh = adapterStatusDevHandle.find(callerName);
    for(;itdh != adapterStatusDevHandle.end();itdh++){
        if(itdh->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(itdh->second->devhandle == hDev){
            break;
        }
    }

    if(itdh == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_GenExtRSAKey(it.second->devhandle,ulBitsLen,pBlob);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	生成RSA签名密钥对并输出签名公钥
 *	hContainer		[IN] 容器句柄
 *	ulBitsLen		[IN] 密钥模长
 *	pBlob			[OUT] 返回的RSA公钥数据结构
 */
ULONG Adapter_SKF_GenRSAKeyPair(
        HCONTAINER hContainer,
        ULONG ulBitsLen,
        RSAPUBLICKEYBLOB *pBlob
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_GenRSAKeyPair(it.second->hcontainer,ulBitsLen,pBlob);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }
    return SAR_INVALIDHANDLEERR;
}

/*
 *	导入RSA加密公私钥对
 *	hContainer		[IN] 容器句柄
 *	ulSymAlgId		[IN] 对称算法密钥标识
 *	pbWrappedKey	[IN] 使用该容器内签名公钥保护的对称算法密钥
 *	ulWrappedKeyLen	[IN] 保护的对称算法密钥长度
 *	pbEncryptedData	[IN] 对称算法密钥保护的RSA加密私钥。私钥的格式遵循PKCS #1 v2.1: RSA Cryptography Standard中的私钥格式定义
 *	ulEncryptedDataLen	[IN] 对称算法密钥保护的RSA加密公私钥对长度
 */
ULONG Adapter_SKF_ImportRSAKeyPair(
        HCONTAINER hContainer,
        ULONG ulSymAlgId,
        BYTE *pbWrappedKey,
        ULONG ulWrappedKeyLen,
        BYTE *pbEncryptedData,
        ULONG ulEncryptedDataLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ImportRSAKeyPair(
                    it.second->hcontainer,ulSymAlgId,pbWrappedKey,ulWrappedKeyLen,pbEncryptedData,ulEncryptedDataLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }
    return SAR_INVALIDHANDLEERR;
}

/*
 *	使用hContainer指定容器的签名私钥，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名的长度
 *	hContainer		[IN] 用来签名的私钥所在容器句柄
 *	pbData			[IN] 被签名的数据
 *	ulDataLen		[IN] 签名数据长度，应不大于RSA密钥模长-11
 *	pbSignature		[OUT] 存放签名结果的缓冲区指针，如果值为NULL，用于取得签名结果长度
 *	pulSigLen		[IN,OUT] 输入为签名结果缓冲区大小，输出为签名结果长度
 */
ULONG Adapter_SKF_RSASignData(
        HCONTAINER hContainer,
        BYTE *pbData,
        ULONG ulDataLen,
        BYTE *pbSignature,
        ULONG *pulSigLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_RSASignData(
                    it.second->hcontainer,pbData,ulDataLen,pbSignature,pulSigLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }
    return SAR_INVALIDHANDLEERR;
}

/*
 *	验证RSA签名。用pRSAPubKeyBlob内的公钥值对待验签数据进行验签。
 *	hDev			[IN] 连接设备时返回的设备句柄
 *	pRSAPubKeyBlob	[IN] RSA公钥数据结构
 *	pbData			[IN] 待验证签名的数据
 *	ulDataLen		[IN] 数据长度，应不大于公钥模长-11
 *	pbSignature		[IN] 待验证的签名值
 *	ulSigLen		[IN] 签名值长度，必须为公钥模长
 */
ULONG Adapter_SKF_RSAVerify(
        DEVHANDLE			hDev,
        RSAPUBLICKEYBLOB*	pRSAPubKeyBlob,
        BYTE*				pbData,
        ULONG				ulDataLen,
        BYTE*				pbSignature,
        ULONG				ulSigLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_RSAVerify(it.second->devhandle,pRSAPubKeyBlob,pbData,ulDataLen,pbSignature,ulSigLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	生成会话密钥并用外部公钥加密输出。
 *	hContainer		[IN] 容器句柄
 *	ulAlgID			[IN] 会话密钥的算法标识
 *	pPubKey			[IN] 加密会话密钥的RSA公钥数据结构
 *	pbData			[OUT] 导出的加密会话密钥密文，按照PKCS#1v1.5的要求封装
 *	pulDataLen		[OUT] 返回导出数据长度
 *	phSessionKey	[OUT] 导出的密钥句柄
 */
ULONG Adapter_SKF_RSAExportSessionKey(HCONTAINER hContainer,
        ULONG ulAlgID,
        RSAPUBLICKEYBLOB* pPubKey,
        BYTE* pbData,
        ULONG* pulDataLen,
        HANDLE* phSessionKey
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer || NULL == phSessionKey){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            HANDLE handle = NULL;
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_RSAExportSessionKey(
                    it.second->hcontainer,ulAlgID,pPubKey,pbData,pulDataLen,&handle);
            if(ret != SAR_OK){
                return ret;
            }
            auto skfInfoCacheHandle = new skf_info_cache_handle();
            skfInfoCacheHandle->handle = handle;
            skfInfoCacheHandle->m_skfFunctionList_ptr = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr;
            *phSessionKey = (HANDLE)handleSq;
            mapHandle.insert(make_pair((HANDLE)handleSq,skfInfoCacheHandle));
            handleSq++;

            return SAR_OK;
        }
    }
    return SAR_INVALIDHANDLEERR;
}

/*
 *	使用外部传入的RSA公钥对输入数据做公钥运算并输出结果
 *	hDev			[IN] 设备句柄
 *	pRSAPubKeyBlob	[IN] RSA公钥数据结构
 *	pbInput			[IN] 指向待运算的原始数据缓冲区
 *	ulInputLen		[IN] 待运算原始数据的长度，必须为公钥模长
 *	pbOutput		[OUT] 指向RSA公钥运算结果缓冲区，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
 *	pulOutputLen	[OUT] 调用前表示pbOutput缓冲区的长度，返回RSA公钥运算结果的实际长度
 */
ULONG Adapter_SKF_ExtRSAPubKeyOperation(
        DEVHANDLE hDev,
        RSAPUBLICKEYBLOB* pRSAPubKeyBlob,
        BYTE* pbInput,
        ULONG ulInputLen,
        BYTE* pbOutput,
        ULONG* pulOutputLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto itdh = adapterStatusDevHandle.find(callerName);
    for(;itdh != adapterStatusDevHandle.end();itdh++){
        if(itdh->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(itdh->second->devhandle == hDev){
            break;
        }
    }

    if(itdh == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ExtRSAPubKeyOperation(it.second->devhandle,pRSAPubKeyBlob,pbInput,ulInputLen,pbOutput,pulOutputLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	直接使用外部传入的RSA私钥对输入数据做私钥运算并输出结果
 *	hDev			[IN] 设备句柄
 *	pRSAPriKeyBlob	[IN] RSA私钥数据结构
 *	pbInput			[IN] 指向待运算数据缓冲区
 *	ulInputLen		[IN] 待运算数据的长度，必须为公钥模长
 *	pbOutput		[OUT] RSA私钥运算结果，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
 *	pulOutputLen	[OUT] 调用前表示pbOutput缓冲区的长度，返回RSA私钥运算结果的实际长度
 */
ULONG Adapter_SKF_ExtRSAPriKeyOperation(
        DEVHANDLE hDev,
        RSAPRIVATEKEYBLOB* pRSAPriKeyBlob,
        BYTE* pbInput,
        ULONG ulInputLen,
        BYTE* pbOutput,
        ULONG* pulOutputLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ExtRSAPriKeyOperation(it.second->devhandle,
                    pRSAPriKeyBlob,pbInput,ulInputLen,pbOutput,pulOutputLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	生成ECC签名密钥对并输出签名公钥。
 *	hContainer		[IN] 容器句柄
 *	ulBitsLen		[IN] 密钥模长
 *	pBlob			[OUT] 返回ECC公钥数据结构
 */
ULONG Adapter_SKF_GenECCKeyPair(
        HCONTAINER hContainer,
        ULONG ulAlgId,
        ECCPUBLICKEYBLOB *pBlob
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer){
            break;
        }
    }

    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    if(itAdapterStatusContainerHandle->second->appHandle->status < SKF_STATUS_APP_LOGGIN_USR){
        return SAR_USER_NOT_LOGGED_IN;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_GenECCKeyPair(it.second->hcontainer,ulAlgId,pBlob);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	导入ECC公私钥对
 *	hContainer		[IN] 容器句柄
 *	pbWrapedData	[IN] 加密保护的ECC加密公私钥对密文
 *	ulWrapedLen		[IN] 数据长度
 */
ULONG Adapter_SKF_ImportECCKeyPair(
        HCONTAINER hContainer,
        PENVELOPEDKEYBLOB pEnvelopedKeyBlob
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer){
            break;
        }
    }

    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    if(itAdapterStatusContainerHandle->second->appHandle->status < SKF_STATUS_APP_LOGGIN_USR){
        return SAR_USER_NOT_LOGGED_IN;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ImportECCKeyPair(it.second->hcontainer,pEnvelopedKeyBlob);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	ECC数字签名。采用ECC算法和指定私钥hKey，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名值的长度
 *	hContainer		[IN] 用来签名的私钥所在容器句柄
 *	pbData			[IN] 被签名的数据
 *	ulDataLen		[IN] 待签名数据长度，必须小于密钥模长
 *	pbSignature		[OUT] 签名值，为NULL时用于获得签名值的长度
 *	pulSigLen		[IN,OUT] 返回签名值长度的指针
 */
ULONG Adapter_SKF_ECCSignData(
        HCONTAINER hContainer,
        BYTE *pbData,
        ULONG ulDataLen,
        PECCSIGNATUREBLOB pSignature
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer){
            break;
        }
    }

    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    if(itAdapterStatusContainerHandle->second->appHandle->status < SKF_STATUS_APP_LOGGIN_USR){
        return SAR_USER_NOT_LOGGED_IN;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ECCSignData(
                    it.second->hcontainer,pbData,ulDataLen,pSignature);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	用ECC公钥对数据进行验签
 *	hDev			[IN] 设备句柄
 *	pECCPubKeyBlob	[IN] ECC公钥数据结构
 *	pbData			[IN] 待验证签名的数据
 *	ulDataLen		[IN] 数据长度
 *	pbSignature		[IN] 待验证的签名值
 *	ulSigLen		[IN] 签名值长度
 */
ULONG Adapter_SKF_ECCVerify(
        DEVHANDLE			hDev,
        ECCPUBLICKEYBLOB*	pECCPubKeyBlob,
        BYTE*				pbData,
        ULONG				ulDataLen,
        PECCSIGNATUREBLOB pSignature
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ECCVerify(it.second->devhandle,pECCPubKeyBlob,pbData,ulDataLen,pSignature);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	生成会话密钥并用外部公钥加密输出。
 *	hContainer		[IN] 容器句柄
 *	ulAlgID			[IN] 会话密钥的算法标识
 *	pPubKey			[IN] 外部输入的公钥结构
 *	pbData			[OUT] 导出的加密会话密钥密文
 *	phSessionKey	[OUT] 会话密钥句柄
 */
ULONG Adapter_SKF_ECCExportSessionKey(
        HCONTAINER hContainer,
        ULONG ulAlgID,
        ECCPUBLICKEYBLOB* pPubKey,
        PECCCIPHERBLOB pData,
        HANDLE* phSessionKey
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer){
            break;
        }
    }

    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            HANDLE handle = NULL;
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ECCExportSessionKey(
                    it.second->hcontainer,ulAlgID,pPubKey,pData,&handle);
            if(ret != SAR_OK){
                return ret;
            }

            *phSessionKey = (HANDLE)handleSq;
            auto skfInfoCacheHandle = new skf_info_cache_handle();
            skfInfoCacheHandle->handle = handle;
            skfInfoCacheHandle->m_skfFunctionList_ptr = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr;
            mapHandle.insert(make_pair(*phSessionKey,skfInfoCacheHandle));
            handleSq++;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	使用外部传入的ECC公钥对输入数据做加密运算并输出结果
 *	hDev			[IN] 设备句柄
 *	pECCPubKeyBlob	[IN] ECC公钥数据结构
 *	pbPlainText		[IN] 待加密的明文数据
 *	ulPlainTextLen	[IN] 待加密明文数据的长度
 *	pbCipherText	[OUT] 指向密文数据缓冲区，如果该参数为NULL，则由pulCipherTextLen返回密文数据的实际长度
 *	pulCipherTextLen[OUT] 调用前表示pbCipherText缓冲区的长度，返回密文数据的实际长度
 */
ULONG Adapter_SKF_ExtECCEncrypt(
        DEVHANDLE hDev,
        ECCPUBLICKEYBLOB* pECCPubKeyBlob,
        BYTE* pbPlainText,
        ULONG ulPlainTextLen,
        PECCCIPHERBLOB pbCipherText
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ExtECCEncrypt(it.second->devhandle,pECCPubKeyBlob,pbPlainText,ulPlainTextLen,pbCipherText);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	使用外部传入的ECC私钥对输入数据做解密运算并输出结果
 *	hDev			[IN] 设备句柄
 *	pRSAPriKeyBlob	[IN] ECC私钥数据结构
 *	pbInput			[IN] 待解密的密文数据
 *	ulInputLen		[IN] 待解密密文数据的长度
 *	pbOutput		[OUT] 返回明文数据，如果该参数为NULL，则由pulPlainTextLen返回明文数据的实际长度
 *	pulOutputLen	[OUT] 调用前表示pbPlainText缓冲区的长度，返回明文数据的实际长度
 */
ULONG Adapter_SKF_ExtECCDecrypt(
        DEVHANDLE hDev,
        ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
        PECCCIPHERBLOB pbCipherText,
        BYTE* pbPlainText,
        ULONG* pulPlainTextLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ExtECCDecrypt(
                    it.second->devhandle,pECCPriKeyBlob,pbCipherText,pbPlainText,pulPlainTextLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	使用外部传入的ECC私钥对输入数据做签名运算并输出结果。
 *	hDev			[IN] 设备句柄
 *	pRSAPriKeyBlob	[IN] ECC私钥数据结构
 *	pbData			[IN] 待签名数据
 *	ulDataLen		[IN] 待签名数据的长度
 *	pbSignature		[OUT] 签名值，如果该参数为NULL，则由pulSignatureLen返回签名结果的实际长度
 *	pulSignatureLen	[OUT] 调用前表示pbSignature缓冲区的长度，返回签名结果的实际长度
 */
ULONG Adapter_SKF_ExtECCSign(
        DEVHANDLE hDev,
        ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
        BYTE* pbData,
        ULONG ulDataLen,
        PECCSIGNATUREBLOB pSignature
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ExtECCSign(
                    it.second->devhandle,pECCPriKeyBlob,pbData,ulDataLen,pSignature);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	外部使用传入的ECC公钥做签名验证
 *	hDev			[IN] 设备句柄
 *	pECCPubKeyBlob	[IN] ECC公钥数据结构
 *	pbData			[IN] 待验证数据
 *	ulDataLen		[IN] 待验证数据的长度
 *	pbSignature		[OUT] 签名值
 *	ulSignLen		[OUT] 签名值的长度
 */
ULONG Adapter_SKF_ExtECCVerify(
        DEVHANDLE hDev,
        ECCPUBLICKEYBLOB* pECCPubKeyBlob,
        BYTE* pbData,
        ULONG ulDataLen,
        PECCSIGNATUREBLOB pSignature
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ExtECCVerify(
                    it.second->devhandle,pECCPubKeyBlob,pbData,ulDataLen,pSignature);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	使用ECC密钥协商算法，为计算会话密钥而产生协商参数，返回临时ECC密钥对的公钥及协商句柄
 *	hContainer		[IN] 容器句柄
 *	ulAlgId			[IN] 会话密钥算法标识
 *	pTempECCPubKeyBlob	[OUT] 发起方临时ECC公钥
 *	pbID			[IN] 发起方的ID
 *	ulIDLen			[IN] 发起方ID的长度，不大于32
 *	phAgreementHandle	[OUT] 返回的密钥协商句柄
 */
ULONG Adapter_SKF_GenerateAgreementDataWithECC(
        HCONTAINER hContainer,
        ULONG ulAlgId,
        ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
        BYTE* pbID,
        ULONG ulIDLen,
        HANDLE *phAgreementHandle
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer){
            break;
        }
    }

    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            HANDLE handle = NULL;
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_GenerateAgreementDataWithECC(
                        it.second->hcontainer,ulAlgId,pTempECCPubKeyBlob,pbID,ulIDLen,&handle
                    );
            if(ret != SAR_OK){
                return ret;
            }

            auto skfInfoCacheHandle = new skf_info_cache_handle();
            skfInfoCacheHandle->handle = handle;
            skfInfoCacheHandle->m_skfFunctionList_ptr = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr;
            mapHandle.insert(make_pair((HANDLE)handleSq,skfInfoCacheHandle));
            handleSq++;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

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
ULONG Adapter_SKF_GenerateAgreementDataAndKeyWithECC(
        HCONTAINER hContainer,
        ULONG ulAlgId,
        ECCPUBLICKEYBLOB* pSponsorECCPubKeyBlob,
        ECCPUBLICKEYBLOB* pSponsorTempECCPubKeyBlob,
        ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
        BYTE* pbID,
        ULONG ulIDLen,
        BYTE *pbSponsorID,
        ULONG ulSponsorIDLen,
        HANDLE *phKeyHandle
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer || NULL == phKeyHandle){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer){
            break;
        }
    }

    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            HANDLE handle = NULL;
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_GenerateAgreementDataAndKeyWithECC(
                        it.second->hcontainer,ulAlgId,pSponsorECCPubKeyBlob,pSponsorTempECCPubKeyBlob,pTempECCPubKeyBlob,pbID,ulIDLen,pbSponsorID,ulSponsorIDLen,&handle
                    );
            if(ret != SAR_OK){
                return ret;
            }

            auto skfInfoCacheHandle = new skf_info_cache_handle();
            skfInfoCacheHandle->handle = handle;
            skfInfoCacheHandle->m_skfFunctionList_ptr = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr;
            *phKeyHandle = (HANDLE)handleSq;
            mapHandle.insert(make_pair(*phKeyHandle,skfInfoCacheHandle));
            handleSq++;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥，同时返回会话密钥句柄
 *	hAgreementHandle			[IN] 密钥协商句柄
 *	pECCPubKeyBlob				[IN] 外部输入的响应方ECC公钥
 *	pTempECCPubKeyBlob			[IN] 外部输入的响应方临时ECC公钥
 *	pbID						[IN] 响应方的ID
 *	ulIDLen						[IN] 响应方ID的长度，不大于32
 *	phKeyHandle					[OUT] 返回的密钥句柄
 */
ULONG Adapter_SKF_GenerateKeyWithECC(
        HANDLE hAgreementHandle,
        ECCPUBLICKEYBLOB* pECCPubKeyBlob,
        ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
        BYTE* pbID,
        ULONG ulIDLen,
        HANDLE *phKeyHandle
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(hAgreementHandle == NULL || phKeyHandle == NULL){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto it = mapHandle.begin();it != mapHandle.end();it++){
        if(it->first == hAgreementHandle){
            HANDLE handle = NULL;
            ULONG ret = it->second->m_skfFunctionList_ptr->SKF_GenerateKeyWithECC(it->second->handle,pECCPubKeyBlob,pTempECCPubKeyBlob,pbID,ulIDLen,&handle);
            if(ret != SAR_OK){
                return ret;
            }

            auto skfInfoCacheHandle = new skf_info_cache_handle();
            skfInfoCacheHandle->handle = handle;
            skfInfoCacheHandle->m_skfFunctionList_ptr = it->second->m_skfFunctionList_ptr;
            *phKeyHandle = (HANDLE)handleSq;
            mapHandle.insert(make_pair(*phKeyHandle,skfInfoCacheHandle));
            handleSq++;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	导出容器中的签名公钥或者加密公钥
 *	hContainer		[IN] 容器句柄
 *	bSignFlag		[IN] TRUE表示导出签名公钥，FALSE表示导出加密公钥
 *	pbBlob			[OUT] 指向RSA公钥结构（RSAPUBLICKEYBLOB）或者ECC公钥结构（ECCPUBLICKEYBLOB），如果此参数为NULL时，由pulBlobLen返回pbBlob的长度
 *	pulBlobLen		[IN,OUT] 调用时表示pbBlob的长度，返回导出公钥结构的大小
 */
ULONG Adapter_SKF_ExportPublicKey(
        HCONTAINER hContainer,
        BOOL bSignFlag,
        BYTE* pbBlob,
        ULONG* pulBlobLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer){
            break;
        }
    }

    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ExportPublicKey(
                        it.second->hcontainer,
                        bSignFlag,
                        pbBlob,
                        pulBlobLen
                    );
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	导入会话密钥
 *	hContainer		[IN] 容器句柄
 *	ulAlgID			[IN] 会话密钥的算法标识
 *	pbWrapedData	[IN] 要导入的数据
 *	ulWrapedLen		[IN] 数据长度
 *	phKey			[OUT] 返回会话密钥句柄
 */
ULONG Adapter_SKF_ImportSessionKey(
        HCONTAINER hContainer,
        ULONG ulAlgID,
        BYTE *pbWrapedData,
        ULONG ulWrapedLen,
        HANDLE* phKey
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer || NULL == phKey){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer){
            break;
        }
    }

    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    if(itAdapterStatusContainerHandle->second->appHandle->status < SKF_STATUS_APP_LOGGIN_USR){
        return SAR_USER_NOT_LOGGED_IN;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            HANDLE handle = NULL;
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ImportSessionKey(
                        it.second->hcontainer,ulAlgID,pbWrapedData,ulWrapedLen,&handle
                    );
            if(ret != SAR_OK){
                return ret;
            }

            auto skfInfoCacheHandle = new skf_info_cache_handle();
            skfInfoCacheHandle->handle = handle;
            skfInfoCacheHandle->m_skfFunctionList_ptr = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr;
            *phKey = (HANDLE)handleSq;
            mapHandle.insert(make_pair(*phKey,skfInfoCacheHandle));
            handleSq++;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	设置明文对称密钥，返回密钥句柄
 *	hContainer		[IN] 容器句柄
 *	pbKey			[IN] 指向会话密钥值的缓冲区
 *	ulAlgID			[IN] 会话密钥的算法标识
 *	phKey			[OUT] 返回会话密钥句柄
 */
ULONG Adapter_SKF_SetSymmKey(
        DEVHANDLE hDev,
        BYTE* pbKey,
        ULONG ulAlgID,
        HANDLE* phKey
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev || NULL == phKey){
        return SAR_INVALIDHANDLEERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            HANDLE handle = NULL;
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_SetSymmKey(it.second->devhandle,pbKey,ulAlgID,&handle);
            if(ret != SAR_OK){
                return ret;
            }

            auto skfInfoCacheHandle = new skf_info_cache_handle();
            skfInfoCacheHandle->handle = handle;
            skfInfoCacheHandle->m_skfFunctionList_ptr = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr;
            *phKey = (HANDLE)handleSq;
            mapHandle.insert(make_pair(*phKey,skfInfoCacheHandle));
            handleSq++;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	数据加密初始化。设置数据加密的算法相关参数。
 *	hKey			[IN] 加密密钥句柄
 *	EncryptParam	[IN] 分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
 */
ULONG Adapter_SKF_EncryptInit(
        HANDLE hKey,
        BLOCKCIPHERPARAM EncryptParam
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hKey){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hKey){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_EncryptInit(it.second->handle,EncryptParam);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

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
ULONG Adapter_SKF_Encrypt(
        HANDLE	hKey,
        BYTE*		pbData,
        ULONG		ulDataLen,
        BYTE*		pbEncryptedData,
        ULONG*	pulEncryptedLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hKey){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hKey){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_Encrypt(it.second->handle,pbData,ulDataLen,pbEncryptedData,pulEncryptedLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

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
ULONG Adapter_SKF_EncryptUpdate(
        HANDLE		hKey,
        BYTE*		pbData,
        ULONG		ulDataLen,
        BYTE*		pbEncryptedData,
        ULONG*	pulEncryptedLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hKey){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hKey){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_EncryptUpdate(it.second->handle,pbData,ulDataLen,pbEncryptedData,pulEncryptedLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	结束多个分组数据的加密，返回剩余加密结果。
    先调用SKF_EncryptInit初始化加密操作，
    再调用SKF_EncryptUpdate对多个分组数据进行加密，
    最后调用SKF_EncryptFinal结束多个分组数据的加密。
 *	hKey			[IN] 加密密钥句柄
 *	pbEncryptedData [OUT] 加密结果的缓冲区
 *	pulEncryptedLen [OUT] 加密结果的长度
 */
ULONG Adapter_SKF_EncryptFinal(
        IN HANDLE hKey,
        BYTE *pbEncryptedData,
        ULONG *pulEncryptedDataLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hKey){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hKey){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_EncryptFinal(it.second->handle,pbEncryptedData,pulEncryptedDataLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	数据解密初始化，设置解密密钥相关参数。
    调用SKF_DecryptInit之后，可以调用SKF_Decrypt对单个分组数据进行解密，
    也可以多次调用SKF_DecryptUpdate之后再调用SKF_DecryptFinal完成对多个分组数据的解密。
 *	hKey [IN] 解密密钥句柄
 *	DecryptParam [IN] 分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
 */
ULONG Adapter_SKF_DecryptInit(
        HANDLE hKey,
        BLOCKCIPHERPARAM DecryptParam
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hKey){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hKey){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_DecryptInit(it.second->handle,DecryptParam);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

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
ULONG Adapter_SKF_Decrypt(
        HANDLE hKey,
        BYTE*	pbEncryptedData,
        ULONG	ulEncryptedLen,
        BYTE* pbData,
        ULONG* pulDataLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hKey){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hKey){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_Decrypt(it.second->handle,pbEncryptedData,ulEncryptedLen,pbData,pulDataLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

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
ULONG Adapter_SKF_DecryptUpdate(
        HANDLE hKey,
        BYTE*	pbEncryptedData,
        ULONG	ulEncryptedLen,
        BYTE* pbData,
        ULONG* pulDataLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hKey){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hKey){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_DecryptUpdate(it.second->handle,pbEncryptedData,ulEncryptedLen,pbData,pulDataLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	结束多个分组数据的解密。
 *	hKey				[IN] 解密密钥句柄
 *	pbPlainText			[OUT] 指向解密结果的缓冲区，如果此参数为NULL时，由pulPlainTextLen返回解密结果的长度
 *	pulDecyptedDataLen	[IN，OUT] 调用时表示pbPlainText缓冲区的长度，返回解密结果的长度
 */
ULONG Adapter_SKF_DecryptFinal(
        HANDLE hKey,
        BYTE *pbPlainText,
        ULONG *pulPlainTextLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hKey){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hKey){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_DecryptFinal(it.second->handle,pbPlainText,pulPlainTextLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	初始化消息杂凑计算操作，指定计算消息杂凑的算法。
 *	hDev			[IN] 连接设备时返回的设备句柄
 *	ulAlgID			[IN] 杂凑算法标识
 *	phHash			[OUT] 杂凑对象句柄
 */
ULONG Adapter_SKF_DigestInit(
        DEVHANDLE	hDev,
        ULONG		ulAlgID,
        ECCPUBLICKEYBLOB *pPubKey,
        unsigned char *pucID,
        ULONG ulIDLen,
        HANDLE*	phHash)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev || NULL == phHash){
        return SAR_INVALIDHANDLEERR;
    }

    auto mapIterator = adapterStatusDevHandle.find(callerName);
    for(;mapIterator != adapterStatusDevHandle.end();mapIterator++){
        if(mapIterator->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(mapIterator->second->devhandle == hDev){
            break;
        }
    }

    if(mapIterator == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev) {
            HANDLE handle = NULL;
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_DigestInit(
                    it.second->devhandle, ulAlgID, pPubKey, pucID, ulIDLen, &handle);
            if (ret != SAR_OK) {
                return ret;
            }
            auto skfInfoCacheHandle = new skf_info_cache_handle();
            *phHash = (HANDLE) handleSq;
            skfInfoCacheHandle->handle = handle;
            skfInfoCacheHandle->m_skfFunctionList_ptr = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr;
            mapHandle.insert(make_pair(*phHash,skfInfoCacheHandle));
            handleSq++;
            return SAR_OK;
        }
    }
    return SAR_INVALIDHANDLEERR;
}
/*
 *	对单一分组的消息进行杂凑计算。
 *	hHash			[IN] 杂凑对象句柄
 *	pbData			[IN] 指向消息数据的缓冲区
 *	ulDataLen		[IN] 消息数据的长度
 *	pbHashData		[OUT] 杂凑数据缓冲区指针，当此参数为NULL时，由pulHashLen返回杂凑结果的长度
 *	pulHashLen		[IN，OUT] 调用时表示pbHashData缓冲区的长度，返回杂凑结果的长度
 */
ULONG Adapter_SKF_Digest(
        HANDLE hHash,
        BYTE *pbData,
        ULONG ulDataLen,
        BYTE *pbHashData,
        ULONG *pulHashLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hHash){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hHash){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_Digest(it.second->handle,pbData,ulDataLen,pbHashData,pulHashLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	对多个分组的消息进行杂凑计算。
 *	hHash			[IN] 杂凑对象句柄
 *	pbPart			[IN] 指向消息数据的缓冲区
 *	ulPartLen		[IN] 消息数据的长度
 */
ULONG Adapter_SKF_DigestUpdate(
        HANDLE hHash,
        BYTE *pbData,
        ULONG ulDataLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hHash){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hHash){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_DigestUpdate(it.second->handle,pbData,ulDataLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	结束多个分组消息的杂凑计算操作，将杂凑保存到指定的缓冲区。
 *	hHash			[IN] 哈希对象句柄
 *	pHashData		[OUT] 返回的杂凑数据缓冲区指针，如果此参数NULL时，由pulHashLen返回杂凑结果的长度
 *	pulHashLen		[IN，OUT] 调用时表示杂凑结果的长度，返回杂凑数据的长度
 */
ULONG Adapter_SKF_DigestFinal(
        HANDLE hHash,
        BYTE *pHashData,
        ULONG *pulHashLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hHash){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hHash){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_DigestFinal(it.second->handle,pHashData,pulHashLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	初始化消息认证码计算操作，设置计算消息认证码的密钥参数，并返回消息认证码句柄。
 *	hKey			[IN] 计算消息认证码的密钥句柄
 *	MacParam		[IN] 消息认证计算相关参数，包括初始向量、初始向量长度、填充方法等
 *	phMac			[OUT] 消息认证码对象句柄
 */
ULONG Adapter_SKF_MacInit(
        HANDLE hKey,
        BLOCKCIPHERPARAM* MacParam,
        HANDLE *phMac
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hKey || NULL == phMac){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto it = mapHandle.begin();it != mapHandle.end();it++){
        if(it->first == hKey){
            HANDLE handle = NULL;
            ULONG ret = it->second->m_skfFunctionList_ptr->SKF_MacInit(it->second->handle,MacParam,&handle);
            if(ret != SAR_OK){
                return ret;
            }
            auto skfInfoCacheHandle = new skf_info_cache_handle();
            skfInfoCacheHandle->handle = handle;
            skfInfoCacheHandle->m_skfFunctionList_ptr = it->second->m_skfFunctionList_ptr;
            mapHandle.insert(make_pair((HANDLE)handleSq,skfInfoCacheHandle));
            *phMac = (HANDLE)handleSq;
            handleSq++;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	SKF_Mac计算单一分组数据的消息认证码。
 *	hMac			[IN] 消息认证码句柄
 *	pbData			[IN] 指向待计算数据的缓冲区
 *	ulDataLen		[IN] 待计算数据的长度
 *	pbMacData		[OUT] 指向计算后的Mac结果，如果此参数为NULL时，由pulMacLen返回计算后Mac结果的长度
 *	pulMacLen		[IN，OUT] 调用时表示pbMacData缓冲区的长度，返回计算Mac结果的长度
 */
ULONG Adapter_SKF_Mac(
        HANDLE hMac,
        BYTE * pbData,
        ULONG ulDataLen,
        BYTE *pbMacData,
        ULONG *pulMacLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hMac){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hMac){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_Mac(it.second->handle,pbData,ulDataLen,pbMacData,pulMacLen);
            if(ret != SAR_OK){
                return ret;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	计算多个分组数据的消息认证码。
 *	hMac			[IN] 消息认证码句柄
 *	pbData			[IN] 指向待计算数据的缓冲区
 *	plDataLen		[IN] 待计算数据的长度
 */
ULONG Adapter_SKF_MacUpdate(
        HANDLE hMac,
        BYTE*	pbData,
        ULONG	ulDataLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hMac){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hMac){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_MacUpdate(it.second->handle,pbData,ulDataLen);
            if(ret != SAR_OK){
                return ret;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	结束多个分组数据的消息认证码计算操作
 *	hMac			[IN] 消息认证码句柄
 *	pbMacData		[OUT] 指向消息认证码的缓冲区，当此参数为NULL时，由pulMacDataLen返回消息认证码返回的长度
 *	pulMacDataLen	[OUT] 调用时表示消息认证码缓冲区的最大长度，返回消息认证码的长度
 */
ULONG Adapter_SKF_MacFinal(
        HANDLE hMac,
        BYTE*	pbMacData,
        ULONG* pulMacDataLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hMac){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapHandle){
        if(it.first == hMac){
            ULONG ret = it.second->m_skfFunctionList_ptr->SKF_MacFinal(it.second->handle,pbMacData,pulMacDataLen);
            if(ret != SAR_OK){
                return ret;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	关闭会话密钥、杂凑、消息认证码句柄。
 *	hHandle			[IN] 要关闭的对象句柄
 */
ULONG Adapter_SKF_CloseHandle(
        HANDLE hHandle
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hHandle){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto it = mapHandle.begin();it != mapHandle.end();){
        if(it->first == hHandle){
            ULONG ret = it->second->m_skfFunctionList_ptr->SKF_CloseHandle(it->second->handle);
            if(ret != SAR_OK){
                return ret;
            }

            delete (it->second);
            mapHandle.erase(it++);
            return SAR_OK;
        }else{
            it++;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	将命令直接发送给设备，并返回结果
 *	hDev			[IN] 设备句柄
 *	pbCommand		[IN] 设备命令
 *	ulCommandLen	[IN] 命令长度
 *	pbData			[OUT] 返回结果数据
 *	pulDataLen		[OUT] 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度
 */
ULONG Adapter_SKF_Transmit(
        DEVHANDLE hDev,
        BYTE* pbCommand,
        ULONG ulCommandLen,
        BYTE* pbData,
        ULONG* pulDataLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hDev){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusDevHandle = adapterStatusDevHandle.find(callerName);
    for(;itAdapterStatusDevHandle != adapterStatusDevHandle.end();itAdapterStatusDevHandle++){
        if(itAdapterStatusDevHandle->first != callerName){
            return SAR_INVALIDPARAMERR;
        }

        if(itAdapterStatusDevHandle->second->devhandle == hDev){
            break;
        }
    }

    if(itAdapterStatusDevHandle == adapterStatusDevHandle.end()){
        return SAR_INVALIDPARAMERR;
    }

    for(auto & it : mapDevHandle){
        if(it.first == hDev){
            ULONG ret = it.second->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_Transmit(it.second->devhandle,pbCommand,ulCommandLen,pbData,pulDataLen);
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	往容器中导入签名证书或者加密证书
 *	hContainer		[IN] 容器句柄
 *	bSignFlag		[IN] TRUE表示导入签名证书，FALSE表示导入加密证书
 *	pbCert			[IN] 指向证书数据的缓冲区
 *	ulCertLen		[IN] 证书数据的长度
 */
ULONG Adapter_SKF_ImportCertificate(
        HCONTAINER hContainer,
        BOOL bSignFlag,
        BYTE* pbCert,
        ULONG ulCertLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer){
            break;
        }
    }

    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ImportCertificate(
                        it.second->hcontainer,bSignFlag,pbCert,ulCertLen
                    );
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	导出容器中的签名证书或者加密证书
 *	hContainer		[IN] 容器句柄
 *	bSignFlag		[IN] TRUE表示导出签名证书，FALSE表示导出加密证书
 *	pbCert			[OUT] 指向证书数据的缓冲区
 *	pulCertLen		[IN,OUT] 调用时表示pbCert的长度，返回导出证书的大小
 */
ULONG Adapter_SKF_ExportCertificate(
        HCONTAINER hContainer,
        BOOL bSignFlag,
        BYTE* pbCert,
        ULONG* pulCertLen
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer){
            break;
        }
    }

    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_ExportCertificate(
                    it.second->hcontainer,bSignFlag,pbCert,pulCertLen
            );
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	获取容器的属性
 *	hContainer		[IN] 容器句柄
 *	pulConProperty	[OUT] 获得的容器属性。指针指向的值为0表示未知、尚未分配属性或者为空容器，为1表示为RSA容器，为2表示为ECC容器。
 */
ULONG Adapter_SKF_GetContainerProperty(
        HCONTAINER hContainer,
        ULONG *pulConProperty
)
{
    if(!devEnumFlg){
        return SAR_NOTSUPPORTYETERR;
    }

    if(NULL == hContainer){
        return SAR_INVALIDHANDLEERR;
    }

    auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.find(callerName);
    for(;itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();itAdapterStatusContainerHandle++){
        if(itAdapterStatusContainerHandle->first != callerName){
            return SAR_INVALIDHANDLEERR;
        }

        if(itAdapterStatusContainerHandle->second->hcontainer == hContainer){
            break;
        }
    }

    if(itAdapterStatusContainerHandle == adapterStatusContainerHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    for(auto & it : mapContainerHandle){
        if(it.first == hContainer){
            ULONG ret = it.second->skfInfoCacheApphandle->skfInfoCacheDevhandle->skfInfoCacheDevname->m_skfFunctionList_ptr->SKF_GetContainerProperty(
                    it.second->hcontainer,pulConProperty
            );
            if(ret != SAR_OK){
                return ret;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

void clearAdapterMap(string name){
    for(auto itAdapterStatusContainerHandle = adapterStatusContainerHandle.begin();
        itAdapterStatusContainerHandle != adapterStatusContainerHandle.end();){
        if(itAdapterStatusContainerHandle->second->appHandle->devHandle->devName->devName == name){
            delete itAdapterStatusContainerHandle->second;
            adapterStatusContainerHandle.erase(itAdapterStatusContainerHandle++);
        } else{
            itAdapterStatusContainerHandle++;
        }
    }

    for(auto itAdapterStatusAppHandle = adapterStatusAppHandle.begin();
        itAdapterStatusAppHandle != adapterStatusAppHandle.end();){
        if(itAdapterStatusAppHandle->second->devHandle->devName->devName == name){
            delete itAdapterStatusAppHandle->second;
            adapterStatusAppHandle.erase(itAdapterStatusAppHandle++);
        } else{
            itAdapterStatusAppHandle++;
        }
    }

    for(auto itAdapterStatusDevHandle = adapterStatusDevHandle.begin();
        itAdapterStatusDevHandle != adapterStatusDevHandle.end();){
        if(itAdapterStatusDevHandle->second->devName->devName == name){
            delete itAdapterStatusDevHandle->second;
            adapterStatusDevHandle.erase(itAdapterStatusDevHandle++);
        } else{
            itAdapterStatusDevHandle++;
        }
    }

    for(auto itAdapterStatusDevName = adapterStatusDevName.begin();
        itAdapterStatusDevName != adapterStatusDevName.end();){
        if(itAdapterStatusDevName->second->devName == name){
            delete itAdapterStatusDevName->second;
            adapterStatusDevName.erase(itAdapterStatusDevName++);
        } else{
            itAdapterStatusDevName++;
        }
    }
}
