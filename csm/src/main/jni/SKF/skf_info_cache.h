//
// Created by wjr on 19-4-19.
//

#ifndef CSM_SKF_INFO_CACHE_H
#define CSM_SKF_INFO_CACHE_H

#include "skf.h"

#include <iostream>
#include <map>
#include <set>
using namespace std;

class skf_info_cache_devname{
public:
    SKFFunctionList_PTR m_skfFunctionList_ptr;
    string name;
};

class skf_info_cache_devhandle{
public:
    skf_info_cache_devname* skfInfoCacheDevname;
    DEVHANDLE devhandle;
};

class skf_info_cache_apphandle{
public:
    skf_info_cache_devhandle* skfInfoCacheDevhandle;
    string appName;
    HAPPLICATION happlication;
};

class skf_info_cache_containerhandle{
public:
    skf_info_cache_apphandle* skfInfoCacheApphandle;
    string containerName;
    HCONTAINER hcontainer;
};

class skf_info_cache_handle{
public:
    SKFFunctionList_PTR m_skfFunctionList_ptr;
    HANDLE handle;
};

class SkfAdapterStatusDevName {
public:
    string devName;
    int status = 0;
};

class SkfAdapterStatusDevHandle {
public:
    DEVHANDLE devhandle;
    SkfAdapterStatusDevName *devName;
};

class SkfAdapterStatusAppHandle {
public:
    string appName;
    HAPPLICATION happlication;
    int status = 0;
    SkfAdapterStatusDevHandle *devHandle;
};

class SkfAdapterStatusContainerHandle {
public:
    string containerName;
    HCONTAINER hcontainer;
    int status = 0;
    SkfAdapterStatusAppHandle *appHandle;
};

#endif //CSM_SKF_INFO_CACHE_H
