//
// Created by wang.junren on 2018/7/13.
//

#include "LibLoadManager.h"
#include <dlfcn.h>
#include "logserver.h"
static const char* tag = "csm_libload";


LibLoadManager::LibLoadManager(const char *pLibPath) {
    handle = dlopen(pLibPath,RTLD_LAZY);
	if (!handle) {
		LOGSERVERE(tag, "dlopen error: %s, path: %s", dlerror(), pLibPath);
	}
}

LibLoadManager::~LibLoadManager() {
    dlclose(handle);
}

void* LibLoadManager::GetFuncPointer(const char *pFuncName){
    if(handle){
        return dlsym(handle,pFuncName);
    }
	
	LOGSERVERE(tag, "GetFuncPointer, handle is null");

    return NULL;
}

