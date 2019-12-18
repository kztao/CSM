//
// Created by wjr on 19-4-18.
//

#ifndef CSM_SKFLIBLOADER_H
#define CSM_SKFLIBLOADER_H


#include "skf.h"

class skfLibLoader {
protected:
    void *handle;
    SKFFunctionList skfFunctionList;
public:
    explicit skfLibLoader(char *libPath);
    ~skfLibLoader();
    void *SKF_GetFuncPointer(char *name);
    SKFFunctionList_PTR SKF_GetFunctionList();

};


#endif //CSM_SKFLIBLOADER_H
