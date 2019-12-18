//
// Created by wang.junren on 2018/7/13.
//

#ifndef CSM_LIBLOADMANAGER_H
#define CSM_LIBLOADMANAGER_H


class LibLoadManager {
public:
    explicit LibLoadManager(const char * pLibPath);
    virtual ~LibLoadManager();
    void *GetFuncPointer(const char* pFuncName);
private:
    void *handle;
};


#endif //CSM_LIBLOADMANAGER_H
