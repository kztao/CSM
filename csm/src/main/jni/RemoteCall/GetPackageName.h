//
// Created by wang.junren on 2018/6/8.
//

#ifndef CSM_GETPACKAGENAME_H
#define CSM_GETPACKAGENAME_H


#include <string>

class GetPackageName {
private:
    pid_t pid;
    std::string packageName;
public:
    GetPackageName();
    std::string GetName();
    virtual ~GetPackageName();
};


#endif //CSM_GETPACKAGENAME_H
