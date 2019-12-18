//
// Created by wang.junren on 2018/6/19.
//

#ifndef CSM_CSMRESACCESS_H
#define CSM_CSMRESACCESS_H

#include <iostream>
#include <map>
#include "logdefine.h"
using std::string;
using std::multimap;

class CSMResAccess {
public:
    static bool CheckCert(string packageName,unsigned char *sign);
private:
    static multimap<string,string> packageNameAndFinger;
};

#endif //CSM_CSMRESACCESS_H
