//
// Created by wang.junren on 2018/11/1.
//

#ifndef CSM_REMOTESERVICEPACK_H
#define CSM_REMOTESERVICEPACK_H


#include "BroadCastPack.h"

class RemoteServicePack : public BroadcastPack{
public:
    string Pack(string funcName,string src);
};


#endif //CSM_REMOTESERVICEPACK_H
