#ifndef __BROADCAST_PACK_H
#define __BROADCAST_PACK_H

#include <iostream>
using std::string;

class BroadcastPack{
public:
    virtual string Pack(string funcName,string src) = 0;
};

#endif
