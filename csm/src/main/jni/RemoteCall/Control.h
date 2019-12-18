//
// Created by wang.junren on 2018/9/28.
//

#ifndef CSM_CONTROL_H
#define CSM_CONTROL_H

#include "CommunicationServer.h"
#include "FunctionParse.h"
#include <iostream>

using std::string;

class Control {
protected:
    FunctionParse *functionParse;
public:
    virtual bool check(CommunicationServer::Communication *pClient,string funcName,string src,string &clientName) = 0;
    virtual void setFunctionParse(FunctionParse *functionParse)final;
    virtual FunctionParse * getFunctionParse()final;
	virtual ~Control(){}
};


#endif //CSM_CONTROL_H
