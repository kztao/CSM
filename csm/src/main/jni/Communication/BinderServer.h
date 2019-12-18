//
// Created by wjr on 19-3-11.
//

#ifndef CSM_BINDERSERVER_H
#define CSM_BINDERSERVER_H


#include "CommunicationServer.h"

typedef int (*pParseClientMsg)(int id,char*serverName,char *in, unsigned int inLen);

typedef void (*pRegParseClientMsg)(pParseClientMsg parseFunc);

typedef void (*pSendMsgToClient)(int id,char* serverName,char *buf,unsigned int len);

typedef void (*pNotifyClientStatus)(int id,char*serverName,int status);

class BinderServerClient: public CommunicationServer::Communication{
public:
    static CommunicationServer::Communication *getClient(char *pName,int id);
    int Send(unsigned char *buf,int len) override;
    int Close() override;
 //   ComLog getlogfunc();
private:
    string serName;
    int pid;
    BinderServerClient(char *pName,int id);
};

class BinderServer : public CommunicationServer{
private:
    string serverName;
    pRegParseClientMsg regParseClientMsg;
    pSendMsgToClient sendMsgToClient;
    CommunicationServer::serverRecvFuncType recvFuncType;
    friend void parseClientMsgFunc(int id,BinderServer *binderServer,char *in, unsigned int inLen);
public:
    explicit BinderServer(char *pServerName) throw(int);
    ~BinderServer();
    int BroadCast(string funcName,string src) override;
    int RegServerRecvFunc(serverRecvFuncType func) override;
    pSendMsgToClient getSendMsgToClient();
};

#endif //CSM_BINDERSERVER_H
