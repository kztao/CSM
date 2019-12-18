//
// Created by wjr on 19-3-11.
//

#ifndef CSM_BINDERCLIENT_H
#define CSM_BINDERCLIENT_H

#include <pthread.h>
#include <iostream>
#include <vector>
#include "CommunicationClient.h"
using namespace std;

typedef int (*RecvMsgFromServer)(unsigned char *buf,int len);
typedef void (*pRegServerMsgParseFunc)(char *pServerName,RecvMsgFromServer func);
typedef int (*pSendMsgToServer)(char *pServerName,char *buf, unsigned int len);

typedef void (*Resetclientfunc)();
typedef void (*pregClientResetFunc)(Resetclientfunc func);


class BinderClient : public CommunicationClient{
public:
    BinderClient(char * pServerName,NotifyClientStatus notifyClientStatus);
    virtual ~BinderClient();
    virtual int init(ClientRecv func) override;
    virtual bool ClientSend(unsigned char *buf,int len) override;
private:
    string serverName;
    pRegServerMsgParseFunc regServerMsgParseFunc;
    pSendMsgToServer sendMsgToServer;
    pthread_mutex_t m_mutex;
    pthread_cond_t m_cond;
    bool m_packFlg;
    vector<string> m_sendList;
//    friend void *SendThread(BinderClient *tmp);
	pregClientResetFunc regClientResetFunc;
};

BinderClient *getInstance(char * pServerName);

#endif //CSM_BINDERCLIENT_H
