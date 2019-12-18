//
// Created by wjr on 19-3-11.
//

#include "BinderServer.h"
#include <dlfcn.h>
#include <map>
#include <iostream>
#include <android/log.h>
using namespace std;

#define LOG(...) __android_log_print(ANDROID_LOG_INFO,"wjr",__VA_ARGS__)


#define BINDER_SERVER_SO_NAME   "libRpcJniServer.so"
#define FUNC_MSG_FROM_CLIENT    "RegParseClientMsg"
#define FUNC_MSG_TO_CLIENT      "SendMsgToClient"

class binderInfo{
public:
    int pid;
    string serverName;
};

static map<binderInfo*, CommunicationServer::Communication*> mapCli; // 客户端列表
static map<string,BinderServer*> mapSer;    //服务端列表
static map<string,CommunicationServer::serverRecvFuncType> mapRecvCall;//接受消息函数列表

BinderServerClient::BinderServerClient(char *pName, int id) {
    serName = pName;
    pid = id;
}

//ComLog BinderServerClient::getlogfunc(){
//
//}

CommunicationServer::Communication* BinderServerClient::getClient(char *pName, int id) {
    map<binderInfo*, CommunicationServer::Communication*>::iterator it;
    binderInfo *pInfo = NULL;
    CommunicationServer::Communication *tmp = NULL;

    for(it = mapCli.begin();it != mapCli.end();++it){
        pInfo = it->first;
        if(pInfo->pid == id && pInfo->serverName.size() == strlen(pName) && (0 == memcmp(pInfo->serverName.data(),pName,strlen(pName)))){
            tmp = it->second;
            break;
        }
    }

    if(tmp == NULL){
        pInfo = new binderInfo();
        pInfo->pid = id;
        pInfo->serverName = pName;
        tmp = new BinderServerClient(pName,id);
        mapCli.insert(make_pair(pInfo,tmp));
    }

    return tmp;
}

int BinderServerClient::Send(unsigned char *buf, int len) {
    LOG("BinderServerClient::Send IN1");
    map<string,BinderServer*>::iterator it;
    BinderServer* tmp = NULL;

    for(it = mapSer.begin();it != mapSer.end();++it){
        if(it->first == serName){
            tmp = it->second;
            break;
        }
    }

    if(tmp == NULL){
        LOG("Can't find server");
        return -1;
    }

    if(tmp->getSendMsgToClient() == NULL){
        LOG("getSendMsgToClient() == NULL ERROR");
    } else{
        (tmp->getSendMsgToClient())(pid,(char*)serName.data(),(char*)buf,len);
        LOG("Success Server send Msg");
    }

    return 0;
}

int BinderServerClient::Close() {
    return 0;
}

int recvClientMsg(int id,char *serverName,char *in, unsigned int inLen){
    LOG("%s IN",__FUNCTION__);
    LOG("id = %d,serverName = %s,in = %p,inLen = %d",id,serverName,in,inLen);

    map<string,CommunicationServer::serverRecvFuncType>::iterator it;
    CommunicationServer::serverRecvFuncType recvFuncType = NULL;
    string s;

    CommunicationServer::Communication *client = BinderServerClient::getClient(serverName,id);

    for(it = mapRecvCall.begin(); it != mapRecvCall.end();++it){
        s = it->first;
        if(s.size() == strlen(serverName) && 0 == memcmp(s.c_str(),serverName,strlen(serverName))){
            recvFuncType = it->second;
            LOG("Has find func %p",recvFuncType);
            break;
        }
    }

    if(NULL != recvFuncType){
        map<string,BinderServer*>::iterator iteratorS;
        for(iteratorS = mapSer.begin();iteratorS != mapSer.end();++iteratorS){
            if(iteratorS->first == serverName){
                recvFuncType((CommunicationServer*)iteratorS->second,client,(unsigned char*)in,inLen);
                break;
            }
        }

    } else{
        LOG("Error Has not find client name!!!");
    }

    return 0;
}

BinderServer::BinderServer(char *pServerName) throw(int) {
    serverName = pServerName;
    regParseClientMsg = NULL;
    sendMsgToClient = NULL;
    mapSer.insert(make_pair(serverName,this));
    void *h = dlopen(BINDER_SERVER_SO_NAME,RTLD_LAZY);
    if(NULL != h){
        regParseClientMsg = (pRegParseClientMsg)dlsym(h,FUNC_MSG_FROM_CLIENT);
        LOG("%s regParseClientMsg = %p",__FUNCTION__,regParseClientMsg);
        sendMsgToClient = (pSendMsgToClient)dlsym(h,FUNC_MSG_TO_CLIENT);
    }

    if(regParseClientMsg != NULL){
        regParseClientMsg(recvClientMsg);
    }
}

BinderServer::~BinderServer() {

}

pSendMsgToClient BinderServer::getSendMsgToClient(){
    return sendMsgToClient;
}

int BinderServer::BroadCast(string funcName, string src) {
    string msg;
    int msgLen = pack->Pack(funcName,src).size();
    msg.append((const char*)&msgLen,sizeof(msgLen));
    msg.append((const char*)pack->Pack(funcName,src).data(),pack->Pack(funcName,src).size());

    binderInfo* pInfo = NULL;
    CommunicationServer::Communication* pClient = NULL;
    map<binderInfo*, CommunicationServer::Communication*>::iterator it;
    for(it = mapCli.begin();it != mapCli.end();++it){
        pInfo = it->first;
        if(pInfo->serverName == serverName){
            pClient = it->second;
            pClient->Send((unsigned char*)msg.data(),msg.size());
        }
    }

    return 0;
}

int BinderServer::RegServerRecvFunc(CommunicationServer::serverRecvFuncType func) {
    LOG("%s IN",__FUNCTION__);
    mapRecvCall.insert(make_pair(serverName,func));
    LOG("%s OUT,serverName = %s,func addr = %p",__FUNCTION__,serverName.c_str(),func);
    return 0;
}


