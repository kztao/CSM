#ifndef __LOCALSOCKETSERVER_H
#define __LOCALSOCKETSERVER_H

#include "CommunicationServer.h"
#include <vector>
#include <map>
#include <pthread.h> 
#include <android/log.h>
#include "logdefine.h"
using std::string;
using std::vector;
using std::map;


class LocalSocketServer:public CommunicationServer
{
private:
	bool flgExit;
    pthread_mutex_t mtx;
    pthread_t tid_recv;
    //friend void *ConnectThread(LocalSocketServer *args);
    friend void *RecvThread(LocalSocketServer *args);
    int sfd;
    vector<int> vectorFd;
    map<int,CommunicationServer::Communication*> mapCommunicationServer;
	ComLog g_mComLog;
	void printlog(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...);
public:	
	LocalSocketServer(char *pServerName, ServerNotifyClientStatus notifyfuc) throw(int);
	LocalSocketServer(char * pServerName, ServerNotifyClientStatus notifyfuc, ComLog log) throw(int);
	LocalSocketServer(unsigned short port, ServerNotifyClientStatus notifyfuc) throw(int);
	~LocalSocketServer();
	int BroadCast(string funcName,string src) override;
	int RegServerRecvFunc(serverRecvFuncType func) override;
};

#endif
