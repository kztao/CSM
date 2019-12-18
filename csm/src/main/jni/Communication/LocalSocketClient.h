#ifndef __LOCALSOCKETCLIENT_H
#define __LOCALSOCKETCLIENT_H

#include "CommunicationClient.h"
#include <vector>
#include <sys/types.h>
#include <sys/un.h>
#include <pthread.h> 
#include <iostream>
#include <android/log.h>
#include "logdefine.h"
using std::string;

#define CLIENTINIT_OK     0
#define CLIENTINIT_ALREADYEXIST 1
#define CLIENTINIT_FAIL   -1




class LocalSocketClient:public CommunicationClient
{
private:
	int fd;
	friend void* clientRecvThread(LocalSocketClient *tmp);
	ClientRecv mrecvfunc; 
	int mconnFlg;
	pthread_mutex_t mutexReconn;
	pthread_mutex_t mutexrecvthread;
	
	string mserverName;
	pthread_t mrecv_threadid;
	NotifyClientStatus mnotifyClientStatusFunc;
	int Connect2Server();
	virtual bool Reconnect();
	ComLog g_mComLog;
	void printlog(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...);
public:
	LocalSocketClient(char * pServerName,NotifyClientStatus func);
	LocalSocketClient(char * pServerName,NotifyClientStatus func,ComLog logfunc);
	virtual ~LocalSocketClient();
	virtual int init(ClientRecv func) override;
	virtual bool ClientSend(unsigned char *buf,int len) override;
	
};

#endif
