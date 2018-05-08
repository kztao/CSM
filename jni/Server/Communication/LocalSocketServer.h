#ifndef __LOCALSOCKETSERVER_H
#define __LOCALSOCKETSERVER_H

#include "CommunicationServer.h"
#include <vector>

using namespace std; 


class CommunicationMessage
{
public:
		int len;
		unsigned char *buf;
};


class LocalSocketServer:public CommunicationServer
{
private:
	int sfd;
	vector<int> vectorFd;
	serverRecvFuncType recvFunc;
	
public:
	typedef void (*NotifyFdServerStatus)(int fd,int status);
	LocalSocketServer(char *pServerName,NotifyFdServerStatus func) throw(int);
	virtual ~LocalSocketServer();
	virtual int BroadCast(unsigned char *buf,int len);
	virtual int RegServerRecvFunc(serverRecvFuncType func);	
	
};

class LocalSocketServerComm : public Communication
{
private:
	int fd;
	
public:
	LocalSocketServerComm(int fd);
	virtual int Send(unsigned char *buf,int len);
	virtual ~LocalSocketServerComm();
};

#endif
