#ifndef __REMOTE_SERVICE_H
#define __REMOTE_SERVICE_H

#include "FunctionParse.h"
#include "Communication.h"
#include "CommunicationServer.h"
#include <string>
#include <map>
using namespace std;

int RemoteRecvFunc(Communication *pClient,unsigned char *buf,int len);

class RemoteService
{
private:
	
	static map<int,CommunicationServer*> mapCommunicationServer;
	
public:
	RemoteService(int type);
	virtual ~RemoteService();
	int BroadcastMsg(string functionName,unsigned char *buf,int len);	
};

#endif //__REMOTE_SERVICE_H
