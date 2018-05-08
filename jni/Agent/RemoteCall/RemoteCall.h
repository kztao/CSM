#ifndef __REMOTE_CALL_H
#define __REMOTE_CALL_H

#include "MsgFrame.h"
#include "Mutex.h"
#include "CommunicationClient.h"

#include <map>
using namespace std;

#define  LOCAL_SOCKET_SERVER_NAME "localName"


class RemoteCall
{
public:		
	friend int msgFrameRecvFunc(unsigned char *buf,int len);
	RemoteCall(int type);
	virtual ~RemoteCall();
	typedef int (*RemoteResponseParseFunc)(const string funcName,const string src);
	int PutRequest(const string funcName,const string src);
	int WaitForResponse(int mseconds,string &dst);
	static int SetRemoteResponseParseFunc(RemoteResponseParseFunc func);
private:
	MsgFrame msgFrame;
	Mutex instance;
	int type;	
	static map<int,CommunicationClient *> mapClient;
	static RemoteResponseParseFunc globeFunc;	
};

#endif //__REMOTE_CALL_H