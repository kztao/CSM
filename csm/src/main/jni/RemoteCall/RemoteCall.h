#ifndef __REMOTE_CALL_H
#define __REMOTE_CALL_H

#include "MsgFrame.h"
#include "Mutex.h"
#include "CommunicationClient.h"
#include "Pack.h"
#include "logdefine.h"
#include <map>
using std::string;

#define  LOCAL_SOCKET_SERVER_NAME "localSockect"

typedef int (*RemoteResponseParseFunc)(const string funcName,const string src);

class RemoteCall
{
public:
	RemoteCall(CommunicationClient *pClient,ComLog logfunc);
	explicit RemoteCall(CommunicationClient *pClient);
	virtual ~RemoteCall();

	int PutRequest(const string funcName,const string src);
	int WaitForResponse(int mseconds,string &dst);
	static int SetRemoteResponseParseFunc(RemoteResponseParseFunc func);
private:
	CommunicationClient *m_pClient;
	MsgFrame m_msgFrame;
	Pack m_instance;
	ComLog g_mComLog;
	void printlog(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...);
};

#endif //__REMOTE_CALL_H