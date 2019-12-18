#ifndef __REMOTE_SERVICE_H
#define __REMOTE_SERVICE_H

#include "CommunicationServer.h"
#include "Control.h"

#include <iostream>
#include <map>
#include <vector>
#include "logdefine.h"

using std::string;

class RemoteService
{
private:
	CommunicationServer *m_server;
	Control *m_Control;
	ComLog g_mComLog;
	void printlog(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...);
public:
	RemoteService(CommunicationServer *pServer,Control *pControl);
	RemoteService(CommunicationServer *pServer,Control *pControl,FunctionParse *functionParse);
	virtual ~RemoteService();
	void setlogFunc(ComLog logfunc);
#ifdef SCP02_ENCRYPT
    static int RecvFunc(CommunicationServer *server,CommunicationServer::Communication *client, unsigned char *buf, int len);
#endif
};

#endif //__REMOTE_SERVICE_H
