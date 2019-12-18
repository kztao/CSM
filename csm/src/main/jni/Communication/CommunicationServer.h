#ifndef __COMMUNICATIONSERVER_H
#define __COMMUNICATIONSERVER_H

#include <iostream>
#include "BroadCastPack.h"
#include "logdefine.h"
using std::string;

#define CLIENT_OK  0
#define CLIENT_DISCONNECTED   1



class CommunicationServer
{
public:
	class Communication{
	public:
		virtual int Close() = 0;
		virtual int Send(unsigned char *buf,int len) = 0;
		virtual ~Communication(){}
	};

	typedef int (*serverRecvFuncType)(CommunicationServer *server,Communication *client,unsigned char *buf,int len);
	virtual int RegServerRecvFunc(serverRecvFuncType func) = 0;
	typedef void (*ServerNotifyClientStatus)(Communication *client,int status);

	virtual void SetBroadcastPack(BroadcastPack *pack)final {
		this->pack = pack;
	}

	virtual int BroadCast(string funcName,string src) = 0;

	virtual ~CommunicationServer(){}
	
protected:
	ServerNotifyClientStatus m_NofityFunc;
    serverRecvFuncType m_RecvFunc;
	BroadcastPack *pack;
};


#endif
