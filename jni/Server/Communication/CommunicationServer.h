#ifndef __COMMUNICATIONSERVER_H
#define __COMMUNICATIONSERVER_H

#include "Communication.h"


class CommunicationServer
{
public:
	CommunicationServer() throw(int);
	virtual ~CommunicationServer();	
	typedef int (*serverRecvFuncType)(Communication *client,unsigned char *buf,int len);	
	virtual int RegServerRecvFunc(serverRecvFuncType func);	
	virtual int BroadCast(unsigned char *buf,int len);
};


#endif
