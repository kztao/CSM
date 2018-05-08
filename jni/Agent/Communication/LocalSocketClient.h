#ifndef __LOCALSOCKETCLIENT_H
#define __LOCALSOCKETCLIENT_H

#include "CommunicationClient.h"
#include <vector>
#include <sys/types.h>
#include <sys/un.h>


using namespace std; 




class CommunicationMessage
{
public:
		int len;
		unsigned char *buf;
};


class LocalSocketClient:public CommunicationClient
{
private:
	int fd;
	CommunicationMessage msg;
	static vector<CommunicationMessage> vector_message;
	ClientRecv recvfunc; 
	struct sockaddr_un serveraddr;
	
public:
	LocalSocketClient(char * pClientName,char * pServerName,NotifyClientStatus func)throw(int);
	virtual ~LocalSocketClient();	
	virtual int ClientSend(unsigned char *buf,int len);
	virtual int Reconnect();
	virtual int RegClientRecvFunc(ClientRecv func);	
};

#endif
