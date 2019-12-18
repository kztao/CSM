#ifndef __COMMUNICATIONCLIENT_H
#define __COMMUNICATIONCLIENT_H

#define CLIENT_OK  0
#define CLIENT_DISCONNECTED   1
#define CLIENT_UNCONNECT  2


typedef void (*NotifyClientStatus)(int status);

class CommunicationClient
{
public:
	typedef int (*ClientRecv)(unsigned char *buf,int len);
	virtual int init(ClientRecv func) = 0;
//	virtual bool Reconnect() = 0;
	virtual bool ClientSend(unsigned char *buf,int len) = 0;	
//	virtual int RegClientRecvFunc(ClientRecv func) = 0;
};
#endif
