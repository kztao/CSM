#ifndef __COMMUNICATIONCLIENT_H
#define __COMMUNICATIONCLIENT_H

#define CLIENT_OK  0
#define CLIENT_DISCONNECTED   1

typedef void (*NotifyClientStatus)(int status);

class CommunicationClient
{
public:
	CommunicationClient()throw(int);
	virtual ~CommunicationClient();
	virtual int Reconnect();
	virtual int RegNotifyFunc(NotifyClientStatus func)final;
	virtual int ClientSend(unsigned char *buf,int len);
	typedef int (*ClientRecv)(unsigned char *buf,int len);
	virtual int RegClientRecvFunc(ClientRecv func);	
protected:
	NotifyClientStatus clientNotifyFunc;
};
#endif
