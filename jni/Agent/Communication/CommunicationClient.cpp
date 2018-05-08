#include "CommunicationClient.h"



CommunicationClient::CommunicationClient() throw(int)
{
}

CommunicationClient::~CommunicationClient()
{

}

int CommunicationClient::RegNotifyFunc(NotifyClientStatus func)
{
	clientNotifyFunc = func;
}

int CommunicationClient::Reconnect()
{
	
}

int CommunicationClient::ClientSend(unsigned char *buf,int len)
{

}

int CommunicationClient::RegClientRecvFunc(ClientRecv func)
{
	
}


