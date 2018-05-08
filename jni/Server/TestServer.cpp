#include "CommunicationServer.h"
#include "LocalSocketServer.h"
#include "Communication.h"
#include <iostream>
#include "FunctionParse.h"
#include "RemoteService.h"
#include "log.h"


#ifdef __cplusplus
extern "C" { 
#endif


void get(int fd, int status)
{
	
}


int serverRecv(Communication *client,unsigned char *buf,int len)
{
	LOGI("serverRecv, len = %d", len);
	Print_Data(buf,len);

	unsigned char data[5] = {
	2,2,2,2,5
	};

	client->Send(data,sizeof(data));
	return 0;
}

int serverInit_comm()
{
	int ret = 0;

	LOGI("serverinit start, servername is testserver");

	char* ServerName = (char*)"localName";
	try{	
		CommunicationServer *testserver = new LocalSocketServer(ServerName,get);
		LOGI("serverinit ok");

		testserver->RegServerRecvFunc(serverRecv);
	}
	catch(int e)
	{
		LOGE("LocalSocketServer, Exception is %d",e);
	}	
}

int serverInit()
{	
	RemoteService(0);

	LOGI("serverinit end");
	return  0;
}

#ifdef __cplusplus
}
#endif

