
#include "CommunicationClient.h"
#include "LocalSocketClient.h"
#include <iostream>
#include "RemoteCall.h"
#include "log.h"


#include <cstring>
#include <string>
#include "TestClient.h"

using namespace std;	




void get(int status)
{
	
}

int client_recv(unsigned char *buf,int len)
{
	int i=0;
	LOGI("received len %d: \n", len);
	Print_Data(buf,len);
	
	return 0;
}

int clientInit_comm()
{
	int ret = 0;
	
	char* pClientName = (char*)"testclient";
	char* pServerName = (char*)"testserver";
	try{
		CommunicationClient *testclient = new LocalSocketClient(pClientName, pServerName, get);
		
		ret = testclient->RegClientRecvFunc(client_recv);
		
		unsigned char buf[4] = {0x01,0x01,0x01,0x01};
		int len = sizeof(buf);
		ret = testclient->ClientSend(buf,len);
		LOGI("client send len: %d, ret is %d\n",len, ret);
	}
	catch(int e){
		
		LOGE("LocalSocketClient, Exception is %d",e);
	}	
	
	return  0;
}

int RemoteResponseParseFuncTest(const string funcName,const string src)
{
	return 0;
}




RemoteCall *tmp;

int clientSend(int count){
	int ret = 0;
	int i=0;
	
	string d;
		d.resize(1000);
		string &r = d;

	LOGI("%s IN num = %d",__FUNCTION__,count);
	for(i=0;i< count;i++)
	{
		tmp->PutRequest("TestFunc1","hello");
		ret = tmp->WaitForResponse(1000,r);

		LOGI("%s i = %d, ret = %d,back para %s","TestFunc1",i,ret,r.c_str());
	}

	return i;
}

int clientInit()
{
	
	int type = 1;
	RemoteCall::SetRemoteResponseParseFunc(RemoteResponseParseFuncTest);
	tmp = new RemoteCall(type);	
	
	return 0;
}





