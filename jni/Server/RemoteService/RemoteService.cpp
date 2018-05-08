#include "RemoteService.h"
#include "ReturnCode.h"
#include "MsgFrame.h"
#include "ContentFrame.h"
#include "ContentFrame0001.h"
#include <iostream>
#include <string>
#include "log.h"
#include "LocalSocketServer.h"

using namespace std;
map<int,CommunicationServer*> RemoteService::mapCommunicationServer;


void get(int fd, int status)
{
	cout<<"fd: " <<fd<<endl;
	cout<<"Server status: " << status<<endl;
}

class P11Test:public FunctionParse{
public:
	P11Test(){
		mapFuncList["TestFunc1"] = (FunctionParse::funcType)&P11Test::TestFunc1;
	}
	virtual ~P11Test(){

	}
private:
	int TestFunc1(string src,string &dst){
		dst = "world";
		return 0;
	}
	
};


FunctionParse function;

int RemoteRecvFunc(Communication *pClient,unsigned char *buf,int len){
	
	MsgFrame msgFrame;
	string recv = "";
	
	string content = "";
	string &pContent = content;

	string funcName = "";
	string &pFuncName = funcName;

	string msg = "";
	string &pMsg = msg;

	string outContent="";
	string &pOutContent = outContent;	

	string out = "";
	string &pOut = out;	

	int ret;
	int msgID;
	short version;

	for(int i = 0;i < len;i++){
		recv += buf[i];
	}

	LOGI("recv len = %d",len);
	Print_Data((unsigned char*)recv.data(),recv.size());
	
	ret = msgFrame.MsgFrameUnpacket(recv,&msgID,&version,pContent);
	if(0 != ret){
		return ret;
	}

	if(version == 0x0001){
		msgFrame.pContentFrame = new ContentFrame0001();
	}
	else{
	    LOGI("content version is %d", version);		
	}
	
	Print_Data((unsigned char*)content.data(),content.size());
	ret = msgFrame.pContentFrame->ContentFrameUnpacket(content,pFuncName,pMsg);
	if(0 != ret){
		delete msgFrame.pContentFrame;
		return ret;
	}

	LOGI("call function len = %d: function is %s,para len is %d", funcName.size(),funcName.c_str(),msg.size());
	ret = function.call(funcName,msg,pOut);
	if(0 != ret){
		delete msgFrame.pContentFrame;
		return ret;
	}

	ret = msgFrame.pContentFrame->ContentFramePacket(funcName,out,pOutContent);
	if(0 != ret){
		delete msgFrame.pContentFrame;
		return ret;
	}

	delete msgFrame.pContentFrame;
	
	ret = msgFrame.MsgFramePacket(msgID,version,outContent,pOut);
	if(0 != ret){
		return ret;
	}

	LOGI("Server send data len  = %d,back",out.size());
	ret = pClient->Send((unsigned char*)out.data(),out.size());

	return RETURN_CODE_OK;
}

RemoteService::RemoteService(int type){

	if(NULL == mapCommunicationServer[type]){
		char* ServerName = (char*)"localName";
		try{
			function = P11Test();
			CommunicationServer *tmp = new LocalSocketServer(ServerName,get);
		mapCommunicationServer[type] = tmp;
		tmp->RegServerRecvFunc((CommunicationServer::serverRecvFuncType)RemoteRecvFunc);
		}catch(int e){

		}
	}
}

RemoteService::~RemoteService(){
}

int RemoteService::BroadcastMsg(string funcName,unsigned char *buf,int len){
	MsgFrame msgFrame;
	string inBuf;
	
	string content;
	string &pContent = content;

	string msg;
	string &pMsg = msg;
	int ret = 0;

	for(int i = 0;i < len;i++){
		inBuf += buf[i];
	}
	
	msgFrame.pContentFrame = new ContentFrame0001();

	ret = msgFrame.pContentFrame->ContentFramePacket(inBuf,funcName,pContent);
	if(0 != ret){
		delete msgFrame.pContentFrame;
		return ret;
	}

	delete msgFrame.pContentFrame;
	
	ret = msgFrame.MsgFramePacket(0,0x0001,content,pMsg);
	if(0 != ret){
		return ret;
	}

	//mapCommunicationServer[type]->BroadCast(msg.data(),msg.size());
	
	return RETURN_CODE_OK;	
}


