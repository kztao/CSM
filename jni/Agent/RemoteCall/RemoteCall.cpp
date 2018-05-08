#include "RemoteCall.h"
#include "CommunicationClient.h"
#include "LocalSocketClient.h"
#include "ReturnCode.h"
#include "ContentFrame0001.h"
#include "log.h"

RemoteCall::RemoteResponseParseFunc RemoteCall::globeFunc = NULL;
map<int,CommunicationClient *> RemoteCall::mapClient;

int msgFrameRecvFunc(unsigned char *buf,int len){
	LOGI("%s IN,client recv len = %d",__FUNCTION__,len);
	string recv;
	
	string content;
	string &pContent = content;
	
	string funcName;
	string &pFuncName = funcName;

	string out;
	string &pOut = out;

	MsgFrame msgFrameTmp;
	int ret;
	int msgID;
	short version;

	for(int i = 0;i < len;i++){
		recv += buf[i];	
	}
	
	ret = msgFrameTmp.MsgFrameUnpacket(recv,&msgID,&version,pContent);
	if(0 != ret){
		return ret;
	}

	if(version == 0x0001){
		msgFrameTmp.pContentFrame = new ContentFrame0001();
	}

	ret = msgFrameTmp.pContentFrame->ContentFrameUnpacket(content,pFuncName,pOut);
	if(0 != ret){
		delete msgFrameTmp.pContentFrame;
		return ret;
	}
	delete msgFrameTmp.pContentFrame;
	LOGI("Start put recv msg ID = %d,len = %d",msgID,out.size());
	if(msgID != 0){
		ret = msgFrameTmp.PutRecvMsg(msgID,out);
		if(0 != ret){
			return ret;
		}

		Mutex::Unlock(msgID);

	}else{
		LOGI("%s callback",__FUNCTION__);
		RemoteCall::globeFunc(funcName,out);
	}
	

	return RETURN_CODE_OK;
}

void NotifyFdClientStatusFunc(int status){

}

RemoteCall::RemoteCall(int type){
	CommunicationClient * pClient = mapClient[type];
	this->type = type;
	if(pClient == NULL){
		pClient = new LocalSocketClient(NULL,(char*)LOCAL_SOCKET_SERVER_NAME,NotifyFdClientStatusFunc);
		pClient->RegClientRecvFunc(msgFrameRecvFunc);
		mapClient[type] = pClient;
	}
}

RemoteCall::~RemoteCall(){

}

int RemoteCall::PutRequest(const string funcName,const string src){
	string contentTmp;
	string msgFrameTmp;
	string &pContentTmp = contentTmp;
	string &pMsgFrameTmp = msgFrameTmp;

	int ret = 0;
	
	msgFrame.pContentFrame = new ContentFrame0001();
	
	ret = msgFrame.pContentFrame->ContentFramePacket(funcName,src,pContentTmp);
	if(ret != 0){
		delete msgFrame.pContentFrame;
		return ret;
	}

	delete msgFrame.pContentFrame;

	msgFrame.MsgFramePacket(instance.GetID(),0x0001,contentTmp,pMsgFrameTmp);
	if(ret != 0){
		return ret;
	}
	
	mapClient[type]->ClientSend((unsigned char*)msgFrameTmp.data(),msgFrameTmp.size());

	return RETURN_CODE_OK;
}



int RemoteCall::WaitForResponse(int mseconds,string &dst){
	int ret;
	
	LOGI("%s  step1",__FUNCTION__);
	ret = instance.TimeWait(mseconds);
	LOGI("%s  step2",__FUNCTION__);
		
	if(ret != 0){
		return RETURN_CODE_ERROR_TIMEOUT;
	}
	LOGI("%s  step3",__FUNCTION__);
	
	ret = msgFrame.GetMsg(instance.GetID(),dst);
	if(ret != 0){
		return ret;
	}
	

	LOGI("%s  Out",__FUNCTION__);
	
	return RETURN_CODE_OK;
}

int RemoteCall::SetRemoteResponseParseFunc(RemoteResponseParseFunc func){
	globeFunc = func;
	return RETURN_CODE_OK;
}


