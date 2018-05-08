#include "MsgFrame.h"
#include "ReturnCode.h"
#include <string>
#include <map>
#include <unistd.h>
#include "log.h"
#include "Mutex.h"

using namespace std;

pthread_mutex_t mapServerResponseMsgMutex = PTHREAD_MUTEX_INITIALIZER;

map<int,string> MsgFrame::mapServerResponseMsg;

MsgFrame::MsgFrame(){
}

MsgFrame::~MsgFrame(){
}

int MsgFrame::GetMsg(int id,string &buf){
	
	map<int,string> ::iterator it;
	
	pthread_mutex_lock(&mapServerResponseMsgMutex);
	it = mapServerResponseMsg.find(id);
	pthread_mutex_unlock(&mapServerResponseMsgMutex);
	if(it != mapServerResponseMsg.end()){

	

		buf = it->second; 
		LOGI("find %d msg len = %d",id,buf.size());
		mapServerResponseMsg.erase(it);
		LOGI("end erase map");
	}

	LOGI("%s Out",__FUNCTION__);
	return RETURN_CODE_OK;
}

int MsgFrame::MsgFramePacket(int msgID,short version,const string content,string &msgFrame){
	LOGI("%s IN",__FUNCTION__);
	msgFrame = "";
	unsigned char *pID = NULL;
	unsigned char *pVersion = NULL;
	pID = new unsigned char[sizeof(int)];
	pVersion = new unsigned char[sizeof(short)];
	memcpy(pID,&msgID,sizeof(int));
	memcpy(pVersion,&version,sizeof(short));

	for(int i = 0;i < sizeof(int);i++){
		msgFrame += pID[i];
	}

	for(int i = 0;i < sizeof(short);i++){
		msgFrame += pVersion[i];
	}

	delete[] pID;
	delete[] pVersion;
	msgFrame.append(content);
	LOGI("%s OUT",__FUNCTION__);
	return RETURN_CODE_OK;
}	

int MsgFrame::MsgFrameUnpacket(const string msg,int *pMsgID,short *pVersion,string &content){
	LOGI("%s IN",__FUNCTION__);
	if(msg.size() <= (sizeof(int) + sizeof(short) )){
		return RETURN_CODE_ERROR_PARAM;
	}

	string msgID;
	string version;
	msgID = msg.substr(0,sizeof(int));
	version = msg.substr(sizeof(int),sizeof(short));
	content = msg.substr(sizeof(int) + sizeof(short),msg.size() - sizeof(int) - sizeof(short));

	if(pMsgID != NULL){
		memcpy(pMsgID,msgID.data(),msgID.size());
	}

	if(pVersion != NULL){
		memcpy(pVersion,version.data(),version.size());
	}
	LOGI("%s OUT",__FUNCTION__);
	return RETURN_CODE_OK;
}

int MsgFrame::PutRecvMsg(int ID,string recvMsg){
	LOGI("%s IN",__FUNCTION__);
	pthread_mutex_lock(&mapServerResponseMsgMutex);
	
	mapServerResponseMsg[ID] = recvMsg;

	Print_Data((unsigned char*)recvMsg.data(),recvMsg.size());
	pthread_mutex_unlock(&mapServerResponseMsgMutex);
	Mutex::Signal(ID);
	
	LOGI("%s OUT",__FUNCTION__);

	return 0;
}

