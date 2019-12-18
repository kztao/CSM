#include "MsgFrame.h"
#include "ReturnCode.h"
#include <string>
#include <map>
#include <unistd.h>
#include "Mutex.h"
#include <string.h>

using std::string;
static const char *tag = "csm_msgframe";
pthread_mutex_t mapServerResponseMsgMutex = PTHREAD_MUTEX_INITIALIZER;

map<int,string> MsgFrame::mapServerResponseMsg;

MsgFrame::MsgFrame(){
}

MsgFrame::~MsgFrame(){
}


void MsgFrame::MsgFramePacket(int msgID,short version,const string content,string &msgFrame){

	msgFrame = "";
	unsigned char *pID = NULL;
	unsigned char *pVersion = NULL;
	pID = new unsigned char[sizeof(int)];
	pVersion = new unsigned char[sizeof(short)];
	memcpy(pID,&msgID,sizeof(int));
	memcpy(pVersion,&version,sizeof(short));

	msgFrame.append((const char*)pID,sizeof(int));
	msgFrame.append((const char*)pVersion,sizeof(short));
	delete[] pID;
	pID = NULL;
	
	delete[] pVersion;
	pVersion = NULL;
	
	msgFrame.append(content);
}	

int MsgFrame::MsgFrameUnpacket(const string msg,int *pMsgID,short *pVersion,string &content){
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
	return 0;
}

