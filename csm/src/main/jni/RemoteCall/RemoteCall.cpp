#include "RemoteCall.h"
#include "LocalSocketClient.h"
#include "ReturnCode.h"
#include "ContentFrame0001.h"
#include "ContentFrame0002.h"
#include "GetPackageName.h"
#include "Export.h"
#include "Scp02Client.h"

static RemoteResponseParseFunc globeFunc = NULL;
static const char *tag = "csm_RemoteCall";

#define VERSION_1 0x0001
#define VERSION_2 0x0002
#define ID_BROADCAST 0

using std::map;

static map<int,string> MapSaveMsg;
static Mutex mutexSaveMap;

static void SaveMsg(int msgId,string buf){
    mutexSaveMap.Lock();
    MapSaveMsg.insert(make_pair(msgId,buf));
    mutexSaveMap.Unlock();

//    Pack::Signal(msgId);
}

int msgFrameRecvFunc(unsigned char *buf,int len){
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

	ContentFrame *contectFrameTmp;

//	printlog(C_info,__FUNCTION__,__LINE__,"%s IN,client recv len = %d",__FUNCTION__,len);
	if( (NULL == buf) && (len > 0))
	{
//		printlog(C_error,__FUNCTION__,__LINE__, "buf error");
		return 0;
	}
		
//	Print_Data((char*)"csm_msgFrameRecvFunc",buf,len);

	recv.append((const char*)buf,len);	
	
	ret = msgFrameTmp.MsgFrameUnpacket(recv,&msgID,&version,pContent);
	if(0 != ret){
		return ret;
	}

//	Print_Data((char*)"csm_pContent",(unsigned char*)pContent.data(),pContent.size());

	if(VERSION_1 == version){
		contectFrameTmp = new ContentFrame0001();
	} else if(VERSION_2 == version){
        contectFrameTmp = new ContentFrame0002();
	}
	else
	{
    //	printlog(C_error,__FUNCTION__,__LINE__, "%s, version error",__FUNCTION__);
		return RETURN_CODE_ERROR_NOT_SUPPORT;
	}

	ret = contectFrameTmp->ContentFrameUnpacket(content,pFuncName,pOut);
	if(0 != ret){
		delete contectFrameTmp;
		contectFrameTmp = NULL;
		return ret;
	}
	delete contectFrameTmp;
	contectFrameTmp = NULL;
	
//	Print_Data((char*)"csm_pOut",(unsigned char*)pOut.data(),pOut.size());
//	printlog(C_info,__FUNCTION__,__LINE__,"Start put recv msg ID = %d,funcName = %s,len = %d",msgID,funcName.data(),out.size());
	if(msgID != ID_BROADCAST){
        SaveMsg(msgID,out);

	}else{
		if(globeFunc != NULL){			
	//		printlog(C_info,__FUNCTION__,__LINE__,"msgID is 0, callback");
			globeFunc(funcName,out);
		}

	}
//	printlog(C_info,__FUNCTION__,__LINE__,"%s OUT",__FUNCTION__);
	return 0;
}

static bool scp02_client_initFlg = false;

RemoteCall::RemoteCall(CommunicationClient * pClient){
	this->m_pClient = pClient;
	int ret  = 0;

	g_mComLog = NULL;


	if(NULL != pClient){
#ifdef SCP02_ENCRYPT
        if(scp02_client_initFlg == false){
            rt_scp02_client_init();
			scp02_client_initFlg = true;
        }
        __android_log_print(ANDROID_LOG_INFO,"printlog","%s, before init1",__FUNCTION__);
		ret = pClient->init(rt_scp02_client_process_secure_channel_message);
        __android_log_print(ANDROID_LOG_INFO,"printlog", "%s, end init1 ret = %d",__FUNCTION__,ret);
		/*if(CLIENTINIT_OK == ret)
		{
			rt_scp02_client_uninit();
		}*/
		rt_scp02_client_register_channel(pClient);
        __android_log_print(ANDROID_LOG_INFO,"printlog","%s, end rt_scp02_client_register_channel1",__FUNCTION__);
		rt_scp02_client_register_recv(msgFrameRecvFunc);
        __android_log_print(ANDROID_LOG_INFO,"printlog","%s, end rt_scp02_client_register_recv1",__FUNCTION__);

#else
		ret = pClient->init(msgFrameRecvFunc);
#endif
	}
}

RemoteCall::RemoteCall(CommunicationClient *pClient,ComLog logfunc){
	this->m_pClient = pClient;
	int ret  = 0;

	g_mComLog = logfunc;
	m_instance.setlogfunc(logfunc);
	setscpclientlogFunc(logfunc);

	if(NULL != pClient){
#ifdef SCP02_ENCRYPT
        if(scp02_client_initFlg == false){
            rt_scp02_client_init();
			scp02_client_initFlg = true;
        }

		__android_log_print(ANDROID_LOG_INFO,"printlog","%s, before init2",__FUNCTION__);

		ret = pClient->init(rt_scp02_client_process_secure_channel_message);
		__android_log_print(ANDROID_LOG_INFO,"printlog", "%s, end init2 ret = %d",__FUNCTION__,ret);
		/*if(CLIENTINIT_OK == ret)
		{
			rt_scp02_client_uninit();
		}*/
		rt_scp02_client_register_channel(pClient);
		__android_log_print(ANDROID_LOG_INFO,"printlog","%s, end rt_scp02_client_register_channel2",__FUNCTION__);
		rt_scp02_client_register_recv(msgFrameRecvFunc);
		__android_log_print(ANDROID_LOG_INFO,"printlog","%s, end rt_scp02_client_register_recv2",__FUNCTION__);

#else
		ret = pClient->init(msgFrameRecvFunc);
#endif
	}
}


RemoteCall::~RemoteCall(){

}

int RemoteCall::PutRequest(const string funcName,const string src){
	string contentTmp;
	string msgFrameTmp;
	string &pContentTmp = contentTmp;
	string &pMsgFrameTmp = msgFrameTmp;
	
	if(NULL == this->m_pClient)
	{
		printlog(C_info,__FUNCTION__,__LINE__, "%s, no client",__FUNCTION__);
		return RETURN_CODE_ERROR_COMM;
	}

	int ret = 0;
	//ContentFrame *contectFrameTmp = new ContentFrame0001();
	ContentFrame *contectFrameTmp = new ContentFrame0002();
	ret = contectFrameTmp->ContentFramePacket(funcName,src,pContentTmp);
	if(ret != 0)
	{
		delete contectFrameTmp;
		contectFrameTmp = NULL;
		return ret;
	}

	delete contectFrameTmp;
	contectFrameTmp = NULL;

	//m_msgFrame.MsgFramePacket(m_instance.GetID(),VERSION_1,contentTmp,pMsgFrameTmp);
    m_msgFrame.MsgFramePacket(m_instance.GetID(),VERSION_2,contentTmp,pMsgFrameTmp);

	int rv = 0;
	if(NULL != this->m_pClient)
	{
		printlog(C_info,__FUNCTION__,__LINE__, "client PutRequest function %s,ID = %d,sendBuf = %d",funcName.data(),m_instance.GetID(),src.size());
#ifdef SCP02_ENCRYPT
        rv = rt_scp02_client_send_secure_message((unsigned char*)msgFrameTmp.data(), msgFrameTmp.size());
#else
		rv = this->m_pClient->ClientSend((unsigned char*)msgFrameTmp.data(),msgFrameTmp.size());
#endif
		if(rv <= 0)
		{
			printlog(C_info,__FUNCTION__,__LINE__, "rt_scp02_client_send_secure_message send error ret = %d",rv);
			ret = RETURN_CODE_ERROR_COMM;
		}
	}

	return ret;
}



int RemoteCall::WaitForResponse(int mseconds,string &dst){
	int ret = 0;

	mutexSaveMap.Lock();
	auto it = MapSaveMsg.find(m_instance.GetID());
	if(it != MapSaveMsg.end()){
		dst = it->second;
		mutexSaveMap.Unlock();
		return ret;
	}
	mutexSaveMap.Unlock();
	
	printlog(C_error,__FUNCTION__,__LINE__, "%s error! id is %d",__FUNCTION__,m_instance.GetID());
	return -1;
/*	
	ret = m_instance.TimeWait(mseconds);
	if(ret != 0){
        printlog(C_info,__FUNCTION__,__LINE__, "%s, TimeWait ret is %d",__FUNCTION__,ret);
		return RETURN_CODE_ERROR_TIMEOUT;
	}

    mutexSaveMap.Lock();
    it = MapSaveMsg.find(m_instance.GetID());
    if(it != MapSaveMsg.end())
    {
    	dst = it->second;
    	MapSaveMsg.erase(it);   
		ret = 0;
    } 
	else
	{
		printlog(C_error,__FUNCTION__,__LINE__, "no msg found!");
		ret = RETURN_CODE_ERROR_COMM;
	}	

    mutexSaveMap.Unlock();

    printlog(C_info,__FUNCTION__,__LINE__, "Before Del %d CondAddr ",m_instance.GetID());
    Pack::Del(m_instance.GetID());
    printlog(C_info,__FUNCTION__,__LINE__, "End Del %d CondAddr ",m_instance.GetID());

	return ret;*/
}

int RemoteCall::SetRemoteResponseParseFunc(RemoteResponseParseFunc func){
	globeFunc = func;
	return 0;
}

void RemoteCall::printlog(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...){
	char buf[1024] = { 0 };
	va_list arg;

	va_start(arg, format);
	vsnprintf(buf, 1024,format, arg);
	va_end(arg);

	if(g_mComLog){
		g_mComLog(severity,func,line,__FILE__,"%s",buf);
	}
	else{
		__android_log_print(ANDROID_LOG_INFO, tag, "printlog,%s",(char *)buf);
	}
}


