#include "RemoteService.h"
#include "MsgFrame.h"
#include "ContentFrame.h"
#include "ContentFrame0001.h"
#include "ContentFrame0002.h"
#include <iostream>
#include <string>
#include "LocalSocketServer.h"
#include "ReturnCode.h"
#include <unistd.h>
#include <set>
#include "Export.h"
#include "Scp02Service.h"


using std::string;
using std::map;
using std::set;

static const char *tag = "csm_remoteService";
static map<CommunicationServer::Communication *,FunctionParse*> mapCommFunctionParse;
static map<CommunicationServer *,RemoteService*> mapRemoteService;
static map<CommunicationServer *,Control*> mapControl;

static ComLog g_Log = NULL;

static void printlog_static(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...){
    char buf[1024] = { 0 };
    va_list arg;

    va_start(arg, format);
	vsnprintf(buf, 1024,format, arg);
    va_end(arg);

    if(g_Log){
        g_Log(severity,func,line,__FILE__,"%s",buf);
    }
    else{
        __android_log_print(ANDROID_LOG_INFO, tag, "printlog,%s",(char *)buf);
    }
}

class RemoteServiceRecvPara
{
public:
	string msg;
	CommunicationServer::Communication *pClient;
};


int RemoteService::RecvFunc(CommunicationServer *server,CommunicationServer::Communication *client, unsigned char *buf,int len) {
	printlog_static(C_debug,__FUNCTION__,__LINE__, "server recv with scp02 IN ,server1 = %p",server);

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

//    string callerName = "";

	int ret;
	int msgID;
	short version;
	ContentFrame *contectFrameTmp;

	recv.append((const char*)buf,len);

	ret = msgFrame.MsgFrameUnpacket(recv,&msgID,&version,pContent);
	if(0 != ret){
		return ret;
	}

	if(version == 0x0001){
		contectFrameTmp = new ContentFrame0001();
	} else if(version == 0x0002){
		contectFrameTmp = new ContentFrame0002();
	}

	else{
        printlog_static(C_error,__FUNCTION__,__LINE__,"content version is %d", version);
		return RETURN_CODE_ERROR_VERSION;
	}

	ret = contectFrameTmp->ContentFrameUnpacket(content,pFuncName,pMsg);
	if(0 != ret){
		delete contectFrameTmp;
		contectFrameTmp = NULL;
		return ret;
	}

	FunctionParse *pFunction = NULL;
    bool flg = false;

	map<CommunicationServer*,Control*>::iterator it;
	for(it = mapControl.begin();it != mapControl.end();++it){
		if(it->first == server){
            if(it->second == NULL){
                printlog_static(C_error,__FUNCTION__,__LINE__,"Not permise control is null");
                break;
            }

		    pFunction = it->second->getFunctionParse();
            string clientName;
            string &rclientName = clientName;
            flg = it->second->check(client,funcName,msg,rclientName);
            pFunction->setClientName(clientName);
            if(version == 0x0002){
                pFunction->setClientName(((ContentFrame0002*)contectFrameTmp)->getCallerName());
            }
            break;
		}
	}


	if(true == flg){
        printlog_static(C_info,__FUNCTION__,__LINE__,"call function is *****%s*****", funcName.c_str());

		if(funcName == "PackageNameCheck"){
			ret = pFunction->PackageNameCheck(msg,pOut);
		}else{
		    ret = pFunction->call(funcName,msg,pOut);
		}
		
	} else{
        printlog_static(C_error,__FUNCTION__,__LINE__,"%s cert check fail",__FUNCTION__);
		ret = pFunction->err(RETURN_CODE_ERROR_CERT,pOut);
	}

    printlog_static(C_info,__FUNCTION__,__LINE__, "pFunction->call Out");
    contectFrameTmp->ContentFramePacket(funcName,out,pOutContent);

	if(0 != ret){
		delete contectFrameTmp;
		contectFrameTmp = NULL;
		return ret;
	}

	delete contectFrameTmp;
	contectFrameTmp = NULL;

	msgFrame.MsgFramePacket(msgID,version,outContent,pOut);
	printlog_static(C_info,__FUNCTION__,__LINE__, "send_secure_message");
    Scp02Service::send_secure_message(client, (unsigned char*)out.data(), out.size());
	printlog_static(C_info,__FUNCTION__,__LINE__, "%s OUT", __FUNCTION__);
    return 0;
}


RemoteService::RemoteService(CommunicationServer *pServer,Control *pControl) {
	__android_log_print(ANDROID_LOG_DEBUG,"wjr","RemoteService::RemoteService IN ,pServer = %p,control = %p",pServer,pControl);
	g_mComLog = NULL;
    m_Control = pControl;
	m_server = pServer;
	mapControl[m_server] = m_Control;
    pServer->RegServerRecvFunc((CommunicationServer::serverRecvFuncType)&Scp02Service::process_secure_channel_message);
}

RemoteService::RemoteService(CommunicationServer *pServer, Control *pControl,
							 FunctionParse *functionParse) {
	__android_log_print(ANDROID_LOG_DEBUG,"wjr","RemoteService::RemoteService IN ,pServer = %p,control = %p",pServer,pControl);
	g_mComLog = NULL;
	m_Control = pControl;
	m_server = pServer;

	if(NULL != pControl){
		pControl->setFunctionParse(functionParse);
	}

	if(NULL != functionParse){
		functionParse->RegCommServer(pServer);
	}

	if(NULL != pServer){
        mapControl[pServer] = pControl;
        pServer->RegServerRecvFunc((CommunicationServer::serverRecvFuncType)&Scp02Service::process_secure_channel_message);
	}
}


RemoteService::~RemoteService(){

}

void RemoteService::printlog(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...){
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




void RemoteService::setlogFunc(ComLog logfunc){
    g_mComLog = logfunc;
    g_Log = logfunc;

	Scp02Service::setlogFunc(logfunc);
}
