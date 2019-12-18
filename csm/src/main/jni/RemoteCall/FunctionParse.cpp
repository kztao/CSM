#include "FunctionParse.h"
#include "Return.pb.h"
#include "ReturnCode.h"
#include "RemoteService.h"
#include "CSMResAccess.h"
#include "Export.h"

using namespace com::westone::returncode;

static const char *tag = "csm_FunctionParse";

#include "Scp02Service.h"
#include "Export.h"
#include "LocalSocketServer.h"

int FunctionParse::BroadCast(string funcName,string src){
    return Scp02Service::BroadCast(pServer,funcName, src);
}

void FunctionParse::RegCommServer(CommunicationServer *pServer){
    this->pServer = pServer;
}

int FunctionParse::call(string name,string src,string &dst){
    pthread_mutex_lock(&mutex);
	map<string,FunctionParse::funcType>::iterator it;
    string error;

    it = mapFuncList.find(name);
    if(it != mapFuncList.end()){
        printlog(C_debug,__FUNCTION__,__LINE__,"begin call1 %s",name.data());
        int ret =  (this->*mapFuncList[name])(src,dst);
        pthread_mutex_unlock(&mutex);
        return ret;
    }

    printlog(C_info,__FUNCTION__,__LINE__,"mapFuncList size = %d",mapFuncList.size());
    pthread_mutex_unlock(&mutex);
    return this->err(RETURN_CODE_ERROR_NOT_SUPPORT,dst);
}

int FunctionParse::err(int errNum,string &dst) {
    ResponsePack responsePack;
    responsePack.set_ret(errNum);
    responsePack.SerializeToString(&dst);
    return 0;
}

FunctionParse::FunctionParse() {
    g_mComLog = NULL;
    pServer = NULL;
    pthread_mutex_init(&mutex,NULL);
}


FunctionParse::~FunctionParse() {

}

void FunctionParse::setClientName(string name) {
    this->packageName = name;
}

string FunctionParse::getPackageName() {
    return packageName;
}

int FunctionParse::PackageNameCheck(string src, string &dst) {
	printlog(C_debug,__FUNCTION__,__LINE__,"%s IN",__FUNCTION__);

    this->packageName = src;
    return err(0,dst);
}

void FunctionParse::printlog(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...){
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

void FunctionParse::setlogFunc(ComLog logfunc){
    g_mComLog = logfunc;
}
