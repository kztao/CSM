#include "Pack.h"
#include "Mutex.h"
#include <unistd.h>
#include "LocalSocketClient.h"
#include "ReturnCode.h"

int Pack::globeID = 1;
map<int,CondAddr*> Pack::MapCond;
//map<int,char> Pack::MapWaitFlag;
static Mutex mutexMapCond;
//static Mutex mutexMapWaitFlag;
#define WAIT 1
#define NO_WAIT 0

static const char *tag = "csm_pack";

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

Pack::Pack() {
	g_mComLog = NULL;
    ID = globeID;
    globeID++;
	if(globeID == 0x7FFFFFFF)
	{
		globeID = 1;
	}

	CondAddr *condAddr = new CondAddr();

    MapCond[ID] = condAddr;
}

Pack::~Pack() {
	MapCond.erase(ID);
	//MapWaitFlag.erase(this->ID);
}

int Pack::GetID() {
    return ID;
}

int Pack::TimeWait(int mseconds) {

    int ret = 0;

	printlog(C_info,__FUNCTION__,__LINE__,"%s IN1, id: %d", __FUNCTION__, this->ID);

	CondAddr *condAddr = NULL;

	auto it = MapCond.begin();
	for(;it != MapCond.end();it++){
        if(it->first == ID){
            condAddr = it->second;
            break;
        }
	}

	if(NULL == condAddr){
        printlog(C_error,__FUNCTION__,__LINE__,"%s OUT,can't find condAddr, id: %d", __FUNCTION__,ID);
        return RETURN_CODE_ERROR_COMM;
	}

    struct timespec tm;
    clock_gettime(CLOCK_REALTIME,&tm);

    tm.tv_nsec += (mseconds % 1000) *1000*1000;
    tm.tv_sec += (mseconds / 1000);
    if(tm.tv_nsec >= 1000000000)
    {
        tm.tv_nsec -= 1000000000;
        tm.tv_sec += 1;
    }
    printlog_static(C_debug,__FUNCTION__,__LINE__,"%s Before lock",__FUNCTION__);
	pthread_mutex_lock(&(condAddr->mutex));
    if(!condAddr->mrecvsponse){
        ret = pthread_cond_timedwait(&(condAddr->cond),&(condAddr->mutex),&tm);
    }else{
        ret = 0;
        printlog_static(C_debug,__FUNCTION__,__LINE__,"warn have received respones");
    }
    printlog_static(C_debug,__FUNCTION__,__LINE__,"%s End wait",__FUNCTION__);
    pthread_mutex_unlock(&(condAddr->mutex));

    printlog_static(C_info,__FUNCTION__,__LINE__,"%s OUT, ret: %d", __FUNCTION__,ret);

    return ret;
}

int Pack::Signal(int id) {
    int ret = 0;
	printlog_static(C_info,__FUNCTION__,__LINE__,"%s IN, id is %d", __FUNCTION__,id);

    CondAddr *condAddr = NULL;

    auto it = MapCond.begin();
    for(;it != MapCond.end();it++){
        if(it->first == id){
            condAddr = it->second;
            break;
        }
    }

    if(NULL != condAddr){
        printlog_static(C_debug,__FUNCTION__,__LINE__,"%s Before lock",__FUNCTION__);
        pthread_mutex_lock(&(condAddr->mutex));
        printlog_static(C_debug,__FUNCTION__,__LINE__,"%s End lock",__FUNCTION__);
        ret = pthread_cond_signal(&(condAddr->cond));
        condAddr->mrecvsponse = true;
        printlog_static(C_debug,__FUNCTION__,__LINE__,"%s End signal",__FUNCTION__);
        pthread_mutex_unlock(&(condAddr->mutex));
    }

	printlog_static(C_info,__FUNCTION__,__LINE__,"%s OUT,ret = %d", __FUNCTION__,ret);
    return 0;
}

void Pack::Del(int id) {
    CondAddr *condAddr = NULL;

    auto it = MapCond.begin();
    for(;it != MapCond.end();it++){
        if(it->first == id){
            condAddr = it->second;
            MapCond.erase(it);
            delete condAddr;
            condAddr = NULL;
            break;
        }
    }
}

void Pack::printlog(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...){
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

void Pack::setlogfunc(ComLog logfunc){
	g_mComLog = logfunc;
	g_Log = logfunc;
}

