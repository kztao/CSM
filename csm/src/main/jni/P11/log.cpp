#include "log.h"
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <plog/Init.h>

static const char* tag = "csm_plog";

bool plog_init_proxy = false;
pthread_mutex_t mutexlog = PTHREAD_MUTEX_INITIALIZER;


#define ERR_PATH 2

static int getApplogPath(char* pAppRecordPath,const char* fileName)
{
	char proc_pid_path[1024] = {0};
	char buf[256] = {0};
	char task_name[256] = {0};
	char AppName[512] = {0};
	const char* path = "/sdcard/Android/data/";
	char strProcessPath[1024] = {0};
	bool Flag_Proc = false;
	int t = 0;
	int state = 0;
	char path_appfile[1024] = {0};

	if(readlink("/proc/self/exe", strProcessPath,1024) <=0)
	{
		return 1;
	}

	sprintf(proc_pid_path, "/proc/%d/cmdline",(int)getpid());
	FILE* fp = fopen(proc_pid_path, "r");
	if(NULL != fp)
	{
		if( fgets(buf, 255, fp)== NULL )
		{
			fclose(fp);
			LOGEE(tag,"no buf in file");
			return 1;
		}
		fclose(fp);
		sscanf(buf, "%255s", task_name);
	}
	else
	{
		LOGEE(tag,"open fail errno = %d", errno);
		return 1;
	}

	LOGDD(tag,"path name to record: %s\n",buf);

	for(t =0; t< sizeof(task_name); t++)
	{
		if(buf[t] == '/')
		{
			return 1;
		}
		else if(buf[t] == ':')
		{
			memcpy(AppName, task_name, t);
			Flag_Proc = true;
			break;
		}
	}
	if(!Flag_Proc)
	{
		sprintf(AppName, "%s", task_name);

	}

	
	sprintf(path_appfile, "%s%s", path, AppName);	
	
	state = access(path_appfile, R_OK|W_OK);
	
	if(state)
	{
		LOGEE(tag,"access app file directory fail! errno:%s",strerror(errno));
		return ERR_PATH;
	}

	sprintf(pAppRecordPath, "%s%s/logs/%s", path, AppName, fileName);
	LOGDD(tag,"path name to record1: %s",pAppRecordPath);

	char logdirectory[1024] = {0};	
	sprintf(logdirectory, "%s%s/logs/", path, AppName);
	state = access(logdirectory, R_OK|W_OK);
	if (state)
	{
		LOGEE(tag, "access fail1!,errno = %s",strerror(errno));
		if(ENOENT == errno)
		{
			LOGII(tag,"try to make dir");
			if(mkdir((const char *)logdirectory, S_IRWXU))
			{
				LOGEE(tag, "create file dir fail!,errno = %s",strerror(errno));
				return ERR_PATH;
			}
		}
		else
		{
			return ERR_PATH;
		}
	}

	return 0;

}


bool initPlog(const char * filename, const char * defaultRecordPath)
{
	char recordPath[256] = {0};
	bool ret = false;
	int result = 0;
		
	pthread_mutex_lock(&mutexlog);
	if(!plog_init_proxy)
	{
		LOGII(tag,"proxy initialize plog interface1...");
		result = getApplogPath(recordPath,filename);
	
		if(result)
		{
			if(ERR_PATH == result)
			{
				plog_init_proxy = false;
				pthread_mutex_unlock(&mutexlog);
				return ret;
			}
								
			LOGII(tag,"record path is default path");
			sprintf(recordPath, "%s", defaultRecordPath);
		}

		plog::init<2>(plog::info, recordPath, 4*1024*1024, 5);

        void* ins = plog::get<2>();


		if(!ins)
		{
			LOGEE(tag,"proxy plog init fail!");
			pthread_mutex_unlock(&mutexlog);
			return ret;
		}
						
		plog_init_proxy = true;

		LOGII(tag,"proxy initialize plog interface done...");
	}
	pthread_mutex_unlock(&mutexlog);
	
	ret = true;

	return ret;
}

void log_proxy(Com_LogSeverity severity, const char* func, unsigned int line, const char* file, const char* format,  ...)
{
	char buf[1024] = { 0 };
	va_list arg;

    if(!(plog::get<2>()
		&& plog::get<2>()->checkSeverity(static_cast<plog::Severity>(severity))))
	{	
		switch(severity){
			case C_info:
				__android_log_print(ANDROID_LOG_INFO, tag, "%s",buf);
				break;
			case C_error:
				__android_log_print(ANDROID_LOG_ERROR, tag, "%s",buf);
				break;
			default:
				break;
		}
		
        return;
	}	
    

	va_start(arg, format);
	vsnprintf(buf, 1024,format, arg);
	va_end(arg);
	(*plog::get<2>()) += plog::Record(static_cast<plog::Severity>(severity), func, line, file, PLOG_GET_THIS()) << buf;

    return;
}



