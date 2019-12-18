#include "logserver.h"
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>


static const char* tag = "csm_plog";

bool plog_init_server = false;


#define ERR_PATH 2


#define LOGII_S(tag,...) __android_log_print(ANDROID_LOG_INFO, tag, __VA_ARGS__);
#define LOGEE_S(tag,...) __android_log_print(ANDROID_LOG_ERROR, tag, __VA_ARGS__);
#define LOGDD_S(tag,...) __android_log_print(ANDROID_LOG_DEBUG, tag, __VA_ARGS__);


int getApplogPath(char* pAppRecordPath,const char* fileName)
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
			LOGEE_S(tag,"no buf in file");
			return 1;
		}
		fclose(fp);
		sscanf(buf, "%255s", task_name);
	}
	else
	{
		LOGEE_S(tag,"open fail errno = %d", errno);
		return 1;
	}

	LOGII_S(tag,"path name to record: %s\n",buf);

	for(t =0; t< sizeof(task_name); t++)
	{
		if((buf[t] == '/'))
		{
			return 1;
		}
		else if((buf[t] == ':'))
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
		LOGEE_S(tag,"access app file directory fail! errno:%s",strerror(errno));
		return ERR_PATH;
	}

	sprintf(pAppRecordPath, "%s%s/logs/%s", path, AppName, fileName);
	LOGII_S(tag,"path name to record1: %s",pAppRecordPath);

	char logdirectory[1024] = {0};	
	sprintf(logdirectory, "%s%s/logs/", path, AppName);
	state = access(logdirectory, R_OK|W_OK);
	if (state)
	{
		LOGEE_S(tag, "access fail1!,errno = %s",strerror(errno));
		if(ENOENT == errno)
		{
			LOGII_S(tag,"try to make dir");
			if(mkdir((const char *)logdirectory, S_IRWXU))
			{
				LOGEE_S(tag, "create file dir fail!,errno = %s",strerror(errno));
				return ERR_PATH;
			}
		}
		else
		{
			LOGII_S(tag,"access error");
			return ERR_PATH;
		}
	}

	return 0;

}


bool initServerPlog(const char * filename, const char * defaultRecordPath)
{
	char recordPath[256] = {0};
	int result = 0;

	
	if (!plog_init_server)
	{
		LOGII_S(tag,"sinitialize plog interface...");
		
		result = getApplogPath(recordPath,filename);
		if(result)
		{
			if(ERR_PATH == result)
			{
				plog_init_server = false;
				return false;
			}
			
			LOGII_S(tag,"record path is default path");
			sprintf(recordPath, "%s", defaultRecordPath);
		}
		
		plog::init(plog::info, recordPath, 4*1024*1024, 5);
		if(!plog::get<PLOG_DEFAULT_INSTANCE>())
		{
			LOGEE_S(tag,"server plog init fail!");
			return false;
		}
		
		plog_init_server = true;

		LOGII_S(tag,"server2 initialize plog interface done...");
		LOGSERVERI(tag,"server initialize plog interface done...");
	}

	return true;
}


void log_server(Com_LogSeverity severity, const char* func, unsigned int line, const char* file, const char* format,  ...)
{
	char buf[1024] = { 0 };
	va_list arg;

	va_start(arg, format);
	vsnprintf(buf, 1024,format, arg);
	va_end(arg);

    if(!(plog::get<PLOG_DEFAULT_INSTANCE>()
		&& plog::get<PLOG_DEFAULT_INSTANCE>()->checkSeverity(static_cast<plog::Severity>(severity))))
	{	
		switch(severity){
			case C_info:
				__android_log_print(ANDROID_LOG_INFO, tag, "%s",buf);
				break;
			case C_error:
				__android_log_print(ANDROID_LOG_ERROR, tag, "%s",buf);
				break;		
		}
		
        return;
	}	
	
	(*plog::get<PLOG_DEFAULT_INSTANCE>()) += plog::Record(static_cast<plog::Severity>(severity), func, line, file, PLOG_GET_THIS()) << buf;

    return;
}




