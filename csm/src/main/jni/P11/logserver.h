#ifndef LOG_SERVER_H__
#define LOG_SERVER_H__

#include <android/log.h>
#include <plog/Log.h>
#include "logdefine.h"


//extern bool plog_init_server;

//#define SERVER_LOG 0

int getApplogPath(char* pAppRecordPath,const char* fileName);
bool initServerPlog(const char * filename, const char * defaultRecordPath);
void log_server(Com_LogSeverity severity, const char* func, unsigned int line, const char* file, const char* format,  ...);


#define LOGSERVERI(tag,...)    do{ \
	log_server(C_info, PLOG_GET_FUNC(), __LINE__, PLOG_GET_FILE(), __VA_ARGS__);\
	__android_log_print(ANDROID_LOG_INFO, tag,  __VA_ARGS__);\
	}while(0);

#define LOGSERVERD(tag,...)    do{ \
	log_server(C_debug, PLOG_GET_FUNC(), __LINE__, PLOG_GET_FILE(), __VA_ARGS__);\
	}while(0);

#define LOGSERVERE(tag,...)    do{ \
	log_server(C_error, PLOG_GET_FUNC(), __LINE__, PLOG_GET_FILE(), __VA_ARGS__);\
	__android_log_print(ANDROID_LOG_ERROR, tag,  __VA_ARGS__);\
	}while(0);



inline void Print_Data_Server(char *tag,unsigned char *buf,int len){

	std::string s;
	char num[3] = {0};
	
	for(int i  = 0;i < len;i++){
		sprintf(num,"%02X",buf[i]);
		s.append(num);
		if((i + 1) %16 == 0){
			s.append("\n");
			continue;
		}
		
		if((i + 1) %4 == 0){
			s.append(" ");
		}
		
	}


	LOGSERVERD(tag,"%s",s.c_str());
}




#endif
