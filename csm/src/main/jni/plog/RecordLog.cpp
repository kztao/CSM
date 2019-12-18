#include "RecordLog.h"
#include "stdio.h"
#include <Log.h>
#include <Logger.h>
#include <Init.h>
#include <FuncMessageFormatter.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <AndroidAppender.h>
#include<sys/time.h>
static struct timeval   timeStart;
static struct timeval   timeEnd;
static struct timeval   timeSum = {0, 0};
#endif

void initLogger(LogSeverity severity, const char* szFile, unsigned int maxFileSize, unsigned int maxFiles)
{
		
        plog::init(static_cast<plog::Severity>(severity) ,szFile, maxFileSize, maxFiles);

#ifndef _WIN32
		plog::AndroidAppender<plog::FuncMessageFormatter> * pAndroidLogAppender
							= new plog::AndroidAppender<plog::FuncMessageFormatter>("PLOG");
		plog::get<PLOG_DEFAULT_INSTANCE>()->addAppender(pAndroidLogAppender);
#endif

        return;
}

void setMaxSeverity(LogSeverity severity)
{
	plog::get<PLOG_DEFAULT_INSTANCE>()->setMaxSeverity(static_cast<plog::Severity>(severity));
}


void log_skf(LogSeverity severity, const char* func, unsigned int line, const char* file, const char* format,  ...)
{
#ifndef _WIN32
	gettimeofday(&timeStart, NULL);
#endif
	char buf[2048] = { 0 };
	va_list arg;

    if(!(plog::get<PLOG_DEFAULT_INSTANCE>()
		&& plog::get<PLOG_DEFAULT_INSTANCE>()->checkSeverity(static_cast<plog::Severity>(severity))))
            return;

	va_start(arg, format);
#ifdef _WIN32
	vsprintf_s(buf, sizeof(buf), format, arg);
#else
	vsnprintf(buf, 2048,format, arg);
#endif
	va_end(arg);

	(*plog::get<PLOG_DEFAULT_INSTANCE>()) += plog::Record(static_cast<plog::Severity>(severity), func, line, file, PLOG_GET_THIS()) << buf;

#ifndef _WIN32
	gettimeofday(&timeEnd, NULL);
    timeSum.tv_sec += (timeEnd.tv_sec - timeStart.tv_sec);
    timeSum.tv_usec += (timeEnd.tv_usec - timeStart.tv_usec);
#endif

    return;
}

//long getTimeUSecond()
//{
//#ifdef _WIN32
//	return 0;
//#else
//      return (timeSum.tv_sec*1000000 + timeSum.tv_usec);
//#endif
//}
