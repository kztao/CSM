#ifndef _RECORDLOG_H_
#define _RECORDLOG_H_

#ifdef __cplusplus
	extern "C" {
#endif


//////////////////////////////////////////////////////////////////////////
// Helper macros that get context info

#if _MSC_VER >= 1600 && !defined(__INTELLISENSE__) // >= Visual Studio 2010 and skip IntelliSense
#   define PLOG_GET_THIS()      __if_exists(this) { this } __if_not_exists(this) { 0 }
#else
#   define PLOG_GET_THIS()      0
#endif

#ifdef _MSC_VER
#   define PLOG_GET_FUNC()      __FUNCTION__
#elif defined(__BORLANDC__)
#   define PLOG_GET_FUNC()      __FUNC__
#else
#   define PLOG_GET_FUNC()      __PRETTY_FUNCTION__
#endif

#if PLOG_CAPTURE_FILE
#   define PLOG_GET_FILE()      __FILE__
#else
#   define PLOG_GET_FILE()      ""
#endif

#ifdef LOG_H__
#else
typedef enum{
        plog_none = 0,
        plog_fatal = 1,
        plog_error = 2,
        plog_warning = 3,
        plog_info = 4,
        plog_debug = 5,
        plog_verbose = 6
} LogSeverity;
#endif

void initLogger(LogSeverity severity, const char* szFile, unsigned int maxFileSize, unsigned int maxFileNum);

void setMaxSeverity(LogSeverity severity);

void log_skf(LogSeverity severity, const char* func, unsigned int line, const char* file, const char* format, ...);


//long getTimeUSecond();

#define PLOGV(...)                             do{ \
                                                  log_(plog_verbose, PLOG_GET_FUNC(), __LINE__, PLOG_GET_FILE(), __VA_ARGS__);\
                                               }while(0);

#define PLOGD(...)                             do{ \
                                                  log_(plog_debug, PLOG_GET_FUNC(), __LINE__, PLOG_GET_FILE(), __VA_ARGS__); \
                                               }while(0);


#define PLOGI(...)                             do{ \
                                                  log_(plog_info, PLOG_GET_FUNC(), __LINE__, PLOG_GET_FILE(), __VA_ARGS__);  \
                                               }while(0);

#define PLOGW(...)                             do{ \
                                                  log_(plog_warning, PLOG_GET_FUNC(), __LINE__, PLOG_GET_FILE(), __VA_ARGS__); \
                                               }while(0);

#define PLOGE(...)                             do{ \
                                                  log_(plog_error, PLOG_GET_FUNC(), __LINE__, PLOG_GET_FILE(), __VA_ARGS__); \
                                               }while(0);

#define PLOGF(...)                             do{ \
                                                  log_(plog_fatal, PLOG_GET_FUNC(), __LINE__, PLOG_GET_FILE(), __VA_ARGS__); \
                                               }while(0);


#ifdef __cplusplus
        };
#endif

#endif