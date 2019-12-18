#ifndef LOG_DEFINE_H__
#define LOG_DEFINE_H__

typedef enum{
        C_none = 0,
        C_fatal = 1,
        C_error = 2,
        C_warning = 3,
        C_info = 4,
        C_debug = 5,
        C_verbose = 6
}Com_LogSeverity;

typedef void (*ComLog)(Com_LogSeverity severity, const char* func, unsigned int line, const char* file, const char* format,  ...);
#define VERSION_MAJOR 3
#define VERSION_MINOR 0



#endif
