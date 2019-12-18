#ifndef UTILSC_C_H_
#define UTILSC_C_H_

#include <stdio.h>
#ifdef WIN32
#include <windows.h>
#elif defined(linux)
#include <sys/time.h>
#include <unistd.h>
#include <dlfcn.h>
#endif

//#include "general.h"




#define VNAME(name) (#name), name
#define PRINT_LINE printf("--------------------------------------------------------------------------\n")


#ifdef __cplusplus
extern "C" {
#endif

typedef struct  {
		long tv_sec; // seconds
		long tv_usec; // and microseconds
}timevalc;

typedef struct{
		long sec;
		long usec;
}UtilscTime;

typedef UtilscTime* UtilscTimePtr;

//void UtilsPrintData(const char *title, const void *data, unsigned int size, unsigned int offset);
//char UtilsStr2Byte(const char *str, char *hex);
//int Utilssprintn(UtilscTimePtr getted_time, char *address, const char* tag, unsigned int n);
//void Utilsprintn(UtilscTimePtr getted_time,const char* tag, unsigned int n);
//int Utilssprint(UtilscTimePtr getted_time,char *address, const char *tag, unsigned int looptime);
//int Utilsprint(UtilscTimePtr getted_time, const char* tag, unsigned int looptime);
int UtilsTimeSubstracted(UtilscTimePtr tt1, UtilscTimePtr tt2);
int UtilsTimeAdded(UtilscTimePtr tt1, UtilscTimePtr tt2);
void Utilsgettime(UtilscTimePtr get_time);
unsigned long long Utilsgetuseconds(UtilscTimePtr getted_time);


#ifdef __cplusplus
}
#endif

#endif