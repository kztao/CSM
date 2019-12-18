#include "skf.h"
#include <android/log.h>
#include <string.h>
#include <string>

using namespace std;
#define OUT_INFO(...) __android_log_print(ANDROID_LOG_INFO, "skftestC", __VA_ARGS__);

#define ASSERT_VALUE(valuename,value,rightvalue,failreason,failinterface,info) \
{ if(value != rightvalue){\
    char n[1024*1024]={0};\
    info.append(failreason);info.append(", ");info.append(failinterface);\
    sprintf(n,",%s=0x%x\n",valuename,value);\
    info.append(n);    \
    return info;}}\

#define ASSERT_VALUE_NOT(valuename,value,wrongvalue,failreason,failinterface,info) \
{ if(value == wrongvalue){\
    char n[1024*1024]={0};\
    info.append(failreason);info.append(", ");info.append(failinterface);\
    info.append(":");info.append(valuename);info.append("\n");\
    return info;}}\

#define WARNING_VALUE(valuename,value,rightvalue,failreason,failinterface,info) \
{ if(value != rightvalue){\
    string info_tmp; \
    char n[1024*1024]={0};\
    info_tmp.append(failreason);info_tmp.append(", ");info_tmp.append(failinterface);\
    sprintf(n,",%s=0x%x\n",valuename,value);\
    info_tmp.append(n);    \
   __android_log_print(ANDROID_LOG_INFO, "skftestC","%s",info_tmp.c_str());}}\


#define USER_PIN "1234567"
#define USER_PIN_WRONG "123456789"
#define USER_PIN_NEW "88888888"
#define ADMIN_PIN "123456789"
#define ADMIN_PIN_WRONG "1234567890"
#define MAX_ADMIN_COUNT 6
#define MAX_USER_COUNT 6

#define TEST_APP_NAME  "testApp0"
#define TEST_CONTAINER_NAME "testcontainer"