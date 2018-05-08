#include <android/log.h>
#include <string>
using namespace std;

#define LOG_TAG "localsocket"

#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

void Print_Data(unsigned char *buf,int len);