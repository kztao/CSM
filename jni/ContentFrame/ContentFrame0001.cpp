#include "ContentFrame0001.h"
#include "ReturnCode.h"
#include "log.h"
#include <cstring>


ContentFrame0001::ContentFrame0001(){

}

ContentFrame0001::~ContentFrame0001(){

}

int ContentFrame0001::ContentFramePacket(const string funcName,const string buf,string &content){
	//函数名长度||函数名||buf
	LOGI("%s IN",__FUNCTION__);
	int len = 0;
	len = funcName.size();
	content = "";
	unsigned char *pLen = (unsigned char*)&len;
	for(int i = 0; i < sizeof(len);i++){
		content += 	pLen[i];
	}
	
	content += funcName;
	content += buf;
	LOGI("%s OUT",__FUNCTION__);

	Print_Data((unsigned char*)content.data(),content.size());
	
	return RETURN_CODE_OK;
}

int ContentFrame0001::ContentFrameUnpacket(const string content,string &funcName,string &buf){
	LOGI("%s IN",__FUNCTION__);
	Print_Data((unsigned char*)content.data(),content.size());
	if(content.size() <= sizeof(int)){
		return RETURN_CODE_ERROR_PARAM;
	}

	string funcNameLen;
	int len = 0;
	funcNameLen = content.substr(0,sizeof(int));
	LOGI("funcNameLen is %d",funcNameLen.size());
	memcpy(&len,funcNameLen.data(),funcNameLen.size());
	LOGI("len is %d,content size is %d",len,content.size());
	if(content.size() <= sizeof(int) + len){
		return RETURN_CODE_ERROR_PARAM;
	}	

	funcName = "";
	
	funcName = content.substr(sizeof(int), len);

	buf = "";
	
	buf = content.substr(sizeof(int) + len,content.size() - sizeof(int) - len);	
	LOGI("%s OUT",__FUNCTION__);
	return RETURN_CODE_OK;
}