#include "ContentFrame0001.h"
#include "ReturnCode.h"
#include <cstring>

ContentFrame0001::ContentFrame0001(){

}

ContentFrame0001::~ContentFrame0001(){

}

int ContentFrame0001::ContentFramePacket(const string funcName,const string buf,string &content){
	int len = 0;
	len = funcName.size();
	content = "";

	content.append((const char*)&len,sizeof(int));
	content.append(funcName);
	content.append(buf);

	return 0;
}

int ContentFrame0001::ContentFrameUnpacket(const string content,string &funcName,string &buf){
	if(content.size() <= sizeof(int)){
		return RETURN_CODE_ERROR_PARAM;
	}

	string funcNameLen;
	int len = 0;
	funcNameLen = content.substr(0,sizeof(int));

	memcpy(&len,funcNameLen.data(),funcNameLen.size());

	if(content.size() < sizeof(int) + len){
		return RETURN_CODE_ERROR_PARAM;
	}	

	funcName = "";
	
	funcName = content.substr(sizeof(int), len);

	buf = "";
	
	buf = content.substr(sizeof(int) + len,content.size() - sizeof(int) - len);	

	return 0;
}