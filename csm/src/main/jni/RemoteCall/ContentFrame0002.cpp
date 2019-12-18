//
// Created by wjr on 19-7-31.
//

#include "ContentFrame0002.h"
#include "GetPackageName.h"
#include "ReturnCode.h"

ContentFrame0002::ContentFrame0002() {

}

ContentFrame0002::~ContentFrame0002() {

}

int ContentFrame0002::ContentFramePacket(const string funcName, const string buf,
                                         string &content) {
    int len = 0;
    len = funcName.size();
    content = "";

    GetPackageName *getPackageName = new GetPackageName();
    string packageName = getPackageName->GetName();

    int callerLen = 0;
    callerLen = packageName.length();

    content.append((const char*)&callerLen, sizeof(int));
    content.append(packageName);
    content.append((const char*)&len,sizeof(int));
    content.append(funcName);
    content.append(buf);
    return 0;
}

int ContentFrame0002::ContentFrameUnpacket(const string content, string &funcName, string &buf) {
    if(content.size() <= sizeof(int)){
        return RETURN_CODE_ERROR_PARAM;
    }

    int len1 = 0;
    string callerNameLen = content.substr(0,sizeof(int));;
    memcpy(&len1,callerNameLen.data(),callerNameLen.size());

    m_callerName = content.substr(sizeof(int),len1);

    if(content.size() <= sizeof(int) + len1 + sizeof(int)){
        return RETURN_CODE_ERROR_PARAM;
    }

    string funcNameLen;
    int len = 0;
    funcNameLen = content.substr(sizeof(int) + len1,sizeof(int));

    memcpy(&len,funcNameLen.data(),funcNameLen.size());

    if(content.size() < sizeof(int) + len1 + sizeof(int) + len){
        return RETURN_CODE_ERROR_PARAM;
    }

    funcName = "";

    funcName = content.substr(sizeof(int) + len1 + sizeof(int), len);

    buf = "";

    buf = content.substr(sizeof(int) + len1 + sizeof(int) + len,content.size() - sizeof(int) - len - sizeof(int) - len1);

    return 0;
}

string ContentFrame0002::getCallerName() {
    return m_callerName;
}