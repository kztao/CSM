//
// Created by wjr on 19-7-31.
//

#ifndef CSM_CONTENTFRAME0002_H
#define CSM_CONTENTFRAME0002_H

#include "ContentFrame.h"

class ContentFrame0002:public ContentFrame {
private:
    string m_callerName;
public:
    ContentFrame0002();
    virtual ~ContentFrame0002();
    string getCallerName();
    virtual int ContentFramePacket(const string funcName,const string buf,string &content) override;
    virtual int ContentFrameUnpacket(const string content,string &funcName,string &buf) override;
};


#endif //CSM_CONTENTFRAME0002_H
