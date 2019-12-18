#ifndef __CONTENT_FRAME_0001_H
#define __CONTENT_FRAME_0001_H

#include "ContentFrame.h"

class ContentFrame0001 :public ContentFrame
{
public:
	ContentFrame0001();
	virtual ~ContentFrame0001();
	virtual int ContentFramePacket(const string funcName,const string buf,string &content) override;
	virtual int ContentFrameUnpacket(const string content,string &funcName,string &buf) override;
};

#endif //__CONTENT_FRAME_0001_H
