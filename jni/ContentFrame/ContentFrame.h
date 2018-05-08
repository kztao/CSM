#ifndef __CONTENT_FRAME_H
#define __CONTENT_FRAME_H

#include <string>
using namespace std;

class ContentFrame
{
public:
	ContentFrame();
	virtual ~ContentFrame();
	virtual int ContentFramePacket(const string funcName,const string buf,string &content);
	virtual int ContentFrameUnpacket(const string content,string &funcName,string &buf);
};

#endif //__CONTENT_FRAME_H
