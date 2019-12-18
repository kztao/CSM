#ifndef __MSG_FRAME_H
#define __MSG_FRAME_H

#include "ContentFrame.h"
#include <map>
using std::string;
using std::map;

class MsgFrame
{
private:
	static map<int,string> mapServerResponseMsg;
public:
//	ContentFrame *pContentFrame;
	MsgFrame();
	virtual ~MsgFrame();
	void MsgFramePacket(int msgID,short version,const string content,string &msgFrame);
	int MsgFrameUnpacket(const string msg,int *pMsgID,short *pVersion,string &content);
};

#endif //__MSG_FRAME_H

