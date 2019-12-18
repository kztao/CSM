//
// Created by wang.junren on 2018/11/1.
//

#include "RemoteServicePack.h"
#include "MsgFrame.h"
#include "ContentFrame0001.h"

static const char *tag = "csm_remoteservicepack";

string RemoteServicePack::Pack(string funcName, string src) {
    MsgFrame msgFrame;

    string content;
    string &pContent = content;

    string msg;
    string &pMsg = msg;
    int ret = 0;

    ContentFrame *contectFrameTmp = new ContentFrame0001();
    ret = contectFrameTmp->ContentFramePacket(funcName,src,pContent);
    if(0 != ret){
        delete contectFrameTmp;
        contectFrameTmp = NULL;
        return "";
    }

    delete contectFrameTmp;
    contectFrameTmp = NULL;

    msgFrame.MsgFramePacket(0,0x0001,content,pMsg);

    return msg;
}