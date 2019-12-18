//
// Created by wjr on 19-3-7.
//

#ifndef CSM_INF_H
#define CSM_INF_H

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*parseClientMsg)(int id,char *serverName,char *in, unsigned int inLen);
typedef void (*notifyClientStatus)(int id,char *serverName,int status);

void RegParseClientMsg(parseClientMsg parseFunc);

void SendMsgToClient(int id,char *serverName,char *buf,unsigned int len);

#ifdef __cplusplus
}
#endif

#endif //CSM_INF_H
