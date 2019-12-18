#ifndef __SCP02_CLIENT_H
#define __SCP02_CLIENT_H

#include "CommunicationClient.h"
#include "logdefine.h"

#define SCP02_CLIENT_CHANNEL_PARAM_ERROR (-2)
#define SCP02_CLIENT_CHANNEL_ESTABLISH_FAILED (-3)
#define SCP02_CLIENT_SEND_TIMEOUT (-4)

typedef int(*scp02_client_channel_monitor_t)(unsigned char *buf,int len);
typedef int(*scp02_client_channel_send_t)(unsigned char *buf,int len);
typedef int(*scp02_client_user_recv_t)(unsigned char *buf,int len);

int rt_scp02_client_process_secure_channel_message(unsigned char *buf,int len);

void rt_scp02_client_init(void);
void rt_scp02_client_uninit(void);
int rt_scp02_client_register_channel(CommunicationClient *channel);
void rt_scp02_client_register_monitor(scp02_client_channel_monitor_t monitor);
void rt_scp02_client_register_recv(scp02_client_user_recv_t user_recv);
int rt_scp02_client_send_secure_message(unsigned char *buf, int len);
void setscpclientlogFunc(ComLog logfunc);

#endif

