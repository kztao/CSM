#ifndef __SCP02_SERVICE_H
#define __SCP02_SERVICE_H

#include "CommunicationServer.h"

#include <iostream>
#include <map>
#include <vector>

using std::string;

#define STATIC_KEY_LEN (16)
#define SESSION_KEY_LEN (16)
#define GLOBAL_IV_LEN (16)

#define CRYPT_ALIGNED (16)

typedef int(*scp02_server_channel_monitor_t)(unsigned char *buf, int len);
typedef int(*scp02_server_get_diversification_data_t)(unsigned char diversification_data[10]);
typedef int(*scp02_server_user_recv_t)(CommunicationServer* pServer,CommunicationServer::Communication *pClient, unsigned char *buf, int len);

struct scp02_server_secure_channel_info
{
    /* agreement data */
    unsigned char host_challenge[8];
    unsigned char card_challenge[6];
    unsigned char sequence_counter[2];

    /* session key */
    unsigned char rmac_session_key[SESSION_KEY_LEN];
    unsigned char cmac_session_key[SESSION_KEY_LEN];
    unsigned char  enc_session_key[SESSION_KEY_LEN];
    unsigned char  dek_session_key[SESSION_KEY_LEN];

    /* static key */
    unsigned char s_mac_key[STATIC_KEY_LEN];
    unsigned char s_enc_key[STATIC_KEY_LEN];
    unsigned char s_dek_key[STATIC_KEY_LEN];

    /* iv */
    unsigned char c_dec_iv[GLOBAL_IV_LEN];
    unsigned char r_enc_iv[GLOBAL_IV_LEN];

    /* key version */
    unsigned char key_version[2];
};
typedef struct scp02_server_secure_channel_info scp02_server_secure_channel_info_t;

struct rt_scp02_server
{
    int secure_channel_state;

    scp02_server_channel_monitor_t monitor;
    scp02_server_get_diversification_data_t get_diversification_data;
    scp02_server_user_recv_t rx;

    scp02_server_secure_channel_info_t channel_info;
};
typedef struct rt_scp02_server rt_scp02_server_t;

class Scp02Service
{
public:
    Scp02Service();
    ~Scp02Service();

    static int process_secure_channel_message(CommunicationServer *pServer, CommunicationServer::Communication *pClient, unsigned char *buf, int len);
    static int send_secure_message(CommunicationServer::Communication *pClient, unsigned char *buf, int len);
    static int BroadCast(CommunicationServer *pServer, string funcName,string src);
    static void clientStatusNotify(CommunicationServer::Communication *pClient,int status);

    int rt_scp02_server_register_monitor(scp02_server_channel_monitor_t monitor);
    int rt_scp02_server_register_get_diversification_data(scp02_server_get_diversification_data_t get_diversification_data);
    int rt_scp02_server_register_recv(scp02_server_user_recv_t rx);
    int rt_scp02_server_send_secure_message(CommunicationServer::Communication *pClient, int msg_id, unsigned char *buf, int len);
    int rt_scp02_server_process_secure_channel_message(CommunicationServer *pServer, CommunicationServer::Communication *pClient, unsigned char *buf, int len);
	static void setlogFunc(ComLog logfunc);

private:
    rt_scp02_server_t pri_thiz;
};

#endif
