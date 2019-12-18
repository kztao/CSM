#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <assert.h>
#include <pthread.h>

#include "LocalSocketClient.h"

#include "Scp02Client.h"
#include "tiny_des.h"
#include "tiny_sha2.h"

#include "sm3.h"
#include "sm4.h"
#include "sm4_core.h"

#include <iostream>
#include <map>
#include <string>
#include "Mutex.h"

using std::string;
using std::map;

/* scp02 common */
#define STATIC_KEY_LEN (16)
#define SESSION_KEY_LEN (16)
#define GLOBAL_IV_LEN (16)

#define HOST_CHALLENGE_LEN (8)
#define CARD_CHALLENGE_LEN (6)
#define SEQUENCE_COUNTER_LEN (2)
#define KEY_VERSION_LEN (2)

#define CRYPT_ALIGNED (16)
#define SHA2_HMAC_RESULT_LEN (32)

#define INITIALIZE_UPDATE_RESPOND_LEN (28)
#define INITIALIZE_UPDATE_RESPOND_OFFSET_DIV_DATA (0)
#define INITIALIZE_UPDATE_RESPOND_OFFSET_KEY_INFO (10)
#define INITIALIZE_UPDATE_RESPOND_OFFSET_SC (12)
#define INITIALIZE_UPDATE_RESPOND_OFFSET_CARD_CHALLENGE (14)
#define INITIALIZE_UPDATE_RESPOND_OFFSET_CARD_CRYPTOGRAM (20)

/* 7816 define */
#define ISO7816_OFFSET_CLA (0)
#define ISO7816_OFFSET_INS (1)
#define ISO7816_OFFSET_P1 (2)
#define ISO7816_OFFSET_P2 (3)
#define ISO7816_OFFSET_CDATA (5)
#define IS07816_OFFSET_EXT_CDATA (7)

#define SW12_LEN (2)

/* */
#define MSG_ID_LEN (2)

/* compatible sync/async process*/
#define COMPATIBLE_MODE

static map<int, string> mapSaveMsg;
static Mutex mutexSaveMap;
static int lastMsgId;
static string lastMsg;

/* */
#define EVENT_FLAG_CHANNEL_ESTABLISHED    0x01
#define EVENT_FLAG_CHANNEL_FAILED         0x02

/* state machine */
enum channel_status
{
    CHANNEL_STATE_DEFAULT = -1,
    CHANNEL_STATE_WAIT_INITIALIZE_UPDATE = 0,
    CHANNEL_STATE_WAIT_EXTERNAL_AUTHENTICATE,
    CHANNEL_STATE_ESTABLISHED,
};
typedef enum channel_status channel_status_t;

typedef uint32_t eventmask_t;

struct eventflag
{
    eventmask_t flags;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

struct scp02_client_secure_channel_info
{
    /* agreement data */
    unsigned char host_challenge[HOST_CHALLENGE_LEN];
    unsigned char card_challenge[CARD_CHALLENGE_LEN];
    unsigned char sequence_counter[SEQUENCE_COUNTER_LEN];

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
    unsigned char c_enc_iv[GLOBAL_IV_LEN];
    unsigned char r_dec_iv[GLOBAL_IV_LEN];

    /* key version */
    unsigned char key_version[KEY_VERSION_LEN];
};
typedef struct scp02_client_secure_channel_info scp02_client_secure_channel_info_t;

struct rt_scp02_client
{
    pthread_mutex_t state_mutex;
    struct eventflag channel_event_flag;
    channel_status_t secure_channel_state;
    unsigned int global_id;

    scp02_client_channel_monitor_t monitor;
    scp02_client_channel_send_t channel_send;
    scp02_client_user_recv_t user_recv;

    scp02_client_secure_channel_info_t channel_info;
};
typedef struct rt_scp02_client rt_scp02_client_t;

/////////////////////////////////////////////////////////////////////////////////
static const char *tag = "csm_Scp02Client";

static pthread_mutex_t global_send_mutex;
static pthread_mutex_t global_recv_mutex;
static rt_scp02_client_t global_thiz = {
    .channel_event_flag = {
        .flags = 0,
    },
    .secure_channel_state = CHANNEL_STATE_DEFAULT,
    .global_id = 0,
    .monitor = NULL,
    .channel_send = NULL,
    .user_recv = NULL,
};

static CommunicationClient *global_channel = NULL;

static void* scp02_client_external_authenticate_request(string *str);
static void* scp02_client_retry_establish_secure_channel(int *pMsgId);

static ComLog g_Log = NULL;

void setscpclientlogFunc(ComLog logfunc){
    g_Log = logfunc;
}

static void printlog_scp(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...){

	char buf[1024] = { 0 };
    va_list arg;

    va_start(arg, format);
	vsnprintf(buf, 1024,format, arg);
    va_end(arg);

    if(g_Log){
        g_Log(severity,func,line,__FILE__,"%s",buf);
    }
    else{
        __android_log_print(ANDROID_LOG_INFO, tag, "printlog,%s",(char *)buf);
    }
}


/////////////////////////////////////////////////////////////////////////////////

static void scp02_client_dump_bytes(const char *str, void *buf, int len)
{
    char printf_buf[16*3+1];
    char *pbuf = &printf_buf[0];
    int i, index;

    if(NULL == str)
    {
        printlog_scp(C_error,__FUNCTION__,__LINE__, "[scp02client]:str must not be null.");
        return;
    }

    printlog_scp(C_info,__FUNCTION__,__LINE__, "[scp02client]:%s(%d bytes):", str, len);

    memset(pbuf, '\0', sizeof(printf_buf));
    index = 0;
    for(i=0;i<len;i++)
    {
        sprintf(pbuf+index, "%02x ", *((unsigned char *)buf+i));
        index += 3;
        if((i+1)%16 == 0)
        {
            printlog_scp(C_info,__FUNCTION__,__LINE__, "%s", pbuf);
            memset(pbuf, '\0', sizeof(printf_buf));
            index = 0;
        }
    }
	if(len >0)
	{
		printlog_scp(C_info,__FUNCTION__,__LINE__, "%s", pbuf);
	}	

}

/******************************************************************************
 * 函数名 eventflag_init
 *
 * 功能描述: 事件标志初始化
 *
 * 参数说明: 
 * ev(in): 事件标志结构指针
 *
 *
 * 返回值: 无
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void eventflag_init (struct eventflag *ev)
{
    ev->flags = 0;
    pthread_mutex_init(&ev->mutex, NULL);
    pthread_cond_init(&ev->cond, NULL);
}

/******************************************************************************
 * 函数名 eventflag_timedwait
 *
 * 功能描述: 事件标志超时等待
 *
 * 参数说明: 
 * ev(in): 事件标志结构指针
 * tm(in): 超时时间
 *
 *
 * 返回值: 事件值
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static eventmask_t eventflag_timedwait (struct eventflag *ev, struct timespec* tm)
{
    int n;
    eventmask_t m;

    pthread_mutex_lock(&ev->mutex);
    if (!ev->flags)
    {
        /* wait until recv eventflag signal */
        int err = pthread_cond_timedwait(&ev->cond, &ev->mutex, tm);
    }

    scp02_client_dump_bytes("eventflag_timedwait flags = ", &ev->flags, sizeof(ev->flags));
    n = __builtin_ffs(ev->flags);
    scp02_client_dump_bytes("eventflag_timedwait n = ", &n, sizeof(n));

    if (n) 
    {
        /* Clear that bit */
        /* Always n > 0 when waked up, but make sure no bad things.  */
        m = (1 << (n - 1));
        ev->flags &= ~m;
    }
    else
    {
        m = 0;
    }

    pthread_mutex_unlock(&ev->mutex);

    return m;
}

/******************************************************************************
 * 函数名 eventflag_signal
 *
 * 功能描述: 事件标志通知
 *
 * 参数说明: 
 * ev(in): 事件标志结构指针
 * m(in): 待通知的事件值
 *
 *
 * 返回值: 事件值
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void eventflag_signal (struct eventflag *ev, eventmask_t m)
{
    pthread_mutex_lock(&ev->mutex);

    ev->flags |= m;

    /* notify evenflag signal */
    pthread_cond_signal(&ev->cond);

    pthread_mutex_unlock(&ev->mutex);
}

/******************************************************************************
 * 函数名 scp02_client_calculate_sm4_enc_ecb
 *
 * 功能描述: 计算sm4加密ecb模式
 *
 * 参数说明: 
 * key(in): 密钥
 * input(in): 输入缓冲区
 * input_len(in): 输入缓冲区长度
 * output(in): 输出缓冲区
 * output_len(in): 输出缓冲区长度
 *
 *
 * 返回值: 无
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void scp02_client_calculate_sm4_enc_ecb(unsigned char key[16], \
    unsigned char *input, \
    int input_len, \
    unsigned char *output, \
    int *output_len)
{
    /*sm4_context ctx_sm4;

    {
        // set sm4 key
        sm4_setkey_enc(&ctx_sm4, key);

        // compute input data
        sm4_crypt_ecb(&ctx_sm4, SM4_ENCRYPT, input_len, input, output);

        *output_len = input_len;
    }*/
    mm_handle h = NULL;
    h = sm4_init(key);
    sm4_ecb_encrypt(h, input,input_len, output);
    sm4_unit(h);
    *output_len = input_len;
}

/******************************************************************************
 * 函数名 scp02_client_calculate_sm4_enc_cbc
 *
 * 功能描述: 计算sm4加密cbc模式
 *
 * 参数说明: 
 * key(in): 密钥
 * iv(in): 初始化向量
 * input(in): 输入缓冲区
 * input_len(in): 输入缓冲区长度
 * output(in): 输出缓冲区
 * output_len(in): 输出缓冲区长度
 *
 *
 * 返回值: 无
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void scp02_client_calculate_sm4_enc_cbc(unsigned char key[16], \
    unsigned char iv[16], \
    unsigned char *input, \
    int input_len, \
    unsigned char *output, \
    int *output_len)
{
 /*   sm4_context ctx_sm4;

    {
        // set sm4 key
        sm4_setkey_enc(&ctx_sm4, key);

        // compute input data
        sm4_crypt_cbc(&ctx_sm4, SM4_ENCRYPT, input_len, iv, input, output);

        *output_len = input_len;
    }*/
    mm_handle h = NULL;
    h = sm4_init(key);
    sm4_set_iv(h, iv);
    sm4_cbc_encrypt(h, input,input_len, output);
    sm4_unit(h);
    *output_len = input_len;
}

/******************************************************************************
 * 函数名 scp02_client_calculate_sm4_dec_cbc
 *
 * 功能描述: 计算sm4解密cbc模式
 *
 * 参数说明: 
 * key(in): 密钥
 * iv(in): 初始化向量
 * input(in): 输入缓冲区
 * input_len(in): 输入缓冲区长度
 * output(in): 输出缓冲区
 * output_len(in): 输出缓冲区长度
 *
 *
 * 返回值: 无
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void scp02_client_calculate_sm4_dec_cbc(unsigned char key[16], \
    unsigned char iv[16], \
    unsigned char *input, \
    int input_len, \
    unsigned char *output, \
    int *output_len)
{
   /* sm4_context ctx_sm4;

    {
        // set sm4 key
        sm4_setkey_dec(&ctx_sm4, key);

        // compute input data
        sm4_crypt_cbc(&ctx_sm4, SM4_DECRYPT, input_len, iv, input, output);

        *output_len = input_len;
    }*/
    mm_handle h = NULL;
    h = sm4_init(key);
    sm4_set_iv(h, iv);
    sm4_cbc_decrypt(h, input,input_len, output);
    sm4_unit(h);
    *output_len = input_len;
}

static void tiny_sm3(unsigned char *input, int ilen, unsigned char output[32])
{
    sm3_hash(input,ilen,output);
    /*SM3_CTX ctx_sm3;

    SM3_Init(&ctx_sm3);
    SM3Update(&ctx_sm3, input, ilen);
    SM3Final(output, &ctx_sm3, 32);*/

}

/******************************************************************************
 * 函数名 scp02_client_calculate_des_enc_cbc
 *
 * 功能描述: 计算des加密cbc模式
 *
 * 参数说明: 
 * key(in): 密钥
 * iv(in): 初始化向量
 * input(in): 输入缓冲区
 * input_len(in): 输入缓冲区长度
 * output(in): 输出缓冲区
 * output_len(in): 输出缓冲区长度
 * flag(in): 填充标准, 1:进行填充, 0:不进行填充.
 *
 *
 * 返回值: 无
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void scp02_client_calculate_des_enc_cbc(unsigned char key[8], \
    unsigned char iv[8], \
    unsigned char *input, \
    int input_len, \
    unsigned char *output, \
    int *output_len)
{
    des_context ctx;

    {
        /* set des key*/
        des_setkey_enc(&ctx, key);

        /* compute input data */
        des_crypt_cbc(&ctx, DES_ENCRYPT, input_len, iv, input, output);

        *output_len = input_len;
    }
}

/******************************************************************************
 * 函数名 scp02_client_calculate_3des_enc_ecb
 *
 * 功能描述: 计算3des加密ecb模式
 *
 * 参数说明: 
 * key(in): 密钥
 * input(in): 输入缓冲区
 * input_len(in): 输入缓冲区长度
 * output(in): 输出缓冲区
 * output_len(in): 输出缓冲区长度
 *
 *
 * 返回值: 无
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void scp02_client_calculate_3des_enc_ecb(unsigned char key[16], \
    unsigned char *input, \
    int input_len, \
    unsigned char *output, \
    int *output_len)
{
    des3_context ctx3;

    int offset = 0;

    *output_len = input_len;

    while(input_len > 0)
    {
        /* set 3des key */
        des3_set2key_enc(&ctx3, key);

        /* compute input data */
        des3_crypt_ecb(&ctx3, input+offset, output+offset);

        offset += 8;
        input_len -= 8;
    };
}

/******************************************************************************
 * 函数名 scp02_client_calculate_3des_enc_cbc
 *
 * 功能描述: 计算3des加密cbc模式
 *
 * 参数说明: 
 * key(in): 密钥
 * iv(in): 初始化向量
 * input(in): 输入缓冲区
 * input_len(in): 输入缓冲区长度
 * output(in): 输出缓冲区
 * output_len(in): 输出缓冲区长度
 *
 *
 * 返回值: 无
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void scp02_client_calculate_3des_enc_cbc(unsigned char key[16], \
    unsigned char iv[8], \
    unsigned char *input, \
    int input_len, \
    unsigned char *output, \
    int *output_len)
{
    des3_context ctx3;

    {
        /* set 3des key */
        des3_set2key_enc(&ctx3, key);

        /* compute input data */
        des3_crypt_cbc(&ctx3, DES_ENCRYPT, input_len, iv, input, output);

        *output_len = input_len;
    }
}

/******************************************************************************
 * 函数名 scp02_client_calculate_3des_dec_cbc
 *
 * 功能描述: 计算3des解密cbc模式
 *
 * 参数说明: 
 * key(in): 密钥
 * iv(in): 初始化向量
 * input(in): 输入缓冲区
 * input_len(in): 输入缓冲区长度
 * output(in): 输出缓冲区
 * output_len(in): 输出缓冲区长度
 *
 *
 * 返回值: 无
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void scp02_client_calculate_3des_dec_cbc(unsigned char key[16], \
    unsigned char iv[8], \
    unsigned char *input, \
    int input_len, \
    unsigned char *output, \
    int *output_len)
{
    des3_context ctx3;

    {
        /* set 3des key */
        des3_set2key_dec(&ctx3, key);

        /* compute input data */
        des3_crypt_cbc(&ctx3, DES_DECRYPT, input_len, iv, input, output);

        *output_len = input_len;
    }
}

/******************************************************************************
 * 函数名 scp02_client_generate_session_key
 *
 * 功能描述: 生成会话密钥
 *
 * 参数说明: 
 * key(in): 密钥
 * constant(in): 常量
 * sequence_counter(in): 序列计数器
 * sesseion_key(out): 会话密钥
 *
 *
 * 返回值: 无
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void scp02_client_generate_session_key(unsigned char key[STATIC_KEY_LEN], unsigned char constant[2], unsigned char sequence_counter[SEQUENCE_COUNTER_LEN], unsigned char sesseion_key[SESSION_KEY_LEN])
{
    unsigned char derivation_data[SESSION_KEY_LEN] = {0};
    unsigned char icv[8] = {0};
    int output_len = 0;

    memset(derivation_data, 0, SESSION_KEY_LEN);
    memcpy(derivation_data, constant, 2);
    memcpy(derivation_data+2, sequence_counter, SEQUENCE_COUNTER_LEN);

    scp02_client_calculate_3des_enc_cbc(key, icv, derivation_data, SESSION_KEY_LEN, \
        sesseion_key, &output_len);
}

/******************************************************************************
 * 函数名 scp02_client_generate_all_session_key
 *
 * 功能描述: 生成所有的会话密钥
 *
 * 参数说明: 
 * thiz(in): rt_scp02_client_t结构指针
 *
 * 返回值: 无
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void scp02_client_generate_all_session_key00(rt_scp02_client_t *thiz, unsigned char diversification_data[10])
{
    /* r-mac */
    /* c-mac */
    /* enc */
    /* dek */
    unsigned char constant_data[4][2] = { \
        {0x01, 0x02}, \
        {0x01, 0x01}, \
        {0x01, 0x82}, \
        {0x01, 0x81}  \
    };

    unsigned char macPlainText[STATIC_KEY_LEN] = {0x00,0x00,0x00,0x00,0x00,0x00,0xF0,0x02,
        0x00,0x00,0x00,0x00,0x00,0x00,0x0F,0x02};

    unsigned char encPlainText[STATIC_KEY_LEN] = {0x00,0x00,0x00,0x00,0x00,0x00,0xF0,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,0x0F,0x01};

    unsigned char dekPlainText[STATIC_KEY_LEN] = {0x00,0x00,0x00,0x00,0x00,0x00,0xF0,0x03,
        0x00,0x00,0x00,0x00,0x00,0x00,0x0F,0x03};

    unsigned char default_s_master_key[STATIC_KEY_LEN] = { \
        0x5D,0x8A,0x5C,0xFD,0x49,0x42,0x9E,0xA8, \
        0xDB,0xD5,0xB5,0x74,0xE6,0x64,0x78,0x8C};

    unsigned char *pstatic_key = NULL;
    unsigned char *psession_key = NULL;

    int output_len;

    if(NULL == thiz)
    {
        scp02_client_dump_bytes("generate_all_session_key:thiz is null !!", NULL, 0);
        return;
    }

////////////////////////////////////////////////////////////////////////////////

    /* load diversification_data */
    /* load default static master key and generate static mac key */
    /* generate c-mac session key */
    pstatic_key = (unsigned char *)&thiz->channel_info.s_mac_key;
    psession_key = (unsigned char *)&thiz->channel_info.cmac_session_key;
    memcpy(&macPlainText[0], &diversification_data[4], 6);
    memcpy(&macPlainText[8], &diversification_data[4], 6);
    scp02_client_calculate_sm4_enc_ecb(default_s_master_key, \
        &macPlainText[0], \
        STATIC_KEY_LEN, 
        pstatic_key, \
        &output_len);
    scp02_client_generate_session_key((unsigned char *)pstatic_key, \
        &constant_data[1][0], \
        (unsigned char *)&thiz->channel_info.sequence_counter, \
        (unsigned char *)psession_key);

    /* load diversification_data */
    /* load default static master key and generate static enc key */
    /* generate enc session key */
    pstatic_key = (unsigned char *)&thiz->channel_info.s_enc_key;
    psession_key = (unsigned char *)&thiz->channel_info.enc_session_key;
    memcpy(&encPlainText[0], &diversification_data[4], 6);
    memcpy(&encPlainText[8], &diversification_data[4], 6);
    scp02_client_calculate_sm4_enc_ecb(default_s_master_key, \
        &encPlainText[0], \
        STATIC_KEY_LEN, 
        pstatic_key, \
        &output_len);
    scp02_client_generate_session_key((unsigned char *)pstatic_key, \
        &constant_data[2][0], \
        (unsigned char *)&thiz->channel_info.sequence_counter, \
        (unsigned char *)psession_key);

    /* load diversification_data */
    /* load default static master key and generate static dek key */
    /* generate dek session key */
    pstatic_key = (unsigned char *)&thiz->channel_info.s_dek_key;
    psession_key = (unsigned char *)&thiz->channel_info.dek_session_key;
    memcpy(&dekPlainText[0], &diversification_data[4], 6);
    memcpy(&dekPlainText[8], &diversification_data[4], 6);
    scp02_client_calculate_sm4_enc_ecb(default_s_master_key, \
        &dekPlainText[0], \
        STATIC_KEY_LEN, 
        pstatic_key, \
        &output_len);
    scp02_client_generate_session_key((unsigned char *)pstatic_key, \
        &constant_data[3][0], \
        (unsigned char *)&thiz->channel_info.sequence_counter, \
        (unsigned char *)psession_key);

    /* r-mac session key */
    pstatic_key = (unsigned char *)&thiz->channel_info.s_mac_key;
    psession_key = (unsigned char *)&thiz->channel_info.rmac_session_key;
    scp02_client_generate_session_key((unsigned char *)pstatic_key, \
        &constant_data[0][0], \
        (unsigned char *)&thiz->channel_info.sequence_counter, \
        (unsigned char *)psession_key);

////////////////////////////////////////////////////////////////////////////////
}

/******************************************************************************
 * 函数名 scp02_client_initialize_all_iv
 *
 * 功能描述: 初始化所有初始化向量
 *
 * 参数说明: 
 * thiz(in): rt_scp02_client_t结构指针
 * piv(in): 待设置的初始化向量缓冲区
 * iv_len(in): 待设置的初始化向量的长度
 *
 * 返回值: 无
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void scp02_client_initialize_all_iv(rt_scp02_client_t *thiz, unsigned char *piv, int iv_len)
{
    unsigned char *p_iv = NULL;

    int i;

    if(NULL == thiz)
    {
        scp02_client_dump_bytes("initialize_all_iv:thiz is null !!", NULL, 0);
        return;
    }

    p_iv = (unsigned char *)&thiz->channel_info.c_enc_iv;
    memcpy((unsigned char *)p_iv, piv, iv_len);

    p_iv = (unsigned char *)&thiz->channel_info.r_dec_iv;
    memcpy((unsigned char *)p_iv, piv, iv_len);
}

/******************************************************************************
 * 函数名 scp02_client_increase_iv
 *
 * 功能描述: 初始化向量递增
 *
 * 参数说明: 
 * iv(in/out): 初始化向量
 *
 * 返回值: 无
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void scp02_client_increase_iv(unsigned char iv[GLOBAL_IV_LEN])
{
    int i;

    for(i=0;i<GLOBAL_IV_LEN;i++)
    {
        if(0xFF == (iv[i]&0xFF))
        {
            iv[i] += 1;
            continue;
        }
        else
        {
            iv[i] += 1;
            break;
        }
    }

    //scp02_client_dump_bytes("increase_iv", iv, GLOBAL_IV_LEN);
}

static int scp02_client_increase_msg_id(rt_scp02_client_t *thiz)
{
    thiz->global_id += 1;
    if((thiz->global_id & 0xFF) == 0)
    {
        thiz->global_id += 1;
    }

    return thiz->global_id & 0xFF;
}

/******************************************************************************
 * 函数名 scp02_client_calculate_authentication_cryptogram
 *
 * 功能描述: 计算校验码
 *
 * 参数说明: 
 * key(in): 密钥
 * host_challenge(in): 主机挑战码
 * sequence_counter(in): 序列计算器
 * card_challenge(in): 卡片挑战码
 * authentication_cryptogram(out): 校验码
 * card_or_host(in): 计算模式, 0:计算卡片校验码, 其他:计算主机检验码
 *
 * 返回值: 无
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void scp02_client_calculate_authentication_cryptogram(unsigned char key[16], \
    unsigned char host_challenge[HOST_CHALLENGE_LEN], \
    unsigned char sequence_counter[SEQUENCE_COUNTER_LEN], \
    unsigned char card_challenge[CARD_CHALLENGE_LEN], \
    unsigned char authentication_cryptogram[8], \
    int card_or_host)
{
    unsigned char calculate_buffer_input[24];
    unsigned char calculate_buffer_output[24];
    unsigned char icv[8];
    int output_len = 0;

    memset(calculate_buffer_input, 0, sizeof(calculate_buffer_input));
    memset(icv, 0, sizeof(icv));
    /* calculate authentication card_cryptogram */
    if(card_or_host == 0)
    {
        memcpy(&calculate_buffer_input[0], host_challenge, HOST_CHALLENGE_LEN);
        memcpy(&calculate_buffer_input[HOST_CHALLENGE_LEN], sequence_counter, SEQUENCE_COUNTER_LEN);
        memcpy(&calculate_buffer_input[HOST_CHALLENGE_LEN+SEQUENCE_COUNTER_LEN], card_challenge, CARD_CHALLENGE_LEN);
        calculate_buffer_input[HOST_CHALLENGE_LEN+SEQUENCE_COUNTER_LEN+CARD_CHALLENGE_LEN] = 0x80;
    }
    else
    {
        memcpy(&calculate_buffer_input[0], sequence_counter, SEQUENCE_COUNTER_LEN);
        memcpy(&calculate_buffer_input[SEQUENCE_COUNTER_LEN], card_challenge, CARD_CHALLENGE_LEN);
        memcpy(&calculate_buffer_input[SEQUENCE_COUNTER_LEN+CARD_CHALLENGE_LEN], host_challenge, HOST_CHALLENGE_LEN);
        calculate_buffer_input[SEQUENCE_COUNTER_LEN+CARD_CHALLENGE_LEN+HOST_CHALLENGE_LEN] = 0x80;
    }

    scp02_client_calculate_3des_enc_cbc(key, \
        icv, calculate_buffer_input, sizeof(calculate_buffer_input), \
        calculate_buffer_output, &output_len);
    memcpy(authentication_cryptogram, &calculate_buffer_output[output_len-8], 8);
}

static void SaveMsg(int msgId, string buf)
{
    mutexSaveMap.Lock();
    mapSaveMsg.insert(make_pair(msgId, buf));
    mutexSaveMap.Unlock();
}

static void DeleteMsg(int msgId)
{
    mutexSaveMap.Lock();
    map<int, string>::iterator it = mapSaveMsg.find(msgId);
    if(it != mapSaveMsg.end())
    {
        mapSaveMsg.erase(it);
    }
    mutexSaveMap.Unlock();
}

static int ExistMsg(int msgId)
{
    int isExist = 0;

    mutexSaveMap.Lock();
    map<int, string>::iterator it = mapSaveMsg.find(msgId);
    if(it != mapSaveMsg.end())
    {
        isExist = 1;
    }
    mutexSaveMap.Unlock();

    return isExist;
}

/******************************************************************************
 * 函数名 scp02_client_unwrap_message
 *
 * 功能描述: 解包消息
 *
 * 参数说明: 
 * thiz(in): rt_scp02_client_t结构指针
 * buf(in): 输入缓冲区
 * len(in): 输入缓冲区长度
 *
 * 返回值: 返回值>=0:处理成功, -1:处理失败.
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static int scp02_client_unwrap_message(rt_scp02_client_t *thiz, int *pmsg_id, unsigned char *buf, int len)
{
    int dataLen, output_len = 0, padding_size, ret = 0;
    unsigned char *data = NULL;

    unsigned char icv[GLOBAL_IV_LEN] = {0};
    unsigned char calc_sha2[SHA2_HMAC_RESULT_LEN];

    int msg_id = 0;

    do
    {
        if(NULL == thiz)
        {
            scp02_client_dump_bytes("unwrap_message:thiz is null !!", NULL, 0);
            ret = -1;
            break;
        }

        if(len < (MSG_ID_LEN + SW12_LEN))
        {
            scp02_client_dump_bytes("unwrap_message:len < 2 !!", NULL, 0);
            ret = -1;
            break;
        }

        /* get msg id */
        msg_id = (*(buf+len-SW12_LEN-2) * 0x100)+ *(buf+len-SW12_LEN-1);
        *pmsg_id = msg_id;

        /* SW12: 0x90, 0x00 mean:No Error */
        if((*(buf+len-2) != 0x90) || (*(buf+len-1) != 0x00))
        {
            scp02_client_dump_bytes("unwrap_message:sw1 sw2 != 0x90 0x00 !!", NULL, 0);
            ret = -1;
            break;
        }

        dataLen = len - MSG_ID_LEN - SW12_LEN;
        /* dataLen invaild */
        if(dataLen < (SHA2_HMAC_RESULT_LEN+CRYPT_ALIGNED+CRYPT_ALIGNED))
        {
            scp02_client_dump_bytes("unwrap_message:dataLen invaild!!", NULL, 0);
            ret = -1;
            break;
        }
        data = (unsigned char *)malloc(dataLen);
        if(data == NULL)
        {
            scp02_client_dump_bytes("unwrap_message:malloc data failed !!", NULL, 0);
            ret = -1;
            break;
        }
        memset(data, 0, dataLen);

        /* compute 3des dec cbc */
        memcpy(icv, (unsigned char *)&thiz->channel_info.r_dec_iv, GLOBAL_IV_LEN);
        scp02_client_calculate_sm4_dec_cbc((unsigned char *)&thiz->channel_info.enc_session_key, \
            icv, (unsigned char *)buf, dataLen, data, &output_len);

        /* compute sha2 and compare it */
        //tiny_sha2(data, output_len-SHA2_HMAC_RESULT_LEN, calc_sha2, 0);
        //tiny_sha2_hmac((unsigned char *)&thiz->channel_info.rmac_session_key, \
            //SESSION_KEY_LEN, data, output_len-SHA2_HMAC_RESULT_LEN, calc_sha2, 0);
        tiny_sm3(data, output_len-SHA2_HMAC_RESULT_LEN, calc_sha2);

        if(memcmp(data+(output_len-SHA2_HMAC_RESULT_LEN), calc_sha2, sizeof(calc_sha2)) != 0)
        {
            scp02_client_dump_bytes("unwrap_message:calc_sha2 not match !!", NULL, 0);
            ret = -1;
            break;
        }

        /* delete msg id and msg */
        DeleteMsg(msg_id);

        /* get padding_desc and get plaintext */
        padding_size = *(data+(output_len-SHA2_HMAC_RESULT_LEN)-1);

        /* update iv */
        scp02_client_increase_iv((unsigned char *)&thiz->channel_info.r_dec_iv);

        /* notify user recv function */
        if(thiz->user_recv)
        {
            thiz->user_recv(data, output_len-SHA2_HMAC_RESULT_LEN-CRYPT_ALIGNED-padding_size);
        }
    }
    while(0);

    if(NULL != data)
    {
        free(data);
        data = NULL;
    }

    return ret;
}

/******************************************************************************
 * 函数名 rt_scp02_client_process_secure_channel_message
 *
 * 功能描述: 处理安全通道消息
 *
 * 参数说明: 
 * buf(in): 输入缓冲区
 * len(in): 输入缓冲区长度
 *
 * 返回值: 返回值>=0:处理成功, -1:处理失败.
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
int rt_scp02_client_process_secure_channel_message(unsigned char *buf,int len)
{
    unsigned char initialize_update_respond[INITIALIZE_UPDATE_RESPOND_LEN+SW12_LEN];
    unsigned char icv[8];

    /* 
     * APDU Header
     * 0x84: Proprietary command with secure messaging
     * 0x82: EXTERNAL AUTHENTICATE
     * 0x00: P1
     * 0x00: P2
     */
    unsigned char external_authenticate_request[ISO7816_OFFSET_CDATA+16] = {
        0x84, 0x82, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    unsigned char diversification_data[10] = {0x00};

    unsigned char card_cryptogram[8];
    unsigned char host_cryptogram[8];
    unsigned char icv1[8];
    unsigned char mac[8];

    int ret = 0;

    int output_len = 0;

    rt_scp02_client_t *thiz = &global_thiz;

    pthread_t retry_threadid;
    int msg_id = 0;

    if(thiz == NULL || buf == NULL || (len < 0))
    {
        scp02_client_dump_bytes("rt_scp02_client_process_secure_channel_message para invalid", NULL, 0);
        return -1;
    }

    //pthread_mutex_lock(&global_recv_mutex);
    pthread_mutex_lock(&thiz->state_mutex);

    /* call channel monitor function */
    if(thiz->monitor)
    {
        thiz->monitor(buf, len);
    }

    switch(thiz->secure_channel_state)
    {
        /* INITIALIZE UPDATE Response */
        case CHANNEL_STATE_WAIT_INITIALIZE_UPDATE:
        {
            do
            {
                /* SW12: 0x90, 0x00 mean:No Error */
                if((len != (sizeof(initialize_update_respond))) || \
                    (*(buf+len-2) != 0x90) || (*(buf+len-1) != 0x00))
                {
                    /* key version not support */
                    scp02_client_dump_bytes("INITIALIZE_UPDATE: process error! len is ", &len, sizeof(len));
                    ret = -1;

                    thiz->secure_channel_state = CHANNEL_STATE_DEFAULT;

                    /* send channel established failed event */
                    eventflag_signal(&thiz->channel_event_flag, EVENT_FLAG_CHANNEL_FAILED);

                    break;
                }

                memcpy(initialize_update_respond, buf, sizeof(initialize_update_respond));

                /* save diversification_data */
                memcpy(diversification_data, buf, sizeof(diversification_data));

                /* save key_version, sequence_counter and card_challenge */
                memcpy((unsigned char *)&thiz->channel_info.key_version, \
                    &initialize_update_respond[INITIALIZE_UPDATE_RESPOND_OFFSET_KEY_INFO], \
                    KEY_VERSION_LEN);

                memcpy((unsigned char *)&thiz->channel_info.sequence_counter, \
                    &initialize_update_respond[INITIALIZE_UPDATE_RESPOND_OFFSET_SC], \
                    SEQUENCE_COUNTER_LEN);

                memcpy((unsigned char *)&thiz->channel_info.card_challenge, \
                    &initialize_update_respond[INITIALIZE_UPDATE_RESPOND_OFFSET_CARD_CHALLENGE], \
                    CARD_CHALLENGE_LEN);

                /* calculate all sessionKey */
                scp02_client_generate_all_session_key00(thiz, diversification_data);

                /* calculate authentication card_cryptogram */
                scp02_client_calculate_authentication_cryptogram((unsigned char *)&thiz->channel_info.enc_session_key, \
                    (unsigned char *)&thiz->channel_info.host_challenge, \
                    (unsigned char *)&thiz->channel_info.sequence_counter, \
                    (unsigned char *)&thiz->channel_info.card_challenge, \
                    card_cryptogram, 0);

                scp02_client_dump_bytes("card_cryptogram", card_cryptogram, sizeof(card_cryptogram));

                /* compare with authentication card_cryptogram */
                if(memcmp(&initialize_update_respond[INITIALIZE_UPDATE_RESPOND_OFFSET_CARD_CRYPTOGRAM], card_cryptogram, sizeof(card_cryptogram)) != 0)
                {
                    /* calculate card_cryptogram not match with respond card_cryptogram */
                    scp02_client_dump_bytes("card_cryptogram not match!", NULL, 0);

                    ret = -1;

                    thiz->secure_channel_state = CHANNEL_STATE_DEFAULT;

                    /* send channel established failed event */
                    eventflag_signal(&thiz->channel_event_flag, EVENT_FLAG_CHANNEL_FAILED);

                    break;
                }

                /* calculate authentication host_cryptogram */
                scp02_client_calculate_authentication_cryptogram((unsigned char *)&thiz->channel_info.enc_session_key, \
                    (unsigned char *)&thiz->channel_info.host_challenge, \
                    (unsigned char *)&thiz->channel_info.sequence_counter, \
                    (unsigned char *)&thiz->channel_info.card_challenge, \
                    host_cryptogram, 1);

                scp02_client_dump_bytes("host_cryptogram", host_cryptogram, sizeof(host_cryptogram));

                /* calculate icv1 */
                memset(icv, 0, sizeof(icv));
                memcpy(&external_authenticate_request[ISO7816_OFFSET_CDATA], host_cryptogram, sizeof(host_cryptogram));
                external_authenticate_request[ISO7816_OFFSET_CDATA+sizeof(host_cryptogram)] = 0x80;
                scp02_client_calculate_des_enc_cbc((unsigned char *)&thiz->channel_info.cmac_session_key, \
                    icv, external_authenticate_request, sizeof(icv1), icv1, &output_len);

                /* initialize all iv */
                scp02_client_initialize_all_iv(thiz, icv1, sizeof(icv1));

                /* calculate mac */
                scp02_client_calculate_3des_enc_cbc((unsigned char *)&thiz->channel_info.cmac_session_key, \
                    icv1, &external_authenticate_request[8], sizeof(mac), mac, &output_len);

                scp02_client_dump_bytes("mac", mac, sizeof(mac));

                /* splice external authenticate data */
                memcpy(&external_authenticate_request[ISO7816_OFFSET_CDATA+8], mac, sizeof(mac));

                scp02_client_dump_bytes("external_authenticate_request request", external_authenticate_request, sizeof(external_authenticate_request));

#ifdef COMPATIBLE_MODE
                thiz->secure_channel_state = CHANNEL_STATE_WAIT_EXTERNAL_AUTHENTICATE;

                /* release mutex */
                pthread_mutex_unlock(&thiz->state_mutex);

                /* send external authenticate request */
                if(global_channel)
                {
                    string *external_authenticate_request_str = new string();
                    external_authenticate_request_str->append((const char*)external_authenticate_request, sizeof(external_authenticate_request));
                    pthread_create(&retry_threadid, NULL, (void*(*)(void*))scp02_client_external_authenticate_request, external_authenticate_request_str);
                }
#else
                /* send external authenticate request */
                if(global_channel)
                {
                    bool sendret = global_channel->ClientSend(external_authenticate_request, sizeof(external_authenticate_request));
                    if(!sendret)
                    {
                        thiz->secure_channel_state = CHANNEL_STATE_DEFAULT;
						ret = -1;

                        /* send channel established failed event */
                        eventflag_signal(&thiz->channel_event_flag, EVENT_FLAG_CHANNEL_FAILED);

                        break;
                    }
                    thiz->secure_channel_state = CHANNEL_STATE_WAIT_EXTERNAL_AUTHENTICATE;
                }
#endif
            }
            while(0);
        }
        break;

        /* EXTERNAL AUTHENTICATE Response */
        case CHANNEL_STATE_WAIT_EXTERNAL_AUTHENTICATE:
        {
            do
            {
                /* SW12: 0x90, 0x00 mean:No Error */
                if((len != SW12_LEN) || (*buf != 0x90) || (*(buf+1) != 0x00))
                {
                    scp02_client_dump_bytes("EXTERNAL_AUTHENTICATE process error!", NULL, 0);
                    ret = -1;

                    thiz->secure_channel_state = CHANNEL_STATE_DEFAULT;

                    /* send channel established failed event */
                    eventflag_signal(&thiz->channel_event_flag, EVENT_FLAG_CHANNEL_FAILED);

                    break;
                }

                scp02_client_dump_bytes("security channel establish success!", NULL, 0);

                thiz->secure_channel_state = CHANNEL_STATE_ESTABLISHED;

                /* send channel established success event */
                eventflag_signal(&thiz->channel_event_flag, EVENT_FLAG_CHANNEL_ESTABLISHED);
            }
            while(0);
        }
        break;

        /* security channel has already established */
        case CHANNEL_STATE_ESTABLISHED:
        {
            /* decrypt data */
            ret = scp02_client_unwrap_message(thiz, &msg_id, buf, len);
            if(ret < 0)
            {
                thiz->secure_channel_state = CHANNEL_STATE_DEFAULT;
                scp02_client_dump_bytes("scp02_client_unwrap_message fail1!", NULL, 0);
                /* create a thread to establish secure channel */
                pthread_create(&retry_threadid, NULL, (void*(*)(void*))scp02_client_retry_establish_secure_channel, &msg_id);
            }
        }
        break;

        default:
        {
            scp02_client_dump_bytes("rt_scp02_client_process_secure_channel_message state unkown!", NULL, 0);
        }
        break;
    }

    pthread_mutex_unlock(&thiz->state_mutex);
    //pthread_mutex_unlock(&global_recv_mutex);

    return ret;
}

/******************************************************************************
 * 函数名 scp02_client_start_establish_secure_channel
 *
 * 功能描述: 发起建立安全通道请求
 *
 * 参数说明: 
 * thiz(in): rt_scp02_client_t结构指针
 *
 * 返回值: 返回值>=0:发起成功, -1:发起失败.
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static int scp02_client_start_establish_secure_channel(rt_scp02_client_t *thiz)
{
    /* 
     * APDU Header
     * 0x80: Proprietary command 
     * 0x50: INITIALIZE UPDATE
     * 0x00: P1
     * 0x00: P2
     */
    unsigned char initialize_update[ISO7816_OFFSET_CDATA+HOST_CHALLENGE_LEN] = {0x80, 0x50, 0x00, 0x01, 0x08, \
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int i, ret = 1;

    if(thiz == NULL)
    {
        return -1;
    }

    /* INITIALIZE UPDATE Request */
    {
        /* generate host challenge */
        srand(time(NULL));
        for(i=0;i<HOST_CHALLENGE_LEN;i++)
        {
            initialize_update[ISO7816_OFFSET_CDATA+i] = (rand()&0xFF);
        }

        /* save host challenge */
        memcpy((unsigned char *)&thiz->channel_info.host_challenge, \
            &initialize_update[ISO7816_OFFSET_CDATA], \
            HOST_CHALLENGE_LEN);

        scp02_client_dump_bytes("initialize_update request", initialize_update, sizeof(initialize_update));

#ifdef COMPATIBLE_MODE
        thiz->secure_channel_state = CHANNEL_STATE_WAIT_INITIALIZE_UPDATE;

        /* release mutex */
        pthread_mutex_unlock(&thiz->state_mutex);

        /* send initialize update request */
        if(global_channel)
        {
            scp02_client_dump_bytes("initialize_update start.", NULL, 0);
            bool sendret = global_channel->ClientSend(initialize_update, sizeof(initialize_update));
            scp02_client_dump_bytes("initialize_update completed.", NULL, 0);
            if(!sendret)
            {
            	ret = -1;
				thiz->secure_channel_state = CHANNEL_STATE_DEFAULT;
                scp02_client_dump_bytes("initialize_update send ret = ", &ret, sizeof(ret));
                return ret;
            }
        }
#else
        /* send initialize update request */
        if(global_channel)
        {
            bool sendret = global_channel->ClientSend(initialize_update, sizeof(initialize_update));
            if(!sendret)
            {
            	ret = -1;
				thiz->secure_channel_state = CHANNEL_STATE_DEFAULT;
                return ret;
            }
            thiz->secure_channel_state = CHANNEL_STATE_WAIT_INITIALIZE_UPDATE;
        }
#endif
    }

    return ret;
}

/******************************************************************************
 * 函数名 scp02_client_wrap_message
 *
 * 功能描述: 打包消息
 *
 * 参数说明: 
 * thiz(in): rt_scp02_client_t结构指针
 * buf(in): 输入缓冲区
 * len(in): 输入缓冲区长度
 *
 * 返回值: 返回值>=0:打包成功, -1:打包失败.
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static int scp02_client_wrap_message(rt_scp02_client_t *thiz, int msg_id, unsigned char *buf, int len)
{
    int ret = 1;

    int output_len;

    int data_len, plaintext_len, ciphertext_len, padding_size = 0, apdu_header_size;
    unsigned char *plaintext_data = NULL, *ciphertext_data = NULL;

    unsigned char icv[16] = {0};
    unsigned char padding_desc[CRYPT_ALIGNED] = {0};

    do
    {
        if(NULL == thiz)
        {
            scp02_client_dump_bytes("wrap_message:thiz is null !!", NULL, 0);
            ret = -1;
            break;
        }

        if(0 != (len%CRYPT_ALIGNED))
        {
            /* padding 1 ~ (1-CRYPT_ALIGNED) bytes */
            padding_size = CRYPT_ALIGNED - (len%CRYPT_ALIGNED);
        }

        plaintext_len = len + padding_size + CRYPT_ALIGNED + SHA2_HMAC_RESULT_LEN;
        plaintext_data = (unsigned char *)malloc(plaintext_len);
        if(plaintext_data == NULL)
        {
            scp02_client_dump_bytes("wrap_message:malloc plaintext_data failed !!", NULL, 0);
            ret = -1;
            break;
        }
        memset(plaintext_data, 0, plaintext_len);
        memcpy(plaintext_data, buf, len);
        if(0 != padding_size)
        {
            /* set padding flag */
            *(plaintext_data+len) = 0x80;
        }
        padding_desc[CRYPT_ALIGNED-1] = padding_size;
        memcpy(plaintext_data+(plaintext_len-SHA2_HMAC_RESULT_LEN-CRYPT_ALIGNED), padding_desc, sizeof(padding_desc));

        /* compute hash */
        //tiny_sha2(plaintext_data, plaintext_len-SHA2_HMAC_RESULT_LEN, plaintext_data+(plaintext_len-SHA2_HMAC_RESULT_LEN), 0);
        //tiny_sha2_hmac((unsigned char *)&thiz->channel_info.cmac_session_key, \
            //SESSION_KEY_LEN, plaintext_data, plaintext_len-SHA2_HMAC_RESULT_LEN, plaintext_data+(plaintext_len-SHA2_HMAC_RESULT_LEN), 0);
        tiny_sm3(plaintext_data, plaintext_len-SHA2_HMAC_RESULT_LEN, plaintext_data+(plaintext_len-SHA2_HMAC_RESULT_LEN));

        data_len = MSG_ID_LEN + plaintext_len;

        /* determine use extern length or not */
        if(data_len <= 0xFF)
        {
            apdu_header_size = ISO7816_OFFSET_CDATA;
        }
        else
        {
            apdu_header_size = IS07816_OFFSET_EXT_CDATA;
        }

        ciphertext_len = apdu_header_size + data_len;
        ciphertext_data = (unsigned char *)malloc(ciphertext_len);
        if(ciphertext_data == NULL)
        {
            scp02_client_dump_bytes("wrap_message:malloc ciphertext_data failed !!", NULL, 0);
            ret = -1;
            break;
        }
        memset(ciphertext_data, 0, ciphertext_len);

        /* compute 3des enc cbc */
        memcpy(icv, (unsigned char *)&thiz->channel_info.c_enc_iv, GLOBAL_IV_LEN);
        scp02_client_calculate_sm4_enc_cbc((unsigned char *)&thiz->channel_info.enc_session_key, \
            icv, plaintext_data, plaintext_len, ciphertext_data+apdu_header_size+MSG_ID_LEN, &output_len);

        /* 
         * APDU Header
         * 0x84: Proprietary command with secure messaging
         * 0xE2: STORE DATA
         * 0x00: P1
         * 0x00: P2
         */
        /* 84 E2 00 00 xx data */
        *(ciphertext_data+ISO7816_OFFSET_CLA) = 0x84;
        *(ciphertext_data+ISO7816_OFFSET_INS) = 0xE2;

        if(data_len <= 0xFF)
        {
            *(ciphertext_data+apdu_header_size-1) = MSG_ID_LEN + output_len;
        }
        else
        {
            *(ciphertext_data+apdu_header_size-2) = ((MSG_ID_LEN+output_len)>>8)&0xFF;
            *(ciphertext_data+apdu_header_size-1) = (MSG_ID_LEN+output_len)&0xFF;
        }

        /* fill msg id */
        *(ciphertext_data+apdu_header_size) = (msg_id>>8)&0xFF;
        *(ciphertext_data+apdu_header_size+1) = msg_id&0xFF;

        /* update iv */
        scp02_client_increase_iv((unsigned char *)&thiz->channel_info.c_enc_iv);

#ifdef COMPATIBLE_MODE
        /* release mutex */
        pthread_mutex_unlock(&thiz->state_mutex);
#endif
        /* send data */
        if(global_channel)
        {
            bool sendret = global_channel->ClientSend(ciphertext_data, ciphertext_len);
			if(!sendret){
				ret = -1;
			}			
        }
    }
    while(0);

    if(NULL != plaintext_data)
    {
        free(plaintext_data);
        plaintext_data = NULL;
    }

    if(NULL != ciphertext_data)
    {
        free(ciphertext_data);
        ciphertext_data = NULL;
    }

    return ret;
}

static void* scp02_client_external_authenticate_request(string *str)
{
    scp02_client_dump_bytes("external_authenticate_request start.", NULL, 0);
    global_channel->ClientSend((unsigned char *)str->data(), str->size());
    scp02_client_dump_bytes("external_authenticate_request completed.", NULL, 0);

    delete str;

    return NULL;
}

static void* scp02_client_retry_establish_secure_channel(int *pMsgId)
{
    int ret = 0;
//    unsigned long recv = 0;
    eventmask_t channel_event;

    struct timespec tm;
    int mseconds = 5000;/* timeout 5s */

    rt_scp02_client_t *thiz = &global_thiz;

    int msgId = *(pMsgId);
    string save;

	scp02_client_dump_bytes("scp02_client_retry_establish_secure_channel IN", NULL, 0);

    /* take mutex */
    pthread_mutex_lock(&global_send_mutex);
    pthread_mutex_lock(&thiz->state_mutex);

    do
    {
        if(thiz->secure_channel_state == CHANNEL_STATE_DEFAULT)
        {
            ret = scp02_client_start_establish_secure_channel(thiz);
            if(ret < 0)
            {
                scp02_client_dump_bytes("retry_establish_secure_channel error!", NULL, 0);
                break;
            }
        }
        else
        {
            scp02_client_dump_bytes("cancel retry_establish_secure_channel!", NULL, 0);
			ret = SCP02_CLIENT_CHANNEL_ESTABLISH_FAILED;
            break;
        }
        pthread_mutex_unlock(&thiz->state_mutex);

        /* wait until recv channel event */
        clock_gettime(CLOCK_REALTIME, &tm);

        tm.tv_nsec += (mseconds % 1000) *1000*1000;
        tm.tv_sec += (mseconds / 1000);
        if(tm.tv_nsec >= 1000000000)
        {
            tm.tv_nsec -= 1000000000;
            tm.tv_sec += 1;
        }


		scp02_client_dump_bytes("retry_establish_secure_channel", NULL, 0);
        channel_event = eventflag_timedwait(&thiz->channel_event_flag, &tm);
        if(channel_event & EVENT_FLAG_CHANNEL_ESTABLISHED)
        {
            /* take mutex */
            pthread_mutex_lock(&thiz->state_mutex);
			msgId = scp02_client_increase_msg_id(thiz);

			mutexSaveMap.Lock();
            map<int, string>::iterator it = mapSaveMsg.find(msgId);
            if(it != mapSaveMsg.end())
            {
            	scp02_client_dump_bytes("new222", NULL, 0);
                save = it->second;
                mapSaveMsg.erase(it);

                // send msg id and msg 
                ret = scp02_client_wrap_message(thiz, msgId, (unsigned char *)save.data(), save.size());
				if(ret > 0)
                {
                    /* save msg id and msg */
                    if(ExistMsg(msgId))
                    {
                        DeleteMsg(msgId);
                    }
                    SaveMsg(msgId, save);
                }
            }
            mutexSaveMap.Unlock();


   /*         mutexSaveMap.Lock();
            map<int, string>::iterator it = mapSaveMsg.find(msgId);
            if(it != mapSaveMsg.end())
            {
                save = it->second;
                mapSaveMsg.erase(it);

                // send msg id and msg 
                ret = scp02_client_wrap_message(thiz, msgId, (unsigned char *)save.data(), save.size());
            }
            mutexSaveMap.Unlock();
*/
        }
        else if(channel_event & EVENT_FLAG_CHANNEL_FAILED)
        {
            /* take mutex */
            pthread_mutex_lock(&thiz->state_mutex);

            scp02_client_dump_bytes("security channel establish failed!", NULL, 0);
        }
        else
        {
            /* take mutex */
            pthread_mutex_lock(&thiz->state_mutex);

            thiz->secure_channel_state = CHANNEL_STATE_DEFAULT;

            scp02_client_dump_bytes("security channel establish timeout1!", NULL, 0);
        }
    }while(0);

    /* release mutex */
    pthread_mutex_unlock(&thiz->state_mutex);
    pthread_mutex_unlock(&global_send_mutex);

    return NULL;
}

/******************************************************************************
 * 函数名 rt_scp02_client_init
 *
 * 功能描述: scp02客户端初始化
 *
 * 参数说明: 
 * 输入:无
 *
 * 返回值: 无.
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
void rt_scp02_client_init(void)
{
    rt_scp02_client_t *thiz = &global_thiz;

    scp02_client_dump_bytes("rt_scp02_client_init.", NULL, 0);

    memset(thiz, 0, sizeof(rt_scp02_client_t));

//    scp02_client_dump_bytes("rt_scp02_client_init2.", NULL, 0);

    thiz->secure_channel_state = CHANNEL_STATE_DEFAULT;

//    scp02_client_dump_bytes("rt_scp02_client_init3.", NULL, 0);

    pthread_mutex_init(&thiz->state_mutex, NULL);

//    scp02_client_dump_bytes("rt_scp02_client_init4.", NULL, 0);

    eventflag_init(&thiz->channel_event_flag);
//    scp02_client_dump_bytes("rt_scp02_client_init5.", NULL, 0);
    /* init global mutex */
    pthread_mutex_init(&global_send_mutex, NULL);
//    scp02_client_dump_bytes("rt_scp02_client_init6.", NULL, 0);
    pthread_mutex_init(&global_recv_mutex, NULL);
//    scp02_client_dump_bytes("rt_scp02_client_init7.", NULL, 0);
    global_channel = NULL;
//    scp02_client_dump_bytes("rt_scp02_client_init8.", NULL, 0);
}

/******************************************************************************
 * 函数名 rt_scp02_client_uninit
 *
 * 功能描述: scp02客户端反初始化
 *
 * 参数说明: 
 * 输入:无
 *
 * 返回值: 无.
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
void rt_scp02_client_uninit(void)
{
    rt_scp02_client_t *thiz = &global_thiz;

    scp02_client_dump_bytes("rt_scp02_client_uninit.", NULL, 0);

    memset(thiz, 0, sizeof(rt_scp02_client_t));

    thiz->secure_channel_state = CHANNEL_STATE_DEFAULT;

    global_channel = NULL;
}

/******************************************************************************
 * 函数名 rt_scp02_client_register_channel
 *
 * 功能描述: 注册传输通道
 *
 * 参数说明: 
 * channel(in): 传输通道
 *
 * 返回值: 0:注册成功, 其他:注册失败.
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
int rt_scp02_client_register_channel(CommunicationClient *channel)
{
    rt_scp02_client_t *thiz = &global_thiz;

    if(NULL != channel)
    {
        global_channel = channel;
    }
    else
    {
        return -1;
    }

    return 0;
}

/******************************************************************************
 * 函数名 rt_scp02_client_register_monitor
 *
 * 功能描述: 注册通道监听回调
 *
 * 参数说明: 
 * monitor(in): 通道监听回调
 *
 * 返回值: 无.
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
void rt_scp02_client_register_monitor(scp02_client_channel_monitor_t monitor)
{
    rt_scp02_client_t *thiz = &global_thiz;

    thiz->monitor = monitor;
}

/******************************************************************************
 * 函数名 rt_scp02_client_register_recv
 *
 * 功能描述: 注册用户接收处理回调
 *
 * 参数说明: 
 * user_recv(in): 用户接收处理回调
 *
 * 返回值: 无.
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
void rt_scp02_client_register_recv(scp02_client_user_recv_t user_recv)
{
    rt_scp02_client_t *thiz = &global_thiz;

    thiz->user_recv = user_recv;
}

/******************************************************************************
 * 函数名 rt_scp02_client_send_secure_message
 *
 * 功能描述: 发送安全消息
 *
 * 参数说明: 
 * buf(in): 输入缓冲区
 * len(in): 输入缓冲区长度
 *
 * 返回值: 返回值>=0:发送成功, -2:安全通道建立失败, -3:安全通道建立超时.
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
int rt_scp02_client_send_secure_message(unsigned char *buf,int len)
{
    int ret = len;
    unsigned long recv = 0;
    eventmask_t channel_event;

    struct timespec tm;
    int mseconds = 5000;/* timeout 5s */

    rt_scp02_client_t *thiz = &global_thiz;

    int msg_id = 0;
    string save;

    if(buf == NULL || (len < 0))
    {
        return SCP02_CLIENT_CHANNEL_PARAM_ERROR;
    }

    /* take mutex */
    pthread_mutex_lock(&global_send_mutex);
    pthread_mutex_lock(&thiz->state_mutex);
    do
    {
        if(thiz->secure_channel_state == CHANNEL_STATE_ESTABLISHED)
        {
            /* increase global id */
            msg_id = scp02_client_increase_msg_id(thiz);

            save.append((const char*)buf, len);

            /* send data */
            ret = scp02_client_wrap_message(thiz, msg_id, buf, len);
            if(ret > 0)
            {
                /* save msg id and msg */
                if(ExistMsg(msg_id))
                {
                    DeleteMsg(msg_id);
                }
                SaveMsg(msg_id, save);
            }
        }
        else
        {
            if(thiz->secure_channel_state == CHANNEL_STATE_DEFAULT)
            {
                ret = scp02_client_start_establish_secure_channel(thiz);
                if(ret < 0)
                {
                    scp02_client_dump_bytes("start_establish_secure_channel error!", NULL, 0);
                    break;
                }
            }
            else
            {
                scp02_client_dump_bytes("cancel start_establish_secure_channel!", NULL, 0);
                ret = SCP02_CLIENT_CHANNEL_ESTABLISH_FAILED;
                break;
            }
            pthread_mutex_unlock(&thiz->state_mutex);

            /* wait until recv channel event */
            clock_gettime(CLOCK_REALTIME, &tm);

            tm.tv_nsec += (mseconds % 1000) *1000*1000;
            tm.tv_sec += (mseconds / 1000);
            if(tm.tv_nsec >= 1000000000)
            {
                tm.tv_nsec -= 1000000000;
                tm.tv_sec += 1;
            }

            scp02_client_dump_bytes("eventflag_timedwait!", NULL, 0);
            channel_event = eventflag_timedwait(&thiz->channel_event_flag, &tm);
            scp02_client_dump_bytes("eventflag_timedwait End!", &channel_event, sizeof(channel_event));

            if(channel_event & EVENT_FLAG_CHANNEL_ESTABLISHED)
            {
                /* take mutex */
                pthread_mutex_lock(&thiz->state_mutex);

                /* increase global id */
                msg_id = scp02_client_increase_msg_id(thiz);

                save.append((const char*)buf, len);

                /* send data */
                ret = scp02_client_wrap_message(thiz, msg_id, buf, len);
                if(ret > 0)
                {
                    /* save msg id and msg */
                    if(ExistMsg(msg_id))
                    {
                        DeleteMsg(msg_id);
                    }
                    SaveMsg(msg_id, save);
                }
            }
            else if(channel_event & EVENT_FLAG_CHANNEL_FAILED)
            {
                /* take mutex */
                pthread_mutex_lock(&thiz->state_mutex);

                scp02_client_dump_bytes("security channel establish failed!", NULL, 0);

                ret = SCP02_CLIENT_CHANNEL_ESTABLISH_FAILED;
            }
            else
            {
                /* take mutex */
                pthread_mutex_lock(&thiz->state_mutex);

                thiz->secure_channel_state = CHANNEL_STATE_DEFAULT;

                scp02_client_dump_bytes("security channel establish timeout0!", NULL, 0);

                ret = SCP02_CLIENT_SEND_TIMEOUT;
            }
        }
    }while(0);

    /* release mutex */
    pthread_mutex_unlock(&thiz->state_mutex);
    pthread_mutex_unlock(&global_send_mutex);

    return ret;
}
