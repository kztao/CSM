#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <assert.h>
#include <pthread.h>
//#include <sm/rand/include/mm_math.h>

#include "LocalSocketServer.h"

#include "Scp02Service.h"
#include "tiny_des.h"
#include "tiny_sha2.h"

#include "sm3.h"
#include "sm4.h"
#include "sm4_core.h"

#include "Mutex.h"
#include "RemoteService.h"

#include "RemoteServicePack.h"
#include "Export.h"

using std::string;
using std::make_pair;

static const char *tag = "csm_Scp02Server";

static BroadcastPack *globalPack = new RemoteServicePack();

static map<CommunicationServer::Communication *, Scp02Service *> mapScp02Service;
static map<Scp02Service *, CommunicationServer *> mapCommunicationService;
static Mutex mutexMapScp02Service;
static Mutex mutexGlobalProcess;

static ComLog g_Log = NULL;

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

static void scp02_server_dump_bytes(const char *str, void *buf, int len)
{

    char printf_buf[16*3+1];
    char *pbuf = &printf_buf[0];
    int i, index;

    printlog_scp(C_info,__FUNCTION__,__LINE__, "[scp02server]:%s(%d bytes):", str, len);

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

static void scp02_server_calculate_sm4_enc_ecb(unsigned char key[16], \
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

static void scp02_server_calculate_sm4_enc_cbc(unsigned char key[16], \
    unsigned char iv[16], \
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

static void scp02_server_calculate_sm4_dec_cbc(unsigned char key[16], \
    unsigned char iv[16], \
    unsigned char *input, \
    int input_len, \
    unsigned char *output, \
    int *output_len)
{
    /*sm4_context ctx_sm4;

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
    /*SM3_CTX ctx_sm3;

    SM3_Init(&ctx_sm3);
    SM3Update(&ctx_sm3, input, ilen);
    SM3Final(output, &ctx_sm3, 32);*/

    mm_handle h = NULL;
    h = sm3_init();
    sm3_process(h,input,ilen);
    sm3_unit(h,output);

}

static void scp02_server_calculate_des_enc_cbc(unsigned char key[8], \
    unsigned char iv[8], \
    unsigned char *input, \
    int input_len, \
    unsigned char *output, \
    int *output_len, \
    int flag)
{
    des_context ctx;

    /* padding data */
    if(1 == flag)
    {

    }
    else
    {
        /* set des key*/
        des_setkey_enc(&ctx, key);

        /* compute input data */
        des_crypt_cbc(&ctx, DES_ENCRYPT, input_len, iv, input, output);

        *output_len = input_len;
    }
}

static void scp02_server_calculate_3des_enc_ecb(unsigned char key[16], \
    unsigned char *input, \
    int input_len, \
    unsigned char *output, \
    int *output_len)
{
    des3_context ctx3;

    int offset = 0;

    {
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
}

static void scp02_server_calculate_3des_enc_cbc(unsigned char key[16], \
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

static void scp02_server_calculate_3des_dec_cbc(unsigned char key[16], \
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

static void scp02_server_generate_session_key(unsigned char key[STATIC_KEY_LEN], \
    unsigned char constant[2], unsigned char sequence_counter[2], unsigned char sesseion_key[SESSION_KEY_LEN])
{
    unsigned char derivation_data[SESSION_KEY_LEN] = {0};
    unsigned char icv[16] = {0};
    int output_len;

    memset(derivation_data, 0, SESSION_KEY_LEN);
    memcpy(derivation_data, constant, 2);
    memcpy(derivation_data+2, sequence_counter, 2);

    scp02_server_calculate_3des_enc_cbc(key, icv, derivation_data, SESSION_KEY_LEN, \
        sesseion_key, &output_len);
}

static void scp02_server_generate_all_session_key00(rt_scp02_server_t *thiz, unsigned char diversification_data[10])
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

    /* load diversification_data */
    /* load default static master key and generate static mac key */
    /* generate c-mac session key */
    pstatic_key = (unsigned char *)&thiz->channel_info.s_mac_key;
    psession_key = (unsigned char *)&thiz->channel_info.cmac_session_key;
    memcpy(&macPlainText[0], &diversification_data[4], 6);
    memcpy(&macPlainText[8], &diversification_data[4], 6);
    scp02_server_calculate_sm4_enc_ecb(default_s_master_key, \
        &macPlainText[0], \
        STATIC_KEY_LEN, 
        pstatic_key, \
        &output_len);
    scp02_server_generate_session_key((unsigned char *)pstatic_key, \
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
    scp02_server_calculate_sm4_enc_ecb(default_s_master_key, \
        &encPlainText[0], \
        STATIC_KEY_LEN, 
        pstatic_key, \
        &output_len);
    scp02_server_generate_session_key((unsigned char *)pstatic_key, \
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
    scp02_server_calculate_sm4_enc_ecb(default_s_master_key, \
        &dekPlainText[0], \
        STATIC_KEY_LEN, 
        pstatic_key, \
        &output_len);
    scp02_server_generate_session_key((unsigned char *)pstatic_key, \
        &constant_data[3][0], \
        (unsigned char *)&thiz->channel_info.sequence_counter, \
        (unsigned char *)psession_key);

    /* r-mac session key */
    pstatic_key = (unsigned char *)&thiz->channel_info.s_mac_key;
    psession_key = (unsigned char *)&thiz->channel_info.rmac_session_key;
    scp02_server_generate_session_key((unsigned char *)pstatic_key, \
        &constant_data[0][0], \
        (unsigned char *)&thiz->channel_info.sequence_counter, \
        (unsigned char *)psession_key);
}

static void scp02_server_initialize_all_iv(rt_scp02_server_t *thiz, unsigned char *piv, int iv_len)
{
    unsigned char *p_iv = NULL;

    int i;

    if(NULL == thiz)
    {
        scp02_server_dump_bytes("initialize_all_iv:thiz is null !!", NULL, 0);
        return;
    }

    p_iv = (unsigned char *)&thiz->channel_info.c_dec_iv;
    memcpy((unsigned char *)p_iv, piv, iv_len);

    p_iv = (unsigned char *)&thiz->channel_info.r_enc_iv;
    memcpy((unsigned char *)p_iv, piv, iv_len);
}

static void scp02_server_increase_iv(unsigned char iv[GLOBAL_IV_LEN])
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

    //scp02_server_dump_bytes("increase_iv", iv, GLOBAL_IV_LEN);
}

static void scp02_server_calculate_authentication_cryptogram(unsigned char key[16], \
    unsigned char host_challenge[8], \
    unsigned char sequence_counter[2], \
    unsigned char card_challenge[6], \
    unsigned char authentication_cryptogram[8], \
    int card_or_host)
{
    unsigned char calculate_buffer_input[24];
    unsigned char calculate_buffer_output[24];
    unsigned char icv[8];
    int output_len;

    memset(calculate_buffer_input, 0, sizeof(calculate_buffer_input));
    memset(icv, 0, sizeof(icv));
    /* calculate authentication card_cryptogram */
    if(card_or_host == 0)
    {
        memcpy(&calculate_buffer_input[0], host_challenge, 8);
        memcpy(&calculate_buffer_input[8], sequence_counter, 2);
        memcpy(&calculate_buffer_input[10], card_challenge, 6);
        calculate_buffer_input[8+2+6] = 0x80;
    }
    else
    {
        memcpy(&calculate_buffer_input[0], sequence_counter, 2);
        memcpy(&calculate_buffer_input[2], card_challenge, 6);
        memcpy(&calculate_buffer_input[8], host_challenge, 8);
        calculate_buffer_input[2+6+8] = 0x80;
    }

    scp02_server_calculate_3des_enc_cbc(key, \
        icv, calculate_buffer_input, sizeof(calculate_buffer_input), \
        calculate_buffer_output, &output_len);
    memcpy(authentication_cryptogram, &calculate_buffer_output[output_len-8], 8);
}

/* INITIALIZE UPDATE Request */
static int scp02_server_initialize_update(CommunicationServer::Communication *pClient, rt_scp02_server_t *thiz, unsigned char *buf, int len)
{
    int i, dataLen, ret = 0, res;
    unsigned char *data = NULL;

    unsigned char card_cryptogram[8];

    unsigned char initialize_update_respond[28+2] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
        0x00, 0x00, \
        0x00, 0x00, \
        0x8B, 0x32, 0x0E, 0xC6, 0x0E, 0x9B, \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
        0x00, 0x00};

    unsigned char diversification_data[10] = {0};

    unsigned char sw12_error[2] = {0x6a, 0x88};

    /* memset channel info structure */
    memset((unsigned char *)&thiz->channel_info, 0, sizeof(scp02_server_secure_channel_info_t));

    dataLen = (unsigned char)buf[4];
    if(dataLen < 0)
    {
        scp02_server_dump_bytes("initialize_update:dataLen < 0 !!", NULL, 0);
        ret = -1;
        goto out;
    }

    data = (unsigned char *)malloc(dataLen);
    if(data == NULL)
    {
        scp02_server_dump_bytes("initialize_update:malloc data failed !!", NULL, 0);
        ret = -1;
        goto out;
    }
    memset(data, 0, dataLen);
    memcpy(data, buf+5, dataLen);

    /* save key version */
    memcpy((unsigned char *)&thiz->channel_info.key_version, \
        buf+2, \
        sizeof(((scp02_server_secure_channel_info_t *)0)->key_version));

    if(sizeof(((scp02_server_secure_channel_info_t *)0)->host_challenge) == dataLen)
    {
        /* save host challenge */
        memcpy((unsigned char *)&thiz->channel_info.host_challenge, data, dataLen);
    }
    else
    {
        scp02_server_dump_bytes("initialize_update:dataLen != 8 !!", NULL, 0);
        ret = -1;
        goto out;
    }

    /* generate card_challenge */
    srand(time(NULL));
    for(i=0;i<(sizeof(((scp02_server_secure_channel_info_t *)0)->card_challenge));i++)
    {
        initialize_update_respond[14+i] = (rand()%0x100);
    }

    /* save card_challenge */
    memcpy((unsigned char *)&thiz->channel_info.card_challenge, \
        &initialize_update_respond[14], \
        sizeof(((scp02_server_secure_channel_info_t *)0)->card_challenge));

    /* generate sequence_counter */

    /* save sequence_counter */
    *(((unsigned char *)&thiz->channel_info.sequence_counter)+0) = (rand()%0x100);
    *(((unsigned char *)&thiz->channel_info.sequence_counter)+1) = (rand()%0x100);

    switch((thiz->channel_info.key_version[1] & 0xFF))
    {
        case 0x01:
        {
            /* get diversification data */
            if(thiz->get_diversification_data)
            {
                thiz->get_diversification_data(diversification_data);
            }
            else
            {
                for(i=0;i<sizeof(diversification_data);i++)
                {
                    diversification_data[i] = (rand()%0x100);
                }
            }

            /* generate all session key */
            scp02_server_generate_all_session_key00(thiz, diversification_data);

            /* calculate authentication card_cryptogram */
            scp02_server_calculate_authentication_cryptogram((unsigned char *)&thiz->channel_info.enc_session_key, \
                (unsigned char *)&thiz->channel_info.host_challenge, \
                (unsigned char *)&thiz->channel_info.sequence_counter, \
                (unsigned char *)&thiz->channel_info.card_challenge, \
                card_cryptogram, 0);
        }
        break;

        default:
        {
            /* not support */
            scp02_server_dump_bytes("key version not support!", NULL, 0);

            ret = -1;
        }
    }

out:
    if(NULL != data)
    {
        free(data);
        data = NULL;
    }

    /* INITIALIZE UPDATE Response */
    if(0 != ret)
    {
        scp02_server_dump_bytes("initialize_update_respond", sw12_error, sizeof(sw12_error));

        res = pClient->Send(sw12_error, sizeof(sw12_error));
    }
    else
    {
        /* fill key diversification data*/
        memcpy(initialize_update_respond, diversification_data, sizeof(diversification_data));

        /* fill key information */
        memcpy(&initialize_update_respond[10], \
            (unsigned char *)&thiz->channel_info.key_version, \
            sizeof(((scp02_server_secure_channel_info_t *)0)->key_version));

        /* fill sequence counter */
        memcpy(&initialize_update_respond[12], \
            (unsigned char *)&thiz->channel_info.sequence_counter, \
            sizeof(((scp02_server_secure_channel_info_t *)0)->sequence_counter));

        /* fill card challenge */
        memcpy(&initialize_update_respond[14], \
            (unsigned char *)&thiz->channel_info.card_challenge, \
            sizeof(((scp02_server_secure_channel_info_t *)0)->card_challenge));

        /* fill authentication card_cryptogram */
        memcpy(&initialize_update_respond[20], card_cryptogram, sizeof(card_cryptogram));

        /* fill sw1 sw2 */
        initialize_update_respond[28] = 0x90;
        initialize_update_respond[29] = 0x00;

        scp02_server_dump_bytes("initialize_update_respond", initialize_update_respond, sizeof(initialize_update_respond));

        res = pClient->Send(initialize_update_respond, sizeof(initialize_update_respond));
    }

    if(res < 0)
    {
    	scp02_server_dump_bytes("initialupdate send fail! res", &res, sizeof(res));
        ret = -1;
    }

    return ret;
}

static int scp02_server_external_authenticate(CommunicationServer::Communication *pClient, rt_scp02_server_t *thiz, unsigned char *buf, int len)
{
    int dataLen, output_len, ret = 0, res;
    unsigned char *data = NULL;

    unsigned char recv_host_cryptogram[8];
    unsigned char calc_host_cryptogram[8];

    unsigned char icv[8];
    unsigned char icv1[8];
    unsigned char recv_mac[8];
    unsigned char calc_mac[8];

    unsigned char external_authenticate_request[5+16] = {
        0x84, 0x82, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    unsigned char sw12_ok[2] = {0x90, 0x00};
    unsigned char sw12_error[2] = {0x63, 0x00};

    dataLen = (unsigned char)buf[4];
    if(dataLen < 0)
    {
        scp02_server_dump_bytes("external_authenticate:dataLen < 0 !!", NULL, 0);
        ret = -1;
        goto out;
    }

    data = (unsigned char *)malloc(dataLen);
    if(data == NULL)
    {
        scp02_server_dump_bytes("external_authenticate:malloc data failed !!", NULL, 0);
        ret = -1;
        goto out;
    }
    memset(data, 0, dataLen);
    memcpy(data, buf+5, dataLen);

    if(0x10 == dataLen)
    {
        memcpy(recv_host_cryptogram, data, sizeof(recv_host_cryptogram));
        memcpy(recv_mac, data+sizeof(recv_host_cryptogram), sizeof(recv_mac));
    }
    else
    {
        scp02_server_dump_bytes("external_authenticate:dataLen != 0x10 !!", NULL, 0);
        ret = -1;
        goto out;
    }

    /* calculate authentication host_cryptogram */
    scp02_server_calculate_authentication_cryptogram((unsigned char *)&thiz->channel_info.enc_session_key, \
        (unsigned char *)&thiz->channel_info.host_challenge, \
        (unsigned char *)&thiz->channel_info.sequence_counter, \
        (unsigned char *)&thiz->channel_info.card_challenge, \
        calc_host_cryptogram, 1);

    scp02_server_dump_bytes("host_cryptogram", calc_host_cryptogram, sizeof(calc_host_cryptogram));

    /* compare with authentication host_cryptogram */
    if(memcmp(recv_host_cryptogram, calc_host_cryptogram, sizeof(calc_host_cryptogram)) != 0)
    {
        /* calculate host_cryptogram not match with respond host_cryptogram */
        scp02_server_dump_bytes("external_authenticate:host_cryptogram not match!", NULL, 0);
        ret = -1;
        goto out;
    }

    /* calculate icv1 */
    memset(icv, 0, sizeof(icv));
    memcpy(&external_authenticate_request[5], recv_host_cryptogram, sizeof(recv_host_cryptogram));
    external_authenticate_request[5+sizeof(recv_host_cryptogram)] = 0x80;
    scp02_server_calculate_des_enc_cbc((unsigned char *)&thiz->channel_info.cmac_session_key, \
        icv, external_authenticate_request, sizeof(icv1), icv1, &output_len, 0);

    /* initialize all iv */
    scp02_server_initialize_all_iv(thiz, icv1, sizeof(icv1));

    /* calculate mac */
    scp02_server_calculate_3des_enc_cbc((unsigned char *)&thiz->channel_info.cmac_session_key, \
        icv1, &external_authenticate_request[output_len], sizeof(calc_mac), calc_mac, &output_len);

    scp02_server_dump_bytes("mac", calc_mac, sizeof(calc_mac));

    /* compare with mac */
    if(memcmp(recv_mac, calc_mac, sizeof(calc_mac)) != 0)
    {
        /* calculate mac not match with respond mac */
        scp02_server_dump_bytes("external_authenticate:mac not match!", NULL, 0);
        ret = -1;
        goto out;
    }

    scp02_server_dump_bytes("security channel establish success!", NULL, 0);

out:
    if(NULL != data)
    {
        free(data);
        data = NULL;
    }

    /* EXTERNAL AUTHENTICATE Response */
    if(0 != ret)
    {
        scp02_server_dump_bytes("external_authenticate_response", sw12_error, sizeof(sw12_error));

        res = pClient->Send(sw12_error, sizeof(sw12_error));
    }
    else
    {
        scp02_server_dump_bytes("external_authenticate_response", sw12_ok, sizeof(sw12_ok));

        res = pClient->Send(sw12_ok, sizeof(sw12_ok));
    }

    if(res < 0)
    {
        ret = -1;
    }

    return ret;
}

static int global_msg_id = 0;

static int scp02_server_unwrap_message(CommunicationServer *pServer, CommunicationServer::Communication *pClient, rt_scp02_server_t *thiz, int *pmsg_id, unsigned char *buf, int len)
{
    int dataLen, output_len, ret = 0;
    unsigned char *data = NULL;

    unsigned char icv[GLOBAL_IV_LEN] = {0};
    unsigned char calc_sha2[32];

    int padding_size = 0, apdu_header_size;
	
	scp02_server_dump_bytes("scp02_server_unwrap_message IN", NULL, 0);
    dataLen = (unsigned char)buf[4];
    if(dataLen < 0)
    {
        scp02_server_dump_bytes("unwrap_message:dataLen < 0 !!", NULL, 0);
        ret = -1;
        goto out;
    }
    else if(dataLen == 0)
    {
        /* use extern length */
        dataLen = ((unsigned char)buf[5] << 8) + (unsigned char)buf[6];
        apdu_header_size = 7;
    }
    else
    {
        apdu_header_size = 5;
    }

    if(len != (apdu_header_size+dataLen))
    {
        scp02_server_dump_bytes("unwrap_message:((apdu_header_size+dataLen) != len) !!", NULL, 0);
        ret = -1;
        goto out;
    }

    /* get msg id */
    global_msg_id = (*(buf+apdu_header_size) * 0x100)+ *(buf+apdu_header_size+1);
    *pmsg_id = global_msg_id;

    /* update dataLen */
    dataLen -= 2;

    data = (unsigned char *)malloc(dataLen);
    if(data == NULL)
    {
        scp02_server_dump_bytes("unwrap_message:malloc data failed !!", NULL, 0);
        ret = -1;
        goto out;
    }
    memset(data, 0, dataLen);

    /* compute 3des dec cbc */
    memcpy(icv, (unsigned char *)&thiz->channel_info.c_dec_iv, GLOBAL_IV_LEN);
    scp02_server_calculate_sm4_dec_cbc((unsigned char *)&thiz->channel_info.enc_session_key, \
        icv, buf+apdu_header_size+2, dataLen, data, &output_len);

    /* compute sha2 and compare it */
    //tiny_sha2(data, output_len-32, calc_sha2, 0);
    //tiny_sha2_hmac((unsigned char *)&thiz->channel_info.cmac_session_key, \
        //SESSION_KEY_LEN, data, output_len-32, calc_sha2, 0);
    tiny_sm3(data, output_len-32, calc_sha2);

    if(memcmp(data+(output_len-32), calc_sha2, sizeof(calc_sha2)) != 0)
    {
        scp02_server_dump_bytes("unwrap_message:calc_sha2 not match !!", NULL, 0);
        ret = -1;
        goto out;
    }

    /* get padding_desc and get plaintext */
    padding_size = *(data+(output_len-32)-1);

    /* update iv */
    scp02_server_increase_iv((unsigned char *)&thiz->channel_info.c_dec_iv);

    /* notify user recv function */
    if(thiz->rx)
    {
        thiz->rx(pServer, pClient, data, output_len-32-CRYPT_ALIGNED-padding_size);
    }

out:
    if(NULL != data)
    {
        free(data);
        data = NULL;
    }

    return ret;
}

static int scp02_server_wrap_message(CommunicationServer::Communication *pClient, rt_scp02_server_t *thiz, int msg_id, unsigned char *buf, int len)
{
    int res, ret = 0;

    int outLen;

    int plaintext_len, ciphertext_len, padding_size = 0;
    unsigned char *plaintext_data = NULL, *ciphertext_data = NULL;

    unsigned char icv[GLOBAL_IV_LEN] = {0};
    unsigned char padding_desc[CRYPT_ALIGNED] = {0};

    if(0 != (len%CRYPT_ALIGNED))
    {
        /* padding 1 ~ (1-CRYPT_ALIGNED) bytes */
        padding_size = CRYPT_ALIGNED - (len%CRYPT_ALIGNED);
    }

    plaintext_len = len + padding_size + CRYPT_ALIGNED + 32;
    plaintext_data = (unsigned char *)malloc(plaintext_len);
    if(plaintext_data == NULL)
    {
        scp02_server_dump_bytes("wrap_message:malloc plaintext_data failed !!", NULL, 0);
        ret = -1;
        goto out;
    }
    memset(plaintext_data, 0, plaintext_len);
    memcpy(plaintext_data, buf, len);
    if(0 != padding_size)
    {
        /* set padding flag */
        *(plaintext_data+len) = 0x80;
    }
    padding_desc[CRYPT_ALIGNED-1] = padding_size;
    memcpy(plaintext_data+(plaintext_len-32-CRYPT_ALIGNED), padding_desc, sizeof(padding_desc));

    /* compute hash */
    //tiny_sha2(plaintext_data, plaintext_len-32, plaintext_data+(plaintext_len-32), 0);
    //tiny_sha2_hmac((unsigned char *)&thiz->channel_info.rmac_session_key, \
        //SESSION_KEY_LEN, plaintext_data, plaintext_len-32, plaintext_data+(plaintext_len-32), 0);
    tiny_sm3(plaintext_data, plaintext_len-32, plaintext_data+(plaintext_len-32));

    ciphertext_len = plaintext_len + 2 + 2;
    ciphertext_data = (unsigned char *)malloc(ciphertext_len);
    if(ciphertext_data == NULL)
    {
        scp02_server_dump_bytes("wrap_message:malloc ciphertext_data failed !!", NULL, 0);
        ret = -1;
        goto out;
    }
    memset(ciphertext_data, 0, ciphertext_len);

    /* compute 3des enc cbc */
    memcpy(icv, (unsigned char *)&thiz->channel_info.r_enc_iv, GLOBAL_IV_LEN);
    scp02_server_calculate_sm4_enc_cbc((unsigned char *)&thiz->channel_info.enc_session_key, \
        icv, plaintext_data, plaintext_len, ciphertext_data, &outLen);

    /* fill msg id */
    *(ciphertext_data+plaintext_len) = (msg_id >> 8) & 0xFF;
    *(ciphertext_data+plaintext_len+1) = msg_id & 0xFF;


    /* data msg id sw1 sw2 */
    *(ciphertext_data+plaintext_len+2) = 0x90;

    /* update iv */
    scp02_server_increase_iv((unsigned char *)&thiz->channel_info.r_enc_iv);

    /* send data */
	scp02_server_dump_bytes("wrap_message:send begin !!", NULL, 0);
    res = pClient->Send(ciphertext_data, ciphertext_len);
	scp02_server_dump_bytes("wrap_message:send end !!", NULL, 0);
    if(res < 0)
    {
        ret = -1;
    }
    else
    {
        ret = len;
    }

out:

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

	scp02_server_dump_bytes("scp02_server_wrap_message out", NULL, 0);
    return ret;
}

static unsigned char global_imei[10] = {0x00};

int get_diversification_data(unsigned char diversification_data[10])
{
    memcpy(&diversification_data[0], &global_imei[0], sizeof(global_imei));

    return 0;
}

Scp02Service::Scp02Service()
{
    rt_scp02_server_t *thiz = &pri_thiz;

    memset(thiz, 0, sizeof(rt_scp02_server_t));

    thiz->secure_channel_state = -1;
}

Scp02Service::~Scp02Service()
{

}

int Scp02Service::process_secure_channel_message(CommunicationServer *pServer, CommunicationServer::Communication *pClient, unsigned char *buf, int len)
{
    int ret = 0;
 //   g_Log = pClient->getlogfunc();
    Scp02Service *pScp02Service = NULL;

    mutexGlobalProcess.Lock();

    mutexMapScp02Service.Lock();
    map<CommunicationServer::Communication *, Scp02Service *>::iterator it = mapScp02Service.find(pClient);
    if(it != mapScp02Service.end())
    {
        /* get pointer and process secure channel message */
        pScp02Service = it->second;
    }
    else
    {
        /* malloc a new secure channel */
        scp02_server_dump_bytes("malloc a new secure channel.", NULL, 0);
        /* malloc new one and insert it */
        pScp02Service = new Scp02Service();
        pScp02Service->rt_scp02_server_register_recv((CommunicationServer::serverRecvFuncType)&(RemoteService::RecvFunc));
        __android_log_print(ANDROID_LOG_INFO,"Scp02Service","mapScp02Service pClient = %p,pScp02Service = %p",pClient, pScp02Service);
        mapScp02Service.insert(make_pair(pClient, pScp02Service));
        __android_log_print(ANDROID_LOG_INFO,"Scp02Service","mapCommunicationService pScp02Service = %p,pServer = %p",pScp02Service, pServer);
        mapCommunicationService.insert(make_pair(pScp02Service, pServer));
    }
    mutexMapScp02Service.Unlock();

    mutexGlobalProcess.Unlock();

    if(NULL != pScp02Service)
    {
        ret = pScp02Service->rt_scp02_server_process_secure_channel_message(pServer, pClient, buf, len);
    }

    return ret;
}

int Scp02Service::send_secure_message(CommunicationServer::Communication *pClient, unsigned char *buf, int len)
{
    int ret = 0;

	scp02_server_dump_bytes("Scp02Service::send_secure_message IN", NULL, 0);

    Scp02Service *pScp02Service = NULL;

    mutexMapScp02Service.Lock();
    map<CommunicationServer::Communication *, Scp02Service *>::iterator it = mapScp02Service.find(pClient);
    if(it != mapScp02Service.end())
    {
        /* get pointer and process secure channel message */
        pScp02Service = it->second;
    }
    mutexMapScp02Service.Unlock();
	scp02_server_dump_bytes("Scp02Service::send_secure_message 1", NULL, 0);

    if(NULL != pScp02Service)
    {
    	
		scp02_server_dump_bytes("Scp02Service::send_secure_message 2", NULL, 0);
        ret = pScp02Service->rt_scp02_server_send_secure_message(pClient, global_msg_id, buf, len);
    }

	scp02_server_dump_bytes("Scp02Service::send_secure_message 3", NULL, 0);
    return ret;
}

int Scp02Service::BroadCast(CommunicationServer *pServer, string funcName,string src)
{
    int ret = 0;

    CommunicationServer::Communication *pClient = NULL;
    Scp02Service *pScp02Service = NULL;
    CommunicationServer *pCommunicationServer = NULL;

    string msg;
    int msgLen = globalPack->Pack(funcName,src).size();
    msg.append((const char*)globalPack->Pack(funcName,src).data(),globalPack->Pack(funcName,src).size());

    scp02_server_dump_bytes("Scp02Service::BroadCast IN", NULL, 0);
    mutexMapScp02Service.Lock();

    map<Scp02Service *, CommunicationServer *>::iterator it1;
    map<CommunicationServer::Communication *, Scp02Service *>::iterator it;

    __android_log_print(ANDROID_LOG_INFO,"Scp02Service","pServer = %p",pServer);

    for(it1 = mapCommunicationService.begin();it1 != mapCommunicationService.end();++it1){
        if(it1->second == pServer){
            pScp02Service = it1->first;

            for(it = mapScp02Service.begin();it != mapScp02Service.end();++it){
               
                if(it->second == pScp02Service){
                    pScp02Service->rt_scp02_server_send_secure_message(it->first, 0, (unsigned char*)msg.data(), msg.size());
                    break;
                }
            }
        }
    }

    if(NULL == pScp02Service){
        scp02_server_dump_bytes("Scp02Service::Not find pScp02Service", NULL, 0);
        mutexMapScp02Service.Unlock();
        return -1;
    }

    mutexMapScp02Service.Unlock();

    return ret;
}

void Scp02Service::clientStatusNotify(CommunicationServer::Communication *pClient,int status)
{
    Scp02Service *pScp02Service = NULL;

    scp02_server_dump_bytes("clientStatusNotify!", NULL, 0);

    /*mutexGlobalProcess.Lock();

    mutexMapScp02Service.Lock();
    map<CommunicationServer::Communication *, Scp02Service *>::iterator it = mapScp02Service.find(pClient);
    if(CLIENT_OK == status)
    {
        if(it == mapScp02Service.end())
        {
            scp02_server_dump_bytes("malloc a new secure channel.", NULL, 0);

            *//* malloc new one and insert it *//*
            pScp02Service = new Scp02Service();

#ifdef SCP02_ENCRYPT
            pScp02Service->rt_scp02_server_register_recv((CommunicationServer::serverRecvFuncType)&(RemoteService::RecvFunc));
            //pScp02Service->rt_scp02_server_register_get_diversification_data(get_diversification_data);
#endif
            mapScp02Service.insert(make_pair(pClient, pScp02Service));
        }
    }
    else
    {
        if(it != mapScp02Service.end())
        {
            scp02_server_dump_bytes("delete an old secure channel.", NULL, 0);

            *//* get pointer and erase it *//*
            pScp02Service = it->second;
            delete pScp02Service;
            pScp02Service = NULL;

            mapScp02Service.erase(it);
        }
    }
    mutexMapScp02Service.Unlock();

    mutexGlobalProcess.Unlock();

    scp02_server_dump_bytes("clientStatusNotify OUT", NULL, 0);*/
}

int Scp02Service::rt_scp02_server_register_monitor(scp02_server_channel_monitor_t monitor)
{
    rt_scp02_server_t *thiz = &pri_thiz;

    thiz->monitor = monitor;

    return 0;
}

int Scp02Service::rt_scp02_server_register_get_diversification_data(scp02_server_get_diversification_data_t get_diversification_data)
{
    rt_scp02_server_t *thiz = &pri_thiz;

    thiz->get_diversification_data = get_diversification_data;

    return 0;
}

int Scp02Service::rt_scp02_server_register_recv(scp02_server_user_recv_t rx)
{
    rt_scp02_server_t *thiz = &pri_thiz;

    thiz->rx = rx;

    return 0;
}

int Scp02Service::rt_scp02_server_send_secure_message(CommunicationServer::Communication *pClient, int msg_id, unsigned char *buf, int len)
{
    int ret = 0, res;

    rt_scp02_server_t *thiz = &pri_thiz;


    res = scp02_server_wrap_message(pClient, thiz, msg_id, buf, len);
    if(res < 0)
    {
        ret = -1;
    }
    else
    {
        ret = res;
    }


    return ret;
}

int Scp02Service::rt_scp02_server_process_secure_channel_message(CommunicationServer *pServer, CommunicationServer::Communication *pClient, unsigned char *buf, int len)
{
    int res, ret = 0;
    unsigned char sw12_error[2] = {0x63, 0x00};
    unsigned char sw12_error1[4] = {0x00, 0x00, 0x63, 0x00};

    rt_scp02_server_t *thiz = &pri_thiz;
    int msg_id;

    /* call channel monitor function */
    if(thiz->monitor)
    {
        thiz->monitor(buf, len);
    }

    switch((unsigned char)buf[1])
    {
        case 0x50:/* INITIALIZE UPDATE Request */
        {
            res = scp02_server_initialize_update(pClient, thiz, buf, len);
            if(0 == res)
            {
                thiz->secure_channel_state = 0;
            }
            else
            {
                thiz->secure_channel_state = -1;
                ret = -1;
            }
        }
        break;

        case 0x82:
        {
			scp02_server_dump_bytes("process external_authenticate request", NULL, 0);
            if(thiz->secure_channel_state == 0)
            {
                res = scp02_server_external_authenticate(pClient, thiz, buf, len);
                if(0 == res)
                {
                    thiz->secure_channel_state = 2;
                }
                else
                {
                    ret = -1;
                }
            }
            else
            {
            	scp02_server_dump_bytes("channel state error!", NULL, 0);
                res = pClient->Send(sw12_error, sizeof(sw12_error));
                if(res < 0)
                {
                    ret = -1;
                }
            }
        }
        break;

        /* security channel has already established */
        case 0xE2:
        {
            {
                /* decrypt message */
                res = scp02_server_unwrap_message(pServer, pClient, thiz, &msg_id, buf, len);
                if(0 != res)
                {
                    /* fill msg id */
                    *(sw12_error1) = (msg_id>>8)&0xFF;
                    *(sw12_error1+1) = msg_id&0xFF;

                    pClient->Send(sw12_error1, sizeof(sw12_error1));

                    ret = -1;
                }
            }
        }
        break;

        default:
        {

        }
        break;
    }

    return ret;
}


void Scp02Service::setlogFunc(ComLog logfunc){
	g_Log = logfunc;
}

