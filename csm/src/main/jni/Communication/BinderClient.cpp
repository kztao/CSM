//
// Created by wjr on 19-3-11.
//

#include "BinderClient.h"
#include <dlfcn.h>
#include <android/log.h>
#include <map>
#include "Scp02Client.h"
using namespace std;

#define MSG_TO_CLIENT_FUNC_NAME     "RegServerMsgParseFunc"
#define MSG_TO_SERVER_FUNC_NAME     "SendMsgToServer"
#define BINDER_CLIENT_SO_NAME       "libRpcJniClient.so"
#define REG_CLIENTRESET_FUNC_NAME   "regresetClient"

#define LOG_PRINT(...) __android_log_print(ANDROID_LOG_DEBUG,"wjr",__VA_ARGS__)
static map<string,bool > mapServerRegFlg;

map<string,BinderClient*> mapClient;

pthread_mutex_t mutexBinderClient = PTHREAD_MUTEX_INITIALIZER;

/*void *SendThread(BinderClient *tmp){
    while (1){
        pthread_mutex_lock(&(tmp->m_mutex));
        if(tmp->m_packFlg == false && tmp->m_sendList.size() == 0){
            pthread_cond_wait(&(tmp->m_cond),&(tmp->m_mutex));
        }

        pthread_mutex_unlock(&(tmp->m_mutex));

        string s;
        while(1){
            pthread_mutex_lock(&(tmp->m_mutex));
            int size = tmp->m_sendList.size();

            LOG_PRINT("[%s] size = %d",__FUNCTION__,size);
            if( size > 0){
                s = *(tmp->m_sendList.begin());
                tmp->m_sendList.erase(tmp->m_sendList.begin());
                if(NULL != tmp->sendMsgToServer){
                    int ret = (tmp->sendMsgToServer)((char*)(tmp->serverName.data()),(char*)(s.data()),s.size());
                    if(ret != 0){
                        //return false;
                        pthread_mutex_unlock(&(tmp->m_mutex));
                        continue;
                    }
                }

                pthread_mutex_unlock(&(tmp->m_mutex));
            } else{
                tmp->m_packFlg = false;
                pthread_mutex_unlock(&(tmp->m_mutex));
                break;
            }

        }

        pthread_mutex_unlock(&(tmp->m_mutex));
    }

    return NULL;
}
*/

BinderClient* getInstance(char *pServerName) {

    LOG_PRINT("mapClient addr = %p",&mapClient);

    pthread_mutex_lock(&mutexBinderClient);
    BinderClient *tmp = NULL;

    auto it = mapClient.begin();
    for(;it != mapClient.end();it++){
        if(it->first == pServerName){
            tmp = it->second;
            break;
        }
    }

    if(tmp == NULL){
        tmp = new BinderClient(pServerName,NULL);
        mapClient[pServerName] = tmp;
    }

    pthread_mutex_unlock(&mutexBinderClient);

    LOG_PRINT("BinderClient* getInstance = %p",tmp);

    return tmp;
}


void ClientReset(){
    LOG_PRINT("%s IN",__FUNCTION__);
	rt_scp02_client_init();
}

BinderClient::BinderClient(char *pServerName,NotifyClientStatus notifyClientStatus) {
    serverName = pServerName;
    sendMsgToServer = NULL;
    regServerMsgParseFunc = NULL;
	regClientResetFunc = NULL;
    pthread_mutex_init(&m_mutex,NULL);
    pthread_cond_init(&m_cond,NULL);
    m_packFlg = false;
    m_sendList.clear();

	
	void *h = dlopen(BINDER_CLIENT_SO_NAME,RTLD_LAZY);
    LOG_PRINT("%s dlopen1 = %p",__FUNCTION__,h);
    if(h != NULL){
        sendMsgToServer = (pSendMsgToServer)dlsym(h,MSG_TO_SERVER_FUNC_NAME);
        regServerMsgParseFunc = (pRegServerMsgParseFunc)dlsym(h,MSG_TO_CLIENT_FUNC_NAME);
		regClientResetFunc = (pregClientResetFunc)dlsym(h,REG_CLIENTRESET_FUNC_NAME);

        LOG_PRINT("%s sendMsgToServer = %p",__FUNCTION__,sendMsgToServer);
        LOG_PRINT("%s regServerMsgParseFunc = %p",__FUNCTION__,regServerMsgParseFunc);
    }

	
	if(NULL != regClientResetFunc){
		regClientResetFunc(ClientReset);
	}
}

BinderClient::~BinderClient() {

}


bool BinderClient::ClientSend(unsigned char *buf, int len) {

    LOG_PRINT("%s IN",__FUNCTION__);

    if(NULL == sendMsgToServer){
        LOG_PRINT("%s send func is null",__FUNCTION__);
        return false;
    }

    int ret = sendMsgToServer((char*)serverName.data(),(char*)buf,len);
    LOG_PRINT("%s OUT,ret = %d",__FUNCTION__,ret);
    return (ret == 0) ? true: false;
}

int BinderClient::init(CommunicationClient::ClientRecv func) {
    if(NULL != regServerMsgParseFunc){

        map<string,bool >::iterator it;
        for(it = mapServerRegFlg.begin();it != mapServerRegFlg.end();++it){
            if(it->first == serverName && it->second == true){
                return 0;
            }
        }

        LOG_PRINT("%s IN",__FUNCTION__);
        regServerMsgParseFunc((char*)serverName.data(),func);
        LOG_PRINT("%s OUT",__FUNCTION__);
        mapServerRegFlg[serverName] = true;
    }

    return 0;
}