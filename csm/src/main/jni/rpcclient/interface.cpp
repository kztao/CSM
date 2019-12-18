//
// Created by wjr on 19-3-4.
//
#include <unistd.h>
#include <jni.h>
#include <map>
#include <vector>
#include <iostream>
#include <android/log.h>
using namespace std;

#define LOG_PRINT(...) __android_log_print(ANDROID_LOG_INFO,"wjr",__VA_ARGS__)


typedef int (*RecvMsgFromServer)(char *buf,unsigned int len);
typedef void (*Resetclientfunc)();
static JavaVM *javaVM = NULL;
static jint version = 0;

static map<string,jobject > mapMsgToServerFunc;
static map<string,RecvMsgFromServer> mapMsgToClientFunc;

static Resetclientfunc g_notifyfunc = NULL;


class ClientMsg{
private:
    bool flg;
    static map<string,ClientMsg*> mapClientMsg;
    string serverNameStr;
    ClientMsg(char *serverName){
        serverNameStr = serverName;
        flg = false;
        ClientMsg::mapClientMsg.insert(make_pair(serverNameStr,this));
    }

public:

    static ClientMsg *getClientMsg(char *serverName){
        map<string,ClientMsg*>::iterator it;
        ClientMsg * tmp = NULL;
        string s = serverName;

        for(it = mapClientMsg.begin();it != mapClientMsg.end();++it){
            if(it->first == s){
                tmp = it->second;
            }
        }

        if(NULL == tmp){
            tmp = new ClientMsg(serverName);
        }

        return tmp;
    }

    void Put(char *pBuf,int len){
        string s;
        s.append(pBuf,len);
        pthread_mutex_lock(&mutex);
        msg.push_back(s);
        flg = true;
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&mutex);
    }

    int Get(){
        string recvMsg;
        RecvMsgFromServer func;
        pthread_mutex_lock(&mutex);

        if(flg == false && msg.size() == 0){
            pthread_cond_wait(&cond,&mutex);
        }

        pthread_mutex_unlock(&mutex);
        while(1){
            pthread_mutex_lock(&mutex);
            if(msg.size() > 0){
                recvMsg = *(msg.begin());
                msg.erase(msg.begin());
                pthread_mutex_unlock(&mutex);

                map<string,RecvMsgFromServer>::iterator it;
                for(it = mapMsgToClientFunc.begin();it != mapMsgToClientFunc.end();++it){
                    if(it -> first == serverNameStr){
                        func = it->second;
                        break;
                    }
                }

                if(func == NULL){
                    return -1;
                }

                int ret = func((char*)recvMsg.data(),recvMsg.size());
                LOG_PRINT("client %s end func",__FUNCTION__);

            } else{
                LOG_PRINT("null list",__FUNCTION__);
                flg = false;
                pthread_mutex_unlock(&mutex);
                break;
            }

        }

        LOG_PRINT("client %s OUT---",__FUNCTION__);
        return 0;
    }

private:
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    vector<string> msg;
};

map<string,ClientMsg*> ClientMsg::mapClientMsg;
static bool binderSuccessFlg = false;
/*
 * Class:     com_westone_rpcclient_JniFunc
 * Method:    RegRemoteCallFunc
 * Signature: (Ljava/lang/String;Lcom/westone/rpcclient/RemoteCallFunc;)V
 */
extern "C" JNIEXPORT void JNICALL Java_com_westone_rpcclient_JniFunc_RegRemoteCallFunc
        (JNIEnv *env, jobject obj, jstring serverName, jobject callbackFunc){
    LOG_PRINT("%s IN",__FUNCTION__);
    env->GetJavaVM(&javaVM);
    version = env->GetVersion();

    jobject func = env->NewGlobalRef(callbackFunc);
    const char* pServerName = env->GetStringUTFChars(serverName,NULL);
    string name;
    name.append(pServerName);
    env->ReleaseStringUTFChars(serverName,pServerName);
    mapMsgToServerFunc.insert(make_pair(name,func));

    binderSuccessFlg = true;

    LOG_PRINT("%s [server = %s,func addr = %p]OUT",__FUNCTION__,name.c_str(),func);
}

/*
 * Class:     com_westone_rpcclient_JniFunc
 * Method:    ParseServerMsg
 * Signature: (Ljava/lang/String;[B)V
 */
extern "C" JNIEXPORT jint JNICALL Java_com_westone_rpcclient_JniFunc_ParseServerMsg
        (JNIEnv *env, jobject obj, jstring serverName, jbyteArray msg){
    LOG_PRINT("%s IN",__FUNCTION__);
    env->GetJavaVM(&javaVM);
    version = env->GetVersion();
    const char *pName = env->GetStringUTFChars(serverName,NULL);
    string nameStr;
    nameStr.append(pName);
    jbyte * pMsg = env->GetByteArrayElements(msg,NULL);
    jsize len = env->GetArrayLength(msg);

//    ClientMsg *tmp = ClientMsg::getClientMsg((char*)pName);
    env->ReleaseStringUTFChars(serverName,pName);
    //tmp->Put((char*) pMsg,len);
    RecvMsgFromServer func = NULL;
    map<string,RecvMsgFromServer>::iterator it;
    for(it = mapMsgToClientFunc.begin();it != mapMsgToClientFunc.end();++it){
        if(it -> first == nameStr){
            func = it->second;
            break;
        }
    }

    if(func == NULL){
        LOG_PRINT("client func = NULL");
        env->ReleaseByteArrayElements(msg,pMsg,0);
        return -1;
    }

    LOG_PRINT("before call func");
    int ret = func((char*)pMsg,len);
    LOG_PRINT("client %s end func",__FUNCTION__);

    env->ReleaseByteArrayElements(msg,pMsg,0);
    LOG_PRINT("%s OUT",__FUNCTION__);
    return 0;
}


static void *ClientMsgThread(ClientMsg * tmp){

    if(NULL == tmp){
        return NULL;
    }

    while(1){
        int ret = tmp->Get();
    }

    return NULL;
}


extern "C" JNIEXPORT void RegServerMsgParseFunc(char *pServerName,RecvMsgFromServer func){

    if(NULL == pServerName || NULL == func){
        return ;
    }

    string s = pServerName;
    map<string,RecvMsgFromServer>::iterator it;

    string tmp;
    for(it = mapMsgToClientFunc.begin();it != mapMsgToClientFunc.end();++it){
        tmp = it->first;
        if(tmp == s){
            return;
        }
    }

//    pthread_t tid;
//    pthread_create(&tid,NULL,(void*(*)(void*))ClientMsgThread,ClientMsg::getClientMsg(pServerName));
    mapMsgToClientFunc.insert(make_pair(s,func));
//    usleep(5000);
    LOG_PRINT("%s OUT",__FUNCTION__);
}

extern "C" JNIEXPORT int SendMsgToServer(char *pServerName,char *buf, unsigned int len){

    if(NULL == pServerName || NULL == buf || 0 == len){
        return -1;
    }

    if(!binderSuccessFlg){
        LOG_PRINT("%s [server = %s] binder has not success!!!",__FUNCTION__,pServerName);
        return -1;
    }

    LOG_PRINT("%s [server = %s] IN",__FUNCTION__,pServerName);
    map<string,jobject >::iterator it;
    string s = pServerName;;
    jobject func = NULL;

    for (it = mapMsgToServerFunc.begin();it != mapMsgToServerFunc.end();++it){
        if(it->first == s){
            func = it->second;
            break;
        }
    }

    if(func == NULL){
        LOG_PRINT("%s Error",__FUNCTION__);
        return -2;
    }

    JNIEnv *env = NULL;
    jint ret = javaVM->GetEnv((void**)&env,version);

    if(ret == JNI_EDETACHED){
        javaVM->AttachCurrentThread(&env,NULL);
    }

    jclass IfMsgToServer = env->GetObjectClass(func);
    jmethodID MsgToServer = env->GetMethodID(IfMsgToServer,"MsgToServer","([B)I");
    jbyteArray msg = env->NewByteArray(len);
    env->SetByteArrayRegion(msg,0,len,(const jbyte*)buf);

    jint res = env->CallIntMethod(func,MsgToServer,msg);
    env->DeleteLocalRef((jobject)msg);
    env->DeleteLocalRef(IfMsgToServer);

    if(ret == JNI_EDETACHED){
        javaVM->DetachCurrentThread();
    }

    LOG_PRINT("%s OUT",__FUNCTION__);
    return res;
}

/*
 * Class:     com_westone_rpcclient_JniFunc
 * Method:    resetClientChannel
 * Signature: ()V
 */
extern "C" JNIEXPORT void JNICALL Java_com_westone_rpcclient_JniFunc_resetClientChannel
        (JNIEnv *, jobject){
    LOG_PRINT("%s IN",__FUNCTION__);
    binderSuccessFlg = false;
    if(g_notifyfunc){
        g_notifyfunc();
    }
    else{
        LOG_PRINT("%s ERROR!",__FUNCTION__);
    }
    LOG_PRINT("%s OUT",__FUNCTION__);
}

extern "C" JNIEXPORT void JNICALL regresetClient(Resetclientfunc func){
    LOG_PRINT("%s IN",__FUNCTION__);
    g_notifyfunc = func;
    LOG_PRINT("%s OUT",__FUNCTION__);
}