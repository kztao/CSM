//
// Created by wjr on 19-3-7.
//

#include "inf.h"
#include <jni.h>
#include <vector>
#include <iostream>
#include <android/log.h>
#include <unistd.h>

using namespace std;

static parseClientMsg parseClientMsgFunc = NULL;
static notifyClientStatus clientStatusFunc = NULL;

static JavaVM *javaVM = NULL;
static jint version = 0;

static jobject glMsgToClient = NULL;
static jmethodID glSendMsgToClient = NULL;

#define LOG(...) __android_log_print(ANDROID_LOG_INFO,"wjr",__VA_ARGS__)

void LOG_DATA(char *buf,int len){
    /*string s;
    char hex[3];

    for(int i = 0; i < len;i++){
        memset(hex,0,sizeof(hex));
        sprintf(hex,"%02x",buf[i]);
        s.append(hex);

        if((i +1) % 16 == 0){
            s.append("\n");
            continue;
        }

        if((i +1) % 4 == 0){
            s.append(" ");
        }
    }

    LOG("data [%d] is %s",len,s.data());*/
}

extern "C" JNIEXPORT void RegParseClientMsg(parseClientMsg parseFunc){
    parseClientMsgFunc = parseFunc;
}

extern "C" JNIEXPORT void SendMsgToClient(int id,char *serverName,char *buf,unsigned int len){

    LOG("%s IN",__FUNCTION__);
    if(NULL == glMsgToClient || NULL == glSendMsgToClient){
        LOG("para invalid");
        return ;
    }

    JNIEnv *env = NULL;
    jint ret = javaVM->GetEnv((void**)&env,version);

    if(ret == JNI_EDETACHED){
        javaVM->AttachCurrentThread(&env,NULL);
    }
    jstring serverNameStr = env->NewStringUTF((const char*)serverName);
    jbyteArray array = env->NewByteArray(len);
    env->SetByteArrayRegion(array,0,len,(const jbyte*)buf);
    env->CallVoidMethod(glMsgToClient,glSendMsgToClient,id,serverNameStr,array);
    env->DeleteLocalRef(serverNameStr);
    env->DeleteLocalRef(array);


    if(ret == JNI_EDETACHED){
        javaVM->DetachCurrentThread();
    }

    LOG("%s OUT",__FUNCTION__);
}

#if 0
/*
class DataMsgToServer{
private:
    int id;
    string serverName;
    string msg;
public:
    DataMsgToServer(int id,string serverName,string msg){
        this->id = id;
        this->serverName = serverName;
        this->msg = msg;
    }

    int getId(){
        return id;
    }

    string getServerName(){
        return serverName;
    }

    string getMsg(){
        return msg;
    }
};

class ListMsgToServer{
private:
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    vector<DataMsgToServer*> vectorData;

    friend void *handleThread(ListMsgToServer *tmp);

public:
    ListMsgToServer(){
        pthread_mutex_init(&mutex,NULL);
        pthread_cond_init(&cond,NULL);
        vectorData.clear();

    }

    void Put(int id,string serverName,string msg){
        DataMsgToServer *tmp = new DataMsgToServer(id,serverName,msg);
        pthread_mutex_lock(&mutex);
        vectorData.push_back(tmp);
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&mutex);
    }
};

static ListMsgToServer listMsgToServer;
static bool handleThreadExitFlg = false;

void *handleThread(ListMsgToServer *tmp){

    while (1){
        pthread_mutex_lock(&(tmp->mutex));
        if(tmp->vectorData.size() == 0){
        pthread_cond_wait(&(tmp->cond),&(tmp->mutex));
        }

        DataMsgToServer *dataMsgToServer = *(tmp->vectorData.begin());
        if(NULL != parseClientMsgFunc){
        int ret = parseClientMsgFunc(dataMsgToServer->getId(),(char*)(dataMsgToServer->getServerName().c_str()),
                                     (char *)(dataMsgToServer->getMsg().data()),(unsigned int)(dataMsgToServer->getMsg().size()));
        }

        delete(dataMsgToServer);
        tmp->vectorData.erase(tmp->vectorData.begin());
        pthread_mutex_unlock(&(tmp->mutex));
    }

    return NULL;
}
*/
#endif
class DataMsgToServer{
public:
    int pid;
    string serverName;
    string msg;

    DataMsgToServer(int pid,string name,string msg){
        this->pid = pid;
        this->serverName = name;
        this->msg = msg;
    }
};


static pthread_mutex_t Mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t Cond = PTHREAD_COND_INITIALIZER;
vector<DataMsgToServer*> vectorListMsg;

void putMsg(int pid,char *serverName,string msg){
    DataMsgToServer *tmp = new DataMsgToServer(pid,serverName,msg);
    pthread_mutex_lock(&Mutex);
    vectorListMsg.push_back(tmp);
    pthread_cond_signal(&Cond);
    pthread_mutex_unlock(&Mutex);
}

void *handleThread(void *para){

    while (1){
        pthread_mutex_lock(&Mutex);
        if(vectorListMsg.size() == 0){
            pthread_cond_wait(&Cond,&Mutex);
        }


        DataMsgToServer *dataMsgToServer = *(vectorListMsg.begin());
        if(NULL != parseClientMsgFunc){
            int ret = parseClientMsgFunc(dataMsgToServer->pid,(char*)(dataMsgToServer->serverName.c_str()),
                                         (char *)(dataMsgToServer->msg.data()),(unsigned int)(dataMsgToServer->msg.size()));
        }

        delete(dataMsgToServer);
        vectorListMsg.erase(vectorListMsg.begin());
        pthread_mutex_unlock(&Mutex);
    }

    return NULL;
}




/*
 * Class:     com_westone_rpcserver_JniFunc
 * Method:    MsgToServer
 * Signature: (ILjava/lang/String;[B)V
 */
extern "C" JNIEXPORT jint JNICALL Java_com_westone_rpcserver_JniFunc_MsgToServer(JNIEnv *env, jobject obj, jint id, jstring serverName, jbyteArray msg){
    LOG("%s IN ",__FUNCTION__);
    if(NULL != parseClientMsgFunc){

        jbyte *pMsg = env->GetByteArrayElements(msg,NULL);
        jsize msgLen = env->GetArrayLength(msg);
        const char *pServerName = env->GetStringUTFChars(serverName,NULL);

        string strMsg;
        strMsg.append((char*)pMsg,msgLen);

        //putMsg((int)id,(char*)pServerName,strMsg);

        if(NULL != parseClientMsgFunc){
            parseClientMsgFunc(id,(char*)pServerName,
                                         (char *)(pMsg),msgLen);
        }

        env->ReleaseStringUTFChars(serverName,pServerName);
        env->ReleaseByteArrayElements(msg,pMsg,0);
    }

    LOG("%s OUT ",__FUNCTION__);
    return 0;
}

/*
 * Class:     com_westone_rpcserver_JniFunc
 * Method:    RegCallback
 * Signature: (Lcom/westone/rpcserver/IfMsgToClient;)V
 */
extern "C" JNIEXPORT void JNICALL Java_com_westone_rpcserver_JniFunc_RegCallback
        (JNIEnv *env, jobject obj, jobject IfMsgToClient){
    version = env->GetVersion();
    env->GetJavaVM(&javaVM);

    if(NULL == glMsgToClient){
        glMsgToClient = env->NewGlobalRef(IfMsgToClient);
        jclass classIfMsgToClient = env->GetObjectClass(IfMsgToClient);
        glSendMsgToClient = env->GetMethodID(classIfMsgToClient,"MsgToClient","(ILjava/lang/String;[B)V");

        pthread_t tid;
        pthread_create(&tid,NULL,handleThread,NULL);
        usleep(5000);
    }
}
