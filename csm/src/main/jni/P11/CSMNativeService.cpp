//
// Created by wang.junren on 2018/5/16.
//

#include "CSMResAccess.h"
#include "RemoteServicePack.h"
#include "p11FunctionParse.h"
#include "p11func_sc.h"
#include "Scp02Service.h"
#include <dlfcn.h>
#include "logserver.h"
#include <RemoteService.h>
#include "LocalSocketServer.h"
#include "Control.h"
#include "P11Adapter.h"
#include <map>
#include "BinderServer.h"
#include "skfFunctionParse.h"

static const char*tag = "csm_jni";
static const char*ServerName = "com.westone.csm.CSM";

static JavaVM *globeVM = NULL;
static jint version = 0;
static jobject gCertVerifyObj;

map<CommunicationServer::Communication*,string> mapClientName;
//static CommunicationServer *tmp = NULL;
bool mountflg = TRUE;

class P11Control:public Control{
public:
    bool check(CommunicationServer::Communication *pClient,string funcName,string src,string &clientName){
        if(funcName == "PackageNameCheck"){
            clientName = src;
            mapClientName[pClient] = src;
        }else{
            map<CommunicationServer::Communication*,string>::iterator it;
            it = mapClientName.find(pClient);
            if(it != mapClientName.end()){
                clientName = it->second;
            }
        }

        LOGSERVERI(tag,"p11 control is true");

        return true;
    }
};

void getClientStatus(CommunicationServer::Communication *client,int status)
{
    LOGSERVERI(tag,"server get notification, client status %d", status);
    Scp02Service::clientStatusNotify(client,status);

	if(status != CLIENT_OK)
	{
		clearmono(mapClientName[client]);
		close_clientsession(client);
	}
}

bool checkAppCert(string packageName, unsigned char *fingerprint,int len){
    JNIEnv *env;
    jint ret = globeVM->GetEnv((void**)&env,version);
    if(ret == JNI_EDETACHED){
        globeVM->AttachCurrentThread(&env,NULL);
    }

    jclass certVerify = env->GetObjectClass(gCertVerifyObj);
    jmethodID jmethodID1 = env->GetMethodID(certVerify,"verify","(Ljava/lang/String;[B)Z");
    jstring pName = env->NewStringUTF(packageName.data());
    jbyteArray array = env->NewByteArray(len);
    env->SetByteArrayRegion(array,0,len,(jbyte*)fingerprint);
    jboolean checkRet= env->CallBooleanMethod(gCertVerifyObj,jmethodID1,pName,array);
    LOGSERVERI(tag,"end gCertVerifyObj,checkRet = %d",checkRet);
    env->DeleteLocalRef(array);
    env->DeleteLocalRef(pName);

    if(ret == JNI_EDETACHED){
        globeVM->DetachCurrentThread();
    }

    return checkRet;
}

/*
 * Class:     com_westone_csm_CSMNative
 * Method:    Init
 * Signature: (Lcom/westone/csm/CertVerify;)V
 */
extern"C" JNIEXPORT void JNICALL Java_com_westone_csm_CSMNative_Init
        (JNIEnv *env, jobject obj, jobject certVerifyObj){
    gCertVerifyObj = env->NewGlobalRef(certVerifyObj);
    env->GetJavaVM(&globeVM);
    version = env->GetVersion();
   /* CSMResAccess::RegCheckCertFunc(checkAppCert);*/

    Control *p11ControlLocal = NULL;
    Control *p11ControlInet = NULL;
    Control *p11ControlBinder = NULL;

    FunctionParse *functionParseLocal = NULL;
    FunctionParse *functionParseInet = NULL;
    FunctionParse *functionParseBinder = NULL;

    CommunicationServer * communicationServerLocal = NULL;
    CommunicationServer * communicationServerInet = NULL;
    CommunicationServer * communicationServerBinder = NULL;

    RemoteService *remoteServiceLocal = NULL;
    RemoteService *remoteServiceInet = NULL;
    RemoteService *remoteServiceBinder = NULL;


	const char * filename = "csmserverlog.txt";
	const char * defaultRecordPath = "/sdcard/csmserverlog.txt";

    initServerPlog(filename, defaultRecordPath);

	LOGSERVERI(tag,"server version: 3.1.8");
	
    try {
        communicationServerLocal = new LocalSocketServer((char *)"localSockect", getClientStatus, log_server);
        communicationServerInet = new LocalSocketServer(4567,getClientStatus);
        communicationServerBinder = new BinderServer((char*)ServerName);

        p11ControlLocal = new P11Control();
        p11ControlInet = new P11Control();
        p11ControlBinder = new P11Control();

        functionParseLocal = new SkfFunctionParse();
        functionParseInet = new SkfFunctionParse();
        functionParseBinder = new SkfFunctionParse();

        remoteServiceLocal = new RemoteService(communicationServerLocal,p11ControlLocal,functionParseLocal);
        remoteServiceInet = new RemoteService(communicationServerInet,p11ControlInet,functionParseInet);
        remoteServiceBinder = new RemoteService(communicationServerBinder,p11ControlBinder,functionParseBinder);

		remoteServiceLocal->setlogFunc(log_server);

        /*p11ControlLocal->setFunctionParse(functionParseLocal);
        functionParseLocal->RegCommServer(communicationServerLocal);

        p11ControlInet->setFunctionParse(functionParseInet);
        functionParseInet->RegCommServer(communicationServerInet);

        p11ControlBinder->setFunctionParse(functionParseBinder);
        functionParseBinder->RegCommServer(communicationServerBinder);*/

    }catch (int e){
        delete communicationServerLocal;
        delete p11ControlLocal;
        delete functionParseLocal;
        delete remoteServiceLocal;

        delete communicationServerInet;
        delete p11ControlInet;
        delete functionParseInet;
        delete remoteServiceInet;

        delete communicationServerBinder;
        delete p11ControlBinder;
        delete functionParseBinder;
        delete remoteServiceBinder;
    }
}

/*
 * Class:     com_westone_csm_CSMNative
 * Method:    TFCardPlugin
 * Signature: (Z)V
 */
extern"C" JNIEXPORT void JNICALL Java_com_westone_csm_CSMNative_TFCardPlugin
        (JNIEnv *env, jobject obj, jboolean flg){
    LOGSERVERI(tag,"TFCardPlugin IN");
    if(JNI_FALSE == flg){
//        if(NULL != tmp){
//            LOGSERVERI(tag,"jni localsocket server is %p",tmp);
//        }
		if(mountflg){
            closeTFCard();
        }
    }else{
//    	delete tmp;
//		tmp = NULL;
        GetTFcardStatus();

	}
	LOGSERVERI(tag,"TFCardPlugin OUT");
}

/*
 * Class:     com_westone_csm_CSMNative
 * Method:    setMountFlag
 * Signature: (Z)V
 */
extern"C" JNIEXPORT void JNICALL Java_com_westone_csm_CSMNative_setMountFlag
        (JNIEnv *env, jobject obj, jboolean flg)
{
    mountflg = flg;
    LOGSERVERI(tag,"card mounted: %d",mountflg);
    setMountCardFlg(flg);
}


/*
 * Class:     com_westone_csm_CSMNative
 * Method:    NotifyClientStatus
 * Signature: (ILjava/lang/String;I)V
 */
extern"C" JNIEXPORT void JNICALL Java_com_westone_csm_CSMNative_NotifyClientStatus
        (JNIEnv *env, jobject obj, jint pid, jstring serverName, jint status){
    const char *pName = env->GetStringUTFChars(serverName,NULL);
    int len = strlen(pName);
    CommunicationServer::Communication *pClient = NULL;

    if(len == strlen(ServerName) && 0 == memcmp(ServerName,pName,len)){
        pClient = BinderServerClient::getClient((char*)pName,pid);
        getClientStatus(pClient,status);
    }

    env->ReleaseStringUTFChars(serverName,pName);
}

extern"C" JNIEXPORT jboolean JNICALL Java_com_westone_csm_CSMNative_checkClientCert
        (JNIEnv *env, jobject obj, jstring name, jbyteArray array){
    const char *pName = env->GetStringUTFChars(name,NULL);
    string s = (char*)pName;
    env->ReleaseStringUTFChars(name,pName);

    jbyte *pByte = env->GetByteArrayElements(array,NULL);
    jsize len = env->GetArrayLength(array);
    if(len != 32){
        env->ReleaseByteArrayElements(array,pByte,0);
        return JNI_FALSE;
    }

    bool flg = CSMResAccess::CheckCert(s,(unsigned char*)pByte);
    __android_log_print(ANDROID_LOG_INFO,"wjr","csm check cert flg11 = %d",flg);
    env->ReleaseByteArrayElements(array,pByte,0);
    return flg;
}

/*
 * Class:     com_westone_csm_CSMNative
 * Method:    NotifyBinderDisconnect
 * Signature: (Ljava/lang/String;)V
 */
extern"C" JNIEXPORT void JNICALL Java_com_westone_csm_CSMNative_NotifyBinderDisconnect
        (JNIEnv *env, jobject, jstring name){
    LOGSERVERI(tag,"%s IN",__FUNCTION__);
	const char *pName = env->GetStringUTFChars(name,NULL);
    string appname = (char*)pName;
    env->ReleaseStringUTFChars(name,pName);
		
	clearmono(appname);
	close_appsession(appname);
	
	LOGSERVERI(tag,"%s disconnet",appname.c_str());
}
