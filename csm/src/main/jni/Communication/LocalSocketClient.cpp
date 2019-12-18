#include "LocalSocketClient.h"

#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h> 
#include <string.h>
#include <Export.h>


#define INVALID_SOCKET	-1
#define MAX_SERVER_LEN (UNIX_PATH_MAX-1)
static const char *tag = "csm_localSocketClient";


void* clientRecvThread(LocalSocketClient *tmp){
	tmp->printlog(C_info,__FUNCTION__,__LINE__, "clientRecvThread: START");
	
	while (1){
		int len = 0;
		int recvLen = 0;
//		printlog(C_debug,__FUNCTION__,__LINE__, "clientRecvThread: Begin Recv 01,fd = %d",tmp->fd);
		recvLen = recv(tmp->fd,&len,sizeof(len),0);

		if((recvLen < 0)&&(errno == EINTR))
		{
            tmp->printlog(C_info,__FUNCTION__,__LINE__, "EINTR, recv again");
			continue;
		}
		
		if(recvLen != sizeof(len)){
            tmp->printlog(C_error,__FUNCTION__,__LINE__, "clientRecvThread: Recv 012, Len = %d", recvLen);
			break;
		}

		if(len > 0 && len < 10240)
		{
			unsigned char *buf = new unsigned char[len];
			memset(buf,0,len);
            tmp->printlog(C_info,__FUNCTION__,__LINE__, "clientRecvThread: Begin Recv fd: %d, len is %d", tmp->fd,len);
			while(1)
			{
				recvLen = recv(tmp->fd,buf,len,0);
				if((recvLen < 0)&&(errno == EINTR))
				{
                    tmp->printlog(C_info,__FUNCTION__,__LINE__, "EINTR2, recv again");
					continue;
				}
				else
				{
					break;
				}
			}
	
			if(recvLen != len){
                tmp->printlog(C_error,__FUNCTION__,__LINE__, "clientRecvThread: Recv 022, recvLen = %d, len = %d", recvLen,len);
				delete[] buf;
				buf = NULL;
				break;
			}

			if(NULL == tmp->mrecvfunc)
			{
                tmp->printlog(C_error,__FUNCTION__,__LINE__, "recv func NULL!");
				delete[] buf;
				buf = NULL;
				break;
			}
			
			tmp->mrecvfunc(buf,len);
			delete[] buf;
			buf = NULL;
		}
		
	}
	
	pthread_mutex_lock(&tmp->mutexrecvthread);
	tmp->mrecv_threadid = 0;
	pthread_mutex_unlock(&tmp->mutexrecvthread);
	
	if(CLIENT_OK == tmp->mconnFlg){
        tmp->mconnFlg = CLIENT_DISCONNECTED;
	}
	
	if(NULL != tmp->mnotifyClientStatusFunc){
		tmp->mnotifyClientStatusFunc(tmp->mconnFlg);
	}

    tmp->printlog(C_error,__FUNCTION__,__LINE__, "clientRecvThread End: connFlg = %d", tmp->mconnFlg);
    return NULL;
}


LocalSocketClient::LocalSocketClient(char * pServerName,NotifyClientStatus func)
	:fd(INVALID_SOCKET)
{
	g_mComLog = NULL;
	mserverName = pServerName;
	mnotifyClientStatusFunc = func;
	mconnFlg = CLIENT_UNCONNECT;
	mutexReconn = PTHREAD_MUTEX_INITIALIZER;
	mutexrecvthread = PTHREAD_MUTEX_INITIALIZER;
	mrecvfunc = NULL;
	mrecv_threadid = 0;
}

LocalSocketClient::LocalSocketClient(char * pServerName,NotifyClientStatus func,ComLog logfunc)
	:fd(INVALID_SOCKET)
{
	g_mComLog = logfunc;
	mserverName = pServerName;
	mnotifyClientStatusFunc = func;
	mconnFlg = CLIENT_UNCONNECT;
	mutexReconn = PTHREAD_MUTEX_INITIALIZER;
	mutexrecvthread = PTHREAD_MUTEX_INITIALIZER;
	mrecvfunc = NULL;
	mrecv_threadid = 0;
}


LocalSocketClient::~LocalSocketClient()
{
	printlog(C_debug,__FUNCTION__,__LINE__, "start ~LocalSocketClient");

	shutdown(fd, SHUT_RDWR);
	close(fd);
	pthread_join(mrecv_threadid, NULL);
	printlog(C_debug,__FUNCTION__,__LINE__, "end ~LocalSocketClient");
}

int LocalSocketClient::init(ClientRecv func)
{	
	//const char * filename = "csmproxylog.txt";
	//const char * defaultRecordPath = "/sdcard/csmproxylog.txt";

	printlog(C_info,__FUNCTION__,__LINE__,"ls client version: 3.0.2");
	
	pthread_mutex_lock(&mutexReconn);
	if(CLIENT_OK == mconnFlg)
	{	
		pthread_mutex_unlock(&mutexReconn);
		return CLIENTINIT_ALREADYEXIST;
	}	
	pthread_mutex_unlock(&mutexReconn);

	if(mserverName.length()>MAX_SERVER_LEN || (0 == mserverName.size()))
	{
		printlog(C_error,__FUNCTION__,__LINE__, "server name error");
		return CLIENTINIT_FAIL;
	}
		
	pthread_mutex_lock(&mutexReconn);
			
	if(0 == Connect2Server()){
		
		mconnFlg = CLIENT_OK;

		if(mrecv_threadid != 0)
		{
			printlog(C_info,__FUNCTION__,__LINE__,"wait for %ld end", mrecv_threadid);
			pthread_join(mrecv_threadid, NULL);
		}

		if(NULL != func)
		{
			pthread_mutex_lock(&mutexrecvthread);
			if(0 == mrecv_threadid){
				mrecvfunc = func;
				printlog(C_info,__FUNCTION__,__LINE__,"create recv thread");
				pthread_create(&mrecv_threadid,NULL,(void*(*)(void*))clientRecvThread,this);
			}
			else
	        {
	            printlog(C_info,__FUNCTION__,__LINE__,"client recv func already registered");
	        }	
			pthread_mutex_unlock(&mutexrecvthread);
		}
		else
		{
			printlog(C_error,__FUNCTION__,__LINE__, "no recv func registered");
		}
	}else{
		printlog(C_error,__FUNCTION__,__LINE__,"connect fail!");
	}

	if(NULL != mnotifyClientStatusFunc)
	{
        mnotifyClientStatusFunc(mconnFlg);
    }
	
	pthread_mutex_unlock(&mutexReconn);
	
	return CLIENTINIT_OK;
}


bool LocalSocketClient::ClientSend(unsigned char *buf,int len)
{
	int sendLen;
	sendLen = len;
	string sendBuf;
	bool rv = false;
	
	if((NULL == buf) && (len != 0))
	{
		printlog(C_error,__FUNCTION__,__LINE__, "%s, buf error",__FUNCTION__);
		return false;
	}

	sendBuf.append((const char*)&sendLen,sizeof(sendLen));
	sendBuf.append((const char*)buf,len);

	int ret = send(this->fd,sendBuf.data(),sendBuf.size(),MSG_NOSIGNAL);
	printlog(C_info,__FUNCTION__,__LINE__, "clientsend, ret = %d", ret);
	if(ret == sendBuf.size()){
		rv = true;
	}else{
		printlog(C_info,__FUNCTION__,__LINE__, "clientsend, error = %s,ret = %d, size is %d", strerror(errno), ret,sendBuf.size());
		Reconnect();
		
		rv = false;
	}
	
	return rv;
}


bool LocalSocketClient::Reconnect()
{
	int nRet = -1;

	if(INVALID_SOCKET != fd)
	{
		printlog(C_info,__FUNCTION__,__LINE__, "reconnect, close current fd: %d", fd);	
		
		pthread_mutex_lock(&mutexReconn);
		
		mconnFlg = CLIENT_UNCONNECT;
		shutdown(fd, SHUT_RDWR);
		close(fd);
		fd = INVALID_SOCKET;		
		
		pthread_mutex_unlock(&mutexReconn);
	}

	nRet = init(mrecvfunc);

	return nRet;
}

int LocalSocketClient::Connect2Server()
{
	int nRet = 0;
	//int socketfd = 0;
	//struct sockaddr_un caddr = { 0 };
	struct sockaddr_un serveraddr = {0};

	
	serveraddr.sun_family = AF_LOCAL;
	strcpy(&serveraddr.sun_path[1], mserverName.c_str());
	serveraddr.sun_path[0] = 0;

	do{
		int socketfd = socket(AF_LOCAL, SOCK_STREAM, 0);
		if(INVALID_SOCKET == socketfd){
			nRet = INVALID_SOCKET;
			break;
		}

		nRet = connect(socketfd, (struct sockaddr *) &serveraddr,strlen(mserverName.c_str()) + 1);
		if(0 == nRet)
		{
			if(INVALID_SOCKET != this->fd){
				printlog(C_info,__FUNCTION__,__LINE__, "free socket resource %d", fd);
				shutdown(fd, SHUT_RDWR);
				close(fd);
				//fd = INVALID_SOCKET;
				
			}
			fd = socketfd;			
			mconnFlg = CLIENT_OK;
			
			printlog(C_info,__FUNCTION__,__LINE__, "%d connect success",fd);
			
			break;
		}
		else
		{			
			printlog(C_error,__FUNCTION__,__LINE__, "connect, error = %s", strerror(errno));
			shutdown(socketfd, SHUT_RDWR);
			close(socketfd);
			break;
		}
	}while(0);

	return nRet;
}

void LocalSocketClient::printlog(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...){
    char buf[1024] = { 0 };
    va_list arg;

    va_start(arg, format);
	vsnprintf(buf, 1024,format, arg);
    va_end(arg);

    if(g_mComLog){
        g_mComLog(severity,func,line,__FILE__,"%s",buf);
    }
    else{
        __android_log_print(ANDROID_LOG_INFO, tag, "printlog,%s",(char *)buf);
    }
}	


