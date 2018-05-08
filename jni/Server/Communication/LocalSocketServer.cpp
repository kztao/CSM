#include "LocalSocketServer.h"
#include <sys/socket.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h> 
#include "log.h"


#define MAX_SET_NUM 5


static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;



class LocalSocketThreadPara{
public:
	int sfd;
	vector<int> *vectorFd;
	CommunicationServer::serverRecvFuncType recvFunc;
};

static LocalSocketThreadPara localSocketThreadPara;


void* ThreadNewConnect(void* args)
{
	
	struct sockaddr_un saddr = { 0 };
	socklen_t clen = sizeof(saddr);
	int clientFd = 0;
	if(NULL == args){
		return NULL;
	}

	LocalSocketThreadPara tmp = *(LocalSocketThreadPara*)args;
	
	while(1){
		LOGI("Wait for connect!!!,sd = %d",tmp.sfd);
		clientFd = accept(tmp.sfd,(struct sockaddr *) &saddr, &clen);
		if(clientFd < 0)
		{
			//sfd error;
			LOGE("accept error, ERRONO is %x, tmp-sfd is %d",errno, tmp.sfd);
			break;
		}
		else
		{
			LOGI("%d connect!!!",clientFd);
			pthread_mutex_lock(&mtx);
			tmp.vectorFd->push_back(clientFd);
			LOGI("Current UserNo: %d",tmp.vectorFd->size());
			pthread_mutex_unlock(&mtx);
		}
		
	}

	return NULL;
}


void *ThreadRecv(void *para){
	
	fd_set fd_client_set;
	struct timeval tval = { 0 };
	int maxfd = 0;

	int ret = 0;
	int tempfd = -1;	
	

	int len;
	unsigned char *buf;
	
	tval.tv_sec = 0;
	tval.tv_usec = 0;
	
	vector<int>::iterator it;
	LocalSocketThreadPara tmp = *(LocalSocketThreadPara*)para;

	LOGI("SERVER: ThreadRecv... ");
	while(1)
	{
		FD_ZERO(&fd_client_set);
		pthread_mutex_lock(&mtx);

		if(tmp.vectorFd->size() == 0){
			pthread_mutex_unlock(&mtx);
			continue;
		}
				
		for (it = tmp.vectorFd->begin(); it != tmp.vectorFd->end(); it++)	//添加客户端句柄到描述符集合
		{
			FD_SET(*it, &fd_client_set);
			maxfd = maxfd > (*it) ? maxfd : (*it) ;
		}
		
		pthread_mutex_unlock(&mtx);
			
		ret = select(maxfd + 1, &fd_client_set, NULL, NULL, &tval);
	
		for (it = tmp.vectorFd->begin(); it != tmp.vectorFd->end(); it++)	//添加客户端句柄到描述符集合
		{		
			if (!FD_ISSET(*it, &fd_client_set))//轮询发生变化的句柄
				continue;

			ret = recv(*it,&len,sizeof(len),0);
			if(ret > 0)
			{
				LOGI("server receive len(no head) is %d", len);
				buf = new unsigned char[len];
				ret = recv(*it,buf,len,0);
				Print_Data(buf,len);
				if(ret <= 0)
				{
					//该连接断开		
					pthread_mutex_lock(&mtx);
					tmp.vectorFd->erase(it);				
					pthread_mutex_unlock(&mtx);	
					
					delete[] buf;	
					continue;
				}

				if(tmp.recvFunc != NULL)
				{
					Communication *parent = new LocalSocketServerComm(*it);
					tmp.recvFunc(parent,buf,len);
				}
				
				delete[] buf;	
			}
			else
			{
				//该连接断开
				LOGI("recv: connection fail, remove client fd: %d", *it);
				pthread_mutex_lock(&mtx);
				tmp.vectorFd->erase(it);				
				pthread_mutex_unlock(&mtx);	
				
				continue;					
			}			
		}
		
	}

}


LocalSocketServer::~LocalSocketServer()
{
}


LocalSocketServer::LocalSocketServer(char * pServerName,NotifyFdServerStatus func) throw(int)
{
	struct sockaddr_un saddr = { 0 };
	struct sockaddr_un caddr = { 0 };
	socklen_t clen = sizeof(caddr);
	
	pthread_t thread_newconnect;
	pthread_t thread_clientsendmonitor;
	
	int tempfd = -1;

	int ret = 0;

	
	//1创建套接字
	sfd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sfd < 0)
	{
		LOGE("Server: Create Socket ERRONO is %d", errno);
		throw errno;
	}
	
	//2设置绑定地址
	saddr.sun_family = AF_LOCAL;
	strcpy(&saddr.sun_path[1], pServerName);
	saddr.sun_path[0] = 0;

	//3绑定
	int on = 1;  
    ret = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (ret < 0)
    {  
        LOGE("setsockopt fail ERRONO is %d", errno);
		throw errno;
    }
        
	ret = bind(sfd, (struct sockaddr *) &saddr, strlen(pServerName) + 1);
	if (ret < 0)
	{
		LOGE("bind fail ERRONO is %d", errno);
		throw errno;
	}

	
	//4监听套接字
	ret = listen(sfd, MAX_SET_NUM);
	if (ret < 0)
	{
		LOGE("listen fail ERRONO is %x", errno);
		throw errno;
	}

	LOGI("SERVER: socket finish. sfd is %d. start thread", sfd);

	recvFunc = NULL;
	
	localSocketThreadPara.sfd = sfd;
	localSocketThreadPara.vectorFd = &vectorFd;
	localSocketThreadPara.recvFunc = recvFunc;

	pthread_create(&thread_newconnect, NULL, ThreadNewConnect, &localSocketThreadPara);

}

int LocalSocketServer::BroadCast(unsigned char *buf,int len)
{
	int ret = 0;
	vector<int>::iterator i = vectorFd.begin();
	CommunicationMessage msg; 

	msg.len = len + sizeof(int);
	msg.buf = new unsigned char[msg.len];
	memcpy(msg.buf,&msg.len,sizeof(int));
	memcpy(msg.buf + sizeof(int),buf,len);

	for(i = vectorFd.begin();i!=vectorFd.end();i++)
	{	
		ret = send(*i,msg.buf,msg.len,0);
		if(ret <= 0)
		{
			LOGI("broadcast send error, ret = %d, socket %d",ret, (*i));
		}
	}

	delete[] msg.buf;
	msg.buf = NULL;

	return ret;
	
}

int LocalSocketServer::RegServerRecvFunc(serverRecvFuncType func)
{
	recvFunc = func;

	pthread_t tid;
	int ret;
	localSocketThreadPara.recvFunc = func;
	LOGI("RegServerRecvFunc start");
	
	ret = pthread_create(&tid,NULL,ThreadRecv,&localSocketThreadPara);
	
	return ret;
	
}


LocalSocketServerComm::LocalSocketServerComm(int fd)
{
	this->fd = fd;
}

LocalSocketServerComm::~LocalSocketServerComm()
{

}

int LocalSocketServerComm::Send(unsigned char *buf, int len)
{	
	CommunicationMessage msg;

	msg.len = len + sizeof(int);
	msg.buf = new unsigned char[msg.len];
	memcpy(msg.buf,&len,sizeof(int));
	memcpy(msg.buf + sizeof(int),buf,len);
	int ret = send(fd,msg.buf,msg.len,0);
	LOGI("Server Send data, fd is %d, ret is %d, len is %d", fd, ret, msg.len);
	delete[] msg.buf;
	msg.buf = NULL;
	return ret;
}



