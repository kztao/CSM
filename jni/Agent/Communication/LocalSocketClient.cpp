#include "LocalSocketClient.h"

#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h> 
#include "log.h"


class LocalClientThreadPara{
public:
	int fd;
	CommunicationClient::ClientRecv recvfunc;
	NotifyClientStatus func;
};

static LocalClientThreadPara localClientThreadPara;

void *clientThreadRecv(void *para)
{
	LocalClientThreadPara tmp = *(LocalClientThreadPara *)para;
	int len;
	unsigned char *buf;
	int ret;
	
	LOGI("fd is %d", tmp.fd);
	
	while(1){
		ret = recv(tmp.fd,&len,sizeof(len),0);
		if(ret > 0)
		{
			if(len > 0)
			{	
				buf = new unsigned char[len];
				ret = recv(tmp.fd,buf,len,0);
				LOGI("Client recv len = %d",len);
				if(tmp.recvfunc!= NULL)
				{
					tmp.recvfunc(buf,len);
				}
		
				delete[] buf;		
			}
			
		}
		else
		{
			LOGE("recv ret is %d, fd is %d", ret, tmp.fd);
			tmp.func(CLIENT_DISCONNECTED);
			break;
		}
				
	}
}

LocalSocketClient::LocalSocketClient(char * pClientName,char * pServerName,NotifyClientStatus func) throw(int)
{
	int ret = 0;
	int i = 0;

	struct sockaddr_un caddr = { 0 };

	//1创建套接字

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
	{	
		LOGE("localsocket create with ret=%d with errno=%d", ret, errno);
		throw errno;
	}

	LOGI("socket() finish, fd is %d", fd);

		
	//2设置绑定地址
	if(pClientName != NULL)
	{
		caddr.sun_family = AF_LOCAL;
		strcpy(caddr.sun_path + 1,pClientName);
		caddr.sun_path[0] = 0;

		//3绑定
		int on = 1;  
	    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	    if (ret < 0)
	    { 
	    	LOGI("setsockopt ret=%d with errno=%d", ret, errno);
			fd = -1;
			throw errno;
	    }  


		ret = bind(fd, (struct sockaddr *) &caddr, strlen(pClientName) + 1);
		if (ret < 0)
		{		
			LOGI("bind ret=%d with errno=%d", ret, errno);
			if (errno != EADDRINUSE)
			{
				close(fd);
				fd = -1;
				throw errno;
			}
		}
		LOGI("bind finish, clientname is %s", pClientName);
	}
	

	serveraddr.sun_family = AF_LOCAL;
	strcpy(&serveraddr.sun_path[1], pServerName);
	serveraddr.sun_path[0] = 0;
	

	for (i = 0; i < 3; i++)
	{
		ret = 0;
		ret = connect(fd, (struct sockaddr *) &serveraddr,strlen(pServerName) + 1);

		if (ret >= 0)
		{
			LOGI("connect SUCCESS, ret:%d, fd is %d", ret, fd);
			break;
		}
		
	 	LOGI("create socket error with return %d: %s(errno: %d)\n",ret, strerror(errno),errno);

		sleep(i+1); //延迟后再次尝试连接

		if (ret < 0 && i == 2)
		{
			LOGI("failed to connect socket");
			fd = -1;
			throw errno;
		}
	}
	
}

LocalSocketClient::~LocalSocketClient()
{
}


int LocalSocketClient::ClientSend(unsigned char *buf,int len)
{
	this->msg.len = len + sizeof(int);
	this->msg.buf = new unsigned char[this->msg.len];
	memcpy(this->msg.buf,&len,sizeof(int));
	memcpy(this->msg.buf + sizeof(int),buf,len);
	
	LOGI("ClientSend,len is %d",this->msg.len);
	Print_Data(this->msg.buf,this->msg.len);
	
	int ret = send(this->fd,this->msg.buf,this->msg.len,0);
	delete[] this->msg.buf;
	this->msg.buf = NULL;
	return ret;
}



int LocalSocketClient::RegClientRecvFunc(ClientRecv func)
{
	recvfunc = func;
	pthread_t tid;
	int ret;
	localClientThreadPara.fd = fd;
	localClientThreadPara.recvfunc = func;
	localClientThreadPara.func = clientNotifyFunc;

	ret = pthread_create(&tid,NULL,clientThreadRecv,&localClientThreadPara);

	return ret;

}

int LocalSocketClient::Reconnect()
{
	int ret = 0;
	
	ret = connect(fd, (struct sockaddr *) &serveraddr,sizeof(serveraddr));
	return ret;
}

