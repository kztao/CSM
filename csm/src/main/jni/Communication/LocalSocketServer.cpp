#include "LocalSocketServer.h"
#include <sys/socket.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <map>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>



using std::string;
using std::map;
using std::vector;
using std::make_pair;

#define MAX_SET_NUM 5
#define SERVER_VERSION "3.1.8"

static const char *tag = "csm_localsocketServer";

class LocalSocketServerComm : public CommunicationServer::Communication
{
private:
    int fd;
    static map<int,LocalSocketServerComm *> mapLocalSocketServerComm;
	ComLog g_Log;
	
	void printlog(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...){
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
public:
    LocalSocketServerComm(int fd,ComLog logfunc){
        this->fd = fd;
        mapLocalSocketServerComm.insert(make_pair(fd,this));
		g_Log = logfunc;
    }

/*    LocalSocketServerComm* GetComm(int fd){
        map<int,LocalSocketServerComm *>::iterator it;
        it = mapLocalSocketServerComm.find(fd);
        if(it != mapLocalSocketServerComm.end()){
            return it->second;
        }
        return NULL;
    }*/

    virtual int Send(unsigned char *buf,int len) override{
        string msg;
        int msgLen = len;

        msg.append((const char*)&msgLen,sizeof(msgLen));
        msg.append((const char*)buf,len);

        int ret = send(fd,msg.data(),msg.size(),0);
        if(ret > 0)
        {
            printlog(C_info,__FUNCTION__,__LINE__,"Server Send data to fd %d, len is %d, ret = %d", fd, msg.size(),ret);
        }
        else
        {
            printlog(C_info,__FUNCTION__,__LINE__,"Server Send Error!, ret is %d, errno is %d", ret, errno);
        }
		
        return ret;
    }

    virtual int Close() override{
        int ret;
        shutdown(fd,SHUT_RDWR);
        ret = close(fd);
        return ret;
    }
    virtual ~LocalSocketServerComm(){
		printlog(C_info,__FUNCTION__,__LINE__,"~LocalSocketServerComm call");
    }

/*	ComLog getlogfunc(){
	    return g_Log;
	}*/
};

map<int,LocalSocketServerComm *> LocalSocketServerComm::mapLocalSocketServerComm;
/*
void* ConnectThread(LocalSocketServer *args)
{
	struct sockaddr_un saddr = { 0 };
	socklen_t clen = sizeof(saddr);
	int clientFd = 0;


	if(NULL == args){
        args->printlog(C_error,__FUNCTION__,__LINE__,"No para in connect thread!");
		printlog(C_info,__FUNCTION__,__LINE__,"No para in connect thread!");
		return NULL;
	}

	while(1){
		printlog(C_info,__FUNCTION__,__LINE__,"Wait for connect!!!,server sd = %d",args->sfd);
		clientFd = accept(args->sfd,(struct sockaddr *) &saddr, &clen);
		if(clientFd < 0)
		{
			printlog(C_error,__FUNCTION__,__LINE__,"accept error, ERRONO is %s, tmp-sfd is %d",strerror(errno), args->sfd);
			printlog(C_error,__FUNCTION__,__LINE__,"End of connect threads");
			return NULL;
		}
		else
		{
			printlog(C_info,__FUNCTION__,__LINE__,"client %d connect!!!",clientFd);
            pthread_mutex_lock(&(args->mtx));
            args->vectorFd.push_back(clientFd);
            CommunicationServer::Communication *tmpCommunication = new LocalSocketServerComm(clientFd);
            args->mapCommunicationServer.insert(make_pair(clientFd,tmpCommunication));
			printlog(C_info,__FUNCTION__,__LINE__,"Current UserNo: %d",args->vectorFd.size());
			if(args->globefunc != NULL)
			{
               args->globefunc(tmpCommunication,CLIENT_OK);
			}
			
            pthread_mutex_unlock(&(args->mtx));
		}
	}
	
}
*/
void* RecvThread(LocalSocketServer *args){
    fd_set fdClientSet;
    struct timeval val = {0,0};
    int clientFd = 0;
    struct sockaddr_un saddr = { 0 };
    socklen_t clen = sizeof(saddr);

    if(NULL == args){		
        return NULL;
    }
    args->printlog(C_info,__FUNCTION__,__LINE__,"recv thread start");
    while (1){	
		int maxFd = 0;
        pthread_mutex_lock(&(args->mtx));
         if(true == args->flgExit){
             args->printlog(C_error,__FUNCTION__,__LINE__,"End of recv thread");
			
			pthread_mutex_unlock(&(args->mtx));
            return NULL;
        }
		 
		pthread_mutex_unlock(&(args->mtx));


        FD_ZERO(&fdClientSet);

        // add server sfd in set
        FD_SET(args->sfd, &fdClientSet);
        maxFd = args->sfd;

        vector<int>::iterator it;

        for(it = args->vectorFd.begin();it != args->vectorFd.end();it++){
            FD_SET(*it,&fdClientSet);
            maxFd = maxFd < *it ? *it:maxFd;
        }

        args->printlog(C_info,__FUNCTION__,__LINE__,"START select");
        int ret = select(maxFd + 1,&fdClientSet,NULL,NULL,NULL);
		
		if(ret == 0){
			args->printlog(C_info,__FUNCTION__,__LINE__,"select return");
            continue;
        }
        if(ret < 0){
			args->printlog(C_info,__FUNCTION__,__LINE__,"select error: %d",errno);
            break;
        }

        // new connection from client
        if(FD_ISSET(args->sfd,&fdClientSet)){
            //clientFd = -1;
            clientFd = accept(args->sfd,(struct sockaddr *) &saddr, &clen);
            if(clientFd < 0)
            {
				args->printlog(C_info,__FUNCTION__,__LINE__,"accept error, ERRONO is %s, tmp-sfd is %d",strerror(errno), args->sfd);
            }
            else
            {
                args->printlog(C_info,__FUNCTION__,__LINE__,"client %d connect!!!",clientFd);
                args->vectorFd.push_back(clientFd);
                CommunicationServer::Communication *tmpCommunication = new LocalSocketServerComm(clientFd,args->g_mComLog);
                args->mapCommunicationServer.insert(make_pair(clientFd,tmpCommunication));
                args->printlog(C_info,__FUNCTION__,__LINE__,"Current UserNo: %d",args->vectorFd.size());
                if(args->m_NofityFunc != NULL)
                {
                    args->m_NofityFunc(tmpCommunication,CLIENT_OK);
                }
            }
            continue;
        }

        // handle msg from client
        for(it = args->vectorFd.begin();it != args->vectorFd.end();it++){
            if(FD_ISSET(*it,&fdClientSet)){
                args->printlog(C_debug,__FUNCTION__,__LINE__,"server receive info");
                int len = 0;
                int recvLen = recv(*it,&len, sizeof(len),0);
                if(recvLen != sizeof(len) || len >10240){
                    args->printlog(C_error,__FUNCTION__,__LINE__,"%d recv error1, recvLen = %d", *it, recvLen);
					if(recvLen==-1)
					{
                        args->printlog(C_error,__FUNCTION__,__LINE__, "errno: %d,reason = %s", errno,strerror(errno));
					}

                    shutdown(*it,SHUT_RDWR);
                    close(*it);
                    
					//notify client the status change
					if(args->m_NofityFunc!=NULL)
					{						
						args->m_NofityFunc(args->mapCommunicationServer[*it],CLIENT_DISCONNECTED);
					}
					delete(args->mapCommunicationServer[*it]);
					args->mapCommunicationServer[*it] = NULL;
                    args->mapCommunicationServer.erase(*it);
					args->vectorFd.erase(it);
                    break;
                } 
				else{
                    unsigned char *buf = new unsigned char[len];
                    recvLen = recv(*it,buf, len,0);
                    if(recvLen != len){						
						args->printlog(C_error,__FUNCTION__,__LINE__,"recv error2, recvLen = %d, len = %d", recvLen,len);
						if(recvLen==-1)
						{
							args->printlog(C_error,__FUNCTION__,__LINE__, "recv errno: %d,reason = %s", errno,strerror(errno));
						}
						
                        shutdown(*it,SHUT_RDWR);
                        close(*it);
                        delete[] buf;
						buf = NULL;
                        					                    						
						//notify client the status change
						if(args->m_NofityFunc!=NULL)
						{						
							args->m_NofityFunc(args->mapCommunicationServer[*it],CLIENT_DISCONNECTED);
						}
						delete(args->mapCommunicationServer[*it]);
						args->mapCommunicationServer[*it] = NULL;
                        args->mapCommunicationServer.erase(*it);
						args->vectorFd.erase(it);
						
                        break;
                    } 
					else{
						if(args->m_RecvFunc != NULL)
						{
	                        map<int,CommunicationServer::Communication*>::iterator itMap;
	                        itMap = args->mapCommunicationServer.find(*it);
	                        args->printlog(C_debug,__FUNCTION__,__LINE__,"before call recv func");
	                        args->m_RecvFunc((CommunicationServer*)args,itMap->second,buf,len);
	                        args->printlog(C_debug,__FUNCTION__,__LINE__,"end call recv func");
                    	}
						else
						{
							args->printlog(C_error,__FUNCTION__,__LINE__,"reg recvfunc is null. nothing to call back");
						}
						delete[] buf;
						buf = NULL;
					}
                }
            }
        }
    }

    args->printlog(C_error,__FUNCTION__,__LINE__,"recvthread end");
    return NULL;
}

LocalSocketServer::~LocalSocketServer() {
	printlog(C_info,__FUNCTION__,__LINE__,"enter ~LocalSocketServer");
    shutdown(sfd, SHUT_RDWR);
    close(sfd);	
    this->flgExit = true;		
}

LocalSocketServer::LocalSocketServer(char * pServerName, ServerNotifyClientStatus notifyfuc) throw(int)
{
	g_mComLog = NULL;
	printlog(C_info,__FUNCTION__,__LINE__,"ls server version: %s",SERVER_VERSION);
	
	struct sockaddr_un saddr = { 0 };
	struct sockaddr_un caddr = { 0 };
//	socklen_t clen = sizeof(caddr);
	pthread_t tid;

//	int tempfd = -1;
	int ret = 0;

	pthread_mutex_init(&mtx,NULL);

    m_NofityFunc = notifyfuc;

	printlog(C_info,__FUNCTION__,__LINE__,"new LocalSocketServer start");
	sfd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sfd < 0)
	{
		printlog(C_error,__FUNCTION__,__LINE__,"Server: Create Socket ERRONO is %d,reason = %s", errno,strerror(errno));
		throw errno;
	}

	saddr.sun_family = AF_LOCAL;
	strcpy(&saddr.sun_path[1], pServerName);
	saddr.sun_path[0] = 0;

	int on = 1;
    ret = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (ret < 0)
    {  
        printlog(C_error,__FUNCTION__,__LINE__,"setsockopt fail ERRONO is %d", errno);
		throw (int)errno;
    }
        
	ret = bind(sfd, (const struct sockaddr *) &saddr, (socklen_t)(strlen(pServerName) + 1));
	if (ret < 0)
	{
		printlog(C_error,__FUNCTION__,__LINE__,"bind fail ERROR is %s", strerror(errno));
		throw (int)errno;
	}

	ret = listen(sfd, MAX_SET_NUM);
	if (ret < 0)
	{
		printlog(C_error,__FUNCTION__,__LINE__,"listen fail ERRONO is %x", errno);
		throw (int)errno;
	}
    
    this->flgExit = false;
}

LocalSocketServer::LocalSocketServer(char * pServerName, ServerNotifyClientStatus notifyfuc, ComLog log) throw(int)
{
	g_mComLog = log;

    printlog(C_info,__FUNCTION__,__LINE__,"ls server version: %s",SERVER_VERSION);
	
	struct sockaddr_un saddr = { 0 };
	struct sockaddr_un caddr = { 0 };
//	socklen_t clen = sizeof(caddr);
	pthread_t tid;

//	int tempfd = -1;
	int ret = 0;

	pthread_mutex_init(&mtx,NULL);

    m_NofityFunc = notifyfuc;

	printlog(C_info,__FUNCTION__,__LINE__,"new LocalSocketServer start");
	sfd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sfd < 0)
	{
		printlog(C_error,__FUNCTION__,__LINE__,"Server: Create Socket ERRONO is %d,reason = %s", errno,strerror(errno));
		throw errno;
	}

	saddr.sun_family = AF_LOCAL;
	strcpy(&saddr.sun_path[1], pServerName);
	saddr.sun_path[0] = 0;

	int on = 1;
    ret = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (ret < 0)
    {  
        printlog(C_error,__FUNCTION__,__LINE__,"setsockopt fail ERRONO is %d", errno);
		throw (int)errno;
    }
        
	ret = bind(sfd, (const struct sockaddr *) &saddr, (socklen_t)(strlen(pServerName) + 1));
	if (ret < 0)
	{
		printlog(C_error,__FUNCTION__,__LINE__,"bind fail ERROR is %s", strerror(errno));
		throw (int)errno;
	}

	ret = listen(sfd, MAX_SET_NUM);
	if (ret < 0)
	{
		printlog(C_error,__FUNCTION__,__LINE__,"listen fail ERRONO is %x", errno);
		throw (int)errno;
	}

	this->flgExit = false;
	
}

LocalSocketServer::LocalSocketServer(unsigned short port,
									 ServerNotifyClientStatus notifyfuc) throw(int){
    g_mComLog = NULL;
	printlog(C_info,__FUNCTION__,__LINE__,"ls server version: %s",SERVER_VERSION);

    struct sockaddr_in saddr = { 0 };
    struct sockaddr_in caddr = { 0 };
//    socklen_t clen = sizeof(caddr);
    pthread_t tid;

//    int tempfd = -1;
    int ret = 0;

    pthread_mutex_init(&mtx,NULL);

    m_NofityFunc = notifyfuc;

    printlog(C_info,__FUNCTION__,__LINE__,"new LocalSocketServer start");
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0)
    {
        printlog(C_error,__FUNCTION__,__LINE__,"Server: Create Socket ERRONO is %d,reason = %s", errno,strerror(errno));
        throw errno;
    }

    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int on = 1;
    ret = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (ret < 0)
    {
        printlog(C_error,__FUNCTION__,__LINE__,"setsockopt fail ERRONO is %d", errno);
        throw (int)errno;
    }

    ret = bind(sfd, (const struct sockaddr *) &saddr, sizeof(saddr));
    if (ret < 0)
    {
        printlog(C_error,__FUNCTION__,__LINE__,"bind fail ERROR is %s", strerror(errno));
        throw (int)errno;
    }

    ret = listen(sfd, MAX_SET_NUM);
    if (ret < 0)
    {
        printlog(C_error,__FUNCTION__,__LINE__,"listen fail ERRONO is %x", errno);
        throw (int)errno;
    }

    this->flgExit = false;
}


int LocalSocketServer::BroadCast(string funcName,string src)
{
	int ret = 0;
	vector<int>::iterator i;
	string msg;
    int msgLen = pack->Pack(funcName,src).size();
    msg.append((const char*)&msgLen,sizeof(msgLen));
    msg.append((const char*)pack->Pack(funcName,src).data(),pack->Pack(funcName,src).size());

	for(i = vectorFd.begin();i!=vectorFd.end();i++)
	{	
		ret = send(*i,msg.data(),msg.size(),0);
		printlog(C_info,__FUNCTION__,__LINE__,"send to %d",*i);
		if(ret <= 0)
		{
			printlog(C_error,__FUNCTION__,__LINE__,"broadcast send error, ret = %d, socket %d",ret, (*i));
		}
	}

	return ret;
}

int LocalSocketServer::RegServerRecvFunc(serverRecvFuncType func)
{
	int ret;
    this->m_RecvFunc = func;
	ret = pthread_create(&tid_recv,NULL,(void*(*)(void*))RecvThread,this);
	return ret;
}

void LocalSocketServer::printlog(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...){
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





