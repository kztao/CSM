#include "Mutex.h"
#include <pthread.h>
#include <time.h>
#include "ReturnCode.h"
#include "log.h"
#include <errno.h>

pthread_mutex_t globeDataMutex = PTHREAD_MUTEX_INITIALIZER;
int Mutex::globeID = 1;
map<int,MutexAndCond> Mutex::mapIDAndMutex;


Mutex::Mutex(){
	pthread_mutex_init(&mutex,NULL);
	pthread_cond_init(&cond,NULL);
	if(globeID == 0){
		globeID++;
	}

	MutexAndCond tmp;
	tmp.pMutex = &mutex;
	tmp.pCond = &cond;

	pthread_mutex_lock(&globeDataMutex);
	ID = globeID;
	globeID++;
	mapIDAndMutex[ID] = tmp;
	pthread_mutex_unlock(&globeDataMutex);
}

Mutex::~Mutex(){
}

int Mutex::Lock(){
	int ret = pthread_mutex_lock(&mutex);
	return ret;
}

int Mutex::Unlock(){
	int ret = pthread_mutex_unlock(&mutex);
	return ret;
}

int Mutex::Lock(int msgID){
	map<int,MutexAndCond>::iterator it;
	pthread_mutex_lock(&globeDataMutex);
	it = mapIDAndMutex.find(msgID);
	pthread_mutex_unlock(&globeDataMutex);
	if(it != mapIDAndMutex.end()){
		MutexAndCond mAndC = it->second;
		pthread_mutex_lock(mAndC.pMutex);
	}
}

int Mutex::Signal(int msgID){
	map<int,MutexAndCond>::iterator it;
	pthread_mutex_lock(&globeDataMutex);
	it = mapIDAndMutex.find(msgID);
	pthread_mutex_unlock(&globeDataMutex);
	if(it != mapIDAndMutex.end()){
		MutexAndCond mAndC = it->second;
		pthread_cond_signal(mAndC.pCond);
	}
	
	return RETURN_CODE_OK;
}

int Mutex::Unlock(int msgID){
	int ret;
	map<int,MutexAndCond>::iterator it;

	pthread_mutex_lock(&globeDataMutex);
	it = mapIDAndMutex.find(msgID);
	pthread_mutex_unlock(&globeDataMutex);

	if(it != mapIDAndMutex.end()){
		
		MutexAndCond mAndC = it->second;		
		ret = pthread_mutex_unlock(mAndC.pMutex);
		return ret;
	}
	
	return RETURN_CODE_OK;
}

int Mutex::TimeWait(int mseconds){
	struct timespec tm;
	int ret = 0;
	LOGI("%s IN",__FUNCTION__);
	clock_gettime(CLOCK_REALTIME,&tm);
	tm.tv_nsec += mseconds * 1000 * 1000;
	if(tm.tv_nsec >= 1000*1000*1000){
		tm.tv_sec += 1;
		tm.tv_nsec -= 1000*1000*1000;	
	}
	
	ret = pthread_cond_timedwait(&cond,&mutex,&tm);

	pthread_mutex_destroy(&mutex);
	pthread_cond_destroy(&cond);
	
	
	return ret;
}

int Mutex::GetID(){
	return ID;
}

