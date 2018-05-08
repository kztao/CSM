#ifndef __WESTONE_MUTEX_H
#define __WESTONE_MUTEX_H
#include <map>
#include <pthread.h>

using namespace std;

class MutexAndCond{
public:
	pthread_mutex_t *pMutex;
	pthread_cond_t *pCond;
};

class Mutex
{
private:
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int ID;
	static int globeID;
	static map<int,MutexAndCond> mapIDAndMutex;
public:
	Mutex();
	virtual ~Mutex();
	int Lock();
	int TimeWait(int mseconds);
	int Unlock();

	static int Lock(int msgID);
	static int Signal(int msgID);
	static int Unlock(int msgID);
	
	int GetID();

};

#endif //__MUTEX_H

