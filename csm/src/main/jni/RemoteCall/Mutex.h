#ifndef __WESTONE_MUTEX_H
#define __WESTONE_MUTEX_H

#include <pthread.h>

class Mutex
{
private:
	pthread_mutex_t m_mutex;
public:
	Mutex();
	virtual ~Mutex();
	int Lock();
	int Unlock();
	pthread_mutex_t* getMutex();
};

#endif //__MUTEX_H

