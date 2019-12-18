#include "Mutex.h"

Mutex::Mutex(){
	pthread_mutex_init(&m_mutex,NULL);
}

Mutex::~Mutex(){
    pthread_mutex_destroy(&m_mutex);
}

int Mutex::Lock(){
	int ret = pthread_mutex_lock(&m_mutex);
	return ret;
}

int Mutex::Unlock(){
	int ret = pthread_mutex_unlock(&m_mutex);
	return ret;
}

pthread_mutex_t* Mutex::getMutex(){
	return &m_mutex;
}	


