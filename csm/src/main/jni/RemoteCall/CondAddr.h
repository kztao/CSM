//
// Created by wang.junren on 2018/6/7.
//

#ifndef CSM_CONDADDR_H
#define CSM_CONDADDR_H

#include <sys/types.h>
#include <pthread.h>

class CondAddr {
public:
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    bool mrecvsponse;

	CondAddr(){
		mrecvsponse= false;
		pthread_mutex_init(&mutex,NULL);
    	pthread_cond_init(&cond,NULL);
	}
	~CondAddr() {
	    pthread_mutex_destroy(&mutex);
	    pthread_cond_destroy(&cond);
	}
};


#endif //CSM_CONDADDR_H
