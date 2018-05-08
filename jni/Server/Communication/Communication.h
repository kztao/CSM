#ifndef __COMMUNICATION_H
#define __COMMUNICATION_H

class Communication{
public:
	Communication();
	virtual int Send(unsigned char *buf,int len);
	virtual  ~Communication();
};

#endif
