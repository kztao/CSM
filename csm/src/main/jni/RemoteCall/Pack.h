#ifndef __WESTONE_PACK_H
#define __WESTONE_PACK_H
#include <map>
#include "CondAddr.h"
#include "logdefine.h"

using std::string;
using std::map;

class Pack
{
private:
	int ID;
	//CondAddr m_condAddr;
	static int globeID;
    static map<int,CondAddr*> MapCond;
	//static map<int,char> MapWaitFlag;
	ComLog g_mComLog;
	void printlog(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...);
public:
	Pack();
	virtual ~Pack();
    int GetID();
    int TimeWait(int mseconds);
    static void Del(int id);
    static int Signal(int id);
	void setlogfunc(ComLog logfunc);

};

#endif //__WESTONE_PACK_H

