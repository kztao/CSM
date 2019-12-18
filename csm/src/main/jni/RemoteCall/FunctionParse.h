#ifndef __FUNCTION_PARSE_H
#define __FUNCTION_PARSE_H

#include "CommunicationServer.h"


#include <string>
#include <map>
#include <logdefine.h>

using std::string;
using std::map;

class FunctionParse
{
public:
    FunctionParse();
    virtual ~FunctionParse();

	int call(string name,string src,string &dst);
 	int err(int errNum,string &dst) ;

	void RegCommServer(CommunicationServer *pServer);
	int BroadCast(string funcName,string src);

	virtual void setClientName(string name)final;
	virtual string getPackageName()final ;
	
	int PackageNameCheck(string src, string &dst);
	string gloMonopolizePackageName;
	void setlogFunc(ComLog logfunc);
protected:
	typedef int (FunctionParse::*funcType)(const string src,string &dst);
	map<string,funcType> mapFuncList;
	string packageName;
	CommunicationServer *pServer;
private:
	pthread_mutex_t mutex;
	ComLog g_mComLog;
	void printlog(Com_LogSeverity severity, const char* func, unsigned int line, const char* format,  ...);
	
};

#endif //__FUNCTION_PARSE_H
