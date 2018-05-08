#ifndef __FUNCTION_PARSE_H
#define __FUNCTION_PARSE_H

#include <string>
#include <map>
using namespace std;

class FunctionParse
{
public:
	virtual int call(string name,string src,string &dst) final;
protected:
	typedef int (FunctionParse::*funcType)(const string src,string &dst);
	static map<string,funcType> mapFuncList;	
};

#endif //__FUNCTION_PARSE_H
