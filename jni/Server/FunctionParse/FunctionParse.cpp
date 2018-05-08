#include "FunctionParse.h"
#include "ReturnCode.h"

map<string,FunctionParse::funcType> FunctionParse::mapFuncList;

int FunctionParse::call(string name,string src,string &dst){
	if(mapFuncList[name] == NULL){
		return RETURN_CODE_NOT_SUPPORT;
	}else{
		return (this->*mapFuncList[name])(src,dst);
	}
}



