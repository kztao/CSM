//
// Created by wang.junren on 2018/6/8.
//

#include "GetPackageName.h"
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>


static const char *tag = "csm_getpackageName";
GetPackageName::GetPackageName() {
	packageName = "";
		
    pid = getpid();
    char pidstr[100];
    char pName[1024];
	memset(pidstr,0,sizeof(pidstr));
	memset(pName,0,sizeof(pName));

	
    std::string s;
    s.append("/proc/");
	if(sizeof(pid)<=sizeof(pidstr))
	{
		snprintf(pidstr,sizeof(pidstr),"%d",(int)pid);
		
		s.append(pidstr);
		s.append("/cmdline");
	
		FILE *p = fopen(s.data(),"r");
		if(p != NULL){
			fread(pName, sizeof(pName),1,p);
			fclose(p);
			packageName.append(pName);
			/*int pos = 0;
			pos = packageName.find(":");
			if(pos != -1){
				packageName = packageName.substr(0,pos);
			}*/
		}
	}

}

GetPackageName::~GetPackageName() {
    this->packageName = "";
}

std::string GetPackageName::GetName() {
    return packageName;
}

