#include "log.h"

void Print_Data(unsigned char * buf,int len){

	string s;
	char num[3] = {0};
	
	for(int i  = 0;i < len;i++){
		sprintf(num,"%02X",buf[i]);
		s.append(num);
		if((i + 1) %16 == 0){
			s.append("\n");
			continue;
		}
		
		if((i + 1) %4 == 0){
			s.append(" ");
		}
		
	}

	if(len % 16 != 0){
	    s += "\n";		
	}

	LOGI("%s\n",s.c_str());
	
}
