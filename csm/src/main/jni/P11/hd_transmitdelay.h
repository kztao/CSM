#include "cryptoki.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include <time.h>
#include "Utils_c.h"
#include <string>

typedef int (*CK_cc_SetTransmitDelay)(unsigned int nDelay1, unsigned int nDelay2); 


bool HD_TransmitDelay_Traning(CK_cc_SetTransmitDelay setfunc,CK_FUNCTION_LIST_PTR function_list_ptr,CK_SESSION_HANDLE hsession, unsigned int nDelay1Start, unsigned int nDelay1End, \
								unsigned int nDelay2Start, unsigned int nDelay2End, \
								unsigned int Interval1, unsigned int Interval2, unsigned int Looptime, int *ret_value);













