#ifndef _MM_MEMORY_H
#define _MM_MEMORY_H

#if (__APPLE__ || __MACH__)
#include <stdlib.h>
//#include <sys/malloc.h>
#else
#include <malloc.h>
#endif

#include <memory.h> 

#define MM_MEMCPY		memcpy		/* �ڴ渴�� */
#define MM_MEMCMP		memcmp		/* �ڴ�Ƚ� */
#define MM_MEMSET		memset		/* �ڴ���� */

#define MM_MALLOC		malloc		/* �ڴ���� */
#define MM_FREE(pt)/* �ڴ��ͷ� */{\
	if ((pt) != NULL) {\
		free(pt);\
		(pt) = NULL;\
	}\
}








#endif /* _MM_MEMORY_H */
