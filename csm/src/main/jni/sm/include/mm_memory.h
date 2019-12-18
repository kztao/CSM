#ifndef _MM_MEMORY_H
#define _MM_MEMORY_H

#if (__APPLE__ || __MACH__)
#include <stdlib.h>
//#include <sys/malloc.h>
#else
#include <malloc.h>
#endif

#include <memory.h> 

#define MM_MEMCPY		memcpy		/* 内存复制 */
#define MM_MEMCMP		memcmp		/* 内存比较 */
#define MM_MEMSET		memset		/* 内存填充 */

#define MM_MALLOC		malloc		/* 内存分配 */
#define MM_FREE(pt)/* 内存释放 */{\
	if ((pt) != NULL) {\
		free(pt);\
		(pt) = NULL;\
	}\
}








#endif /* _MM_MEMORY_H */
