//
// Created by wjr on 19-4-18.
//

#ifndef __SKF_H
#define __SKF_H

#include "skf_t.h"

#undef SKF_NEED_ARGS
#define SKF_NEED_ARGS

#undef SKF_FUNCTION
#define SKF_FUNCTION(returnType,name) returnType name
#include "skf_f.h"


#undef SKF_FUNCTION
#define SKF_FUNCTION(returnType,name) returnType (* name)


typedef struct SKFFunctionList{
#include "skf_f.h"
}SKFFunctionList,*SKFFunctionList_PTR,**SKFFunctionList_PTR_PTR;

ULONG SKF_GetFunctionList(SKFFunctionList_PTR_PTR ppList);



#undef SKF_FUNCTION
#define SKF_FUNCTION(returnType,name) typedef returnType (*Pointer_##name)
#include <skf_f.h>
#define SKF_POINTER(name) Pointer_##name

#endif//__SKF_H