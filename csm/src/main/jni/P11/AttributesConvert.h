//
// Created by wang.junren on 2018/7/17.
//

#ifndef CSM_ATTRIBUTESCONVERT_H
#define CSM_ATTRIBUTESCONVERT_H

#include "cryptoki.h"
#define INVALID_VALUE 0xFF

CK_KEY_TYPE get_KeytypeAndClass(CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulCount, CK_OBJECT_CLASS_PTR pclass);
CK_RV switchSecretKeyTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount,CK_ATTRIBUTE_PTR* pTemplate_new,CK_ULONG_PTR pulCount_new);
void freeTemplate(CK_ATTRIBUTE_PTR* pTemplate,CK_ULONG ulCount);
CK_BBOOL checkIdAndSID(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount, CK_BYTE_PTR pidIndex, CK_BYTE_PTR psidIndex);
CK_RV cutIDandSID(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount,CK_ATTRIBUTE_PTR pTemplate_new,CK_ULONG_PTR pulCountNew);
CK_BYTE isCOKEK(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount);



#endif //CSM_ATTRIBUTESCONVERT_H
