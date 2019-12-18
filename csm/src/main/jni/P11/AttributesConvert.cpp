//
// Created by wang.junren on 2018/7/17.
//

#include <cstring>
#include "AttributesConvert.h"
#include "logserver.h"

using std::string;
static const char *tag = "csm_attributeconvert";
const char *cokekstring = "cokdk_wst_cloud";



CK_KEY_TYPE get_KeytypeAndClass(CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulCount, CK_OBJECT_CLASS_PTR pclass)
{
	CK_KEY_TYPE keyType = 0;
	if(NULL == pTemplate || 0 == ulCount){
		return keyType;
	}

	for(int i = 0; i < ulCount;i++){
		if(CKA_KEY_TYPE == pTemplate[i].type && NULL != pTemplate[i].pValue){
			memcpy(&keyType,
				   pTemplate[i].pValue,
				   pTemplate[i].ulValueLen > sizeof(CK_KEY_TYPE) ? sizeof(CK_KEY_TYPE):pTemplate[i].ulValueLen);
		}

		if(CKA_CLASS == pTemplate[i].type){
			if(pTemplate[i].pValue && pclass){
				memcpy(pclass,pTemplate[i].pValue,pTemplate[i].ulValueLen > sizeof(CK_OBJECT_CLASS) ? sizeof(CK_OBJECT_CLASS):pTemplate[i].ulValueLen);
			}
		}
	}

	return keyType;
}


CK_RV switchSecretKeyTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount,CK_ATTRIBUTE_PTR* pTemplate_new,CK_ULONG_PTR pulCount_new)
{
	CK_BBOOL findSID = CK_FALSE;   //flag whether pTemplate has CKA_SESSKEY_ID attribute
	CK_BYTE_PTR ptmp_id = NULL_PTR;
	CK_ULONG switchtmp_nidlen = 1;   //store the new id length
	CK_ULONG switchidlen = 0;
	CK_BYTE_PTR newid = NULL_PTR;
	CK_ULONG index = 0;
	CK_ULONG j = 0;
	CK_BYTE sid = INVALID_VALUE;
	
	LOGSERVERI(tag,"%s IN", __FUNCTION__);

	
	*pTemplate_new = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * ulCount);	
	if(NULL == *pTemplate_new)
	{
		LOGSERVERE(tag,"%s, malloc fail1",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	
	for(int i=0;i<ulCount;i++)
	{
		(*pTemplate_new)[i].pValue = NULL_PTR;
	}
	
	for(index = 0; index < ulCount; index++)
	{
		if(pTemplate[index].type==CKA_SESSKEY_ID)
		{
			switchtmp_nidlen = switchtmp_nidlen + pTemplate[index].ulValueLen;
			sid = *(CK_BYTE_PTR)pTemplate[index].pValue;
			
			findSID = CK_TRUE;
			continue;
		}

		if(pTemplate[index].type==CKA_ID)
		{
			if(memcmp(pTemplate[index].pValue,cokekstring,strlen(cokekstring)))
			{
				switchidlen = pTemplate[index].ulValueLen;
				switchtmp_nidlen = switchtmp_nidlen + switchidlen;
				ptmp_id = (CK_BYTE_PTR)pTemplate[index].pValue;
				continue;
			}
			else
			{
				//cokek key is used in westone softcard
				LOGSERVERI(tag, "find cokek template");
			}
		}
				
		(*pTemplate_new)[j].type= pTemplate[index].type;
		
		(*pTemplate_new)[j].pValue = NULL_PTR;
		if(pTemplate[index].pValue)
		{		
			(*pTemplate_new)[j].pValue = (CK_BYTE_PTR)malloc(pTemplate[index].ulValueLen*sizeof(CK_BYTE));			
			memcpy((*pTemplate_new)[j].pValue,pTemplate[index].pValue,pTemplate[index].ulValueLen);
		}
		(*pTemplate_new)[j].ulValueLen = pTemplate[index].ulValueLen;
		j++;		
	}

	if(switchtmp_nidlen == 1)
	{	
		*pulCount_new = j;
		LOGSERVERI(tag,"%s OUT, no id or SID", __FUNCTION__);
		return CKR_OK;
	}
	
	newid = (CK_BYTE_PTR)malloc(switchtmp_nidlen);

	if(NULL == newid)
	{
		LOGSERVERE(tag,"%s, malloc fail",__FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	memset(newid,0,switchtmp_nidlen);
	if(findSID)
	{	
		newid[0] = 1;
		newid[1] = sid;
		if(ptmp_id!=NULL_PTR)
		{						
			memcpy(newid+2,ptmp_id,switchidlen);
		}	
	}
	else
	{	
		newid[0] = 0;
		if(ptmp_id!=NULL_PTR)
		{
			memcpy(newid+1,ptmp_id,switchidlen);
		}
	}

	(*pTemplate_new)[j].type = CKA_ID;
	(*pTemplate_new)[j].ulValueLen = switchtmp_nidlen;	
	(*pTemplate_new)[j].pValue = (CK_BYTE_PTR)malloc(switchtmp_nidlen*sizeof(CK_BYTE)); 		
	memcpy((*pTemplate_new)[j].pValue,newid,switchtmp_nidlen);
	
	LOGSERVERI(tag,"new template, id at %ld, len is %ld",j,switchtmp_nidlen);
		
	j++;
	*pulCount_new = j;
	free(newid);
	newid = NULL_PTR;

	LOGSERVERI(tag,"%s OUT2", __FUNCTION__);
	return CKR_OK;
}

void freeTemplate(CK_ATTRIBUTE_PTR* pTemplate,CK_ULONG ulCount)
{
	if(NULL == pTemplate || NULL == (*pTemplate))
	{
		return;
	}
	
	for(int index = 0; index < ulCount; index++)
	{		
		if((*pTemplate)[index].pValue != NULL)
		{
			free((*pTemplate)[index].pValue);
			(*pTemplate)[index].pValue = NULL;
		}
	}
	if(pTemplate)
	{
		free(*pTemplate);
		*pTemplate = NULL;
	}

}

CK_BYTE checkIdAndSID(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount, CK_BYTE_PTR pidIndex, CK_BYTE_PTR psidIndex)
{	
	LOGSERVERD(tag,"%s IN", __FUNCTION__);
	int i=0;
	CK_BYTE ret = 0;
	if(pidIndex)
	{		
		*pidIndex = INVALID_VALUE;
	}
	if(psidIndex)
	{		
		*psidIndex = INVALID_VALUE;
	}
	
	for(i=0;i<ulCount;i++)
	{
		if(pTemplate[i].type == CKA_ID)
		{
			ret++;
			if(pidIndex)
			{
				*pidIndex = i;
			}
		}
		if(pTemplate[i].type == CKA_SESSKEY_ID)
		{
			ret++;
			if(psidIndex)
			{
				*psidIndex = i;
			}
		}
	}
	LOGSERVERI(tag,"%s OUT with ret %d", __FUNCTION__,ret);
	return ret;
}

CK_RV cutIDandSID(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount,CK_ATTRIBUTE_PTR pTemplate_new,CK_ULONG_PTR pulCountNew)
{
	LOGSERVERD(tag,"%s IN", __FUNCTION__);

	int i=0,j=0;
	for(i=0;i<ulCount;i++)
	{
		if((pTemplate[i].type!=CKA_ID) && (pTemplate[i].type!=CKA_SESSKEY_ID))
		{			
			pTemplate_new[j].type = pTemplate[i].type;
			
			pTemplate_new[j].pValue = NULL_PTR;
			if(pTemplate[i].pValue)
			{		
				pTemplate_new[j].pValue = (CK_BYTE_PTR)malloc(pTemplate[i].ulValueLen);			
				memcpy(pTemplate_new[j].pValue,pTemplate[i].pValue,pTemplate[i].ulValueLen);
			}
			pTemplate_new[j].ulValueLen = pTemplate[i].ulValueLen;
			j++;
		}
	}
	*pulCountNew = j;
	
	LOGSERVERI(tag,"%s OUT,ulCountNew is %ld", __FUNCTION__,*pulCountNew);
	return CKR_OK;
}


CK_BYTE isCOKEK(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount)
{	
	LOGSERVERD(tag,"%s IN", __FUNCTION__);
	int i=0;
	CK_BYTE ret = 0;
	
	
	for(i=0;i<ulCount;i++)
	{
		if(pTemplate[i].type == CKA_ID)
		{		
			if(pTemplate[i].pValue && (pTemplate[i].ulValueLen == strlen(cokekstring)))
			{				
				if(!memcmp(pTemplate[i].pValue,cokekstring,strlen(cokekstring)))
				{				
					LOGSERVERI(tag,"%s OUT1 with ret %d", __FUNCTION__,ret);
					return 1;
				}				
			}	
		}	
	}
	
	LOGSERVERI(tag,"%s OUT0 with ret %d", __FUNCTION__,ret);
	return ret;
}



