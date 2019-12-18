#include "hd_transmitdelay.h"
#include "p11definef.h"
#include "logserver.h"

// p11LibMtx is created to eliminate P11 interface confliction (HD card time parameter training)
// ECM call HD_TransmitDelay_Traning/ZucTest interface and bypass normal socket/proxy routine
// ZucTest call P11 interface which could possibly conflict with normal P11 call from socket/proxy
//pthread_mutex_t p11LibMtx = PTHREAD_MUTEX_INITIALIZER;
static const char *tag = "csm_hd_trans";


CK_BBOOL login = CK_FALSE;
CK_SESSION_HANDLE glob_session = 0;
CK_cc_SetTransmitDelay glob_set_func;



enum DELAY_TRAN_STATE
{
    DELAY_TRAN_STATE_UNUSE = 0,
    DELAY_TRAN_STATE_YES,
    DELAY_TRAN_STATE_NO
};

struct DELAY_TRAN_ATTR
{
	int delay01;
	int delay02;
	float average_time;
	int max_times;
	enum DELAY_TRAN_STATE state;
};
typedef struct DELAY_TRAN_ATTR *PDELAY_TRAN_ATTR;


#define STD_MAX_AVERAGE_TIME 15
#define STD_MAX_TIMES 4
#define GROUP_SIZE 2
#define MAX(a,b)  (((a) > (b)) ? (a) : (b))
#define MIN(a,b)  (((a) < (b)) ? (a) : (b))

//Set all buffer data to zero
#define BUFFER_REFRESH_ZERO(data1,data1len,data2,data2len)\
	do\
{\
	data1len = sizeof(data1);\
	memset(data1, 0, data1len);\
	data2len=sizeof(data2);\
	memset(data2, 0, data2len);\
}while(0)


int global_datalen;
int global_looptime;

static void RandomGenerate(unsigned char* dataaddress, unsigned int cnt)
{
	int i,randt,randmaxx=0x7FFFFFFF-0x7FFFFFFF%0xFF;
	for(i=0;i<cnt;i++)
	{
		randt = rand();
		while( randt > randmaxx ) 
		{
			randt = rand();
		}
		dataaddress[i] = (unsigned char)(randt % 0x100); // 符合要求的随机数
	}
}


/******************************************************************************
 * 函数名 ZucTest
 *
 * 功能描述: 进行zuc加解密测试
 *
 * 参数说明: 
 * delay01(in): delay01值
 * delay02(in): delay02值
 * datalen(in): 加解密数据长度
 * looptime(in): 加解密运行次数
 * average_time(out): 加解密平均时间
 * max_times(out): 超出门限次数
 *
 * 返回值: ture测试成功。false测试出错。
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static bool ZucTest(CK_FUNCTION_LIST_PTR function_list_ptr,int delay01,int delay02,int datalen,int looptime,float *average_time,int *max_times)
{

	CK_RV rv;
	int i,count;
	bool bRtn = false;

	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_BBOOL ttrue = CK_TRUE;
	CK_BBOOL ffalse = CK_FALSE;
	CK_KEY_TYPE ZUCkeyType = CKK_ZUC;

	//加密参数
	unsigned char ZUCkeyVal_Enc[]={0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char ZUCplain_Enc[128] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char ZUCcipher_Enc[128] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
		0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};
	unsigned char ZUCiv_Enc[] = {0x00, 0x05, 0x68, 0x23, 0x38};

	CK_ATTRIBUTE ZUCkeyTemplate_Enc[5] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Enc,sizeof(ZUCkeyVal_Enc)}
	};
	CK_MECHANISM ZUCmechanism_Enc = {CKM_ZUC_EEA, ZUCiv_Enc, sizeof(ZUCiv_Enc)};
	CK_OBJECT_HANDLE hKey_Enc = NULL_PTR;

	//解密参数
	unsigned char ZUCkeyVal_Dec[]={0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54, 0x30, 0x2a};
	unsigned char ZUCplain_Dec[128] = {0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00, 0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8, 0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22, 0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, \
		0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf, 0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66, 0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba, 0x22, 0x0d, 0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67, 0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00};
	unsigned char ZUCcipher_Dec[128] = {0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85, 0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8, 0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf, 0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb, 0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, \
		0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3, 0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a, 0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0, 0x7b, 0x01, 0x9b, 0x48, 0xac, 0xd1, 0xfe, 0xf3, 0x01, 0x1f, 0x5e, 0x22, 0xd2, 0x97, 0x75, 0xcc, 0x94, 0xc2, 0xca, 0x6f, 0xb0, 0x9c, 0x2d, 0x86, 0xd6, 0xd0, 0x18, 0x3c, 0x24, 0x34};
	unsigned char ZUCiv_Dec[]={0x00, 0x05, 0x68, 0x23, 0x38};

	CK_ATTRIBUTE ZUCkeyTemplate_Dec[5] = 
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_KEY_TYPE, &ZUCkeyType, sizeof(CK_KEY_TYPE)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE,ZUCkeyVal_Dec,sizeof(ZUCkeyVal_Dec)}
	};
	CK_MECHANISM ZUCmechanism_Dec = {CKM_ZUC_EEA, ZUCiv_Dec, sizeof(ZUCiv_Dec)};
	CK_OBJECT_HANDLE hKey_Dec = NULL_PTR;

	CK_ULONG ulSlotCount;
	CK_SLOT_ID_PTR pSlotList = NULL_PTR;
	int slotID;
	CK_SESSION_HANDLE hSession = glob_session;
	unsigned char default_usrerr_pin[] = { 0x31,0x32,0x33,0x34,0x35,0x36};

	CK_BYTE indata[256];
	CK_ULONG indatalen=sizeof(indata);
	CK_BYTE outdata[256];
	CK_ULONG outdatalen=sizeof(outdata);

	CK_BYTE indata1[256];
	CK_ULONG indatalen1=sizeof(indata1);
	CK_BYTE outdata1[256];
	CK_ULONG outdatalen1=sizeof(outdata1);

	unsigned long long t3 = 0;
	unsigned long long t4 = 0;
	UtilscTime ttc1={0, 0},ttc2={0,0},ttc3={0,0},ttc4={0,0},ttc5={0,0};

	int datalen22[] = {32, 64, 96 /*,128, 141*/};
	//int threshold[] = {12, 12, 12 , 15, 18 },timeout;//适用于WT1
	int threshold[] = {15, 15, 15 , 15, 18 },timeout;//适用于WT1

	
	static bool init_flag = false;
//	LOGSERVERI(tag,"enter ZucTest with init_flag=%d, parameter delay01=%d, delay02=%d, datalen=%d, looptime=%d", init_flag, delay01, delay02, datalen, looptime);

	/* 此部分代码调用相当耗时，故整个测试过程中只调用一次 */
	if(init_flag == false)
	{

		//对称加密初始化
		hKey_Enc = NULL_PTR;
		rv =function_list_ptr->C_CreateObject(hSession, ZUCkeyTemplate_Enc, sizeof(ZUCkeyTemplate_Enc)/sizeof(CK_ATTRIBUTE), &hKey_Enc);
		if(rv != CKR_OK)
		{
			LOGSERVERE(tag,"Error:%s rv=0x%lx.","C_CreateObject",rv);
			goto END;
		}

		rv =function_list_ptr->C_EncryptInit(hSession, &ZUCmechanism_Enc, hKey_Enc);
		if(rv != CKR_OK)
		{
			LOGSERVERE(tag,"Error:%s rv=0x%lx.","C_EncryptInit",rv);
			goto END;
		}

		//对称解密初始化
		hKey_Dec = NULL_PTR;
		rv =function_list_ptr->C_CreateObject(hSession, ZUCkeyTemplate_Dec, sizeof(ZUCkeyTemplate_Dec)/sizeof(CK_ATTRIBUTE), &hKey_Dec);
		if(rv != CKR_OK)
		{
			LOGSERVERE(tag,"Error:%s rv=0x%lx.","C_CreateObject",rv);
			goto END;
		}

		rv =function_list_ptr->C_DecryptInit(hSession, &ZUCmechanism_Dec, hKey_Dec);
		if(rv != CKR_OK)
		{
			LOGSERVERE(tag,"Error:%s rv=0x%lx.","C_DecryptInit",rv);
			goto END;
		}
	}


		init_flag = true;
	


	{
		//TODO
		///* 设置延时参数 */
        glob_set_func(delay01, delay02);

		for(i = 0;i < (sizeof(datalen22)/sizeof(datalen22[0]));i++)
		{
			if(datalen22[i] == datalen)break;
		}
		if(i != (sizeof(datalen22)/sizeof(datalen22[0])))
		{
			timeout = threshold[i];
			//LOGSERVERI("threshold:%d \n",timeout);
		}
		else
		{
			goto END;
		}

		count = 0;
		for(i = 0;i < looptime;i++)
		{
			memset(indata,0,indatalen);
			memset(outdata,0,outdatalen);
			memset(indata1,0,indatalen1);
			memset(outdata1,0,outdatalen1);

			//将IV拼接到明文之前
			memcpy(indata, ZUCiv_Enc, sizeof(ZUCiv_Enc));
			memcpy(indata+sizeof(ZUCiv_Enc), ZUCplain_Enc, datalen);
			indatalen = sizeof(ZUCiv_Enc) + datalen;

			/*******************加密过程**********************/
			Utilsgettime(&ttc1);
			rv =function_list_ptr->C_EncryptUpdate(hSession, indata, indatalen, outdata, &outdatalen);
			if(rv != CKR_OK)
			{
				LOGSERVERE(tag,"Error:%s rv=0x%lx.","C_EncryptUpdate",rv);
				goto END;
			}

			Utilsgettime(&ttc2);
			UtilsTimeSubstracted(&ttc2,&ttc1);
			UtilsTimeAdded(&ttc3,&ttc2);

			//将IV拼接到密文之前
			memcpy(indata1, ZUCiv_Dec, sizeof(ZUCiv_Dec));
			memcpy(indata1+sizeof(ZUCiv_Dec), outdata, outdatalen);
			indatalen1 = sizeof(ZUCiv_Dec) + outdatalen;

			/******************解密过程***********************/
			Utilsgettime(&ttc1);
			rv =function_list_ptr->C_DecryptUpdate(hSession, indata1, indatalen1, outdata1, &outdatalen1);
			if(rv != CKR_OK)
			{
				LOGSERVERE(tag,"Error:%s rv=0x%lx.","C_DecryptUpdate",rv);
				goto END;
			}

			Utilsgettime(&ttc5);
			UtilsTimeSubstracted(&ttc5,&ttc1);
			UtilsTimeAdded(&ttc4,&ttc5);

			if (((ttc2).usec + (ttc5).usec) /1000.0f > timeout)
			{
				count++;
			}

			srand((unsigned)time(NULL));//随机数初始化
			//生成随机数明文
			RandomGenerate(ZUCplain_Enc,datalen);
			//生成随机数初始向量
			RandomGenerate(ZUCiv_Enc,5);
			memcpy(ZUCiv_Dec,ZUCiv_Enc,5);
		}


//		Utilsprint(&ttc3,"****Encrypt", looptime);
//		Utilsprint(&ttc4,"****Dencrypt", looptime);


		t3 = Utilsgetuseconds(&ttc3);
		t4 = Utilsgetuseconds(&ttc4);

		*average_time = t3/looptime/1000.0f + t4/looptime/1000.0f;
		*max_times = count;

		bRtn = true;
	}

END:


zuctest_end:

//	LOGSERVERI(tag,"ZucTest return with %d, average_time=%f, max_times=%d", bRtn, *average_time, *max_times);
	function_list_ptr->C_EncryptFinal(hSession, outdata, &outdatalen);
	function_list_ptr->C_DecryptFinal(hSession, outdata, &outdatalen);
	init_flag = false;

	return bRtn;
}


/******************************************************************************
 * 函数名 checkentrybyindex
 *
 * 功能描述: 通过索引判断条目是否满足要求
 *
 * 参数说明: 
 * pobj_attr(in): 条目指针
 * attr_index(in): 条目索引
 * delay02_count(in): delay02的数量
 *
 * 返回值: ture满足要求。false不满足要求。
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static bool checkentrybyindex(CK_FUNCTION_LIST_PTR function_list_ptr,PDELAY_TRAN_ATTR pobj_attr,int attr_index,int delay02_count)
{
		float total_average_time,average_time;
		int total_max_times,max_times;
		int i;
		enum DELAY_TRAN_STATE result;

		int nDelay01 = 0,nDelay02 = 0;
		bool rv = false;

		/* 已经算过了，直接pass */
		if((result = (pobj_attr[attr_index].state)) == DELAY_TRAN_STATE_YES)
		{
			return true;
		}
		if((result = (pobj_attr[attr_index].state)) == DELAY_TRAN_STATE_NO)
		{
			return false;
		}

		total_average_time = 0;
		total_max_times = 0;
		for (i = 0; i < delay02_count; i++)
		{
			nDelay01 = pobj_attr[attr_index + i].delay01;
			nDelay02 = pobj_attr[attr_index + i].delay02;

			/* 设置delay01,delay02获取到平均耗时及超过门限次数 */
			if((rv = ZucTest(function_list_ptr,nDelay01, nDelay02, global_datalen, global_looptime, &average_time, &max_times)) == false)
			{
				return false;	
			}

			pobj_attr[attr_index + i].average_time = average_time;
			pobj_attr[attr_index + i].max_times = max_times;

			/* 得到平均耗时的累加值，获得超过门限次数的累加值 */
			total_average_time += pobj_attr[attr_index + i].average_time;
			total_max_times += pobj_attr[attr_index + i].max_times;
		}
		LOGSERVERI(tag,"delay01_search:%d total_average_time:%1.3f total_max_times:%d",nDelay01,total_average_time,total_max_times);
		if((total_average_time > (STD_MAX_AVERAGE_TIME * delay02_count)) || (total_max_times > STD_MAX_TIMES))
		{
			pobj_attr[attr_index].state = DELAY_TRAN_STATE_NO;
		}
		else
		{
			pobj_attr[attr_index].state = DELAY_TRAN_STATE_YES;
			return true;		
		}

	return false;
}

/******************************************************************************
 * 函数名 checkentrybydelay01
 *
 * 功能描述: 通过delay01判断条目是否满足要求
 *
 * 参数说明: 
 * pobj_attr(in): 条目指针
 * delay01_start(in): delay01起始值
 * delay01_search(in): 待判断的delay01值
 * delay01_step(in): delay01步长
 * delay02_count(in): delay02的数量
 *
 * 返回值: ture满足要求。false不满足要求。
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static bool checkentrybydelay01(CK_FUNCTION_LIST_PTR function_list_ptr, PDELAY_TRAN_ATTR pobj_attr, \
						int delay01_start,int delay01_search,int delay01_step, \
						int delay02_count
						)
{
		float total_average_time,average_time;
		int total_max_times,max_times;
		int i;
		enum DELAY_TRAN_STATE result;

		int nDelay01,nDelay02;
		bool rv = false;

		total_average_time = 0;
		total_max_times = 0;

		/* 已经算过了，直接pass */
		if((result = (pobj_attr[((delay01_search - delay01_start)/delay01_step) * delay02_count].state)) == DELAY_TRAN_STATE_YES)
		{
			return true;
		}
		if((result = (pobj_attr[((delay01_search - delay01_start)/delay01_step) * delay02_count].state)) == DELAY_TRAN_STATE_NO)
		{
			return false;
		}

		for (i = 0; i < delay02_count; i++)
		{
			nDelay01 = pobj_attr[((delay01_search - delay01_start)/delay01_step) * delay02_count + i].delay01;
			nDelay02 = pobj_attr[((delay01_search - delay01_start)/delay01_step) * delay02_count + i].delay02;

			/* 设置delay01,delay02获取到平均耗时及超过门限次数 */
			if((rv = ZucTest(function_list_ptr,nDelay01, nDelay02, global_datalen, global_looptime, &average_time, &max_times)) == false)
			{
				return false;
			}

			/* 设置delay01,delay02获取到平均耗时及超过门限次数 */
			pobj_attr[((delay01_search - delay01_start)/delay01_step) * delay02_count + i].average_time = average_time;
			pobj_attr[((delay01_search - delay01_start)/delay01_step) * delay02_count + i].max_times = max_times;

			/* 得到平均耗时的累加值，获得超过门限次数的累加值 */
			total_average_time += pobj_attr[((delay01_search - delay01_start)/delay01_step) * delay02_count + i].average_time;
			total_max_times += pobj_attr[((delay01_search - delay01_start)/delay01_step) * delay02_count + i].max_times;
		}
		LOGSERVERI(tag,"delay01_search:%d total_average_time:%1.3f total_max_times:%d",delay01_search,total_average_time,total_max_times);
		/* 填充结果 */
		if((total_average_time > (STD_MAX_AVERAGE_TIME * delay02_count)) || (total_max_times > STD_MAX_TIMES))
		{
			pobj_attr[((delay01_search - delay01_start)/delay01_step) * delay02_count].state = DELAY_TRAN_STATE_NO;
		}
		else
		{
			pobj_attr[((delay01_search - delay01_start)/delay01_step) * delay02_count].state = DELAY_TRAN_STATE_YES;
			return true;		
		}

	return false;
}


/******************************************************************************
 * 函数名 entrycompare
 *
 * 功能描述: 条目比较，返回更符合要求的delay01值
 *
 * 参数说明: 
 * pobj_attr(in): 条目指针
 * delay01_1(in): delay01_1值
 * delay01_2(in): delay01_2值
 * delay01_start(in): delay01起始值
 * delay01_step(in): delay01步长
 * delay02_count(in): delay02的数量
 *
 * 返回值: delay01值
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static int entrycompare(PDELAY_TRAN_ATTR pobj_attr,int delay01_1,int delay01_2, \
							int delay01_start,int delay01_step,int delay02_count)
{
	int i;

	float delay01_1_total_average_time;
	int delay01_1_total_max_times;

	float delay01_2_total_average_time;
	int delay01_2_total_max_times;

	delay01_1_total_average_time = 0;
	delay01_1_total_max_times = 0;
	for (i = 0; i < delay02_count; i++)
	{
		/* 得到平均耗时的累加值，获得超过门限次数的累加值 */
		delay01_1_total_average_time += pobj_attr[((delay01_1 - delay01_start)/delay01_step) * delay02_count + i].average_time;
		delay01_1_total_max_times += pobj_attr[((delay01_1 - delay01_start)/delay01_step) * delay02_count + i].max_times;
	}

	delay01_2_total_average_time = 0;
	delay01_2_total_max_times = 0;
	for (i = 0; i < delay02_count; i++)
	{
		/* 得到平均耗时的累加值，获得超过门限次数的累加值 */
		delay01_2_total_average_time += pobj_attr[((delay01_2 - delay01_start)/delay01_step) * delay02_count + i].average_time;
		delay01_2_total_max_times += pobj_attr[((delay01_2 - delay01_start)/delay01_step) * delay02_count + i].max_times;
	}

	if(delay01_1_total_average_time >= delay01_2_total_average_time)
	{
		return delay01_2;
	}
	else
	{
		return delay01_1;
	}
}


/******************************************************************************
 * 函数名 checkleftentry
 *
 * 功能描述: 判断左边条目是否满足要求
 *
 * 参数说明: 
 * pobj_attr(in): 条目指针
 * delay01_start(in): delay01起始值
 * delay01_end(in): delay01_1结束值
 * delay01_step(in): delay01步长
 * delay01_search(in): delay01查询值
 * delay02_count(in): delay02的数量
 *
 * 返回值: ture满足要求。false不满足要求。
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static bool checkleftentry(CK_FUNCTION_LIST_PTR function_list_ptr,PDELAY_TRAN_ATTR pobj_attr, \
						int delay01_start,int delay01_end,int delay01_step, \
						int delay01_search, \
						int delay02_count
						)
{
	if(delay01_search < (delay01_start + delay01_step))return false;
	if(delay01_search > (delay01_end + delay01_step))return false;

	return checkentrybydelay01(function_list_ptr,pobj_attr,delay01_start,delay01_search - delay01_step,delay01_step,delay02_count);
}

/******************************************************************************
 * 函数名 checkrightentry
 *
 * 功能描述: 判断右边条目是否满足要求
 *
 * 参数说明: 
 * pobj_attr(in): 条目指针
 * delay01_start(in): delay01起始值
 * delay01_end(in): delay01_1结束值
 * delay01_step(in): delay01步长
 * delay01_search(in): delay01查询值
 * delay02_count(in): delay02的数量
 *
 * 返回值: ture满足要求。false不满足要求。
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static bool checkrightentry(CK_FUNCTION_LIST_PTR function_list_ptr,PDELAY_TRAN_ATTR pobj_attr, \
						int delay01_start,int delay01_end,int delay01_step, \
						int delay01_search, \
						int delay02_count
						)
{
	if(delay01_search < (delay01_start - delay01_step))return false;
	if(delay01_search > (delay01_end - delay01_step))return false;

	return checkentrybydelay01(function_list_ptr,pobj_attr,delay01_start,delay01_search + delay01_step,delay01_step,delay02_count);
}

/******************************************************************************
 * 函数名 search_range
 *
 * 功能描述: 查找范围
 *
 * 参数说明: 
 * pobj_attr(in): 条目指针
 * delay01_start(in): delay01起始值
 * delay01_end(in): delay01_1结束值
 * delay01_step(in): delay01步长
 * delay01_search_middle(in): delay01查询值
 * delay02_count(in): delay02的数量
 * psearch_array(out)：满足要求的delay01值
 * range_count(in/out)：(in)描述psearch_array数组的大小。(out)满足要求的delay01值个数
 *
 * 返回值: 无。
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static void search_range(CK_FUNCTION_LIST_PTR function_list_ptr,PDELAY_TRAN_ATTR pobj_attr, \
						int delay01_start,int delay01_end,int delay01_step, \
						int delay01_search_middle,int delay02_count, \
						int *psearch_array,int *range_count)
{
	int wish_goal,wish_goal_half,left_goal,right_goal;
	int padding_count;
	int search_current;
	int count,i;
	bool result;

	/* 保证不为偶数 */
	wish_goal = (*range_count - 1) - ((*range_count - 1)%2);
	wish_goal_half = wish_goal/2;

	left_goal = 0;
	right_goal = 0;

	/* 从左侧找 */
	for(i = 0;i < wish_goal;i++)
	{
		search_current = delay01_search_middle - delay01_step * i;
		if((result = checkleftentry(function_list_ptr,pobj_attr,delay01_start,delay01_end,delay01_step, \
									search_current, \
									delay02_count)) == true)
		{
			left_goal++;
		}
		else
		{
			break;
		}
	}

	/* 从右侧找 */
	for(i = 0;i < wish_goal;i++)
	{
		search_current = delay01_search_middle + delay01_step * i;
		if((result = checkrightentry(function_list_ptr,pobj_attr,delay01_start,delay01_end,delay01_step, \
									search_current, \
									delay02_count)) == true)
		{
			right_goal++;
		}
		else
		{
			break;
		}
	}

	count = 0;
	/* 两边都大于等于需求数一半，各取一半 */
	if((left_goal >= wish_goal_half) && (right_goal >= wish_goal_half))
	{
		padding_count = wish_goal_half;
		for(i = 0;i < padding_count;i++)
		{
			*(psearch_array + i) = delay01_search_middle - (delay01_step * (padding_count - i));
			count++;
		}
		*(psearch_array + padding_count) = delay01_search_middle;
		count++;
		for(i = 0;i < padding_count;i++)
		{
			*(psearch_array + padding_count + 1 + i) = delay01_search_middle + (delay01_step * (1 + i));
			count++;
		}
	}
	/* 左边大于等于需求数一半，先取右边，再取左边 */
	else if((left_goal >= wish_goal_half) && (right_goal < wish_goal_half))
	{
		padding_count = MIN((wish_goal - right_goal),left_goal);
		for(i = 0;i < padding_count;i++)
		{
			*(psearch_array + i) = delay01_search_middle - (delay01_step * (padding_count - i));
			count++;
		}
		*(psearch_array + padding_count) = delay01_search_middle;
		count++;
		for(i = 0;i < right_goal;i++)
		{
			*(psearch_array + padding_count + 1 + i) = delay01_search_middle + (delay01_step * (1 + i));
			count++;
		}
	}
	else if((right_goal >= wish_goal_half) && (left_goal < wish_goal_half))
	{
		for(i = 0;i < left_goal;i++)
		{
			*(psearch_array + i) = delay01_search_middle - (delay01_step * (left_goal - i));
			count++;
		}
		*(psearch_array + left_goal) = delay01_search_middle;
		count++;
		padding_count = MIN((wish_goal - left_goal),right_goal);
		for(i = 0;i < padding_count;i++)
		{
			*(psearch_array + left_goal + 1 + i) = delay01_search_middle + (delay01_step * (1 + i));
			count++;
		}
	}
	/* 两边都未达到需求数一半，两边皆取完 */
	else
	{
		for(i = 0;i < left_goal;i++)
		{
			*(psearch_array + i) = delay01_search_middle - (delay01_step * (left_goal - i));
			count++;
		}
		*(psearch_array + left_goal) = delay01_search_middle;
		count++;
		for(i = 0;i < right_goal;i++)
		{
			*(psearch_array + left_goal + 1 + i) = delay01_search_middle + (delay01_step * (1 + i));
			count++;
		}
	}
	*range_count = count;
}

/******************************************************************************
 * 函数名 searchbottom
 *
 * 功能描述: 查找波谷(本函数需要多次调用)
 *
 * 参数说明: 
 * pobj_attr(in): 条目指针
 * delay01_start(in): delay01起始值
 * delay01_end(in): delay01_1结束值
 * delay01_step(in): delay01步长
 * delay01_search_middle(in): delay01查询值
 * delay02_count(in): delay02的数量
 *
 * 返回值: 满足要求的值。
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static int searchbottom(CK_FUNCTION_LIST_PTR function_list_ptr,PDELAY_TRAN_ATTR pobj_attr, \
						int delay01_start,int delay01_end,int delay01_step, \
						int delay01_search_middle,int delay02_count
						)
{
	bool left_result = false,right_result = false;
	int delay01_search_left,delay01_search_right;
	bool compare_result = true;
	int compare_value = 0;

	delay01_search_left = delay01_search_middle - delay01_step;
	delay01_search_right = delay01_search_middle + delay01_step;

	/* 计算两端条目的值 */
	if(delay01_search_left >= delay01_start)
	{
		left_result = checkentrybydelay01(function_list_ptr,pobj_attr,delay01_start,delay01_search_left,delay01_step,delay02_count);
	}

	if(delay01_search_right <= delay01_end)
	{
		right_result = checkentrybydelay01(function_list_ptr,pobj_attr,delay01_start,delay01_search_right,delay01_step,delay02_count);
	}

	/* 得出谁来和middle进行比较 */
	if(left_result == true && right_result == true)
	{
		compare_value = entrycompare(pobj_attr,delay01_search_left,delay01_search_right, \
												delay01_start,delay01_step,delay02_count);
	}
	else if(left_result == true)
	{
		compare_value = delay01_search_left;
	}
	else if(right_result == true)
	{
		compare_value = delay01_search_right;
	}
	else
	{
		compare_result = false;
	}

	if(compare_result == false)return delay01_search_middle;

	return entrycompare(pobj_attr,delay01_search_middle,compare_value, \
									delay01_start,delay01_step,delay02_count);
}

/******************************************************************************
 * 函数名 getfinalresult
 *
 * 功能描述: 获得最终结果
 *
 * 参数说明: 
 * pobj_attr(in): 条目指针
 * group_size(in): pobj_attr中包含的长度组数
 * delay02_count(in): delay02数量
 * pcompare_array(in): 结果delay01数组
 * array_count(in): pcompare_array个数
 * final_result(out): 最终结果
 *
 * 返回值: true表示最终结果有效，false表示最终结果无效。
 *
 * 修改历史:       
 *
 * 修改时间    修改人      修改内容说明
 * 
******************************************************************************/
static bool getfinalresult(PDELAY_TRAN_ATTR pobj_attr,int group_size,int delay02_count, \
							int *pcompare_array,int array_count,int *final_result)
{
	int i,j;
	PDELAY_TRAN_ATTR psearch_obj_attr;
	float *ptotal_average_time_array = NULL,max_total_average_time;

	if(array_count == 0)return false;

	if(array_count == 1)
	{
		*final_result= *pcompare_array;
		return true;
	}

	ptotal_average_time_array = (float *)malloc(array_count * sizeof(float));
	if(ptotal_average_time_array == NULL)
	{
		LOGSERVERE(tag,"malloc memory failed! ");
		return false;
	}

	/* 初始化ptotal_average_time_array和max_total_average_time */
	memset(ptotal_average_time_array,0x00,array_count * sizeof(float));
	max_total_average_time = 9999;
	for(i = 0;i < array_count;i++)
	{
		psearch_obj_attr = pobj_attr;
		/* psearch_obj_attr移动到满足delay01的首项 */
		do
		{
			if(psearch_obj_attr->delay01 == pcompare_array[i])break;
			psearch_obj_attr++;
		}
		while(psearch_obj_attr->delay01 < pcompare_array[i]);

		/* 该项不满足条件，为了不让其参与最终结果计算，故将其平均值赋值为较大值 */
		if(psearch_obj_attr->state == DELAY_TRAN_STATE_NO)
		{
			ptotal_average_time_array[i] = 9999;
			continue;
		}

		for(j = 0;j < (group_size * delay02_count);j++)
		{
			ptotal_average_time_array[i] += psearch_obj_attr->average_time;
			//LOGSERVERI("delay01:%d delay02:%d average_time:%1.3f \n",psearch_obj_attr->delay01, \
			//	psearch_obj_attr->delay02, psearch_obj_attr->average_time);
			psearch_obj_attr++;
		}
		//LOGSERVERI("ptotal_average_time_array[%d]:%1.3f \n",i,ptotal_average_time_array[i]);
		max_total_average_time = MIN(max_total_average_time,ptotal_average_time_array[i]);
	}
	for(i = 0;i < array_count;i++)
	{
		if(ptotal_average_time_array[i] == max_total_average_time)
		{
			*final_result = pcompare_array[i];
			break;
		}
	}

	free(ptotal_average_time_array);

	return true;
}

bool HD_TransmitDelay_Traning(CK_cc_SetTransmitDelay setfunc,CK_FUNCTION_LIST_PTR function_list_ptr,CK_SESSION_HANDLE hsession, unsigned int nDelay1Start, unsigned int nDelay1End, \
								unsigned int nDelay2Start, unsigned int nDelay2End, \
								unsigned int Interval1, unsigned int Interval2, unsigned int Looptime, int *ret_value)
{
	int i,total_count,proper_delay01;
	int delay01_start,delay01_end,delay01_step,delay01_count;
	int delay02_start,delay02_end,delay02_step,delay02_count;
	int range_array[5] = {0},range_index,range_count;
	bool result,rv = false;

	PDELAY_TRAN_ATTR pobj_attr = NULL;
	
	global_looptime = Looptime;
	glob_session = hsession;
	glob_set_func = setfunc;
	if(glob_set_func == NULL_PTR)
	{
		LOGSERVERE(tag,"no set func");
		return false;
	}
	
	
	delay01_start = nDelay1Start;
	delay01_end = nDelay1End;
	delay01_step = Interval1;
	delay01_count = (delay01_end - delay01_start)/delay01_step + 1;

	delay02_start = nDelay2Start;
	delay02_end = nDelay2End;
	delay02_step = Interval2;
	delay02_count = (delay02_end - delay02_start)/delay02_step + 1;

	LOGSERVERI(tag,"Enter HD_TransmitDelay_Traning");

	total_count = delay01_count*delay02_count;
	pobj_attr = (PDELAY_TRAN_ATTR)malloc(sizeof(struct DELAY_TRAN_ATTR)*total_count);
	if(pobj_attr == NULL)
	{
		LOGSERVERE(tag,"malloc memory failed!");
		goto exit_traning_pass_free;
	}

	/* 初始化结构体，并填充delay01,delay02*/
	memset(pobj_attr,0x00,sizeof(struct DELAY_TRAN_ATTR)*total_count);
	for (i = 0; i < total_count; i++)
	{
		pobj_attr[i].delay01 = delay01_start + (i/delay02_count)*delay01_step;
		pobj_attr[i].delay02 = delay02_start + (i%delay02_count)*delay02_step;
	}

	/* 找到首个满足要求的条目，并拿到满足要求的范围 */
	{
		int search_array[3] = {0},search_current,search_return;

		search_array[0] = delay01_start;
		search_array[1] = delay01_start + ((delay01_end - delay01_start)/2) - (((delay01_end - delay01_start)/2)%delay01_step);
		search_array[2] = delay01_end;

		global_datalen = 96;

		/* 进行首次检索，以找到一个满足条件的项 */
		for(i = 0; i < (sizeof(search_array)/sizeof(search_array[0])); i++)
		{
			search_current = search_array[i];
			if((result = checkentrybydelay01(function_list_ptr,pobj_attr,delay01_start,search_current,delay01_step,delay02_count)) == true)
			{
				//LOGSERVERI("result:%d \n",result);
				goto check_result;
			}
			//LOGSERVERI("result:%d \n",result);
		}
check_result:
		/* 找到满足项*/
		if(result == true)
		{
			search_array[1] = search_current;
		}
		else
		{
			do
			{
				/* 压缩范围 */
				search_array[0] = search_array[0] + ((search_array[1] - search_array[0])/2) \
				 - (((search_array[1] - search_array[0])/2)%delay01_step);
				search_array[2] = search_array[1] + ((search_array[2] - search_array[1])/2) \
				 - (((search_array[2] - search_array[1])/2)%delay01_step);
				for(i = 0;i < (sizeof(search_array)/sizeof(search_array[0])); i++)
				{
					if(i == 1)continue;
					search_current = search_array[i];
					if((result = checkentrybydelay01(function_list_ptr,pobj_attr,delay01_start,search_current,delay01_step,delay02_count)) == true)
					{
						//LOGSERVERI("result:%d \n",result);
						goto check_result;
					}
					//LOGSERVERI("result:%d \n",result);
				}
				/* 检索完毕，并未找到 */
				if(((search_array[0] + delay01_step) == search_array[1]) || \
				((search_array[1]) == search_array[2]))
				{
					break;
				}
			}while(1);
		}
		if(result != true)
		{
			LOGSERVERE(tag,"search failed!");
			goto exit_traning;
		}

		/* 开始查找波谷 */
		search_return = search_array[1];
		do
		{
			search_current = search_return;
			search_return = searchbottom(function_list_ptr,pobj_attr,delay01_start,delay01_end,delay01_step, \
											search_current,delay02_count);
		}
		while(search_return != search_current);

		//LOGSERVERI("search_return:%d \n",search_return);

		range_count = sizeof(range_array)/sizeof(range_array[0]);
		/* 以波谷为中心，试图找出range_count组满足要求的条目 */
		search_range(function_list_ptr,pobj_attr,delay01_start,delay01_end,delay01_step, \
						search_return,delay02_count, \
						&range_array[0],&range_count);

	/*	for(i = 0;i < range_count;i++)
		{
			LOGSERVERI(tag,"range_count[%d]:%d",i,range_array[i]);
		}*/
	}
	free(pobj_attr);
	pobj_attr = NULL;

	/* 延伸到其他几组中进行计算 */
	total_count = GROUP_SIZE * range_count * delay02_count;
	//LOGSERVERI("total_count:%d \n",total_count);

	pobj_attr = (PDELAY_TRAN_ATTR)malloc(sizeof(struct DELAY_TRAN_ATTR)*total_count);
	if(pobj_attr == NULL)
	{
		LOGSERVERE(tag,"malloc memory failed!");
		goto exit_traning_pass_free;
	}

	/* 初始化结构体，并填充delay01,delay02*/
	memset(pobj_attr,0x00,sizeof(struct DELAY_TRAN_ATTR)*total_count);
	for (i = 0; i < total_count; i++)
	{
		pobj_attr[i].delay01 = range_array[i/(GROUP_SIZE * delay02_count)];
		pobj_attr[i].delay02 = delay02_start + (i%delay02_count)*delay02_step;
	}

	{
		int max_goal,max_count,*result_array = NULL,*compare_array = NULL;
		int datalen22[] = {32, 64, 128, 141};

		result_array = (int *)malloc(range_count * sizeof(int));
		if(result_array == NULL)
		{
			LOGSERVERE(tag,"malloc memory failed!");
			goto exit_traning;
		}

		compare_array = (int *)malloc(range_count * sizeof(int));
		if(compare_array == NULL)
		{
			LOGSERVERE(tag,"malloc memory failed!");
			free(result_array);
			goto exit_traning;
		}

		for(i = 0;i < range_count;i++)
		{
			result_array[i] = 0;
		}

		/* 计算 */
		for (i = 0; i <= (total_count - delay02_count);)
		{
			global_datalen = datalen22[(i/delay02_count)%GROUP_SIZE];
			range_index = i / (GROUP_SIZE * delay02_count);
			if((result = checkentrybyindex(function_list_ptr,pobj_attr,i,delay02_count)) == true)
			{
				result_array[range_index] = result_array[range_index] + 1;
				//LOGSERVERI("i:%d range_index:%d result_array[%d]:%d \n",i,range_index,range_index,result_array[range_index]);
			}

			i += delay02_count;
		}
		/* 找到最高分 */
		max_goal = 0;
		for(i = 0;i < range_count;i++)
		{
			max_goal = MAX(max_goal,result_array[i]);
//			LOGSERVERI(tag,"range_array[%d]:%d",i,range_array[i]);
//			LOGSERVERI(tag,"result_array[%d]:%d",i,result_array[i]);
		}
		/* 得出最高分出现的次数 */
		max_count = 0;
		for(i = 0;i < range_count;i++)
		{
			if((result_array[i] == max_goal) && (max_goal >= GROUP_SIZE))
			{
				compare_array[max_count++] = range_array[i];
			}
		}
		if((result = getfinalresult(pobj_attr,GROUP_SIZE,delay02_count,compare_array,max_count,&proper_delay01)) == true)
		{
			LOGSERVERI(tag,"delay01 is:%d",proper_delay01);
			*ret_value = proper_delay01;
			rv = true;
		}

		free(compare_array);
		free(result_array);
	}

exit_traning:
	free(pobj_attr);
exit_traning_pass_free:

	LOGSERVERI(tag,"Leave HD_TransmitDelay_Traning");

	return rv;
}



