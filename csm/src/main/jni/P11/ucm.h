/********************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2017-2018. All rights reserved.
文件名称: ucm.h
文件描述: UCM模块外部接口定义
创 建 者: kwq
创建时间: 2017年12月4日
修改历史: xx,2017年12月7日
修改历史: xx,2018年2月5日
********************************************************************************/
#ifndef _UCM_H
#define _UCM_H

#include "ucm_error.h"

#ifdef  WIN32
#define UCM_EXPORT     __declspec(dllexport)
#else
#define UCM_EXPORT
#endif

#ifdef __cplusplus
    extern "C" {
#endif
#define SCM_FOR_VOLTE


/***  默认密钥Tag  ***/
#define UCM_DEFAULT_KEY_TAG "DefaultKeyTag"

typedef enum
{
    UCM_NOT_REGISTER,                    /*** 无任何用户注册 ***/
    UCM_USER_REGISTER_ING,                /*** 该用户正在注册 ***/
    UCM_OTHER_USER_REGISTER_ING,        /*** 其它用户正在注册 ***/
    UCM_REGISTER_DONE_USER_MATCH,        /*** 该用户已注册 ***/
    UCM_REGISTER_DONE_USER_UNMATCH,        /*** 其它用户已注册,不支持该用户再次注册 ***/
}ucm_status_e_t;

typedef enum
{
    ASTYPE_START = 0,
    ASTYPE_SMS,
    ASTYPE_EMAIL,
	ASTYPE_CXMAIL_TOKEN,
    ASTYPE_SERVER,
    //EXTEND HERE
    ASTYPE_END = 255
}ucm_astype_e_t;

typedef enum
{
  RID_LDAP_ADDR,           /**iPara: NULL, oPara: ipAddr[UCM_MAX_IP_LEN] + port(unsigned int)**/
  RID_CERT_TEMPLATE,       /**iPara: user_cm_cert_template_param_t   oPara: certTemplate[UCM_MAX_STR_LEN]**/
  RID_USER_DEFINED     /**用户自定义，透传，iPara格式由上层业务定义(如: resourceId，数据类型unsigned long,iParaLen=sizeof(unsigned long))，oPara 格式由上层业务定义**/
}RES_ID;

#define UCM_MAX_STR_LEN            256
#define UCM_MAX_APPID_LEN          UCM_MAX_STR_LEN
#define UCM_MAX_APP_LABLE_LEN      UCM_MAX_STR_LEN
#define UCM_MAX_CERT_TEMPLATE_LEN  UCM_MAX_STR_LEN
#define UCM_MAX_IP_LEN             UCM_MAX_STR_LEN
#define UCM_MAX_USER_NAME_LEN      80
#define UCM_MAX_KEY_TAG_LEN        32
#define UCM_MAX_AS_KEY_LEN         32
#define UCM_MAX_AS_VALUE_LEN       UCM_MAX_STR_LEN
#define UCM_MAX_RES_ID_LEN         UCM_MAX_STR_LEN


#define UCM_MAX_VERIFY_CODE_LEN    6
#define UCM_MAX_GROUP_ID_LEN   	   6
#define UCM_MAX_PIN_LEN   	   32
#define UCM_MIN_PIN_LEN   	   6
#define UCM_MAX_AS_KEY_VALUE_COUNT 16

typedef struct
{
	char key[UCM_MAX_AS_KEY_LEN]; /** 填入字符串key,strlen(key)<UCM_MAX_AS_KEY_LEN **/
	char value[UCM_MAX_AS_VALUE_LEN]; /** 填入字符串value,strlen(value)<UCM_MAX_AS_VALUE_LEN **/
}ucm_askeyvalue_t;

typedef struct
{
	ucm_astype_e_t asType;
	unsigned char asKeyValueCnt;
	ucm_askeyvalue_t asKeyValue[UCM_MAX_AS_KEY_VALUE_COUNT];

}ucm_asparam_t;

typedef struct
{
    ucm_astype_e_t asType;
    unsigned char keyTag[UCM_MAX_KEY_TAG_LEN];
    unsigned int keyTagLen;
}ucm_cert_qcn_param_t;

#define CERT_TEMPLATE_APPID        "$appid"
#define CERT_TEMPLATE_USERNAME   "$username"
#define CERT_TEMPLATE_TAG          "$tag" 

#define RES_LDAP_URL                "LDAP_URL"
#define RES_LDAP_CERT_QCN            "CERT_QCN"
#define RES_LDAP_CERT_TMPLATE        "CERT_TEMPLATE"


typedef void * UCM_HANDLE;
typedef void * SAF_HANDLE;
typedef void * P11_HANDLE;

typedef struct 
{
  char ip[UCM_MAX_IP_LEN];           /*** 生产平台ip   比如"192.168.xxx.xxx" ***/
  unsigned int oWayPort;                 /*** 单向(one-way)SSL服务端口 比如 39069 ，一般指生产与协同计算平台***/
  unsigned int tWayPort;                 /*** 双向(two-way)SSL服务端口 比如 39070 ，一般指密码密码服务管理平台***/
}ucm_ip_para_t;


#ifdef SCM_FOR_VOLTE

#define UCM_MAX_CER_LEN 2048
#define UCM_SIGN_LEN 64
#define UCM_PUBKEY_LEN 64
#define UCM_MAX_DEV_ID_LEN 64


typedef struct 
{	
	unsigned int certLen;
	unsigned char cert[UCM_MAX_CER_LEN];
}ucm_cer_t;

typedef struct
{
 unsigned char  ispuk[UCM_PUBKEY_LEN];         /***初始签名公钥***/
 unsigned char  ispukSign[UCM_SIGN_LEN];  /***对初始签名公钥的签名值***/
 ucm_cer_t drsSCER;                               /***设备注册服务签名证书 ***/
}ucm_dev_info_t;


/********************************************************************************
函 数 名:  ucm_init_with_saf
功能描述:  依赖SAF实例句柄的UCM实例初始化
参数说明: 
  pUcmHandle(out): 指向UCM实例句柄的指针  
  safHandle(in)：SAF实例句柄
  userName(in)：用户名，最大长度UCM_MAX_USER_NAME_LEN
  cspp(in)：UCM_IPPARA *，生产平台地址指针 
 
返 回 值: 
  UCM_OK:  成功
  其它:  失败，返回错误代码
备注:
  
修改历史: 
*********************************************************************************/
UCM_EXPORT int ucm_init_with_saf(UCM_HANDLE *pUcmHandle, SAF_HANDLE safHandle, 
                    const char *userName,  const ucm_ip_para_t *cspp);
                    
/********************************************************************************
函 数 名:  ucm_init_with_p11
功能描述:  依赖P11会话句柄的UCM实例初始化
参数说明: 
  pUcmHandle(out): 指向UCM实例句柄的指针  
  p11Handle(in)：P11会话句柄
  userName(in)：用户名，最大长度UCM_MAX_USER_NAME_LEN
  cspp(in)：生产平台地址指针
返 回 值: 
  UCM_OK:  成功
  其它:  失败，返回错误代码
备注:
  
修改历史: 
*********************************************************************************/
UCM_EXPORT int ucm_init_with_p11(UCM_HANDLE *pUcmHandle, P11_HANDLE p11Handle, 
                    const char *userName, const ucm_ip_para_t *cspp);
                    
/********************************************************************************
函 数 名:  ucm_get_dev_info
功能描述:  获取设备的初始密码服务信息
参数说明: 
  pUcmHandle(out):  指向UCM实例句柄的指针  
  devInfo(out)：设备的初始密码服务信息
 
返 回 值: 
  UCM_OK:  成功
  其它:  失败，返回错误代码
备注:
  
修改历史:             
*********************************************************************************/
UCM_EXPORT int ucm_get_dev_info(UCM_HANDLE pUcmHandle, ucm_dev_info_t *devInfo);

/********************************************************************************
函 数 名:  ucm_get_dev_id
功能描述:  获取设备的id
参数说明: 
  pUcmHandle(out): 指向UCM实例句柄的指针  
  deviceId(out)：设备的ID
  deviceIdLen(out)：设备的ID长度
返 回 值: 
  UCM_OK:  成功
  其它:  失败，返回错误代码
备注:
  
修改历史:             
*********************************************************************************/
UCM_EXPORT int ucm_get_dev_id(UCM_HANDLE pUcmHandle, unsigned char *deviceId, unsigned int *deviceIdLen);

/********************************************************************************
函 数 名:  ucm_dev_sign
功能描述:  获取设备签名
参数说明: 
  pUcmHandle(out): 指向UCM实例句柄的指针
  data(in)：签名数据
  dataLen(in)：签名数据长度
  sign(out)：签名值
  signLen(in/out)：签名值长度
返 回 值: 
  UCM_OK:  成功
  其它:  失败，返回错误代码
备注:
  
修改历史:             
*********************************************************************************/
UCM_EXPORT int ucm_dev_sign(UCM_HANDLE pUcmHandle, const unsigned char *data, 
    unsigned int dataLen, unsigned char *sign, unsigned int *signLen);

#else 

/********************************************************************************
函 数 名:  ucm_init_with_saf
功能描述:  依赖SAF实例句柄的UCM实例初始化
参数说明: 
  pUcmHandle(out): 指向UCM实例句柄的指针  
  safHandle(in)：SAF实例句柄
  userName(in)：用户名，最大长度UCM_MAX_USER_NAME_LEN
  cspp(in)：生产平台地址指针
  csmp(in)：密码服务管理平台地址指针
 
返 回 值: 
  UCMP_OK:  成功
  其它:  失败，返回错误代码
备注:
  
修改历史: 
*********************************************************************************/
UCM_EXPORT int ucm_init_with_saf(UCM_HANDLE *pUcmHandle, SAF_HANDLE safHandle, 
        const char *userName, const ucm_ip_para_t *cspp, const ucm_ip_para_t *csmp);

/********************************************************************************
函 数 名:  ucm_init_with_p11
功能描述:  依赖P11会话句柄的UCM实例初始化
参数说明: 
  pUcmHandle(out): 指向UCM实例句柄的指针  
  p11Handle(in)：P11会话句柄
  userName(in)：用户名，最大长度UCM_MAX_USER_NAME_LEN
  cspp(in)：生产平台地址指针
  csmp(in)：密码服务管理平台地址指针                        
 
返 回 值: 
  UCM_OK:  成功
  其它:  失败，返回错误代码
备注:
  
修改历史: 
*********************************************************************************/
UCM_EXPORT int ucm_init_with_p11(UCM_HANDLE *pUcmHandle, P11_HANDLE p11Handle, 
        const char *userName, const ucm_ip_para_t *cspp, const ucm_ip_para_t *csmp);

#endif   

/********************************************************************************
函 数 名:  ucm_get_appid
功能描述:  获取app的ID
参数说明:              
  appLabel(in): 指向应用标识字符串的指针, 最大长度UCM_MAX_STR_LEN
  appID(out): 指向应用ID字符串的指针, 最大长度UCM_MAX_STR_LEN
  appIDLen(in/out): 指向appID长度值的指针，支持传空取长.
返 回 值: 
  UCM_OK:  成功
  其它:  失败，返回错误代码
备注:
  
修改历史:
********************************************************************************/
UCM_EXPORT int ucm_get_appid(const char *appLabel, char *appID, unsigned int *appIDLen);

/********************************************************************************
函 数 名:  ucm_get_ldap_url
功能描述:  获取ldap的url
参数说明:              
  appID(in): 指向应用ID字符串的指针, 最大长度UCM_MAX_STR_LEN
  url(out): 指向应用url字符串的指针, 最大长度UCM_MAX_STR_LEN
  urlLen(in/out): 指向url长度值的指针，支持传空取长.
返 回 值: 
  UCM_OK:  成功
  其它:  失败，返回错误代码
备注:
  
修改历史:
********************************************************************************/
UCM_EXPORT int ucm_get_ldap_url(const char *appID, char *url, unsigned int *urlLen);

/********************************************************************************
函 数 名:  ucm_get_ldap_cert_qcn
功能描述:  获取ldap的cert查询条件
参数说明:              
  appID(in): 指向应用ID字符串的指针, 最大长度UCM_MAX_STR_LEN
  userName(in): 指向安全账户名字符串的指针，最大长度UCM_MAX_STR_LEN
  keyTag(in): 指向证书标签名字符串的指针，最大长度UCM_MAX_STR_LEN
  certQcn(out): 指向应用certQcn字符串的指针, 最大长度UCM_MAX_STR_LEN
  certQcnLen(in/out): 指向certQcn长度值的指针，支持传空取长.
返 回 值: 
  UCM_OK:  成功
  其它:  失败，返回错误代码
备注:
  
修改历史:
********************************************************************************/
UCM_EXPORT int ucm_get_ldap_cert_qcn(const char *appID, const char *userName,const char *keyTag, char *certQcn, unsigned int *certQcnLen);

/********************************************************************************
函 数 名:  ucm_get_resource
功能描述:  APP获取后台服务资源
参数说明:
  appID(in): 指向应用ID字符串的指针, 最大长度UCM_MAX_STR_LEN
  userName(in): 指向安全账户名字符串的指针，最大长度UCM_MAX_STR_LEN
  resID(in): resource id, 格式：在用户自定义，例如:"LDAP_URL","LDAP_CERT_QCN"
  oPara(out): 指向输出value的指针, 格式 : 用户自定义
  oParaLen(in/out): 指向oPara长度值的指针，支持传空取长.

返 回 值: 
  UCM_OK:  成功
  其它:  失败，返回错误代码
备注:
  
修改历史:
********************************************************************************/
UCM_EXPORT int ucm_get_resource(const char *appID, const char *userName, const char *resID, 
    void *oParam, unsigned int *oParamLen);

/********************************************************************************
函 数 名:  ucm_get_resource_list
功能描述:  APP获取多个后台服务资源
参数说明:
  appID(in): 指向应用ID字符串的指针, 最大长度UCM_MAX_STR_LEN
  userName(in): 指向安全账户名字符串的指针，最大长度UCM_MAX_STR_LEN
  resIDList(in): resource id, 格式：在用户自定义，例如:"LDAP_URL","LDAP_CERT_QCN"
  resIDCnt(in): resource id 个数，最多支持16个
  oPara(out): 指向输出value的指针, 格式 : 用户自定义
  oParaLen(in/out): 指向oPara长度值的指针，支持传空取长.

返 回 值: 
  UCM_OK:  成功
  其它:  失败，返回错误代码
备注:此接口暂时未实现
  
修改历史:
********************************************************************************/
UCM_EXPORT int ucm_get_resource_list(const char *appID, const char *userName, const char *resIDList[16], unsigned int resIDCnt,
        void *oParam[16], unsigned int *oParamLen[16]);

/********************************************************************************
函 数 名:    ucm_release
功能描述:    ucm模块卸载,scm卸载前调用
参数说明:
	ucmHandle :UCM实例句柄
返 回 值: 
    UCM_OK:  成功
    其它:  失败，返回错误代码
备注:
    安全应用退出时须调用
修改历史: 
     
********************************************************************************/
UCM_EXPORT int ucm_release(UCM_HANDLE ucmHandle);

/********************************************************************************
函 数 名:    ucm_get_user_status
功能描述:    获取user的注册状态
参数说明: 
    userName(in):   手机号或邮件账号
    pStatus(out):   ucm_status_e_t 
返 回 值: 
    UCM_OK:  成功
    其它:  失败，返回错误代码
备注:
    
修改历史:      
********************************************************************************/
UCM_EXPORT int ucm_get_user_status(const char *userName, ucm_status_e_t *pStatus);


/********************************************************************************
函 数 名:    ucm_get_devsn
功能描述:    获取中间件唯一标识
参数说明: 
    sn(out):    char* 
    snLen(in/out):int*
返 回 值: 
      0:  成功
    非0:  失败，返回错误代码
备注:
修改历史:      
********************************************************************************/
UCM_EXPORT int ucm_get_devsn(char*sn,int *snLen);


/********************************************************************************
函 数 名:    ucm_local_destroy
功能描述:    本地销毁
参数说明: 
      pin(in):      密码
    pinLen(in):   密码长度
返 回 值: 
    UCM_OK:    成功
    其它:    失败，返回错误代码 
备注:
修改历史:      
********************************************************************************/
UCM_EXPORT int ucm_local_destroy(const char *pin,unsigned int pinLen);


/*******************************************************************************
函 数 名:	ucm_user_get_verifycode
功能描述:	用户获取注册验证码
参数说明: 
  	appID(in):      应用识别码
    userName(in):   用户账号
  	asType(in):		认证类型
返 回 值: 
	USER_CM_OK:  成功
	其它:   失败，返回错误代码
修改历史: 
*******************************************************************************/
UCM_EXPORT int ucm_user_get_verifycode(const char *appID, const char *userName, ucm_astype_e_t asType);


/*******************************************************************************
函 数 名:	ucm_user_register
功能描述:	用户注册
参数说明: 
  	appID(in):      应用识别码
    userName(in):   用户账号
  	asParam(in):    认证参数
返 回 值: 
	USER_CM_OK:  成功
	其它:   失败，返回错误代码
修改历史: 
*******************************************************************************/
UCM_EXPORT int ucm_user_register(const char *appID, const char *userName, const ucm_asparam_t * asParam);


/********************************************************************************
函 数 名:    ucm_cert_req
功能描述:    证书请求，根据认证类型获取签名/加密证书或只获取加密证书
参数说明:
    appId(in):        应用标识
    userName(in):      指定的安全用户账号
    keyTag(in):       证书标签
    asParam(in):      认证参数
返 回 值: 
    UCM_OK:   成功
    其它:   失败，返回错误代码

修改历史: 

********************************************************************************/
UCM_EXPORT int ucm_cert_req(const char* appID,const char* userName, const char* keyTag, const ucm_asparam_t * asParam);


/********************************************************************************
函 数 名:    ucm_enc_cert_req
功能描述:    加密证书请求
参数说明: 
    appId(in):        应用标识   
    userName(in):      指定的安全用户账号  
    keyTag(in):       证书标签
返 回 值: 
    UCM_OK:   成功
    其它:   失败，返回错误代码

修改历史: 

********************************************************************************/
UCM_EXPORT int ucm_enc_cert_req(const char* appID,const char* userName,const char* keyTag);

/********************************************************************************
函 数 名:    ucm_update_cert
功能描述:    更新证书
参数说明: 
返 回 值: 
    UCM_OK:   成功
    其它:   失败，返回错误代码
修改历史: 

********************************************************************************/
UCM_EXPORT int ucm_update_cert();

/********************************************************************************
函 数 名:    ucm_update_kdk
功能描述:    更新密钥分发密钥
参数说明: 
返 回 值: 
    UCM_OK:   成功
    其它:   失败，返回错误代码
修改历史: 

********************************************************************************/
UCM_EXPORT int ucm_update_kdk();

/********************************************************************************
函 数 名:    ucm_get_gk
功能描述:    获取群组密钥
参数说明: 
    appId(in):            应用标识
    userName(in):         指定的安全用户账号 
    groupID(in):          群组编号
    groupKeyVersion(in):  群组密钥版本
返 回 值: 
    UCM_OK:   成功
    其它:   失败，返回错误代码
修改历史: 

********************************************************************************/
UCM_EXPORT int ucm_get_gk(const char* appID,const char* userName,const char* groupID, int groupKeyVersion);

 
#ifdef __cplusplus
}
#endif


#endif/*** _UCM_H ***/                    
