//
// Created by wjr on 19-8-12.
//

#ifndef CSM_SKF_SOFT_UTIL_H
#define CSM_SKF_SOFT_UTIL_H

#include <iostream>
#include <set>
#include "skf_t.h"

using namespace std;

#define SKF_STATUS_DEV_DISCONNECT  0
#define SKF_STATUS_DEV_CONNECT     1
#define SKF_STATUS_DEV_AUTH        2

#define SKF_STATUS_APP_CLOSE        0
#define SKF_STATUS_APP_OPEN         1
#define SKF_STATUS_APP_LOGGIN_ADMIN 2
#define SKF_STATUS_APP_LOGGIN_USR   4

#define SKF_STATUS_CONTAINER_CLOSE        0
#define SKF_STATUS_CONTAINER_OPEN         1


typedef struct skf_soft_devh{
public:
    int status;
    string devName = "westone_soft_skf";
    unsigned char devAuthPlain[16] = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};
    string devLabel;
}SKF_SOFT_DEVH,*SKF_SOFT_DEVH_PTR;

typedef struct skf_soft_apph{
public:
    SKF_SOFT_DEVH_PTR devh_ptr;
    int status;
    string appName;

    string soDefaultPin;
    string soPin;
    DWORD  soPinMaxCount;
    DWORD  soPinRemainCount;

    string usrDefaultPin;
    string usrPin;
    DWORD  usrPinMaxCount;
    DWORD  usrPinRemainCount;

    DWORD rights;
}SKF_SOFT_APPH,*SKF_SOFT_APPH_PTR;


typedef struct skf_soft_containerh{
public:
    SKF_SOFT_APPH_PTR apph_ptr = NULL;
    int status = SKF_STATUS_CONTAINER_CLOSE;
    string containerName;
    DWORD type = 0;
    string pukSign;
    string priSign;
    string pukCry;
    string priCry;
    string certSign;
    string certCry;
}SKF_SOFT_CONTAINERH,*SKF_SOFT_CONTAINERH_PTR;


/*文件句柄*/
typedef struct skf_soft_fileh{
    SKF_SOFT_APPH_PTR apph_ptr;
    string fileName;
    DWORD readRights;
    DWORD writeRights;
    string value;
}SKF_SOFT_FILEH,*SKF_SOFT_FILEH_PTR;

/*证书*/
typedef struct skf_soft_certh{
    SKF_SOFT_CONTAINERH_PTR containerh_ptr;
    ULONG EccType;
    ULONG SignFlg;
    string cert;
}SKF_SOFT_CERTH,*SKF_SOFT_CERTH_PTR;

/*非对称密钥*/
typedef struct skf_soft_asymh{
    SKF_SOFT_CONTAINERH_PTR containerh_ptr;
    bool EccType;
    bool SignFlg;
    string puk;
    string pri;
}SKF_SOFT_ASYMH,*SKF_SOFT_ASYMH_PTR;

/*对称密钥*/
typedef struct skf_soft_symh{
    SKF_SOFT_DEVH_PTR devh_ptr;
    SKF_SOFT_CONTAINERH_PTR containerh_ptr;
    ULONG ulAlgId;
    ULONG paddingType;
    string iv;
    string key;
}SKF_SOFT_SYMH,*SKF_SOFT_SYMH_PTR;

/*HASH MAC对象*/
typedef struct skf_soft_handleh{
    SKF_SOFT_DEVH_PTR devh_ptr;
    ULONG ulAlgID;
}SKF_SOFT_HANDLEH,*SKF_SOFT_HANDLEH_PTR;

class skf_soft_util {
public:
    static string prefixApp;
    static string prefixContainer;
    static string prefixFile;

    static string nameAuthKey;
    static string nameLabel;
    static string nameSoDefaultPin;
    static string nameSoPin;
    static string nameSoPinMaxCount;
    static string nameSoPinRemainCount;

    static string nameUsrDefaultPin;
    static string nameUsrPin;
    static string nameUsrPinMaxCount;
    static string nameUsrPinRemainCount;
    static string nameRights;

    static string nameFileContent;
    static string nameFileReadRight;
    static string nameFileWriteRight;

    static string nameContainerPukSign;
    static string nameContainerPriSign;
    static string nameContainerCertSign;

    static string nameContainerPukCry;
    static string nameContainerPriCry;
    static string nameContainerCertCry;

    static string nameContainerType;

    static string devAuthRnd;
    static string devDir;
    static string devManufacturer;

    static set<SKF_SOFT_DEVH_PTR > setDevHandle;//设备句柄
    static set<SKF_SOFT_APPH_PTR> setAppHandle;//应用句柄
    static set<SKF_SOFT_CONTAINERH_PTR > setContainerHandle;//容器句柄
    static set<SKF_SOFT_SYMH_PTR > setSessionKeyHandle;  // session key handle
    static set<SKF_SOFT_FILEH_PTR > setFileHandle;//文件句柄
    static set<SKF_SOFT_CERTH_PTR > setCertHandle;//证书句柄
    static set<SKF_SOFT_ASYMH_PTR > setAysmHandle;//密钥句柄
    static set<SKF_SOFT_HANDLEH_PTR > setHashHandle;//Hash 句柄
private:

};


#endif //CSM_SKF_SOFT_UTIL_H
