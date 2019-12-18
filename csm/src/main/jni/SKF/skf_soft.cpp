//
// Created by wjr on 19-8-12.
//
#include <jni.h>
#include <iostream>
#include "skf_soft_util.h"
#include "sm4.h"
#include "sm2.h"
#include "sm3.h"
#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

using namespace std;

#if 1
#include <android/log.h>
#define SKF_DEBUG(...) __android_log_print(ANDROID_LOG_INFO,"skf_wjr",__VA_ARGS__)
void SKF_DEBUG_DATA(char *data,int len){
    string s;
    char num[3] = {0};
    for(int i = 0;i < len;i++){
        sprintf(num,"%02x",(data[i] & 0xFF));
        s.append(num);
        if((i + 1) % 16 == 0){
            s.append("\n");
            continue;
        }

        if((i + 1) % 4 == 0){
            s.append(" ");
        }

    }

    SKF_DEBUG("data[%d]",len);
    SKF_DEBUG("%s",s.c_str());
}

#endif

#define CHECK_BOOL(flg) { \
    if(!flg){ \
    return false; \
    } \
}

int mkDirApp(string appName){
    string dir;
    dir.append(skf_soft_util::devDir);
    dir.append("/");
    dir.append(skf_soft_util::prefixApp);
    dir.append(appName);

    int ret = mkdir(dir.c_str(),S_IRWXU);
    return ret;
}

int mkDirFile(string appName,string fileName){
    string dir;
    dir.append(skf_soft_util::devDir);
    dir.append("/");
    dir.append(skf_soft_util::prefixApp);
    dir.append(appName);

    dir.append("/");
    dir.append(skf_soft_util::prefixFile);
    dir.append(fileName);

    int ret = mkdir(dir.c_str(),S_IRWXU);
    return ret;
}

int mkDirContainer(string appName,string containerName){
    string dir;
    dir.append(skf_soft_util::devDir);
    dir.append("/");
    dir.append(skf_soft_util::prefixApp);
    dir.append(appName);

    dir.append("/");
    dir.append(skf_soft_util::prefixContainer);
    dir.append(containerName);

    int ret = mkdir(dir.c_str(),S_IRWXU);
    if(ret != 0){
        SKF_DEBUG("%s mkdir error %s",__FUNCTION__,strerror(errno));
        return ret;
    }

    return ret;
}

string getAppDir(string appName){
    string dir;
    dir.append(skf_soft_util::devDir);
    dir.append("/");
    dir.append(skf_soft_util::prefixApp);
    dir.append(appName);
    return dir;
}

string getContainerDir(string appName,string containerName){
    string dir;
    dir.append(skf_soft_util::devDir);
    dir.append("/");
    dir.append(skf_soft_util::prefixApp);
    dir.append(appName);

    dir.append("/");
    dir.append(skf_soft_util::prefixContainer);
    dir.append(containerName);
    return dir;
}

string getFileDir(string appName,string fileName){
    string dir;
    dir.append(skf_soft_util::devDir);
    dir.append("/");
    dir.append(skf_soft_util::prefixApp);
    dir.append(appName);

    dir.append("/");
    dir.append(skf_soft_util::prefixFile);
    dir.append(fileName);
    return dir;
}


void rmPath(string path){
    DIR *dir = opendir(path.c_str());
    if(NULL == dir){
        SKF_DEBUG("dir name is %s,opendir error = %s",path.c_str(),strerror(errno));
        return;
    }

    struct dirent *ptr = NULL;
    while ((ptr=readdir(dir)) != NULL)
    {
        if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0)    ///current dir OR parrent dir
            continue;
        else if(ptr->d_type == DT_REG || ptr->d_type == DT_LNK){
            ///file
            string filePath;
            filePath.append(path);
            filePath.append("/");
            filePath.append(ptr->d_name);
            printf("d_name:%s/%s\n",path.c_str(),ptr->d_name);
            remove(filePath.c_str());
        }
        else if(ptr->d_type == DT_DIR)    ///dir
        {
            string dirPath;
            dirPath.append(path);
            dirPath.append("/");
            dirPath.append(ptr->d_name);
            rmPath(dirPath);
        }
    }

    closedir(dir);
    rmdir(path.c_str());
}

string getContext(string path){
    string s;
    char buf[1024] = {0};
    size_t size = 0;

    FILE *fp = fopen(path.c_str(),"rb");
    if(NULL != fp){
        SKF_DEBUG("%s fopen succeess",path.c_str());
        while ((size = fread(buf,1,sizeof(buf),fp)) > 0){
            s.append(buf,size);
        }

        fclose(fp);
    }

    return s;
}

bool setContext(string path,string context){
    FILE *fp = fopen(path.c_str(),"wb");
    if(NULL == fp){
        SKF_DEBUG("%s set context error %s",path.c_str(),strerror(errno));
        return false;
    }

    fwrite(context.data(),1,context.size(),fp);
    fflush(fp);
    fclose(fp);
    return true;
}


void getDir(string path,set<string> &setDir){
    DIR *dir = opendir(path.c_str());
    if(NULL == dir){
        SKF_DEBUG("dir name is %s,opendir error = %s",path.c_str(),strerror(errno));
        return;
    }

    setDir.clear();
    struct dirent *ptr = NULL;
    while ((ptr=readdir(dir)) != NULL)
    {
        if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0)    ///current dir OR parrent dir
            continue;
        else if(ptr->d_type == DT_REG)    ///file
            printf("d_name:%s/%s\n",path.c_str(),ptr->d_name);
        else if(ptr->d_type == DT_LNK)    ///link file
            printf("d_name:%s/%s\n",path.c_str(),ptr->d_name);
        else if(ptr->d_type == DT_DIR)    ///dir
        {
            setDir.insert(ptr->d_name);
        }
    }

    closedir(dir);
}

void getPathFile(string path,set<string> &setDir){
    DIR *dir = opendir(path.c_str());
    if(NULL == dir){
        SKF_DEBUG("dir name is %s,opendir error = %s",path.c_str(),strerror(errno));
        return;
    }

    setDir.clear();
    struct dirent *ptr = NULL;
    while ((ptr=readdir(dir)) != NULL)
    {
        if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0)    ///current dir OR parrent dir
            continue;
        else if(ptr->d_type == DT_REG)    ///file
            SKF_DEBUG("dir %s file is %s",path.c_str(),ptr->d_name);
        else if(ptr->d_type == DT_LNK)    ///link file
            printf("d_name:%s/%s\n",path.c_str(),ptr->d_name);
        else if(ptr->d_type == DT_DIR)    ///dir
        {
            //SKF_DEBUG("dir name is %s",ptr->d_name);
            setDir.insert(ptr->d_name);
        }
    }

    closedir(dir);
}

bool isFileExist(string path){
    FILE *fp = fopen(path.c_str(),"rb");
    if(NULL == fp){
        SKF_DEBUG("%s open error = %s",path.c_str(),strerror(errno));
        return false;
    }

    fclose(fp);
    return true;
}


bool checkDirAppCom(string path){
    string nameSoDefaultPin;
    string nameSoPin;
    string nameSoPinMaxCount;
    string nameSoPinRemainCount;

    string nameUsrDefaultPin;
    string nameUsrPin;
    string nameUsrPinMaxCount;
    string nameUsrPinRemainCount;

    nameSoDefaultPin.append(path);
    nameSoPin.append(path);
    nameSoPinMaxCount.append(path);
    nameSoPinRemainCount.append(path);

    nameSoDefaultPin.append("/");
    nameSoPin.append("/");
    nameSoPinMaxCount.append("/");
    nameSoPinRemainCount.append("/");

    nameSoDefaultPin.append(skf_soft_util::nameSoDefaultPin);
    nameSoPin.append(skf_soft_util::nameSoPin);
    nameSoPinMaxCount.append(skf_soft_util::nameSoPinMaxCount);
    nameSoPinRemainCount.append(skf_soft_util::nameSoPinRemainCount);

    nameUsrDefaultPin.append(path);
    nameUsrPin.append(path);
    nameUsrPinMaxCount.append(path);
    nameUsrPinRemainCount.append(path);

    nameUsrDefaultPin.append("/");
    nameUsrPin.append("/");
    nameUsrPinMaxCount.append("/");
    nameUsrPinRemainCount.append("/");

    nameUsrDefaultPin.append(skf_soft_util::nameUsrDefaultPin);
    nameUsrPin.append(skf_soft_util::nameUsrPin);
    nameUsrPinMaxCount.append(skf_soft_util::nameUsrPinMaxCount);
    nameUsrPinRemainCount.append(skf_soft_util::nameUsrPinRemainCount);
    
    CHECK_BOOL(isFileExist(nameSoDefaultPin));
    CHECK_BOOL(isFileExist(nameSoPin));
    CHECK_BOOL(isFileExist(nameSoPinMaxCount));
    CHECK_BOOL(isFileExist(nameSoPinRemainCount));

    CHECK_BOOL(isFileExist(nameUsrDefaultPin));
    CHECK_BOOL(isFileExist(nameUsrPin));
    CHECK_BOOL(isFileExist(nameUsrPinMaxCount));
    CHECK_BOOL(isFileExist(nameUsrPinRemainCount));

    return true;
}

string getFileContent(string path,int offset){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameFileContent);
    string src = getContext(s);
    return src;
}

string getFileContent(string path,int offset,int len){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameFileContent);
    string src = getContext(s);

    if(offset > src.size() || offset < 0){
        return "";
    }

    if(offset + len < src.size()){
        return src.substr(offset,offset + len);
    } else{
        return src.substr(offset,src.size());
    }
}


bool setFileContent(string path,int offset,string newContent){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameFileContent);

    string src = getContext(s);
    if(offset > src.size() || offset < 0){
        return false;
    }

    string newOut;

    newOut.append(src.substr(0,offset));
    newOut.append(newContent);
    if(offset + newContent.size() < src.size()){
        newOut.append(src.substr(offset + newContent.size(),src.size()));
    }

    return setContext(s,newOut);
}


DWORD getFileReadRight(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameFileReadRight);

    string src = getContext(s);
    DWORD dword = 0;
    memcpy(&dword,src.data(),src.size());
    return dword;
}

bool setFileReadRight(string path,DWORD right){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameFileReadRight);

    string src;
    DWORD dword = right;

    src.append((char*)&dword, sizeof(dword));

    return setContext(s,src);
}

DWORD getFileWriteRight(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameFileWriteRight);

    string src = getContext(s);
    DWORD dword = 0;
    memcpy(&dword,src.data(),src.size());
    return dword;
}

bool setFileWriteRight(string path,DWORD right){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameFileWriteRight);

    string src;
    DWORD dword = right;

    src.append((char*)&dword, sizeof(dword));

    return setContext(s,src);
}


DWORD getContainerType(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerType);

    string src = getContext(s);
    DWORD dword = 0;
    memcpy(&dword,src.data(),src.size());
    return dword;
}

bool setContainerType(string path,DWORD type){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerType);

    string src;
    DWORD dword = type;

    src.append((char*)&dword, sizeof(dword));

    return setContext(s,src);
}

string getContainerCertSign(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerCertSign);

    return getContext(s);
}

bool setContainerCertSign(string path,string cert){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerCertSign);
    return setContext(s,cert);
}

string getContainerPukSign(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerPukSign);

    return getContext(s);
}

bool setContainerPukSign(string path,string puk){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerPukSign);
    return setContext(s,puk);
}

string getContainerPriSign(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerPriSign);

    return getContext(s);
}

bool setContainerPriSign(string path,string pri){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerPriSign);
    return setContext(s,pri);
}


string getContainerCertCry(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerCertCry);

    return getContext(s);
}

bool setContainerCertCry(string path,string cert){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerCertCry);
    return setContext(s,cert);
}

string getContainerPukCry(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerPukCry);

    return getContext(s);
}

bool setContainerPukCry(string path,string puk){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerPukCry);
    return setContext(s,puk);
}

string getContainerPriCry(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerPriCry);

    return getContext(s);
}

bool setContainerPriCry(string path,string pri){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameContainerPriCry);
    return setContext(s,pri);
}


string getSoDefaultPin(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameSoDefaultPin);
    return getContext(s);
}

bool setSoDefaultPin(string path,string pin){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameSoDefaultPin);
    return setContext(s,pin);
}

string getSoPin(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameSoPin);
    return getContext(s);
}

bool setSoPin(string path,string pin){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameSoPin);
    return setContext(s,pin);
}

DWORD getsoPinMaxCount(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameSoPinMaxCount);

    string context = getContext(s);
    if(context.size() != sizeof(DWORD)){
        return 0;
    }

    DWORD dword = 0;
    memcpy(&dword,context.data(),sizeof(DWORD));
    return dword;
}

bool setsoPinMaxCount(string path,DWORD count){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameSoPinMaxCount);

    DWORD tmp = count;
    string context;
    context.append((char*)&tmp, sizeof(tmp));
    return setContext(s,context);
}


DWORD getsoPinRemainCount(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameSoPinRemainCount);
    string context = getContext(s);
    if(context.size() != sizeof(DWORD)){
        return 0;
    }

    DWORD dword = 0;
    memcpy(&dword,context.data(),sizeof(DWORD));
    return dword;
}

bool setsoPinRemainCount(string path,DWORD count){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameSoPinRemainCount);

    DWORD tmp = count;
    string context;
    context.append((char*)&tmp, sizeof(tmp));
    return setContext(s,context);
}

string getUsrDefaultPin(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameUsrDefaultPin);
    return getContext(s);
}

bool setUsrDefaultPin(string path,string pin){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameUsrDefaultPin);
    return setContext(s,pin);
}

string getUsrPin(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameUsrPin);
    return getContext(s);
}

bool setUsrPin(string path,string pin){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameUsrPin);
    return setContext(s,pin);
}

DWORD getusrPinMaxCount(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameUsrPinMaxCount);
    string context = getContext(s);
    if(context.size() != sizeof(DWORD)){
        return 0;
    }

    DWORD dword = 0;
    memcpy(&dword,context.data(),sizeof(DWORD));
    return dword;
}

bool setusrPinMaxCount(string path,DWORD count){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameUsrPinMaxCount);

    DWORD tmp = count;
    string context;
    context.append((char*)&tmp, sizeof(tmp));
    return setContext(s,context);
}


DWORD getusrPinRemainCount(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameUsrPinRemainCount);
    string context = getContext(s);
    if(context.size() != sizeof(DWORD)){
        return 0;
    }

    DWORD dword = 0;
    memcpy(&dword,context.data(),sizeof(DWORD));
    return dword;
}

bool setusrPinRemainCount(string path,DWORD count){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameUsrPinRemainCount);

    DWORD tmp = count;
    string context;
    context.append((char*)&tmp, sizeof(tmp));
    return setContext(s,context);
}

DWORD getAppRights(string path){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameRights);
    string context = getContext(s);
    if(context.size() != sizeof(DWORD)){
        return 0;
    }

    DWORD dword = 0;
    memcpy(&dword,context.data(),sizeof(DWORD));
    return dword;
}

bool setAppRightst(string path,DWORD rights){
    string s = path;
    s.append("/");
    s.append(skf_soft_util::nameRights);

    DWORD tmp = rights;
    string context;
    context.append((char*)&tmp, sizeof(tmp));
    return setContext(s,context);
}

void checkDevAuthKey(){
    string dir_devAuthKey = skf_soft_util::devDir;
    dir_devAuthKey.append("/");
    dir_devAuthKey.append(skf_soft_util::nameAuthKey);

    string auth_key = getContext(dir_devAuthKey.c_str());
    if(16 != auth_key.size()){
        SKF_DEBUG("%s auth key len error len %d",__FUNCTION__,auth_key.size());
        return;
    }


    string dir_devLabel = skf_soft_util::devDir;
    dir_devLabel.append("/");
    dir_devLabel.append(skf_soft_util::nameLabel);

    string label = getContext(dir_devLabel.c_str());

    if(skf_soft_util::setDevHandle.size() == 0){
        SKF_SOFT_DEVH_PTR devh_ptr = new SKF_SOFT_DEVH();
        memcpy(devh_ptr->devAuthPlain,auth_key.data(), auth_key.size());
        devh_ptr->devLabel = label;
        skf_soft_util::setDevHandle.insert(devh_ptr);
    }

}

void checkApp(){
    string dir_devAuthKey = skf_soft_util::devDir;
    string dir_app = skf_soft_util::devDir;
    set<string> dir;

    getDir(dir_devAuthKey,dir);

    auto it = dir.begin();
    for(;it != dir.end();it++){
        if((*it).size() > skf_soft_util::prefixApp.size() && (*it).find(skf_soft_util::prefixApp) == 0){
            dir_app.clear();
            dir_app.append(dir_devAuthKey);
            dir_app.append("/");
            dir_app.append(*it);
            if(checkDirAppCom(dir_app)){
                SKF_SOFT_APPH_PTR apph_ptr = new SKF_SOFT_APPH();

                apph_ptr->devh_ptr = *skf_soft_util::setDevHandle.begin();
                apph_ptr->status = SKF_STATUS_APP_CLOSE;
                apph_ptr->appName = (*it).substr(skf_soft_util::prefixApp.size());
                apph_ptr->soDefaultPin = getSoDefaultPin(dir_app);
                apph_ptr->soPin = getSoPin(dir_app);
                apph_ptr->soPinMaxCount = getsoPinMaxCount(dir_app);
                apph_ptr->soPinRemainCount = getsoPinRemainCount(dir_app);
                apph_ptr->usrDefaultPin = getUsrDefaultPin(dir_app);
                apph_ptr->usrPin = getUsrPin(dir_app);
                apph_ptr->usrPinMaxCount = getusrPinMaxCount(dir_app);
                apph_ptr->usrPinRemainCount = getusrPinRemainCount(dir_app);
                apph_ptr->rights = getAppRights(dir_app);

                skf_soft_util::setAppHandle.insert(apph_ptr);
            }

        }
    }

}


void checkContainerAndFile(){
    auto it = skf_soft_util::setAppHandle.begin();
    for(;it != skf_soft_util::setAppHandle.end();it++){
        string appDir = getAppDir((*it)->appName);
        set<string> setName;
        setName.clear();
        getDir(appDir,setName);
        auto item = setName.begin();
        for(;item != setName.end();item++){
            if((*item).find(skf_soft_util::prefixContainer) == 0){
                SKF_SOFT_CONTAINERH_PTR containerh_ptr = new SKF_SOFT_CONTAINERH();
                containerh_ptr->apph_ptr = *it;
                containerh_ptr->status = SKF_STATUS_CONTAINER_CLOSE;
                containerh_ptr->containerName = (*item).substr(skf_soft_util::prefixContainer.size());
                containerh_ptr->type = getContainerType(getContainerDir(containerh_ptr->apph_ptr->appName,containerh_ptr->containerName));

                containerh_ptr->certSign = getContainerCertSign(getContainerDir(containerh_ptr->apph_ptr->appName,containerh_ptr->containerName));
                containerh_ptr->pukSign = getContainerPukSign(getContainerDir(containerh_ptr->apph_ptr->appName,containerh_ptr->containerName));
                containerh_ptr->priSign = getContainerPriSign(getContainerDir(containerh_ptr->apph_ptr->appName,containerh_ptr->containerName));

                containerh_ptr->certCry = getContainerCertCry(getContainerDir(containerh_ptr->apph_ptr->appName,containerh_ptr->containerName));
                containerh_ptr->pukCry = getContainerPukCry(getContainerDir(containerh_ptr->apph_ptr->appName,containerh_ptr->containerName));
                containerh_ptr->priCry = getContainerPriCry(getContainerDir(containerh_ptr->apph_ptr->appName,containerh_ptr->containerName));

                skf_soft_util::setContainerHandle.insert(containerh_ptr);

                SKF_DEBUG("%s app contains %s container",(*it)->appName.c_str(),containerh_ptr->containerName.c_str());

            } else if((*item).find(skf_soft_util::prefixFile) == 0){
                SKF_SOFT_FILEH_PTR fileh_ptr = new SKF_SOFT_FILEH();
                fileh_ptr->apph_ptr = *it;
                fileh_ptr->fileName = (*item).substr(skf_soft_util::prefixFile.size());
                fileh_ptr->readRights = getFileReadRight(getFileDir((*it)->appName,fileh_ptr->fileName));
                fileh_ptr->writeRights = getFileWriteRight(getFileDir((*it)->appName,fileh_ptr->fileName));
                fileh_ptr->value = getFileContent(getFileDir((*it)->appName,fileh_ptr->fileName),0);
                skf_soft_util::setFileHandle.insert(fileh_ptr);
                SKF_DEBUG("%s app contains %s file",(*it)->appName.c_str(),fileh_ptr->fileName.c_str());
            }

        }
    }
}

ULONG checkRights(DWORD rights,int status){
    switch (rights){
        case SECURE_ANYONE_ACCOUNT:
            if(status >= SKF_STATUS_APP_OPEN){
                return SAR_OK;
            } else{
                return SAR_INVALIDHANDLEERR;
            }
        case SECURE_USER_ACCOUNT:
            if(status >= SKF_STATUS_APP_LOGGIN_USR){
                return SAR_OK;
            } else{
                return SAR_USER_NOT_LOGGED_IN;
            }
            break;

        case SECURE_ADM_ACCOUNT:
        case (SECURE_ADM_ACCOUNT | SECURE_USER_ACCOUNT):
            if(status >= SKF_STATUS_APP_LOGGIN_ADMIN){
                return SAR_OK;
            } else{
                return SAR_USER_NOT_LOGGED_IN;
            }
        case SECURE_NEVER_ACCOUNT:
            return SAR_UNKNOWNERR;
        default:
            return SAR_UNKNOWNERR;
    }
}

template <typename T>

void unit(set<T> & setT){
    auto it = setT.begin();
    for(;it != setT.end();){
        delete *it;
        setT.erase(it++);
    }
}

/*
 * Class:     com_westone_cardmanager_SoftSkf
 * Method:    setSkfSoftPath
 * Signature: (Ljava/lang/String;)V
 */
extern "C" JNIEXPORT void JNICALL Java_com_westone_cardmanager_SoftSkf_setSkfSoftPath
        (JNIEnv *env, jclass SoftSkf, jstring dir){
    if(NULL == dir){
        skf_soft_util::devDir = "";
    } else{
        const char *dirStr = env->GetStringUTFChars(dir,NULL);
        skf_soft_util::devDir = dirStr;
        env->ReleaseStringUTFChars(dir,dirStr);
    }


    unit(skf_soft_util::setHashHandle);//Hash 句柄
    unit(skf_soft_util::setSessionKeyHandle);  // session key handle
    unit(skf_soft_util::setCertHandle);//证书句柄
    unit(skf_soft_util::setAysmHandle);//密钥句柄
    unit(skf_soft_util::setContainerHandle);//容器句柄
    unit(skf_soft_util::setFileHandle);//文件句柄
    unit(skf_soft_util::setAppHandle);//应用句柄
    unit(skf_soft_util::setDevHandle);//设备句柄

    checkDevAuthKey();
    checkApp();
    checkContainerAndFile();
}



DEVAPI extern "C" ULONG SKF_WaitForDevEvent(
        OUT LPSTR szDevName,
        OUT ULONG *pulDevNameLen,
        OUT ULONG *pulEvent
){ return SAR_OK;
}
/*
 *	取消等待设备的插拔事件
 */
DEVAPI extern "C" ULONG SKF_CancelWaitForDevEvent(){ return SAR_OK;
}


void str2Byte(char *str,unsigned char *byte){
    if(strlen(str) % 2 != 0){
        SKF_DEBUG("str len = %d",strlen(str));
        return;
    }

    unsigned char hi = 0;
    unsigned char low = 0;

    for(int i = 0; i < strlen(str)/2;i++){
        if('0'<=str[2*i] && str[2*i]<='9'){
            hi = str[2*i] - '0';
        }

        if('a'<=str[2*i] && str[2*i]<='f'){
            hi = str[2*i] - 'a' + 10;
        }

        if('A'<=str[2*i] && str[2*i]<='F'){
            hi = str[2*i] - 'A' + 10;
        }

        if('0'<=str[2*i + 1] && str[2*i + 1]<='9'){
            low = str[2*i + 1] - '0';
        }

        if('a'<=str[2*i + 1] && str[2*i + 1]<='f'){
            low = str[2*i + 1] - 'a' + 10;
        }

        if('A'<=str[2*i + 1] && str[2*i + 1]<='F'){
            low = str[2*i + 1] - 'A' + 10;
        }
        hi &= 0xFF;
        low &= 0xFF;
        byte[i] = ((hi << 4) | low) & 0xFF;
    }
}

/*
 *	获得当前系统中的设备列表
 *	bPresent		[IN]为TRUE表示取当前设备状态为存在的设备列表。为FALSE表示取当前驱动支持的设备列表
 *	szNameList		[OUT]设备名称列表。如果该参数为NULL，将由pulSize返回所需要的内存空间大小。每个设备的名称以单个'\0'结束，以双'\0'表示列表的结束
 *	pulSize			[IN,OUT]输入参数，输入设备名称列表的缓冲区长度，输出参数，返回szNameList所需要的空间大小
 */
DEVAPI extern "C" ULONG SKF_EnumDev(
        IN BOOL bPresent,
        OUT LPSTR szNameList,
        OUT ULONG* pulSize
){
    SKF_DEBUG("%s line %d IN",__FUNCTION__,__LINE__);

    if(NULL == pulSize || bPresent != TRUE){
        return SAR_INVALIDPARAMERR;
    }

    string devName;
    char pad[1] = {0};

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        SKF_DEBUG("dev name is %s",(*it)->devName.c_str());
        devName.append((*it)->devName);
        devName.append(pad,1);
    }

    if(devName.size() > 0){
        devName.append(pad,1);
    }

    *pulSize = devName.size();
    if(NULL != szNameList){
        memcpy(szNameList,devName.data(),devName.size());
    }

    SKF_DEBUG("%s line %d OUT l = %d",__FUNCTION__,__LINE__,*pulSize);
    return SAR_OK;
}

/*
 *	通过设备名称连接设备，返回设备的句柄
 *	szName		[IN]设备名称
 *	phDev		[OUT]返回设备操作句柄
 */
DEVAPI extern "C" ULONG SKF_ConnectDev(
        IN LPSTR szName,
        OUT DEVHANDLE* phDev
){
    if(NULL == szName || NULL == phDev){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if((*it)->devName == szName){
            if((*it)->status == SKF_STATUS_DEV_DISCONNECT){
                (*it)->status = SKF_STATUS_DEV_CONNECT;
            }

            *phDev = *it;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	断开一个已经连接的设备，并释放句柄。
 *	hDev		[IN]连接设备时返回的设备句柄
 */
DEVAPI extern "C" ULONG SKF_DisConnectDev(
        IN DEVHANDLE hDev
){
    if(NULL == hDev){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if(*it == hDev){
            (*it)->status = SKF_STATUS_DEV_DISCONNECT;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	获取设备是否存在的状态
 *	szDevName	[IN]连接名称
 *	pulDevState	[OUT]返回设备状态
 */
DEVAPI extern "C" ULONG SKF_GetDevState(
        IN  LPSTR	 szDevName,
        OUT ULONG* pulDevState
){
    if(NULL == szDevName || NULL == pulDevState){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if((*it)->devName == szDevName){
            if((*it)->status == SKF_STATUS_DEV_DISCONNECT){
                *pulDevState = 0;
            } else{
                *pulDevState = 1;
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	设置设备标签
 *	hDev		[IN]连接设备时返回的设备句柄
 *	szLabel		[OUT]设备标签字符串。该字符串应小于32字节
 */
DEVAPI extern "C" ULONG SKF_SetLabel(
        IN DEVHANDLE hDev,
        IN LPSTR szLabel){
    if(NULL == hDev || NULL == szLabel){
        return SAR_INVALIDPARAMERR;
    }

    if(strlen(szLabel) > 30){
        return SAR_NAMELENERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if(*it == hDev){

            string dir_devLabel = skf_soft_util::devDir;
            dir_devLabel.append("/");
            dir_devLabel.append(skf_soft_util::nameLabel);
            setContext(dir_devLabel,szLabel);
            (*it)->devLabel = szLabel;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	获取设备的一些特征信息，包括设备标签、厂商信息、支持的算法等
 *	hDev		[IN]连接设备时返回的设备句柄
 *	pDevInfo	[OUT]返回设备信息
 */
DEVAPI extern "C" ULONG SKF_GetDevInfo(
        IN DEVHANDLE	hDev,
        OUT PDEVINFO	pDevInfo
){
    if(NULL == hDev || NULL == pDevInfo){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if(*it == hDev){
            memset(pDevInfo,0,sizeof(DEVINFO));
            pDevInfo->Version.major = 0x00;
            pDevInfo->Version.minor = 0x01;
            memcpy(pDevInfo->Manufacturer,skf_soft_util::devManufacturer.data(),skf_soft_util::devManufacturer.size());
            pDevInfo->AlgSymCap = SGD_SMS4_ECB | SGD_SMS4_OFB | SGD_SMS4_CBC;
            pDevInfo->AlgAsymCap = SGD_SM2_1 | SGD_SM2_2 | SGD_SM2_3;
            pDevInfo->AlgHashCap = SGD_SM3;
            pDevInfo->DevAuthAlgId = SGD_SMS4_ECB;
            memcpy(pDevInfo->Label,(*it)->devLabel.data(),(*it)->devLabel.size());
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	获得设备的独占使用权
 *	hDev		[IN]连接设备时返回的设备句柄
 *	ulTimeOut	[IN]超时时间，单位为毫秒。如果为0xFFFFFFFF表示无限等待
 */
DEVAPI extern "C" ULONG SKF_LockDev(
        IN DEVHANDLE	hDev,
        IN ULONG ulTimeOut
){
    if(NULL == hDev){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if(*it == hDev){
            return SAR_NOTSUPPORTYETERR;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	释放对设备的独占使用权
 *	hDev		[IN]连接设备时返回的设备句柄
 */
DEVAPI extern "C" ULONG SKF_UnlockDev(
        IN DEVHANDLE	hDev
){
    if(NULL == hDev){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if(*it == hDev){
            return SAR_NOTSUPPORTYETERR;
        }
    }

    return SAR_INVALIDHANDLEERR;
}


/************************************************************************/
/*  2. 访问控制				                                            */
/*	SKF_ChangeDevAuthKey												*/
/*	SKF_DevAuth															*/
/*	SKF_ChangePIN														*/
/*	SKF_GetPINInfo														*/
/*	SKF_VerifyPIN														*/
/*	SKF_UnblockPIN														*/
/*	SKF_ClearSecureState												*/
/************************************************************************/

/*
 *	更改设备认证密钥
 *	hDev		[IN]连接时返回的设备句柄
 *	pbKeyValue	[IN]密钥值
 *	ulKeyLen	[IN]密钥长度
 */
DEVAPI extern "C" ULONG SKF_ChangeDevAuthKey(
        IN DEVHANDLE	hDev,
        IN BYTE		*pbKeyValue,
        IN ULONG		ulKeyLen
){
    if(NULL == hDev || NULL == pbKeyValue || ulKeyLen != 16){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if((*it) == hDev){
            break;
        }
    }

    if(it == skf_soft_util::setDevHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    if((*it)->status != SKF_STATUS_DEV_AUTH){
        return SAR_FAIL;
    }

    string dir_devAuthKey = skf_soft_util::devDir;
    dir_devAuthKey.append("/");
    dir_devAuthKey.append(skf_soft_util::nameAuthKey);

    string devAuthKeyStr;
    devAuthKeyStr.append((char*)pbKeyValue,ulKeyLen);
    setContext(dir_devAuthKey,devAuthKeyStr);
    memcpy((*it)->devAuthPlain,pbKeyValue,ulKeyLen);
    return SAR_OK;
}

/*
 *	设备认证是设备对应用程序的认证
 *	hDev			[IN]连接时返回的设备句柄
 *	pbAuthData		[IN]认证数据
 *	ulLen			[IN]认证数据的长度
 */
DEVAPI extern "C" ULONG SKF_DevAuth(
        IN DEVHANDLE	hDev,
        IN BYTE*		pbAuthData,
        IN ULONG		ulLen
){
    if(NULL == hDev || NULL == pbAuthData || ulLen != 16){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if((*it) == hDev){
            if((*it)->status == SKF_STATUS_DEV_DISCONNECT){
                return SAR_DEVICE_REMOVED;
            }

            unsigned char output[16];
            memset(output,0, sizeof(output));
            mm_handle h = NULL;
            h = sm4_init((*it)->devAuthPlain);
            sm4_ecb_decrypt(h,pbAuthData,ulLen,output);
            sm4_unit(h);


            string strOut;
            strOut.append((char*)output,8);
            if(skf_soft_util::devAuthRnd != strOut){
                return SAR_FAIL;
            }

            (*it)->status = SKF_STATUS_DEV_AUTH;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	修改PIN，可以修改Admin和User的PIN，如果原PIN错误，返回剩余重试次数，当剩余次数为0时，表示PIN已经被锁死
 *	hApplication	[IN]应用句柄
 *	ulPINType		[IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
 *	szOldPIN		[IN]原PIN值
 *	szNewPIN		[IN]新PIN值
 *	pulRetryCount	[OUT]出错后重试次数
 */
DEVAPI extern "C" ULONG SKF_ChangePIN(
        IN HAPPLICATION	hApplication,
        IN ULONG			ulPINType,
        IN LPSTR			szOldPIN,
        IN LPSTR			szNewPIN,
        OUT ULONG*		pulRetryCount
){
    if(NULL == hApplication || NULL == szOldPIN || NULL == szNewPIN || NULL == pulRetryCount ||
    (ulPINType != ADMIN_TYPE && ulPINType != USER_TYPE) || strlen(szOldPIN) == 0 || strlen(szNewPIN) == 0){
        return SAR_INVALIDPARAMERR;
    }

    ULONG ret = SAR_INVALIDHANDLEERR;
    string appDir;
    bool setFlg = false;

    auto it = skf_soft_util::setAppHandle.begin();
    for(;it != skf_soft_util::setAppHandle.end();it++){
        if(*it == ((SKF_SOFT_APPH_PTR)hApplication)){
            appDir.append(skf_soft_util::devDir);
            appDir.append("/");
            appDir.append(skf_soft_util::prefixApp);
            appDir.append((*it)->appName);

            if(ulPINType == ADMIN_TYPE){
                if((*it)->soPin == szOldPIN){
                    setFlg = setSoPin(appDir,szNewPIN);
                    if(!setFlg){
                        return SAR_FAIL;
                    }
                    *pulRetryCount = (*it)->soPinMaxCount;
                    (*it)->soPin = szNewPIN;
                    ret = SAR_OK;
                } else{
                    if((*it)->soPinRemainCount > 0){
                        setFlg = setsoPinRemainCount(appDir,(*it)->soPinRemainCount - 1);
                        if(!setFlg){
                            return SAR_FAIL;
                        }

                        (*it)->soPinRemainCount--;
                        *pulRetryCount = (*it)->soPinRemainCount;
                        ret = SAR_PIN_INCORRECT;
                    }
                }

            } else{
                if((*it)->usrPin == szOldPIN){
                    setFlg = setUsrPin(appDir,szNewPIN);
                    if(!setFlg){
                        return SAR_FAIL;
                    }
                    *pulRetryCount = (*it)->usrPinMaxCount;
                    (*it)->usrPin = szNewPIN;
                    ret = SAR_OK;
                } else{
                    if((*it)->usrPinRemainCount > 0){
                        setFlg = setusrPinRemainCount(appDir,(*it)->usrPinRemainCount - 1);
                        if(!setFlg){
                            return SAR_FAIL;
                        }

                        (*it)->usrPinRemainCount--;
                        *pulRetryCount = (*it)->usrPinRemainCount;
                        ret = SAR_PIN_INCORRECT;
                    }
                }
            }

            break;
        }
    }

    return ret;
}

/*
 *	获取PIN码信息，包括最大重试次数、当前剩余重试次数，以及当前PIN码是否为出厂默认PIN码
 *	hApplication		[IN]应用句柄
 *	ulPINType			[IN]PIN类型
 *	pulMaxRetryCount	[OUT]最大重试次数
 *	pulRemainRetryCount	[OUT]当前剩余重试次数，当为0时表示已锁死
 *	pbDefaultPin		[OUT]是否为出厂默认PIN码
 */
DEVAPI extern "C" ULONG SKF_GetPINInfo(
        IN HAPPLICATION	hApplication,
        IN ULONG			ulPINType,
        OUT ULONG*		pulMaxRetryCount,
        OUT ULONG*		pulRemainRetryCount,
        OUT BOOL*			pbDefaultPin
){
    if(NULL == hApplication || NULL == pulRemainRetryCount || NULL == pulMaxRetryCount || NULL == pbDefaultPin || (ADMIN_TYPE != ulPINType && USER_TYPE != ulPINType)){
        return SAR_INVALIDPARAMERR;
    }

    ULONG ret = SAR_INVALIDHANDLEERR;
    auto it = skf_soft_util::setAppHandle.begin();
    for(;it != skf_soft_util::setAppHandle.end();it++){
        if(*it == ((SKF_SOFT_APPH_PTR)hApplication)){
            if(ulPINType == ADMIN_TYPE){
                *pulMaxRetryCount = (*it)->soPinMaxCount;
                *pulRemainRetryCount = (*it)->soPinRemainCount;
                *pbDefaultPin = ((*it)->soPin == (*it)->soDefaultPin);
            } else{
                *pulMaxRetryCount = (*it)->usrPinMaxCount;
                *pulRemainRetryCount = (*it)->usrPinRemainCount;
                *pbDefaultPin = ((*it)->usrPin == (*it)->usrDefaultPin);
            }
            ret = SAR_OK;
            break;
        }
    }

    return ret;
}

/*
 *	校验PIN码。校验成功后，会获得相应的权限，如果PIN码错误，会返回PIN码的重试次数，当重试次数为0时表示PIN码已经锁死
 *	hApplication	[IN]应用句柄
 *	ulPINType		[IN]PIN类型，可以为ADMIN_TYPE=0，或USER_TYPE=1
 *	szPIN			[IN]PIN值
 *	pulRetryCount	[OUT]出错后返回的重试次数
 */
DEVAPI extern "C" ULONG SKF_VerifyPIN(
        IN HAPPLICATION	hApplication,
        IN ULONG			ulPINType,
        IN LPSTR			szPIN,
        OUT ULONG*		pulRetryCount
){
    if(NULL == hApplication || NULL == szPIN || strlen(szPIN) == 0 || NULL == pulRetryCount || (ulPINType != ADMIN_TYPE && ulPINType != USER_TYPE)){
        return SAR_INVALIDPARAMERR;
    }

    ULONG ret = SAR_INVALIDHANDLEERR;
    string appDir;
    bool setFlg = false;

    auto it = skf_soft_util::setAppHandle.begin();
    for(;it != skf_soft_util::setAppHandle.end();it++){
        if(*it == ((SKF_SOFT_APPH_PTR)hApplication)){
            if((*it)->status == SKF_STATUS_APP_CLOSE){
                SKF_DEBUG("%s application has not open",__FUNCTION__);
                return SAR_INVALIDHANDLEERR;
            }

            appDir = getAppDir((*it)->appName);

            if(ulPINType == ADMIN_TYPE){
                if((*it)->soPin == szPIN){
                    (*it)->status |= SKF_STATUS_APP_LOGGIN_ADMIN;
                    setFlg = setsoPinRemainCount(appDir,(*it)->soPinMaxCount);
                    if(!setFlg){
                        return SAR_FAIL;
                    }
                    *pulRetryCount = (*it)-> soPinRemainCount = (*it)->soPinMaxCount;
                    ret = SAR_OK;
                } else{
                    if((*it)->soPinRemainCount > 0){
                        setFlg = setsoPinRemainCount(appDir,(*it)->soPinRemainCount - 1);
                        if(!setFlg){
                            return SAR_FAIL;
                        }

                        (*it)->soPinRemainCount--;
                        *pulRetryCount = (*it)->soPinRemainCount;
                        ret = SAR_PIN_INCORRECT;
                    }
                }

            } else{
                if((*it)->usrPin == szPIN){
                    (*it)->status |= SKF_STATUS_APP_LOGGIN_USR;
                    setFlg = setusrPinRemainCount(appDir,(*it)->usrPinMaxCount);
                    if(!setFlg){
                        return SAR_FAIL;
                    }

                    *pulRetryCount = (*it)->usrPinRemainCount = (*it)->usrPinMaxCount;

                    ret = SAR_OK;
                } else{
                    if((*it)->usrPinRemainCount > 0){
                        setFlg = setusrPinRemainCount(appDir,(*it)->usrPinRemainCount - 1);
                        if(!setFlg){
                            return SAR_FAIL;
                        }

                        (*it)->usrPinRemainCount--;
                        *pulRetryCount = (*it)->usrPinRemainCount;
                        ret = SAR_PIN_INCORRECT;
                    }
                }
            }

            break;
        }
    }

    return ret;
}

/*
 *	当用户的PIN码锁死后，通过调用该函数来解锁用户PIN码。
 *	解锁后，用户PIN码被设置成新值，用户PIN码的重试次数也恢复到原值。
 *	hApplication	[IN]应用句柄
 *	szAdminPIN		[IN]管理员PIN码
 *	szNewUserPIN	[IN]新的用户PIN码
 *	pulRetryCount	[OUT]管理员PIN码错误时，返回剩余重试次数
 */
DEVAPI extern "C" ULONG SKF_UnblockPIN(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szAdminPIN,
        IN LPSTR			szNewUserPIN,
        OUT ULONG*		pulRetryCount
){
    if(NULL == hApplication || NULL == szAdminPIN || strlen(szAdminPIN) == 0 || NULL == szNewUserPIN || strlen(szNewUserPIN) == 0 || NULL == pulRetryCount){
        return SAR_INVALIDPARAMERR;
    }

    ULONG ret = SAR_INVALIDHANDLEERR;
    string appDir;
    bool setFlg = false;

    auto it = skf_soft_util::setAppHandle.begin();
    for(;it != skf_soft_util::setAppHandle.end();it++){
        if((*it)->status == SKF_STATUS_APP_CLOSE){
            return SAR_INVALIDHANDLEERR;
        }

        if(*it == ((SKF_SOFT_APPH_PTR)hApplication)){
            appDir.append(skf_soft_util::devDir);
            appDir.append("/");
            appDir.append(skf_soft_util::prefixApp);
            appDir.append((*it)->appName);

            if((*it)->soPin == szAdminPIN){
                setFlg = setUsrPin(appDir,szNewUserPIN);
                if(!setFlg){
                    return SAR_FAIL;
                }

                setFlg = setusrPinRemainCount(appDir,(*it)->usrPinMaxCount);
                if(!setFlg){
                    return SAR_FAIL;
                }

                (*it)->usrPin = szNewUserPIN;
                (*it)->usrPinRemainCount = (*it)->usrPinMaxCount;
                *pulRetryCount = (*it)->soPinMaxCount;
                ret = SAR_OK;
            } else{
                if((*it)->soPinRemainCount > 0){
                    setFlg = setsoPinRemainCount(appDir,(*it)->soPinRemainCount - 1);
                    if(!setFlg){
                        return SAR_FAIL;
                    }

                    (*it)->soPinRemainCount--;
                    *pulRetryCount = (*it)->soPinRemainCount;
                    ret = SAR_PIN_INCORRECT;
                }
            }

            break;
        }
    }

    return ret;


}

/*
 *	清除应用当前的安全状态
 *	hApplication	[IN]应用句柄
 */
DEVAPI extern "C" ULONG SKF_ClearSecureState(
        IN HAPPLICATION	hApplication
){
    if(NULL == hApplication){
        return SAR_INVALIDPARAMERR;
    }

    ULONG ret = SAR_INVALIDHANDLEERR;

    auto it = skf_soft_util::setAppHandle.begin();
    for(;it != skf_soft_util::setAppHandle.end();it++){
        if(*it == ((SKF_SOFT_APPH_PTR)hApplication)){
            (*it)->status = SKF_STATUS_APP_OPEN;
            ret = SAR_OK;
            break;
        }
    }

    return ret;
}

/************************************************************************/
/*  3. 应用管理				                                            */
/*	SKF_CreateApplication												*/
/*	SKF_EnumApplication													*/
/*	SKF_DeleteApplication												*/
/*	SKF_OpenApplication													*/
/*	SKF_CloseApplication												*/
/************************************************************************/

/*
 *	创建一个应用
 *	hDev					[IN]连接设备时返回的设备句柄
 *	szAppName				[IN]应用名称
 *	szAdminPIN				[IN]管理员PIN
 *	dwAdminPinRetryCount	[IN]管理员PIN最大重试次数
 *	szUserPIN				[IN]用户PIN
 *	dwAdminPinRetryCount	[IN]用户PIN最大重试次数
 *	dwCreateFileRights		[IN]在该应用下创建文件和容器的权限
 *	phApplication			[OUT]应用的句柄
 */
DEVAPI extern "C" ULONG SKF_CreateApplication(
        IN DEVHANDLE		hDev,
        IN LPSTR			szAppName,
        IN LPSTR			szAdminPIN,
        IN DWORD			dwAdminPinRetryCount,
        IN LPSTR			szUserPIN,
        IN DWORD			dwUserPinRetryCount,
        IN DWORD			dwCreateFileRights,
        OUT HAPPLICATION*	phApplication
){
    if(NULL == hDev || NULL == szAppName || strlen(szAppName) == 0 || NULL == szAdminPIN || strlen(szAdminPIN) == 0 ||
        dwAdminPinRetryCount < 1 || NULL == szUserPIN || strlen(szUserPIN) == 0 || dwUserPinRetryCount < 1 ||
        NULL == phApplication || (dwCreateFileRights != SECURE_ADM_ACCOUNT &&
        dwCreateFileRights != SECURE_USER_ACCOUNT && dwCreateFileRights != SECURE_NEVER_ACCOUNT &&
        dwCreateFileRights != SECURE_EVERYONE_ACCOUNT && dwCreateFileRights != (SECURE_ADM_ACCOUNT | SECURE_USER_ACCOUNT))){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if((*it) == hDev){
            break;
        }
    }

    if(it == skf_soft_util::setDevHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    if((*it)->status < SKF_STATUS_DEV_AUTH){
        return SAR_UNKNOWNERR;
    }

    auto item = skf_soft_util::setAppHandle.begin();
    for(;item != skf_soft_util::setAppHandle.end();item++){
        if((*item)->appName == szAppName){
            return SAR_APPLICATION_EXISTS;
        }
    }


    int mkdirRet = mkDirApp(szAppName);
    if(mkdirRet != 0){
        SKF_DEBUG("%s create dir error %s",szAppName,strerror(errno));
        return SAR_FAIL;
    }

    string appDir = getAppDir(szAppName);

    setSoDefaultPin(appDir,szAdminPIN);
    setSoPin(appDir,szAdminPIN);
    setsoPinMaxCount(appDir,dwAdminPinRetryCount);
    setsoPinRemainCount(appDir,dwAdminPinRetryCount);

    setUsrDefaultPin(appDir,szUserPIN);
    setUsrPin(appDir,szUserPIN);
    setusrPinMaxCount(appDir,dwUserPinRetryCount);
    setusrPinRemainCount(appDir,dwUserPinRetryCount);

    setAppRightst(appDir,dwCreateFileRights);

    SKF_SOFT_APPH_PTR apph_ptr = new SKF_SOFT_APPH();
    apph_ptr->devh_ptr = (SKF_SOFT_DEVH_PTR)hDev;
    apph_ptr->status = SKF_STATUS_APP_OPEN;
    apph_ptr->appName = szAppName;

    apph_ptr->soDefaultPin = szAdminPIN;
    apph_ptr->soPin = szAdminPIN;
    apph_ptr->soPinMaxCount = dwAdminPinRetryCount;
    apph_ptr->soPinRemainCount = dwAdminPinRetryCount;

    apph_ptr->usrDefaultPin = szUserPIN;
    apph_ptr->usrPin = szUserPIN;
    apph_ptr->usrPinMaxCount = dwUserPinRetryCount;
    apph_ptr->usrPinRemainCount = dwUserPinRetryCount;
    apph_ptr->rights = dwCreateFileRights;

    skf_soft_util::setAppHandle.insert(apph_ptr);

    *phApplication = apph_ptr;

    SKF_DEBUG("%s OUT, happlication = %p",__FUNCTION__,*phApplication);
    return SAR_OK;
}

/*
 *	枚举设备中所存在的所有应用
 *	hDev			[IN]连接设备时返回的设备句柄
 *	szAppName		[OUT]返回应用名称列表, 如果该参数为空，将由pulSize返回所需要的内存空间大小。
 *						 每个应用的名称以单个'\0'结束，以双'\0'表示列表的结束。
 *	pulSize			[IN,OUT]输入参数，输入应用名称的缓冲区长度，输出参数，返回szAppName所占用的的空间大小
 */
DEVAPI extern "C" ULONG SKF_EnumApplication(
        IN DEVHANDLE		hDev,
        OUT LPSTR			szAppName,
        OUT ULONG*		pulSize
){
    if(NULL == hDev || NULL == pulSize){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if((*it) == hDev){
            break;
        }
    }

    if(it == skf_soft_util::setDevHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    *pulSize = 0;

    if(skf_soft_util::setAppHandle.size() == 0){
        return SAR_OK;
    }

    string appName;
    char pad[1] = {0};
    auto item = skf_soft_util::setAppHandle.begin();
    for(;item != skf_soft_util::setAppHandle.end();item++){
        appName.append((*item)->appName);
        appName.append(pad,1);
    }
    appName.append(pad,1);

    *pulSize = appName.size();
    if(NULL != szAppName){
        memcpy(szAppName,appName.data(),*pulSize);
    }

    return SAR_OK;
}

/*
 *	删除指定的应用
 *	hDev			[IN]连接设备时返回的设备句柄
 *	szAppName		[IN]应用名称
 */
DEVAPI extern "C" ULONG SKF_DeleteApplication(
        IN DEVHANDLE		hDev,
        IN LPSTR			szAppName
){
    if(NULL == hDev || NULL == szAppName || strlen(szAppName) == 0){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if((*it) == hDev){
            break;
        }
    }

    if(it == skf_soft_util::setDevHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    if((*it)->status < SKF_STATUS_DEV_AUTH){
        return SAR_UNKNOWNERR;
    }

    auto itAppHandle = skf_soft_util::setAppHandle.begin();
    for(;itAppHandle != skf_soft_util::setAppHandle.end();itAppHandle++){
        if((*itAppHandle)->appName == szAppName){
            //SKF_SOFT_APPH_PTR ptr = *itAppHandle;

            //TODO
                //删除容器和文件
                //删除容器的证书和非对称密钥
                //删除容器中导入的会话密钥
            auto itCert = skf_soft_util::setCertHandle.begin();
            for(;itCert != skf_soft_util::setCertHandle.end();){
                if((*itCert)->containerh_ptr->apph_ptr == *itAppHandle){
                    delete (*itCert);
                    skf_soft_util::setCertHandle.erase(itCert++);
                } else{
                    itCert++;
                }
            }

            auto itASym = skf_soft_util::setAysmHandle.begin();
            for(;itASym != skf_soft_util::setAysmHandle.end();){
                if((*itASym)->containerh_ptr->apph_ptr == *itAppHandle){
                    delete (*itASym);
                    skf_soft_util::setAysmHandle.erase(itASym++);
                } else{
                    itASym++;
                }
            }

            auto itSym = skf_soft_util::setSessionKeyHandle.begin();
            for(;itSym != skf_soft_util::setSessionKeyHandle.end();){
                if((*itSym)->containerh_ptr->apph_ptr == *itAppHandle){
                    delete (*itSym);
                    skf_soft_util::setSessionKeyHandle.erase(itSym++);
                } else{
                    itSym++;
                }
            }

            auto itContainer = skf_soft_util::setContainerHandle.begin();
            for(;itContainer != skf_soft_util::setContainerHandle.end();){
                if((*itContainer)->apph_ptr == *itAppHandle){
                    delete (*itContainer);
                    skf_soft_util::setContainerHandle.erase(itContainer++);
                } else{
                    itContainer++;
                }
            }

            auto itFile = skf_soft_util::setFileHandle.begin();
            for(;itFile != skf_soft_util::setFileHandle.end();){
                if((*itFile)->apph_ptr == *itAppHandle){
                    delete (*itFile);
                    skf_soft_util::setFileHandle.erase(itFile++);
                } else{
                    itFile++;
                }
            }

            string appPath = getAppDir(szAppName);
            rmPath(appPath);

            delete (*itAppHandle);
            skf_soft_util::setAppHandle.erase(itAppHandle);
            break;
        }
    }

    if(itAppHandle == skf_soft_util::setAppHandle.end()){
        return SAR_APPLICATION_NOT_EXISTS;
    }

    return SAR_OK;
}

/*
 *	打开指定的应用
 *	hDev			[IN]连接设备时返回的设备句柄
 *	szAppName		[IN]应用名称
 *	phApplication	[OUT]应用的句柄
 */
DEVAPI extern "C" ULONG SKF_OpenApplication(
        IN DEVHANDLE		hDev,
        IN LPSTR			szAppName,
        OUT HAPPLICATION*	phApplication
){ 
    if(NULL == hDev || NULL == szAppName || strlen(szAppName) == 0 || NULL == phApplication){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if(hDev == *it){
            break;
        }
    }

    if(it == skf_soft_util::setDevHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    auto item = skf_soft_util::setAppHandle.begin();
    for(;item != skf_soft_util::setAppHandle.end();item++){
        if((*item)->appName == szAppName){
            *phApplication = *item;
            if((*item)->status == SKF_STATUS_APP_CLOSE){
                (*item)->status = SKF_STATUS_APP_OPEN;
            }

            return SAR_OK;
        }

    }

    return SAR_APPLICATION_NOT_EXISTS;
}

/*
 *	关闭应用并释放应用句柄
 *	hApplication	[IN]应用的句柄
 */
DEVAPI extern "C" ULONG SKF_CloseApplication(
        IN HAPPLICATION	hApplication
){
    if(NULL == hApplication){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setAppHandle.begin();
    for(;it != skf_soft_util::setAppHandle.end();it++){
        if(hApplication == *it){
            (*it)->status = SKF_STATUS_APP_CLOSE;
            break;
        }
    }

    if(it == skf_soft_util::setAppHandle.end()){
        return SAR_INVALIDHANDLEERR;
    }

    return SAR_OK;
}


/************************************************************************/
/*  4. 文件管理				                                            */
/*	SKF_CreateFile														*/
/*	SKF_DeleteFile														*/
/*	SKF_EnumFiles														*/
/*	SKF_GetFileInfo														*/
/*	SKF_ReadFile														*/
/*	SKF_WriteFile														*/
/************************************************************************/

/*
 *	创建一个文件。创建文件时要指定文件的名称，大小，以及文件的读写权限
 *	hApplication		[IN]应用句柄
 *	szFileName			[IN]文件名称，长度不得大于32个字节
 *	ulFileSize			[IN]文件大小
 *	ulReadRights		[IN]文件读权限
 *	ulWriteRights		[IN]文件写权限
 */
DEVAPI extern "C" ULONG SKF_CreateFile(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szFileName,
        IN ULONG			ulFileSize,
        IN ULONG			ulReadRights,
        IN ULONG			ulWriteRights
){
    if(NULL == hApplication || NULL == szFileName || strlen(szFileName) == 0){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setAppHandle.begin();
    for(;it != skf_soft_util::setAppHandle.end();it++){
        if(*it == hApplication){
            ULONG ret = checkRights((*it)->rights,(*it)->status);
            if(ret != SAR_OK){
                return ret;
            }

            auto item = skf_soft_util::setFileHandle.begin();
            for(;item != skf_soft_util::setFileHandle.end();item++){
                if((*item)->fileName == szFileName){
                    return SAR_FILE_ALREADY_EXIST;
                }
            }

            int mkdirRet = mkDirFile((*it)->appName,szFileName);
            if(mkdirRet != 0){
                SKF_DEBUG("mkdir %s error %s",szFileName,strerror(errno));
                return SAR_FAIL;
            }

            char *pData = new char[ulFileSize];
            memset(pData,0,ulFileSize);
            SKF_SOFT_FILEH_PTR fileh_ptr = new SKF_SOFT_FILEH();
            fileh_ptr->apph_ptr = *it;
            fileh_ptr->fileName = szFileName;
            fileh_ptr->value.append(pData,ulFileSize);
            delete[] pData;
            pData = NULL;
            fileh_ptr->readRights = ulReadRights;
            fileh_ptr->writeRights = ulWriteRights;

            setFileContent(getFileDir(fileh_ptr->apph_ptr->appName,fileh_ptr->fileName),0,fileh_ptr->value);
            setFileReadRight(getFileDir(fileh_ptr->apph_ptr->appName,fileh_ptr->fileName),ulReadRights);
            setFileWriteRight(getFileDir(fileh_ptr->apph_ptr->appName,fileh_ptr->fileName),ulWriteRights);

            skf_soft_util::setFileHandle.insert(fileh_ptr);
            break;
        }
    }

    if(it == skf_soft_util::setAppHandle.end()){
        return SAR_APPLICATION_NOT_EXISTS;
    }

    return SAR_OK;
}

/*
 *	删除指定文件，文件删除后，文件中写入的所有信息将丢失。文件在设备中的占用的空间将被释放。
 *	hApplication		[IN]要删除文件所在的应用句柄
 *	szFileName			[IN]要删除文件的名称
 */
DEVAPI extern "C" ULONG SKF_DeleteFile(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szFileName
){
    if(NULL == hApplication || NULL == szFileName || strlen(szFileName) == 0){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setFileHandle.begin();
    for(;it != skf_soft_util::setFileHandle.end();it++){
        if((*it)->apph_ptr == hApplication && (*it)->fileName == szFileName){
            string filePath = getFileDir((*it)->apph_ptr->appName,(*it)->fileName);
            rmPath(filePath);
            SKF_SOFT_FILEH_PTR fileh_ptr = *it;
            skf_soft_util::setFileHandle.erase(it);
            delete fileh_ptr;
            fileh_ptr = NULL;
            return SAR_OK;
        }
    }

    return SAR_FILE_NOT_EXIST;
}

/*
 *	枚举一个应用下存在的所有文件
 *	hApplication		[IN]应用的句柄
 *	szFileList			[OUT]返回文件名称列表，该参数为空，由pulSize返回文件信息所需要的空间大小。每个文件名称以单个'\0'结束，以双'\0'表示列表的结束。
 *	pulSize				[OUT]输入为数据缓冲区的大小，输出为实际文件名称的大小
 */
DEVAPI extern "C" ULONG SKF_EnumFiles(
        IN HAPPLICATION	hApplication,
        OUT LPSTR			szFileList,
        OUT ULONG*		pulSize
){
    if(NULL == hApplication || NULL == pulSize){
        return SAR_INVALIDPARAMERR;
    }

    *pulSize = 0;
    if(skf_soft_util::setFileHandle.size() == 0){
        return SAR_OK;
    }

    string fileName;
    char pad[1] = {0};
    auto it = skf_soft_util::setFileHandle.begin();
    for(;it != skf_soft_util::setFileHandle.end();it++){
        if((*it)->apph_ptr == hApplication){
            fileName.append((*it)->fileName);
            fileName.append(pad,1);
        }
    }

    if(fileName.size() > 0){
        fileName.append(pad,1);
    }

    *pulSize = fileName.size();
    if(fileName.size() == 0){
        return SAR_OK;
    }

    if(NULL != szFileList){
        memcpy(szFileList,fileName.data(),fileName.size());
    }

    return SAR_OK;
}

/*
 *	获取应用文件的属性信息，例如文件的大小、权限等
 *	hApplication		[IN]文件所在应用的句柄
 *	szFileName			[IN]文件名称
 *	pFileInfo			[OUT]文件信息，指向文件属性结构的指针
 */
DEVAPI extern "C" ULONG SKF_GetFileInfo(
        IN HAPPLICATION		hApplication,
        IN LPSTR				szFileName,
        OUT FILEATTRIBUTE*	pFileInfo
){
    if(NULL == hApplication || NULL == szFileName || strlen(szFileName) == 0 || NULL == pFileInfo) {
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setFileHandle.begin();
    for(;it != skf_soft_util::setFileHandle.end();it++){
        if((*it)->apph_ptr == hApplication && (*it)->fileName == szFileName){
            memset(pFileInfo->FileName,0,sizeof(pFileInfo->FileName));
            memcpy(pFileInfo->FileName,(*it)->fileName.data(),(*it)->fileName.size());
            pFileInfo->FileSize = (*it)->value.size();
            pFileInfo->ReadRights = (*it)->readRights;
            pFileInfo->WriteRights = (*it)->writeRights;

            return SAR_OK;
        }
    }

    return SAR_FILE_NOT_EXIST;
}

/*
 *	读取文件内容
 *	hApplication		[IN]文件所在的应用句柄
 *	szFileName			[IN]文件名
 *	ulOffset			[IN]文件读取偏移位置
 *	ulSize				[IN]要读取的长度
 *	pbOutData			[OUT]返回数据的缓冲区
 *	pulOutLen			[OUT]输入表示给出的缓冲区大小；输出表示实际读取返回的数据大小
 */
DEVAPI extern "C" ULONG SKF_ReadFile(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szFileName,
        IN ULONG			ulOffset,
        IN ULONG			ulSize,
        OUT BYTE*			pbOutData,
        OUT ULONG*		pulOutLen
){
    if(NULL == hApplication || NULL == szFileName || strlen(szFileName) == 0 || NULL == pulOutLen){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setFileHandle.begin();
    for(;it != skf_soft_util::setFileHandle.end();it++){
        if((*it)->apph_ptr == hApplication && (*it)->fileName == szFileName){
            ULONG ret = checkRights((*it)->readRights,(*it)->apph_ptr->status);
            if(ret != SAR_OK){
                return ret;
            }
            string filePath = getFileDir((*it)->apph_ptr->appName,(*it)->fileName);
            string out = getFileContent(filePath.c_str(),ulOffset,ulSize);
            *pulOutLen = out.size();
            if(NULL != pbOutData){
                memcpy(pbOutData,out.data(),out.size());
                return SAR_OK;
            }

            return SAR_OK;
        }
    }

    return SAR_FILE_NOT_EXIST;
}

/*
 *	写数据到文件中
 *	hApplication		[IN]文件所在的应用句柄
 *	szFileName			[IN]文件名
 *	ulOffset			[IN]写入文件的偏移量
 *	pbData				[IN]写入数据缓冲区
 *	ulSize				[IN]写入数据的大小
 */
DEVAPI extern "C" ULONG SKF_WriteFile(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szFileName,
        IN ULONG			ulOffset,
        IN BYTE*			pbData,
        IN ULONG			ulSize
){
    if(NULL == hApplication || NULL == szFileName || strlen(szFileName) == 0 || NULL == pbData || ulSize == 0){
        return SAR_INVALIDPARAMERR;
    }

    string pDate;
    pDate.append((char*)pbData,ulSize);

    auto it = skf_soft_util::setFileHandle.begin();
    for(;it != skf_soft_util::setFileHandle.end();it++){
        if((*it)->apph_ptr == hApplication && (*it)->fileName == szFileName){
            ULONG ret = checkRights((*it)->writeRights,(*it)->apph_ptr->status);
            if(ret != SAR_OK){
                return ret;
            }

            string filePath = getFileDir((*it)->apph_ptr->appName,(*it)->fileName);
            setFileContent(filePath,ulOffset,pDate);
            return SAR_OK;
        }
    }

    return SAR_FILE_NOT_EXIST;
}


/************************************************************************/
/*  5. 容器管理				                                            */
/*	SKF_CreateContainer													*/
/*	SKF_DeleteContainer													*/
/*	SKF_OpenContainer													*/
/*	SKF_CloseContainer													*/
/*	SKF_EnumContainer													*/
/************************************************************************/

/*
 *	在应用下建立指定名称的容器并返回容器句柄
 *	hApplication		[IN]应用句柄
 *	szContainerName		[IN]ASCII字符串，表示所建立容器的名称，容器名称的最大长度不能超过64字节
 *	phContainer			[OUT]返回所建立容器的容器句柄
 */
DEVAPI extern "C" ULONG SKF_CreateContainer(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szContainerName,
        OUT HCONTAINER*	phContainer
){
    if(NULL == hApplication || NULL == szContainerName || strlen(szContainerName) == 0 || NULL == phContainer){
        return SAR_INVALIDPARAMERR;
    }

    if(strlen(szContainerName) > 64){
        return SAR_NAMELENERR;
    }

    auto it = skf_soft_util::setContainerHandle.begin();
    for(;it != skf_soft_util::setContainerHandle.end();it++){
        if((*it)->apph_ptr == hApplication && (*it)->containerName == szContainerName){
            SKF_DEBUG("%s IN,%s container has create yet",__FUNCTION__,szContainerName);
            return SAR_FAIL;
        }
    }

    auto item = skf_soft_util::setAppHandle.begin();
    for(;item != skf_soft_util::setAppHandle.end();item++){
        if(hApplication == *item){
            if((*item)->status < SKF_STATUS_APP_LOGGIN_USR){
                return SAR_USER_NOT_LOGGED_IN;
            }

            ULONG ret = mkDirContainer((*item)->appName,szContainerName);
            if(ret != 0){
                return SAR_FAIL;
            }

            setContainerType(getContainerDir((*item)->appName,szContainerName),0);
            setContainerCertSign(getContainerDir((*item)->appName,szContainerName),"");
            setContainerPukSign(getContainerDir((*item)->appName,szContainerName),"");
            setContainerPriSign(getContainerDir((*item)->appName,szContainerName),"");

            setContainerCertCry(getContainerDir((*item)->appName,szContainerName),"");
            setContainerPukCry(getContainerDir((*item)->appName,szContainerName),"");
            setContainerPriCry(getContainerDir((*item)->appName,szContainerName),"");

            SKF_SOFT_CONTAINERH_PTR containerh_ptr = new SKF_SOFT_CONTAINERH();
            containerh_ptr->apph_ptr = *item;
            containerh_ptr->type = 0;
            containerh_ptr->containerName = szContainerName;
            skf_soft_util::setContainerHandle.insert(containerh_ptr);
            *phContainer = containerh_ptr;

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	在应用下删除指定名称的容器并释放容器相关的资源
 *	hApplication		[IN]应用句柄
 *	szContainerName		[IN]指向删除容器的名称
 */
DEVAPI extern "C" ULONG SKF_DeleteContainer(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szContainerName
){
    if(NULL == hApplication || NULL == szContainerName || strlen(szContainerName) == 0){
        return SAR_INVALIDPARAMERR;
    }

    SKF_SOFT_CONTAINERH_PTR containerh_ptr = NULL;
    auto it = skf_soft_util::setContainerHandle.begin();
    for(;it != skf_soft_util::setContainerHandle.end();it++){
        if((*it)->apph_ptr == hApplication && (*it)->containerName == szContainerName){
            if((*it)->apph_ptr->status < SKF_STATUS_APP_LOGGIN_USR){
                return SAR_USER_NOT_LOGGED_IN;
            }

            string containerDir = getContainerDir((*it)->apph_ptr->appName,szContainerName);
            rmPath(containerDir);
            containerh_ptr = *it;
            skf_soft_util::setContainerHandle.erase(it);
            delete containerh_ptr;
            containerh_ptr = NULL;

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	获取容器句柄
 *	hApplication		[IN]应用句柄
 *	szContainerName		[IN]容器名称
 *	phContainer			[OUT]返回所打开容器的句柄
 */
DEVAPI extern "C" ULONG SKF_OpenContainer(
        IN HAPPLICATION	hApplication,
        IN LPSTR			szContainerName,
        OUT HCONTAINER*	phContainer
){
    if(NULL == hApplication || NULL == szContainerName || strlen(szContainerName) == 0 || NULL == phContainer){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setContainerHandle.begin();
    for(;it != skf_soft_util::setContainerHandle.end();it++){
        if((*it)->apph_ptr == hApplication && (*it)->containerName == szContainerName){
            *phContainer = *it;
            (*it)->status = SKF_STATUS_CONTAINER_OPEN;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	关闭容器句柄，并释放容器句柄相关资源
 *	hContainer			[OUT]容器句柄
 */
DEVAPI extern "C" ULONG SKF_CloseContainer(
        IN HCONTAINER hContainer
){
    if(NULL == hContainer){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setContainerHandle.begin();
    for(;it != skf_soft_util::setContainerHandle.end();it++){
        if(*it == hContainer){
            (*it)->status = SKF_STATUS_CONTAINER_CLOSE;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	枚举应用下的所有容器并返回容器名称列表
 *	hApplication		[IN]应用句柄
 *	szContainerName		[OUT]指向容器名称列表缓冲区，如果此参数为NULL时，pulSize表示返回数据所需要缓冲区的长度，如果此参数不为NULL时，返回容器名称列表，每个容器名以单个'\0'为结束，列表以双'\0'结束
 *	pulSize				[OUT]调用前表示szContainerName缓冲区的长度，返回容器名称列表的长度
 */
DEVAPI extern "C" ULONG SKF_EnumContainer(
        IN HAPPLICATION	hApplication,
        OUT LPSTR			szContainerName,
        OUT ULONG*		pulSize
){
    if(NULL == hApplication || NULL == pulSize){
        return SAR_INVALIDPARAMERR;
    }

    string containerName;
    char pad[1] = {0};
    for(auto it = skf_soft_util::setContainerHandle.begin();it != skf_soft_util::setContainerHandle.end();it++){
        if((*it)->apph_ptr == hApplication){
            containerName.append((*it)->containerName);
            containerName.append(pad,1);
        }
    }

    if(containerName.size() > 0){
        containerName.append(pad,1);
    }

    *pulSize = containerName.size();
    if(NULL != szContainerName){
        memcpy(szContainerName,containerName.data(),containerName.size());
    }

    return SAR_OK;
}

/*
 *	功能描述	获取容器的类型
 *	hContainer	[IN]容器句柄。
 *	pulContainerType	[OUT] 获得的容器类型。指针指向的值为0表示未定、尚未分配类型或者为空容器，为1表示为RSA容器，为2表示为SM2容器。
 *
 */
DEVAPI extern "C" ULONG SKF_GetContainerType(IN HCONTAINER hContainer,
        OUT ULONG *pulContainerType){
    if(NULL == hContainer || NULL == pulContainerType){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setContainerHandle.begin();
    for(;it != skf_soft_util::setContainerHandle.end();it++){
        if(*it == hContainer){
            *pulContainerType = getContainerType(getContainerDir((*it)->apph_ptr->appName,(*it)->containerName));
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}
/************************************************************************/
/*  6. 密码服务				                                            */
/*	SKF_GetRandom														*/
/*	SKF_GenExtRSAKey													*/
/*	SKF_GenRSAKeyPair													*/
/*	SKF_ImportRSAKeyPair												*/
/*	SKF_RSASignData														*/
/*	SKF_RSAVerify														*/
/*	SKF_RSAExportSessionKey												*/
/*	SKF_ExtRSAPubKeyOperation											*/
/*	SKF_ExtRSAPriKeyOperation											*/
/*	SKF_GenECCKeyPair													*/
/*	SKF_ImportECCKeyPair												*/
/*	SKF_ECCSignData														*/
/*	SKF_ECCVerify														*/
/*	SKF_ECCExportSessionKey												*/
/*	SKF_ExtECCEncrypt													*/
/*	SKF_ExtECCDecrypt													*/
/*	SKF_ExtECCSign														*/
/*	SKF_ExtECCVerify													*/
/*	SKF_ExportPublicKey													*/
/*	SKF_ImportSessionKey												*/
/*	SKF_SetSymmKey														*/
/*	SKF_EncryptInit														*/
/*	SKF_Encrypt															*/
/*	SKF_EncryptUpdate													*/
/*	SKF_EncryptFinal													*/
/*	SKF_DecryptInit														*/
/*	SKF_Decrypt															*/
/*	SKF_DecryptUpdate													*/
/*	SKF_DecryptFinal													*/
/*	SKF_DegistInit														*/
/*	SKF_Degist															*/
/*	SKF_DegistUpdate													*/
/*	SKF_DegistFinal														*/
/*	SKF_MACInit															*/
/*	SKF_MAC																*/
/*	SKF_MACUpdate														*/
/*	SKF_MACFinal														*/
/************************************************************************/

/*
 *	产生指定长度的随机数
 *	hDev			[IN] 设备句柄
 *	pbRandom		[OUT] 返回的随机数
 *	ulRandomLen		[IN] 随机数长度
 */
DEVAPI extern "C" ULONG SKF_GenRandom(
        IN DEVHANDLE hDev,
        OUT BYTE *pbRandom,
        IN ULONG ulRandomLen
){
    if(NULL == hDev || NULL == pbRandom || ulRandomLen == 0){
        return SAR_INVALIDPARAMERR;
    }
    srand(time(NULL));

    for(ULONG loop = 0; loop < ulRandomLen;loop++){
        pbRandom[loop] = rand() & 0xFF;
    }

    if(ulRandomLen == 8){
        skf_soft_util::devAuthRnd.clear();
        skf_soft_util::devAuthRnd.append((char*)pbRandom,8);
    }

    return SAR_OK;
}

/*
 *	由设备生成RSA密钥对并明文输出
 *	hDev			[IN] 设备句柄
 *	ulBitsLen		[IN] 密钥模长
 *	pBlob			[OUT] 返回的私钥数据结构
 */
DEVAPI extern "C" ULONG SKF_GenExtRSAKey(
        IN DEVHANDLE hDev,
        IN ULONG ulBitsLen,
        OUT RSAPRIVATEKEYBLOB* pBlob
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	生成RSA签名密钥对并输出签名公钥
 *	hContainer		[IN] 容器句柄
 *	ulBitsLen		[IN] 密钥模长
 *	pBlob			[OUT] 返回的RSA公钥数据结构
 */
DEVAPI extern "C" ULONG SKF_GenRSAKeyPair(
        IN HCONTAINER hContainer,
        IN ULONG ulBitsLen,
        OUT RSAPUBLICKEYBLOB *pBlob
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	导入RSA加密公私钥对
 *	hContainer		[IN] 容器句柄
 *	ulSymAlgId		[IN] 对称算法密钥标识
 *	pbWrappedKey	[IN] 使用该容器内签名公钥保护的对称算法密钥
 *	ulWrappedKeyLen	[IN] 保护的对称算法密钥长度
 *	pbEncryptedData	[IN] 对称算法密钥保护的RSA加密私钥。私钥的格式遵循PKCS #1 v2.1: RSA Cryptography Standard中的私钥格式定义
 *	ulEncryptedDataLen	[IN] 对称算法密钥保护的RSA加密公私钥对长度
 */
DEVAPI extern "C" ULONG SKF_ImportRSAKeyPair(
        IN HCONTAINER hContainer,
        IN ULONG ulSymAlgId,
        IN BYTE *pbWrappedKey,
        IN ULONG ulWrappedKeyLen,
        IN BYTE *pbEncryptedData,
        IN ULONG ulEncryptedDataLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	使用hContainer指定容器的签名私钥，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名的长度
 *	hContainer		[IN] 用来签名的私钥所在容器句柄
 *	pbData			[IN] 被签名的数据
 *	ulDataLen		[IN] 签名数据长度，应不大于RSA密钥模长-11
 *	pbSignature		[OUT] 存放签名结果的缓冲区指针，如果值为NULL，用于取得签名结果长度
 *	pulSigLen		[IN,OUT] 输入为签名结果缓冲区大小，输出为签名结果长度
 */
DEVAPI extern "C" ULONG SKF_RSASignData(
        IN HANDLE hContainer,
        IN BYTE *pbData,
        IN ULONG ulDataLen,
        OUT BYTE *pbSignature,
        OUT ULONG *pulSigLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	验证RSA签名。用pRSAPubKeyBlob内的公钥值对待验签数据进行验签。
 *	hDev			[IN] 连接设备时返回的设备句柄
 *	pRSAPubKeyBlob	[IN] RSA公钥数据结构
 *	pbData			[IN] 待验证签名的数据
 *	ulDataLen		[IN] 数据长度，应不大于公钥模长-11
 *	pbSignature		[IN] 待验证的签名值
 *	ulSigLen		[IN] 签名值长度，必须为公钥模长
 */
DEVAPI extern "C" ULONG SKF_RSAVerify(
        IN DEVHANDLE			hDev,
        IN RSAPUBLICKEYBLOB*	pRSAPubKeyBlob,
        IN BYTE*				pbData,
        IN ULONG				ulDataLen,
        IN BYTE*				pbSignature,
        IN ULONG				ulSigLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	生成会话密钥并用外部公钥加密输出。
 *	hContainer		[IN] 容器句柄
 *	ulAlgID			[IN] 会话密钥的算法标识
 *	pPubKey			[IN] 加密会话密钥的RSA公钥数据结构
 *	pbData			[OUT] 导出的加密会话密钥密文，按照PKCS#1v1.5的要求封装
 *	pulDataLen		[OUT] 返回导出数据长度
 *	phSessionKey	[OUT] 导出的密钥句柄
 */
DEVAPI extern "C" ULONG SKF_RSAExportSessionKey(
        IN HCONTAINER hContainer,
        IN ULONG ulAlgID,
        IN RSAPUBLICKEYBLOB* pPubKey,
        OUT BYTE* pbData,
        OUT ULONG* pulDataLen,
        OUT HANDLE* phSessionKey
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	使用外部传入的RSA公钥对输入数据做公钥运算并输出结果
 *	hDev			[IN] 设备句柄
 *	pRSAPubKeyBlob	[IN] RSA公钥数据结构
 *	pbInput			[IN] 指向待运算的原始数据缓冲区
 *	ulInputLen		[IN] 待运算原始数据的长度，必须为公钥模长
 *	pbOutput		[OUT] 指向RSA公钥运算结果缓冲区，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
 *	pulOutputLen	[OUT] 调用前表示pbOutput缓冲区的长度，返回RSA公钥运算结果的实际长度
 */
DEVAPI extern "C" ULONG SKF_ExtRSAPubKeyOperation(
        IN DEVHANDLE hDev,
        IN RSAPUBLICKEYBLOB* pRSAPubKeyBlob,
        IN BYTE* pbInput,
        IN ULONG ulInputLen,
        OUT BYTE* pbOutput,
        OUT ULONG* pulOutputLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	直接使用外部传入的RSA私钥对输入数据做私钥运算并输出结果
 *	hDev			[IN] 设备句柄
 *	pRSAPriKeyBlob	[IN] RSA私钥数据结构
 *	pbInput			[IN] 指向待运算数据缓冲区
 *	ulInputLen		[IN] 待运算数据的长度，必须为公钥模长
 *	pbOutput		[OUT] RSA私钥运算结果，如果该参数为NULL，则由pulOutputLen返回运算结果的实际长度
 *	pulOutputLen	[OUT] 调用前表示pbOutput缓冲区的长度，返回RSA私钥运算结果的实际长度
 */
DEVAPI extern "C" ULONG SKF_ExtRSAPriKeyOperation(
        IN DEVHANDLE hDev,
        IN RSAPRIVATEKEYBLOB* pRSAPriKeyBlob,
        IN BYTE* pbInput,
        IN ULONG ulInputLen,
        OUT BYTE* pbOutput,
        OUT ULONG* pulOutputLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	生成ECC签名密钥对并输出签名公钥。
 *	hContainer		[IN] 容器句柄
 *	ulBitsLen		[IN] 密钥模长
 *	pBlob			[OUT] 返回ECC公钥数据结构
 */
DEVAPI extern "C" ULONG SKF_GenECCKeyPair(
        IN HCONTAINER hContainer,
        IN ULONG ulAlgId,
        OUT ECCPUBLICKEYBLOB *pBlob
){
    if(NULL == hContainer || NULL == pBlob || SGD_SM2_1 != ulAlgId){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setContainerHandle.begin();
    for(;it != skf_soft_util::setContainerHandle.end();it++){
        if(hContainer == *it){
            if((*it)->apph_ptr->status < SKF_STATUS_APP_LOGGIN_USR){
                return SAR_USER_NOT_LOGGED_IN;
            }

            unsigned char pri[32] = {0};
            int priLen = 32;
            unsigned char puk[64] = {0};
            int pukLen = 64;
            mm_handle sm2Handle = NULL;

            sm2Handle = ECC_Init(NULL);
            ECC_PUBLIC_KEY publicKey;
            ECC_PRIVATE_KEY privateKey;
            int ret = ECC_GenerateKeyPair(sm2Handle,
                    &publicKey, &privateKey);
            if(ret != 1){
                return SAR_FAIL;
            }

            memcpy(pri,privateKey.Ka,32);
            memcpy(puk,publicKey.Qx,32);
            memcpy(puk+32,publicKey.Qy,32);
            ret = ECC_Unit(sm2Handle);
            if(ret != 1){
                return SAR_FAIL;
            }


            memset(pBlob,0, sizeof(ECCPUBLICKEYBLOB));
            pBlob->BitLen = 32 * 8;
            memcpy(pBlob->XCoordinate + 32,puk,32);
            memcpy(pBlob->YCoordinate + 32,puk + 32,32);

            (*it)->pukSign.clear();
            (*it)->priSign.clear();
            (*it)->pukSign.append((char*)puk, sizeof(puk));
            (*it)->priSign.append((char*)pri, sizeof(pri));
            (*it)->type = 2;

            setContainerPriSign(getContainerDir((*it)->apph_ptr->appName,(*it)->containerName),(*it)->priSign);
            setContainerPukSign(getContainerDir((*it)->apph_ptr->appName,(*it)->containerName),(*it)->pukSign);
            setContainerType(getContainerDir((*it)->apph_ptr->appName,(*it)->containerName),2);

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	导入ECC公私钥对
 *	hContainer		[IN] 容器句柄
 *	pbWrapedData	[IN] 加密保护的ECC加密公私钥对密文
 *	ulWrapedLen		[IN] 数据长度
 */
DEVAPI extern "C" ULONG SKF_ImportECCKeyPair(
        IN HCONTAINER hContainer,
        IN PENVELOPEDKEYBLOB pEnvelopedKeyBlob
){
    if(NULL == hContainer || NULL == pEnvelopedKeyBlob){
        return SAR_INVALIDPARAMERR;
    }

    if(pEnvelopedKeyBlob->ECCCipherBlob.CipherLen != 16){
        SKF_DEBUG("Error cipher Len");
        return SAR_INDATALENERR;
    }

    auto it = skf_soft_util::setContainerHandle.begin();
    for(;it != skf_soft_util::setContainerHandle.end();it++){
        if((*it) == hContainer){
            if((*it)->apph_ptr->status < SKF_STATUS_APP_LOGGIN_USR){
                return SAR_USER_NOT_LOGGED_IN;
            }

            if((*it)->priSign.size() != 32){
                SKF_DEBUG("Sign keypair is not exist!!");
                return SAR_FAIL;
            }

            string cipher;
            cipher.append((char*)pEnvelopedKeyBlob->ECCCipherBlob.XCoordinate + 32,32);
            cipher.append((char*)pEnvelopedKeyBlob->ECCCipherBlob.YCoordinate + 32,32);
            cipher.append((char*)pEnvelopedKeyBlob->ECCCipherBlob.HASH, sizeof(pEnvelopedKeyBlob->ECCCipherBlob.HASH));
            cipher.append((char*)pEnvelopedKeyBlob->ECCCipherBlob.Cipher,pEnvelopedKeyBlob->ECCCipherBlob.CipherLen);

            unsigned char key[16],plain[64];
            int keyLen = 16;

            ECC_PRIVATE_KEY eccPrivateKey;
            memcpy(eccPrivateKey.Ka,(*it)->priSign.data(),(*it)->priSign.size());
            mm_handle sm2Handle = NULL;
            sm2Handle = ECC_Init(NULL);

            int ret = ECES_Decryption(sm2Handle,(BYTE*)cipher.data(),cipher.size(),&eccPrivateKey,key);
            if(ret != 1){
                SKF_DEBUG("%s IN ECES_Decryption error,ret = %d",__FUNCTION__,ret);
                return SAR_FAIL;
            }

            ret = ECC_Unit(sm2Handle);
            if(ret != 1){
                SKF_DEBUG("%s IN ECC_Unit error",__FUNCTION__);
                return SAR_FAIL;
            }

            /*int ret = SM2Init();
            if(ret != SAR_OK){
                return ret;
            }

            ret = SM2Decrypt((unsigned char*)cipher.data(),cipher.size(),
                       (unsigned char*)(*it)->priSign.data(),(*it)->priSign.size(),key,&keyLen);
            if(ret != SAR_OK){
                return ret;
            }
*/
            mm_handle h = NULL;
            h = sm4_init(key);

            ret = sm4_ecb_decrypt(h,pEnvelopedKeyBlob->cbEncryptedPriKey,sizeof(pEnvelopedKeyBlob->cbEncryptedPriKey),plain);
            if(ret != 1){
                SKF_DEBUG("%s IN sm4_ecb_decrypt error",__FUNCTION__);
                return SAR_FAIL;
            }

            sm4_unit(h);

            (*it)->pukCry.clear();
            (*it)->pukCry.append((char*)pEnvelopedKeyBlob->PubKey.XCoordinate + 32,32);
            (*it)->pukCry.append((char*)pEnvelopedKeyBlob->PubKey.YCoordinate + 32,32);

            (*it)->priCry.clear();
            (*it)->priCry.append((char*)plain + 32,32);

            setContainerPriCry(getContainerDir((*it)->apph_ptr->appName,(*it)->containerName),(*it)->priCry);
            setContainerPukCry(getContainerDir((*it)->apph_ptr->appName,(*it)->containerName),(*it)->pukCry);
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	ECC数字签名。采用ECC算法和指定私钥hKey，对指定数据pbData进行数字签名。签名后的结果存放到pbSignature缓冲区，设置pulSignLen为签名值的长度
 *	hContainer		[IN] 用来签名的私钥所在容器句柄
 *	pbData			[IN] 被签名的数据
 *	ulDataLen		[IN] 待签名数据长度，必须小于密钥模长
 *	pbSignature		[OUT] 签名值，为NULL时用于获得签名值的长度
 *	pulSigLen		[IN,OUT] 返回签名值长度的指针
 */
DEVAPI extern "C" ULONG SKF_ECCSignData(
        IN HANDLE hContainer,
        IN BYTE *pbData,
        IN ULONG ulDataLen,
        OUT PECCSIGNATUREBLOB pSignature
){
    if(NULL == hContainer || NULL == pbData || 32 != ulDataLen || NULL == pSignature){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setContainerHandle.begin();
    for(;it != skf_soft_util::setContainerHandle.end();it++){
        if(*it == hContainer){
            if((*it)->apph_ptr->status < SKF_STATUS_APP_LOGGIN_USR){
                return SAR_USER_NOT_LOGGED_IN;
            }

            unsigned char sign[64];
            int signLen = 64;

            ECC_PRIVATE_KEY eccPrivateKey;
            memcpy(eccPrivateKey.Ka,(*it)->priSign.data(),(*it)->priSign.size());
            ECC_SIGNATURE eccSignature;

            mm_handle sm2Handle = NULL;
            sm2Handle = ECC_Init(NULL);
            int ret = ECDSA_Signature(sm2Handle,pbData,&eccPrivateKey,&eccSignature,NULL);
            if(ret != 1){
                return SAR_FAIL;
            }

            ret = ECC_Unit(sm2Handle);
            if(ret != 1){
                return SAR_FAIL;
            }

            memcpy(sign,eccSignature.r,32);
            memcpy(sign+32,eccSignature.s,32);

            memset(pSignature->s,0, sizeof(pSignature->s));
            memset(pSignature->r,0, sizeof(pSignature->r));

            memcpy(pSignature->r + 32,sign,32);
            memcpy(pSignature->s + 32,sign + 32,32);

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	用ECC公钥对数据进行验签
 *	hDev			[IN] 设备句柄
 *	pECCPubKeyBlob	[IN] ECC公钥数据结构
 *	pbData			[IN] 待验证签名的数据
 *	ulDataLen		[IN] 数据长度
 *	pbSignature		[IN] 待验证的签名值
 *	ulSigLen		[IN] 签名值长度
 */
DEVAPI extern "C" ULONG SKF_ECCVerify(
        IN DEVHANDLE			hDev,
        IN ECCPUBLICKEYBLOB*	pECCPubKeyBlob,
        IN BYTE*				pbData,
        IN ULONG				ulDataLen,
        IN PECCSIGNATUREBLOB pSignature
){
    if(NULL == hDev || NULL == pECCPubKeyBlob || NULL == pbData || ulDataLen != 32 || NULL == pSignature){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if(*it == hDev){
            ECC_PUBLIC_KEY eccPublicKey;
            ECC_SIGNATURE eccSignature;

            memcpy(eccPublicKey.Qx,pECCPubKeyBlob->XCoordinate + 32,32);
            memcpy(eccPublicKey.Qy,pECCPubKeyBlob->YCoordinate + 32,32);

            memcpy(eccSignature.r,pSignature->r + 32,32);
            memcpy(eccSignature.s,pSignature->s + 32,32);

            mm_handle sm2Handle = NULL;
            sm2Handle = ECC_Init(NULL);

            int ret = ECDSA_Verification(sm2Handle,pbData,&eccPublicKey,&eccSignature);
            if(ret != 1){
                return SAR_FAIL;
            }

            ret = ECC_Unit(sm2Handle);
            if(ret != 1){
                return SAR_FAIL;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	生成会话密钥并用外部公钥加密输出。
 *	hContainer		[IN] 容器句柄
 *	ulAlgID			[IN] 会话密钥的算法标识
 *	pPubKey			[IN] 外部输入的公钥结构
 *	pbData			[OUT] 导出的加密会话密钥密文
 *	phSessionKey	[OUT] 会话密钥句柄
 */
DEVAPI extern "C" ULONG SKF_ECCExportSessionKey(
        IN HCONTAINER hContainer,
        IN ULONG ulAlgID,
        IN ECCPUBLICKEYBLOB* pPubKey,
        OUT PECCCIPHERBLOB pData,
        OUT HANDLE* phSessionKey
){
    if(NULL == hContainer || NULL == pPubKey || NULL == pData || NULL == phSessionKey){
        return SAR_INVALIDPARAMERR;
    }

    SKF_SOFT_SYMH_PTR symh_ptr = new SKF_SOFT_SYMH();
    srand(time(NULL));
    unsigned char rnd[16];
    for(int loop = 0; loop < 16;loop++){
        rnd[loop] = rand() & 0xFF;
    }

    unsigned char puk[64];
    memcpy(puk,pPubKey->XCoordinate + 32,32);
    memcpy(puk + 32,pPubKey->YCoordinate + 32,32);

    unsigned char cipher[64 + 16 + 32];
    int cipherLen = 64 + 16 + 32;

    ECC_PUBLIC_KEY eccPublicKey;
    memcpy(eccPublicKey.Qx,puk,32);
    memcpy(eccPublicKey.Qy,puk + 32,32);
    mm_handle sm2Handle = NULL;
    sm2Handle = ECC_Init(NULL);
    int ret = ECES_Encryption(sm2Handle,rnd,16,&eccPublicKey,cipher,NULL);
    if(ret != 1){
        return SAR_FAIL;
    }

    ret = ECC_Unit(sm2Handle);
    if(ret != 1){
        return SAR_FAIL;
    }

    memset(pData,0, sizeof(ECCCIPHERBLOB));
    memcpy(pData->XCoordinate + 32,cipher,32);
    memcpy(pData->YCoordinate+32,cipher+32,32);
    memcpy(pData->Cipher,cipher + 64,16);
    memcpy(pData->HASH,cipher + 64 + 16,32);
    pData->CipherLen = 16;

    symh_ptr->ulAlgId = ulAlgID;
    symh_ptr->key.append((char*)rnd,16);
    *phSessionKey = symh_ptr;
    skf_soft_util::setSessionKeyHandle.insert(symh_ptr);

    return SAR_OK;
}

/*
 *	使用外部传入的ECC公钥对输入数据做加密运算并输出结果
 *	hDev			[IN] 设备句柄
 *	pECCPubKeyBlob	[IN] ECC公钥数据结构
 *	pbPlainText		[IN] 待加密的明文数据
 *	ulPlainTextLen	[IN] 待加密明文数据的长度
 *	pbCipherText	[OUT] 指向密文数据缓冲区，如果该参数为NULL，则由pulCipherTextLen返回密文数据的实际长度
 *	pulCipherTextLen[OUT] 调用前表示pbCipherText缓冲区的长度，返回密文数据的实际长度
 */
DEVAPI extern "C" ULONG SKF_ExtECCEncrypt(
        IN DEVHANDLE hDev,
        IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
        IN BYTE* pbPlainText,
        IN ULONG ulPlainTextLen,
        OUT PECCCIPHERBLOB pbCipherText
){
    if(NULL == hDev || NULL == pECCPubKeyBlob || NULL == pbPlainText || NULL == pbCipherText || ulPlainTextLen == 0){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if(*it == hDev){
            ECC_PUBLIC_KEY eccPublicKey;
            memcpy(eccPublicKey.Qx,pECCPubKeyBlob->XCoordinate+32,32);
            memcpy(eccPublicKey.Qy,pECCPubKeyBlob->YCoordinate+32,32);

            unsigned char cipher[64 + 32 + ulPlainTextLen];
            int cipherLen = 64 + ulPlainTextLen + 32;

            mm_handle sm2Handle = ECC_Init(NULL);

            int ret = ECES_Encryption(sm2Handle,pbPlainText,ulPlainTextLen,&eccPublicKey,cipher,NULL);
            if(ret != 1){
                SKF_DEBUG("%s IN ECES_Encryption error",__FUNCTION__);
                return SAR_FAIL;
            }

            ret = ECC_Unit(sm2Handle);
            if(ret != 1){
                SKF_DEBUG("%s IN ECC_Unit error",__FUNCTION__);
                return SAR_FAIL;
            }

            memset(pbCipherText,0, sizeof(ECCCIPHERBLOB));
            memcpy(pbCipherText->XCoordinate + 32,cipher,32);
            memcpy(pbCipherText->YCoordinate+32,cipher+32,32);
            memcpy(pbCipherText->HASH,cipher + 64,32);
            memcpy(pbCipherText->Cipher,cipher + 64 + 32,ulPlainTextLen);
            pbCipherText->CipherLen = ulPlainTextLen;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	使用外部传入的ECC私钥对输入数据做解密运算并输出结果
 *	hDev			[IN] 设备句柄
 *	pRSAPriKeyBlob	[IN] ECC私钥数据结构
 *	pbInput			[IN] 待解密的密文数据
 *	ulInputLen		[IN] 待解密密文数据的长度
 *	pbOutput		[OUT] 返回明文数据，如果该参数为NULL，则由pulPlainTextLen返回明文数据的实际长度
 *	pulOutputLen	[OUT] 调用前表示pbPlainText缓冲区的长度，返回明文数据的实际长度
 */
DEVAPI extern "C" ULONG SKF_ExtECCDecrypt(
        IN DEVHANDLE hDev,
        IN ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
        IN PECCCIPHERBLOB pbCipherText,
        OUT BYTE* pbPlainText,
        OUT ULONG* pulPlainTextLen
){
    if(NULL == hDev || NULL == pECCPriKeyBlob || NULL == pbCipherText || NULL == pulPlainTextLen){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if(*it == hDev){

            *pulPlainTextLen = pbCipherText->CipherLen;
            if(NULL != pbPlainText){
                ECC_PRIVATE_KEY eccPrivateKey;
                memcpy(eccPrivateKey.Ka,pECCPriKeyBlob->PrivateKey + 32,32);

                unsigned char cipher[pbCipherText->CipherLen + 96];
                memcpy(cipher,pbCipherText->XCoordinate+32,32);
                memcpy(cipher + 32,pbCipherText->YCoordinate+32,32);
                memcpy(cipher + 32 + 32 ,pbCipherText->HASH,32);
                memcpy(cipher + 32 + 32 + 32,pbCipherText->Cipher,pbCipherText->CipherLen);

                mm_handle sm2Handle = ECC_Init(NULL);
                int ret = ECES_Decryption(sm2Handle,cipher,pbCipherText->CipherLen + 96,&eccPrivateKey,pbPlainText);
                if(ret != 1){
                    SKF_DEBUG("%s IN ECES_Decryption error",__FUNCTION__);
                    return SAR_FAIL;
                }

                ret = ECC_Unit(sm2Handle);
                if(ret != 1){
                    SKF_DEBUG("%s IN ECC_Unit error",__FUNCTION__);
                    return SAR_FAIL;
                }
            }
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	使用外部传入的ECC私钥对输入数据做签名运算并输出结果。
 *	hDev			[IN] 设备句柄
 *	pRSAPriKeyBlob	[IN] ECC私钥数据结构
 *	pbData			[IN] 待签名数据
 *	ulDataLen		[IN] 待签名数据的长度
 *	pbSignature		[OUT] 签名值，如果该参数为NULL，则由pulSignatureLen返回签名结果的实际长度
 *	pulSignatureLen	[OUT] 调用前表示pbSignature缓冲区的长度，返回签名结果的实际长度
 */
DEVAPI extern "C" ULONG SKF_ExtECCSign(
        IN DEVHANDLE hDev,
        IN ECCPRIVATEKEYBLOB* pECCPriKeyBlob,
        IN BYTE* pbData,
        IN ULONG ulDataLen,
        OUT PECCSIGNATUREBLOB pSignature
){
    if(NULL == hDev || NULL == pECCPriKeyBlob || NULL == pbData || ulDataLen != 32 || NULL == pSignature){
        return SAR_INVALIDHANDLEERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if(*it == hDev){


            ECC_PRIVATE_KEY eccPrivateKey;
            ECC_SIGNATURE eccSignature;

            memcpy(eccPrivateKey.Ka,pECCPriKeyBlob->PrivateKey + 32,32);

            mm_handle sm2Handle = ECC_Init(NULL);
            int ret = ECDSA_Signature(sm2Handle,pbData,&eccPrivateKey,&eccSignature,NULL);
            if(ret != 1){
                SKF_DEBUG("%s IN ECDSA_Signature error",__FUNCTION__);
                return SAR_FAIL;
            }

            ret = ECC_Unit(sm2Handle);
            if(ret != 1){
                SKF_DEBUG("%s IN ECC_Unit error",__FUNCTION__);
                return SAR_FAIL;
            }

            memset(pSignature,0, sizeof(ECCSIGNATUREBLOB));
            memcpy(pSignature->r + 32,eccSignature.r,32);
            memcpy(pSignature->s + 32,eccSignature.s,32);
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	外部使用传入的ECC公钥做签名验证
 *	hDev			[IN] 设备句柄
 *	pECCPubKeyBlob	[IN] ECC公钥数据结构
 *	pbData			[IN] 待验证数据
 *	ulDataLen		[IN] 待验证数据的长度
 *	pbSignature		[OUT] 签名值
 *	ulSignLen		[OUT] 签名值的长度
 */
DEVAPI extern "C" ULONG SKF_ExtECCVerify(
        IN DEVHANDLE hDev,
        IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
        IN BYTE* pbData,
        IN ULONG ulDataLen,
        IN PECCSIGNATUREBLOB pSignature
){
    if(NULL == hDev || NULL == pECCPubKeyBlob || NULL == pbData || ulDataLen != 32 || NULL == pSignature){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if(*it == hDev){

            ECC_SIGNATURE eccSignature;
            ECC_PUBLIC_KEY eccPublicKey;

            memcpy(eccPublicKey.Qx,pECCPubKeyBlob->XCoordinate + 32,32);
            memcpy(eccPublicKey.Qy,pECCPubKeyBlob->YCoordinate + 32,32);

            memcpy(eccSignature.r,pSignature->r + 32,32);
            memcpy(eccSignature.s,pSignature->s + 32,32);


            mm_handle sm2Handle = ECC_Init(NULL);

            int ret = ECDSA_Verification(sm2Handle,pbData,&eccPublicKey,&eccSignature);
            if(ret != 1){
                SKF_DEBUG("%s IN ECDSA_Verification error",__FUNCTION__);
                return SAR_FAIL;
            }

            ret = ECC_Unit(sm2Handle);
            if(ret != 1){
                SKF_DEBUG("%s IN ECC_Unit error",__FUNCTION__);
                return SAR_FAIL;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	使用ECC密钥协商算法，为计算会话密钥而产生协商参数，返回临时ECC密钥对的公钥及协商句柄
 *	hContainer		[IN] 容器句柄
 *	ulAlgId			[IN] 会话密钥算法标识
 *	pTempECCPubKeyBlob	[OUT] 发起方临时ECC公钥
 *	pbID			[IN] 发起方的ID
 *	ulIDLen			[IN] 发起方ID的长度，不大于32
 *	phAgreementHandle	[OUT] 返回的密钥协商句柄
 */
DEVAPI extern "C" ULONG SKF_GenerateAgreementDataWithECC(
        IN HCONTAINER hContainer,
        IN ULONG ulAlgId,
        OUT ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
        IN BYTE* pbID,
        IN ULONG ulIDLen,
        OUT HANDLE *phAgreementHandle
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	使用ECC密钥协商算法，产生协商参数并计算会话密钥，输出临时ECC密钥对公钥，并返回产生的密钥句柄
 *	hContainer					[IN] 容器句柄
 *	ulAlgId						[IN] 会话密钥算法标识
 *	pSponsorECCPubKeyBlob		[IN] 发起方的ECC公钥
 *	pSponsorTempECCPubKeyBlob	[IN] 发起方的临时ECC公钥
 *	pTempECCPubKeyBlob			[OUT] 响应方的临时ECC公钥
 *	pbID						[IN] 响应方的ID
 *	ulIDLen						[IN] 响应方ID的长度，不大于32
 *	pbSponsorID					[IN] 发起方的ID
 *	ulSponsorIDLen				[IN] 发起方ID的长度，不大于32
 *	phKeyHandle					[OUT] 返回的对称算法密钥句柄
 */
DEVAPI extern "C" ULONG SKF_GenerateAgreementDataAndKeyWithECC(
        IN HANDLE hContainer,
        IN ULONG ulAlgId,
        IN ECCPUBLICKEYBLOB* pSponsorECCPubKeyBlob,
        IN ECCPUBLICKEYBLOB* pSponsorTempECCPubKeyBlob,
        OUT ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
        IN BYTE* pbID,
        IN ULONG ulIDLen,
        IN BYTE *pbSponsorID,
        IN ULONG ulSponsorIDLen,
        OUT HANDLE *phKeyHandle
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥，同时返回会话密钥句柄
 *	hAgreementHandle			[IN] 密钥协商句柄
 *	pECCPubKeyBlob				[IN] 外部输入的响应方ECC公钥
 *	pTempECCPubKeyBlob			[IN] 外部输入的响应方临时ECC公钥
 *	pbID						[IN] 响应方的ID
 *	ulIDLen						[IN] 响应方ID的长度，不大于32
 *	phKeyHandle					[OUT] 返回的密钥句柄
 */
DEVAPI extern "C" ULONG SKF_GenerateKeyWithECC(
        IN HANDLE hAgreementHandle,
        IN ECCPUBLICKEYBLOB* pECCPubKeyBlob,
        IN ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
        IN BYTE* pbID,
        IN ULONG ulIDLen,
        OUT HANDLE *phKeyHandle
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	导出容器中的签名公钥或者加密公钥
 *	hContainer		[IN] 容器句柄
 *	bSignFlag		[IN] TRUE表示导出签名公钥，FALSE表示导出加密公钥
 *	pbBlob			[OUT] 指向RSA公钥结构（RSAPUBLICKEYBLOB）或者ECC公钥结构（ECCPUBLICKEYBLOB），如果此参数为NULL时，由pulBlobLen返回pbBlob的长度
 *	pulBlobLen		[IN,OUT] 调用时表示pbBlob的长度，返回导出公钥结构的大小
 */
DEVAPI extern "C" ULONG SKF_ExportPublicKey(
        IN HCONTAINER hContainer,
        IN BOOL bSignFlag,
        OUT BYTE* pbBlob,
        OUT ULONG* pulBlobLen
){
    if(NULL == hContainer || NULL == pulBlobLen){
        return SAR_INVALIDPARAMERR;
    }

    ECCPUBLICKEYBLOB eccpublickeyblob;
    memset(&eccpublickeyblob,0,sizeof(eccpublickeyblob));
    eccpublickeyblob.BitLen = 32 * 8;

    *pulBlobLen = sizeof(eccpublickeyblob);
    if(NULL == pbBlob){
        return SAR_OK;
    }
    memset(pbBlob,0,sizeof(eccpublickeyblob));

    auto it = skf_soft_util::setContainerHandle.begin();
    for(;it != skf_soft_util::setContainerHandle.end();it++){
        if(*it == hContainer){
            if(bSignFlag){
                if((*it)->pukSign.size() != 64){
                    SKF_DEBUG("%s IN error puksign size =%d",__FUNCTION__,(*it)->pukSign.size());
                    return SAR_FAIL;
                }



                memcpy(eccpublickeyblob.XCoordinate + 32,(*it)->pukSign.data(),32);
                memcpy(eccpublickeyblob.YCoordinate + 32,(*it)->pukSign.data() + 32,32);
            } else{
                if((*it)->pukCry.size() != 64){
                    SKF_DEBUG("%s IN error pukCry size =%d",__FUNCTION__,(*it)->pukSign.size());
                    return SAR_FAIL;
                }
                memcpy(eccpublickeyblob.XCoordinate + 32,(*it)->pukCry.data(),32);
                memcpy(eccpublickeyblob.YCoordinate + 32,(*it)->pukCry.data() + 32,32);
            }
            memcpy(pbBlob,&eccpublickeyblob,sizeof(eccpublickeyblob));
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	导入会话密钥
 *	hContainer		[IN] 容器句柄
 *	ulAlgID			[IN] 会话密钥的算法标识
 *	pbWrapedData	[IN] 要导入的数据
 *	ulWrapedLen		[IN] 数据长度
 *	phKey			[OUT] 返回会话密钥句柄
 */
DEVAPI extern "C" ULONG SKF_ImportSessionKey(
        IN HCONTAINER hContainer,
        IN ULONG ulAlgID,
        IN BYTE *pbWrapedData,
        IN ULONG ulWrapedLen,
        OUT HANDLE* phKey
){
    if(NULL == hContainer || NULL == pbWrapedData || NULL == phKey || ulWrapedLen <= sizeof(ECCCIPHERBLOB)){
        return SAR_INVALIDPARAMERR;
    }

    PECCCIPHERBLOB pecccipherblob = (PECCCIPHERBLOB)new unsigned char[ulWrapedLen];
    memcpy(pecccipherblob,pbWrapedData,ulWrapedLen);

    if(pecccipherblob->CipherLen != 16){
        SKF_DEBUG("%s IN session key len = %d error",__FUNCTION__,pecccipherblob->CipherLen);
        return SAR_KEYUSAGEERR;
    }

    auto it = skf_soft_util::setContainerHandle.begin();
    for(;it != skf_soft_util::setContainerHandle.end();it++){
        if(*it == hContainer){
            if((*it)->apph_ptr->status < SKF_STATUS_APP_LOGGIN_USR){
                return SAR_USER_NOT_LOGGED_IN;
            }

            if((*it)->priCry.size() != 32){
                SKF_DEBUG("%s IN session priCry len = %d error",__FUNCTION__,(*it)->priCry.size());
                return SAR_FAIL;
            }

            unsigned char cipher[64 + 16 + 32];
            memcpy(cipher,pecccipherblob->XCoordinate + 32,32);
            memcpy(cipher + 32,pecccipherblob->YCoordinate + 32,32);
            memcpy(cipher + 64,pecccipherblob->HASH,32);
            memcpy(cipher + 64 + 32,pecccipherblob->Cipher,pecccipherblob->CipherLen);


            unsigned char key[16];
            int keyLen = 16;

            mm_handle sm2Handle = ECC_Init(NULL);
            ECC_PRIVATE_KEY eccPrivateKey;
            memcpy(eccPrivateKey.Ka,(*it)->priCry.data(),(*it)->priCry.size());
            int ret = ECES_Decryption(sm2Handle,cipher, sizeof(cipher),&eccPrivateKey,key);
            if(ret != 1){
                SKF_DEBUG("%s IN,ECES_Decryption error",__FUNCTION__);
                return SAR_FAIL;
            }

            ret = ECC_Unit(sm2Handle);
            if(ret != 1){
                SKF_DEBUG("%s IN,ECC_Unit error",__FUNCTION__);
                return SAR_FAIL;
            }

            SKF_SOFT_SYMH_PTR symh_ptr = new SKF_SOFT_SYMH();
            symh_ptr->containerh_ptr = *it;
            symh_ptr->key.append((char*)key,16);
            symh_ptr->devh_ptr = (*it)->apph_ptr->devh_ptr;
            symh_ptr->ulAlgId = ulAlgID;

            skf_soft_util::setSessionKeyHandle.insert(symh_ptr);
            *phKey = symh_ptr;

            SKF_DEBUG("%s OUT OK",__FUNCTION__);
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	设置明文对称密钥，返回密钥句柄
 *	hContainer		[IN] 容器句柄
 *	pbKey			[IN] 指向会话密钥值的缓冲区
 *	ulAlgID			[IN] 会话密钥的算法标识
 *	phKey			[OUT] 返回会话密钥句柄
 */
DEVAPI extern "C" ULONG SKF_SetSymmKey(
        IN DEVHANDLE hDev,
        IN BYTE* pbKey,
        IN ULONG ulAlgID,
        OUT HANDLE* phKey
){
    if(NULL == hDev || NULL == pbKey || NULL == phKey){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if(*it == hDev){
            SKF_SOFT_SYMH_PTR symh_ptr = new SKF_SOFT_SYMH();
            symh_ptr->devh_ptr = (SKF_SOFT_DEVH_PTR)hDev;
            symh_ptr->ulAlgId = ulAlgID;
            symh_ptr->key.clear();
            symh_ptr->key.append((char*)pbKey,16);

            skf_soft_util::setSessionKeyHandle.insert(symh_ptr);
            *phKey = symh_ptr;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	数据加密初始化。设置数据加密的算法相关参数。
 *	hKey			[IN] 加密密钥句柄
 *	EncryptParam	[IN] 分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
 */
DEVAPI extern "C" ULONG SKF_EncryptInit(
        IN HANDLE hKey,
        IN BLOCKCIPHERPARAM EncryptParam
){
    if(NULL == hKey){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setSessionKeyHandle.begin();
    for(;it != skf_soft_util::setSessionKeyHandle.end();it++){
        if(*it == hKey){
            (*it)->iv.clear();
            (*it)->iv.append((char*)EncryptParam.IV,EncryptParam.IVLen);
            (*it)->paddingType = EncryptParam.PaddingType;

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	单一分组数据的加密操作。
    用指定加密密钥对指定数据进行加密，被加密的数据只包含一个分组，加密后的密文保存到指定的缓冲区中。
    SKF_Encrypt只对单个分组数据进行加密，在调用SKF_Encrypt之前，必须调用SKF_EncryptInit初始化加密操作。
    SKF_Encypt等价于先调用SKF_EncryptUpdate再调用SKF_EncryptFinal。
 *	hKey			[IN] 加密密钥句柄
 *	pbData			[IN] 待加密数据
 *	ulDataLen		[IN] 待加密数据长度
 *	pbEncryptedData [OUT] 加密后的数据缓冲区指针
 *	pulEncryptedLen [IN,OUT] 输入，给出的缓冲区大小；输出，返回加密后的数据
长度
 *	成功: SAR_OK
 *	失败: SAR_FAIL SAR_MEMORYERR SAR_UNKNOWNERR  SAR_INVALIDPARAMERR SAR_BUFFER_TOO_SMALL
 */
DEVAPI extern "C" ULONG SKF_Encrypt(
        HANDLE	hKey,
        BYTE*		pbData,
        ULONG		ulDataLen,
        BYTE*		pbEncryptedData,
        ULONG*	pulEncryptedLen
){
    if(NULL == hKey || NULL == pbData || ulDataLen == 0 || NULL == pulEncryptedLen || ulDataLen % 16 != 0){
        return SAR_INVALIDPARAMERR;
    }


    auto it = skf_soft_util::setSessionKeyHandle.begin();
    for(;it != skf_soft_util::setSessionKeyHandle.end();it++){
        if(*it == hKey){
            if((*it)->key.size() != 16){
                return SAR_KEYINFOTYPEERR;
            }

            if(NULL == pbEncryptedData){
                *pulEncryptedLen = ulDataLen;
                return SAR_OK;
            }

            unsigned char key[16];
            memcpy(key,(*it)->key.data(),(*it)->key.size());

            mm_handle h = NULL;
            h = sm4_init(key);

            int ret = 1;

            if((*it)->ulAlgId == SGD_SMS4_ECB){
                ret = sm4_ecb_encrypt(h,pbData,ulDataLen,pbEncryptedData);
                if(ret != 1){
                    sm4_unit(h);
                    SKF_DEBUG("%s IN,sm4_ecb_encrypt error",__FUNCTION__);
                    return SAR_FAIL;
                }

            } else if((*it)->ulAlgId == SGD_SMS4_CBC){
                ret = sm4_set_iv(h,(mm_u8_t*)(*it)->iv.data());
                if(ret != 1){
                    sm4_unit(h);
                    SKF_DEBUG("%s IN,sm4_set_iv error",__FUNCTION__);

                    return SAR_FAIL;
                }
                ret = sm4_cbc_encrypt(h,pbData,ulDataLen,pbEncryptedData);
                if(ret != 1){
                    sm4_unit(h);
                    SKF_DEBUG("%s IN,sm4_cbc_encrypt error",__FUNCTION__);
                    return SAR_FAIL;
                }
            } else if((*it)->ulAlgId == SGD_SMS4_OFB){
                ret = sm4_set_iv(h,(mm_u8_t*)(*it)->iv.data());
                if(ret != 1){
                    sm4_unit(h);
                    SKF_DEBUG("%s IN,sm4_set_iv error",__FUNCTION__);
                    return SAR_FAIL;
                }
                ret = sm4_ofb_encrypt(h,pbData,ulDataLen,pbEncryptedData);
                if(ret != 1){
                    sm4_unit(h);
                    SKF_DEBUG("%s IN,sm4_ofb_encrypt error",__FUNCTION__);
                    return SAR_FAIL;
                }
            } else {
                sm4_unit(h);
                SKF_DEBUG("%s IN,alg error = 0x%08x",__FUNCTION__,(*it)->ulAlgId);
                return SAR_KEYINFOTYPEERR;
            }

            sm4_unit(h);

            return SAR_OK;
        }
    }

    return SAR_KEYNOTFOUNDERR;
}

/*
 *	多个分组数据的加密操作。
    用指定加密密钥对指定数据进行加密，被加密的数据包含多个分组，加密后的密文保存到指定的缓冲区中。
    SKF_EncryptUpdate对多个分组数据进行加密，在调用SKF_EncryptUpdate之前，必须调用SKF_EncryptInit初始化加密操作；
    在调用SKF_EncryptUpdate之后，必须调用SKF_EncryptFinal结束加密操作。
 *	hKey			[IN] 加密密钥句柄
 *	pbData			[IN] 待加密数据
 *	ulDataLen		[IN] 待加密数据长度
 *	pbEncryptedData [OUT] 加密后的数据缓冲区指针
 *	pulEncryptedLen [OUT] 返回加密后的数据长度
 */
DEVAPI extern "C" ULONG SKF_EncryptUpdate(
        IN HANDLE		hKey,
        IN BYTE*		pbData,
        IN ULONG		ulDataLen,
        OUT BYTE*		pbEncryptedData,
        OUT ULONG*	pulEncryptedLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	结束多个分组数据的加密，返回剩余加密结果。
    先调用SKF_EncryptInit初始化加密操作，
    再调用SKF_EncryptUpdate对多个分组数据进行加密，
    最后调用SKF_EncryptFinal结束多个分组数据的加密。
 *	hKey			[IN] 加密密钥句柄
 *	pbEncryptedData [OUT] 加密结果的缓冲区
 *	pulEncryptedLen [OUT] 加密结果的长度
 */
DEVAPI extern "C" ULONG SKF_EncryptFinal(
        IN HANDLE hKey,
        OUT BYTE *pbEncryptedData,
        OUT ULONG *pulEncryptedDataLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	数据解密初始化，设置解密密钥相关参数。
    调用SKF_DecryptInit之后，可以调用SKF_Decrypt对单个分组数据进行解密，
    也可以多次调用SKF_DecryptUpdate之后再调用SKF_DecryptFinal完成对多个分组数据的解密。
 *	hKey [IN] 解密密钥句柄
 *	DecryptParam [IN] 分组密码算法相关参数：算法标识号、密钥长度、初始向量、初始向量长度、填充方法、加密模式、反馈值的位长度
 */
DEVAPI extern "C" ULONG SKF_DecryptInit(
        IN HANDLE hKey,
        IN BLOCKCIPHERPARAM DecryptParam
){
    if(NULL == hKey){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setSessionKeyHandle.begin();
    for(;it != skf_soft_util::setSessionKeyHandle.end();it++){
        if(*it == hKey){
            (*it)->iv.clear();
            (*it)->iv.append((char*)DecryptParam.IV,DecryptParam.IVLen);
            (*it)->paddingType = DecryptParam.PaddingType;

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	单个分组数据的解密操作
    用指定解密密钥对指定数据进行解密，被解密的数据只包含一个分组，解密后的明文保存到指定的缓冲区中
    SKF_Decrypt只对单个分组数据进行解密，在调用SKF_Decrypt之前，必须调用SKF_DecryptInit初始化解密操作
    SKF_Decypt等价于先调用SKF_DecryptUpdate再调用SKF_DecryptFinal
 *	hKey			[IN] 解密密钥句柄
 *	pbEncryptedData [IN] 待解密数据
 *	ulEncryptedLen	[IN] 待解密数据长度
 *	pbData			[OUT] 指向解密后的数据缓冲区指针，当为NULL时可获得解密后的数据长度
 *	pulDataLen		[IN，OUT] 返回解密后的数据长度
 */
DEVAPI extern "C" ULONG SKF_Decrypt(
        IN HANDLE hKey,
        IN BYTE*	pbEncryptedData,
        IN ULONG	ulEncryptedLen,
        OUT BYTE* pbData,
        OUT ULONG* pulDataLen
){
    if(NULL == hKey || NULL == pbEncryptedData || ulEncryptedLen == 0 || NULL == pulDataLen || ulEncryptedLen % 16 != 0){
        return SAR_INVALIDPARAMERR;
    }


    auto it = skf_soft_util::setSessionKeyHandle.begin();
    for(;it != skf_soft_util::setSessionKeyHandle.end();it++){
        if(*it == hKey){
            if((*it)->key.size() != 16){
                return SAR_KEYINFOTYPEERR;
            }

            if(NULL == pbData){
                *pulDataLen = ulEncryptedLen;
                return SAR_OK;
            }

            //sm4_context sm4Context;
            unsigned char key[16];
            memcpy(key,(*it)->key.data(),(*it)->key.size());

            mm_handle mmHandle = NULL;
            mmHandle = sm4_init(key);
            int ret = 1;

            if((*it)->ulAlgId == SGD_SMS4_ECB){
                ret = sm4_ecb_decrypt(mmHandle,pbEncryptedData,ulEncryptedLen,pbData);
                if(ret != 1){
                    sm4_unit(mmHandle);
                    SKF_DEBUG("%s IN,sm4_ecb_decrypt error",__FUNCTION__);
                    return SAR_FAIL;
                }

            } else if((*it)->ulAlgId == SGD_SMS4_CBC){
                ret = sm4_set_iv(mmHandle,(mm_u8_t*)(*it)->iv.data());
                if(ret != 1){
                    sm4_unit(mmHandle);
                    SKF_DEBUG("%s IN,sm4_set_iv error",__FUNCTION__);
                    return SAR_FAIL;
                }

                ret = sm4_cbc_decrypt(mmHandle,pbEncryptedData,ulEncryptedLen,pbData);
                if(ret != 1){
                    sm4_unit(mmHandle);
                    SKF_DEBUG("%s IN,sm4_cbc_decrypt error",__FUNCTION__);
                    return SAR_FAIL;
                }
            } else if((*it)->ulAlgId == SGD_SMS4_OFB){
                ret = sm4_set_iv(mmHandle,(mm_u8_t*)(*it)->iv.data());
                if(ret != 1){
                    sm4_unit(mmHandle);
                    SKF_DEBUG("%s IN,sm4_set_iv error",__FUNCTION__);
                    return SAR_FAIL;
                }

                ret = sm4_ofb_decrypt(mmHandle,pbEncryptedData,ulEncryptedLen,pbData);
                if(ret != 1){
                    sm4_unit(mmHandle);
                    SKF_DEBUG("%s IN,sm4_ofb_decrypt error",__FUNCTION__);
                    return SAR_FAIL;
                }

            } else{
                sm4_unit(mmHandle);
                return SAR_KEYINFOTYPEERR;
            }

            sm4_unit(mmHandle);
            SKF_DEBUG("%s OUT OK",__FUNCTION__);
            return SAR_OK;
        }
    }

    return SAR_KEYNOTFOUNDERR;
}

/*
*	多个分组数据的解密操作。
    用指定解密密钥对指定数据进行解密，被解密的数据包含多个分组，解密后的明文保存到指定的缓冲区中。
    SKF_DecryptUpdate对多个分组数据进行解密，在调用SKF_DecryptUpdate之前，必须调用SKF_DecryptInit初始化解密操作；
    在调用SKF_DecryptUpdate之后，必须调用SKF_DecryptFinal结束解密操作。
 *	hKey			[IN] 解密密钥句柄
 *	pbEncryptedData [IN] 待解密数据
 *	ulEncryptedLen	[IN] 待解密数据长度
 *	pbData			[OUT] 指向解密后的数据缓冲区指针
 *	pulDataLen		[IN，OUT] 返回解密后的数据长度
 */
DEVAPI extern "C" ULONG SKF_DecryptUpdate(
        IN HANDLE hKey,
        IN BYTE*	pbEncryptedData,
        IN ULONG	ulEncryptedLen,
        OUT BYTE* pbData,
        OUT ULONG* pulDataLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	结束多个分组数据的解密。
 *	hKey				[IN] 解密密钥句柄
 *	pbPlainText			[OUT] 指向解密结果的缓冲区，如果此参数为NULL时，由pulPlainTextLen返回解密结果的长度
 *	pulDecyptedDataLen	[IN，OUT] 调用时表示pbPlainText缓冲区的长度，返回解密结果的长度
 */
DEVAPI extern "C" ULONG SKF_DecryptFinal(
        IN HANDLE hKey,
        OUT BYTE *pbPlainText,
        OUT ULONG *pulPlainTextLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	初始化消息杂凑计算操作，指定计算消息杂凑的算法。
 *	hDev			[IN] 连接设备时返回的设备句柄
 *	ulAlgID			[IN] 杂凑算法标识
 *	phHash			[OUT] 杂凑对象句柄
 */
DEVAPI extern "C" ULONG SKF_DigestInit(
        IN DEVHANDLE	hDev,
        IN ULONG		ulAlgID,
        IN ECCPUBLICKEYBLOB *pPubKey,
        IN unsigned char *pucID,
        IN ULONG ulIDLen,
        OUT HANDLE*	phHash
){
    if(NULL == hDev || NULL == phHash){
        return SAR_INVALIDPARAMERR;
    }

    if(ulAlgID != SGD_SM3){
        return SAR_HASHERR;
    }

    auto it = skf_soft_util::setDevHandle.begin();
    for(;it != skf_soft_util::setDevHandle.end();it++){
        if(*it == hDev){
            SKF_SOFT_HANDLEH_PTR handleh_ptr = new SKF_SOFT_HANDLEH();
            handleh_ptr->devh_ptr = *it;
            handleh_ptr->ulAlgID = SGD_SM3;
            skf_soft_util::setHashHandle.insert(handleh_ptr);
            *phHash = handleh_ptr;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}
/*
 *	对单一分组的消息进行杂凑计算。
 *	hHash			[IN] 杂凑对象句柄
 *	pbData			[IN] 指向消息数据的缓冲区
 *	ulDataLen		[IN] 消息数据的长度
 *	pbHashData		[OUT] 杂凑数据缓冲区指针，当此参数为NULL时，由pulHashLen返回杂凑结果的长度
 *	pulHashLen		[IN，OUT] 调用时表示pbHashData缓冲区的长度，返回杂凑结果的长度
 */
DEVAPI extern "C" ULONG SKF_Digest(
        IN HANDLE hHash,
        IN BYTE *pbData,
        IN ULONG ulDataLen,
        OUT BYTE *pbHashData,
        OUT ULONG *pulHashLen
){
    if(NULL == hHash || NULL == pbData || ulDataLen == 0 || NULL == pulHashLen){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setHashHandle.begin();
    for(;it != skf_soft_util::setHashHandle.end();it++){
        if(*it == hHash){
            *pulHashLen = 32;
            if(NULL != pbHashData){
                sm3_hash(pbData,ulDataLen,pbHashData);
            }
            return SAR_OK;
        }
    }
    return SAR_INVALIDHANDLEERR;
}

/*
 *	对多个分组的消息进行杂凑计算。
 *	hHash			[IN] 杂凑对象句柄
 *	pbPart			[IN] 指向消息数据的缓冲区
 *	ulPartLen		[IN] 消息数据的长度
 */
DEVAPI extern "C" ULONG SKF_DigestUpdate(
        IN HANDLE hHash,
        IN BYTE *pbData,
        IN ULONG ulDataLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	结束多个分组消息的杂凑计算操作，将杂凑保存到指定的缓冲区。
 *	hHash			[IN] 哈希对象句柄
 *	pHashData		[OUT] 返回的杂凑数据缓冲区指针，如果此参数NULL时，由pulHashLen返回杂凑结果的长度
 *	pulHashLen		[IN，OUT] 调用时表示杂凑结果的长度，返回杂凑数据的长度
 */
DEVAPI extern "C" ULONG SKF_DigestFinal(
        IN HANDLE hHash,
        OUT BYTE *pHashData,
        OUT ULONG *pulHashLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	初始化消息认证码计算操作，设置计算消息认证码的密钥参数，并返回消息认证码句柄。
 *	hKey			[IN] 计算消息认证码的密钥句柄
 *	MacParam		[IN] 消息认证计算相关参数，包括初始向量、初始向量长度、填充方法等
 *	phMac			[OUT] 消息认证码对象句柄
 */
DEVAPI extern "C" ULONG SKF_MacInit(
        IN HANDLE hKey,
        IN BLOCKCIPHERPARAM* MacParam,
        OUT HANDLE *phMac
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	SKF_Mac计算单一分组数据的消息认证码。
 *	hMac			[IN] 消息认证码句柄
 *	pbData			[IN] 指向待计算数据的缓冲区
 *	ulDataLen		[IN] 待计算数据的长度
 *	pbMacData		[OUT] 指向计算后的Mac结果，如果此参数为NULL时，由pulMacLen返回计算后Mac结果的长度
 *	pulMacLen		[IN，OUT] 调用时表示pbMacData缓冲区的长度，返回计算Mac结果的长度
 */
DEVAPI extern "C" ULONG SKF_Mac(
        IN HANDLE hMac,
        IN BYTE * pbData,
        IN ULONG ulDataLen,
        OUT BYTE *pbMacData,
        OUT ULONG *pulMacLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	计算多个分组数据的消息认证码。
 *	hMac			[IN] 消息认证码句柄
 *	pbData			[IN] 指向待计算数据的缓冲区
 *	plDataLen		[IN] 待计算数据的长度
 */
DEVAPI extern "C" ULONG SKF_MacUpdate(
        IN HANDLE hMac,
        IN BYTE*	pbData,
        IN ULONG	ulDataLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	结束多个分组数据的消息认证码计算操作
 *	hMac			[IN] 消息认证码句柄
 *	pbMacData		[OUT] 指向消息认证码的缓冲区，当此参数为NULL时，由pulMacDataLen返回消息认证码返回的长度
 *	pulMacDataLen	[OUT] 调用时表示消息认证码缓冲区的最大长度，返回消息认证码的长度
 */
DEVAPI extern "C" ULONG SKF_MacFinal(
        IN HANDLE hMac,
        OUT BYTE*	pbMacData,
        OUT ULONG* pulMacDataLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	关闭会话密钥、杂凑、消息认证码句柄。
 *	hHandle			[IN] 要关闭的对象句柄
 */
DEVAPI extern "C" ULONG SKF_CloseHandle(
        IN HANDLE hHandle
){
    if(NULL == hHandle){
        return SAR_INVALIDPARAMERR;
    }
    auto it1 = skf_soft_util::setSessionKeyHandle.begin();
    for(;it1 != skf_soft_util::setSessionKeyHandle.end();it1++){
        if(*it1 == hHandle){
            SKF_SOFT_SYMH_PTR symh_ptr = *it1;
            skf_soft_util::setSessionKeyHandle.erase(it1);
            delete symh_ptr;
            symh_ptr = NULL;
            SKF_DEBUG("Success close key handle");
            return SAR_OK;
        }
    }

    auto it2 = skf_soft_util::setHashHandle.begin();
    for(;it2 != skf_soft_util::setHashHandle.end();it2++){
        if(*it2 == hHandle){
            SKF_SOFT_HANDLEH_PTR handleh_ptr = *it2;
            skf_soft_util::setHashHandle.erase(it2);
            delete handleh_ptr;
            handleh_ptr = NULL;
            SKF_DEBUG("Success close hash handle");
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	将命令直接发送给设备，并返回结果
 *	hDev			[IN] 设备句柄
 *	pbCommand		[IN] 设备命令
 *	ulCommandLen	[IN] 命令长度
 *	pbData			[OUT] 返回结果数据
 *	pulDataLen		[OUT] 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度
 */
DEVAPI extern "C" ULONG SKF_Transmit(
        IN DEVHANDLE hDev,
        IN BYTE* pbCommand,
        IN ULONG ulCommandLen,
        OUT BYTE* pbData,
        OUT ULONG* pulDataLen
){
    return SAR_NOTSUPPORTYETERR;
}

/*
 *	往容器中导入签名证书或者加密证书
 *	hContainer		[IN] 容器句柄
 *	bSignFlag		[IN] TRUE表示导入签名证书，FALSE表示导入加密证书
 *	pbCert			[IN] 指向证书数据的缓冲区
 *	ulCertLen		[IN] 证书数据的长度
 */
DEVAPI extern "C" ULONG SKF_ImportCertificate(
        IN HCONTAINER hContainer,
        IN BOOL bSignFlag,
        IN BYTE* pbCert,
        IN ULONG ulCertLen
){ 
    if(NULL == hContainer || NULL == pbCert || 0 == ulCertLen){
        return SAR_INVALIDPARAMERR;
    }

    bool setFlg = false;
    string cert;
    cert.append((char*)pbCert,ulCertLen);

    auto it = skf_soft_util::setContainerHandle.begin();
    for(;it != skf_soft_util::setContainerHandle.end();it++){
        if(*it == hContainer){
            if((*it)->apph_ptr->status < SKF_STATUS_APP_LOGGIN_USR){
                return SAR_USER_NOT_LOGGED_IN;
            }

            if(bSignFlag){
                setFlg = setContainerCertSign(getContainerDir((*it)->apph_ptr->appName,(*it)->containerName),cert);
                if(!setFlg){
                    return SAR_FAIL;
                }

                (*it)->certSign = cert;
            } else{

                setFlg = setContainerCertCry(getContainerDir((*it)->apph_ptr->appName,(*it)->containerName),cert);
                if(!setFlg){
                    return SAR_FAIL;
                }

                (*it)->certCry = cert;
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	导出容器中的签名证书或者加密证书
 *	hContainer		[IN] 容器句柄
 *	bSignFlag		[IN] TRUE表示导出签名证书，FALSE表示导出加密证书
 *	pbCert			[OUT] 指向证书数据的缓冲区
 *	pulCertLen		[IN,OUT] 调用时表示pbCert的长度，返回导出证书的大小
 */
DEVAPI extern "C" ULONG SKF_ExportCertificate(
        IN HCONTAINER hContainer,
        IN BOOL bSignFlag,
        OUT BYTE* pbCert,
        IN OUT ULONG* pulCertLen
){
    if(NULL == hContainer || NULL == pulCertLen){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setContainerHandle.begin();
    for(;it != skf_soft_util::setContainerHandle.end();it++){
        if(*it == hContainer){
            if(bSignFlag){
                *pulCertLen = (*it)->certSign.size();
                if(NULL != pbCert){
                    memcpy(pbCert,(*it)->certSign.data(),(*it)->certSign.size());
                }

            } else{
                *pulCertLen = (*it)->certCry.size();
                if(NULL != pbCert){
                    memcpy(pbCert,(*it)->certCry.data(),(*it)->certCry.size());
                }
            }

            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}

/*
 *	获取容器的属性
 *	hContainer		[IN] 容器句柄
 *	pulConProperty	[OUT] 获得的容器属性。指针指向的值为0表示未知、尚未分配属性或者为空容器，为1表示为RSA容器，为2表示为ECC容器。
 */
DEVAPI extern "C" ULONG SKF_GetContainerProperty(
        IN HCONTAINER hContainer,
        OUT ULONG *pulConProperty
){
    if(NULL == hContainer){
        return SAR_INVALIDPARAMERR;
    }

    auto it = skf_soft_util::setContainerHandle.begin();
    for(;it != skf_soft_util::setContainerHandle.end();it++){
        if(*it == hContainer){
            *pulConProperty = (*it)->type;
            return SAR_OK;
        }
    }

    return SAR_INVALIDHANDLEERR;
}
