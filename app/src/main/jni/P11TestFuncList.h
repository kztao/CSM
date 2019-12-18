//
// Created by wang.junren on 2018/7/6.
//

#ifndef CSM_P11TESTFUNCLIST_H
#define CSM_P11TESTFUNCLIST_H

#include <string>
#include <iostream>
#include "cryptoki.h"

using std::string;
void TimeStart();
long TimeEnd();
void Save(string funcName,long ret,string otherInfo,long msec);
void Clear();


class P11TestFuncList {
private:
    void ObjDataFunc();
    void ObjKeyFunc();

    void SM2KeyFunc();

public:
    void BaseFunc(string userPIN,string soPin,register_status_callback_func func);
    void ObjFunc();
    void KeyFunc();
    void EncFunc();
    void DigFunc();
    void SignFunc();
    void RndFunc();
    void ExtFunc();
    void SCsetup();
    void calltest();
    void testthreadFunc(string userPIN);


    long** SM2_PerTest(long count,long length,string &dst);
    long** SM4_PerTest(long which,long count,long length,string &dst);
    long** Zuc_PerTest(long count,long length,string &dst);

    void Zuc_PerTest(int count,int length,string &dst,long *mtimes);

};



#endif //CSM_P11TESTFUNCLIST_H
