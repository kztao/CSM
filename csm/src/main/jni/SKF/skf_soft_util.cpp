//
// Created by wjr on 19-8-12.
//

#include "skf_soft_util.h"

string skf_soft_util::nameAuthKey = "AuthKey";
string skf_soft_util::nameLabel = "DevLabel";

string skf_soft_util::prefixApp = "App_";
string skf_soft_util::prefixContainer = "Container_";
string skf_soft_util::prefixFile = "File_";

string skf_soft_util::nameSoDefaultPin = "SoDefaultPin";
string skf_soft_util::nameSoPin = "SoPin";
string skf_soft_util::nameSoPinMaxCount = "SoPinMaxCount";
string skf_soft_util::nameSoPinRemainCount = "SoPinRemainCount";

string skf_soft_util::nameUsrDefaultPin = "UsrDefaultPin";
string skf_soft_util::nameUsrPin = "UsrPin";
string skf_soft_util::nameUsrPinMaxCount = "UsrPinMaxCount";
string skf_soft_util::nameUsrPinRemainCount = "UsrPinRemainCount";
string skf_soft_util::nameRights = "Rights";

string skf_soft_util::nameFileContent = "Content";
string skf_soft_util::nameFileReadRight = "ReadRights";
string skf_soft_util::nameFileWriteRight = "WriteRights";

string skf_soft_util::nameContainerPukSign = "ContainerPukSign";
string skf_soft_util::nameContainerPriSign = "ContainerPriSign";
string skf_soft_util::nameContainerCertSign = "ContainerCertSign";

string skf_soft_util::nameContainerPukCry = "ContainerPukCry";
string skf_soft_util::nameContainerPriCry = "ContainerPriCry";
string skf_soft_util::nameContainerCertCry = "ContainerCertCry";

string skf_soft_util::nameContainerType = "ContainerType";



string skf_soft_util::devDir;
string skf_soft_util::devAuthRnd;
string skf_soft_util::devManufacturer = "YDHLW";

set<SKF_SOFT_DEVH_PTR > skf_soft_util::setDevHandle;//设备句柄
set<SKF_SOFT_APPH_PTR > skf_soft_util::setAppHandle;//应用句柄
set<SKF_SOFT_CONTAINERH_PTR > skf_soft_util::setContainerHandle;//容器句柄
set<SKF_SOFT_SYMH_PTR > skf_soft_util::setSessionKeyHandle;  // session key handle
set<SKF_SOFT_FILEH_PTR > skf_soft_util::setFileHandle;//文件句柄
set<SKF_SOFT_CERTH_PTR > skf_soft_util::setCertHandle;//证书句柄
set<SKF_SOFT_ASYMH_PTR > skf_soft_util::setAysmHandle;//密钥句柄

set<SKF_SOFT_HANDLEH_PTR > skf_soft_util::setHashHandle;