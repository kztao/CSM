package com.westone.rpcserver;

interface IfNotifyClientStatus {
    void notifyStatus(int pid,String serverName,int status);
}
