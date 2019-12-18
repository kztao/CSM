package com.westone.rpcserver;

interface IfMsgToClient {
    void MsgToClient(int pid, String serverName,byte[] msg);
}
