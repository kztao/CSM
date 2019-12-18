package com.westone.csm;

interface CallbackServer {
    void SendMsgToClient(int pid, byte[] msg);
}
