package com.westone.rpcserver;

class JniFunc {
    static {
        System.loadLibrary("RpcJniServer");
    }

    public native int MsgToServer(int id, String serverName, byte[] recvMsg);

    public native void RegCallback(IfMsgToClient ifMsgToClient);
}
