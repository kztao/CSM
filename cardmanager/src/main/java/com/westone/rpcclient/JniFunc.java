package com.westone.rpcclient;

class JniFunc {
    static {
        System.loadLibrary("RpcJniClient");
    }

    public native void RegRemoteCallFunc(String serviceName, IfMsgToServer ifMsgToServer);

    public native int ParseServerMsg(String serviceName,byte[] msg);

    public native void resetClientChannel();
}
