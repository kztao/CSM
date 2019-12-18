package com.westone.csm;

class CSMNative{

    static {
        System.loadLibrary("Server");
    }

    public native void Init(CertVerify certVerify);

    public  native void TFCardPlugin(boolean flg);

    public  native void setMountFlag(boolean flg);

    public native void NotifyClientStatus(int pid,String serverName,int status);

    public native void NotifyBinderDisconnect(String appname);

    public native boolean checkClientCert(String name,byte[] sign);

}
