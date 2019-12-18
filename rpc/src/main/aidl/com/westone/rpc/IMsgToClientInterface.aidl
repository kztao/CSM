// IMsgToClientInterface.aidl
package com.westone.rpc;

// Declare any non-default types here with import statements

interface IMsgToClientInterface {
    int MsgToClient(String server,in byte[] msg);
}
