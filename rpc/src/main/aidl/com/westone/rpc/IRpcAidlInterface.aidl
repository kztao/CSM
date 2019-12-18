// IRpcAidlInterface.aidl
package com.westone.rpc;
import com.westone.rpc.IMsgToClientInterface;

// Declare any non-default types here with import statements

interface IRpcAidlInterface {
    int MsgToServer(int pid,in byte[] msg);
    void RegCallback(int pid ,in IMsgToClientInterface ins);
}
