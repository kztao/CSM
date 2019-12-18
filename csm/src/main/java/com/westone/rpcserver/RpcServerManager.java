package com.westone.rpcserver;
import android.app.Service;
import android.os.IBinder;
import android.os.RemoteException;

import com.westone.rpc.IMsgToClientInterface;
import com.westone.rpc.IRpcAidlInterface;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class RpcServerManager {
    private JniFunc jniFunc = new JniFunc();
    private static IBinder iBinder = null;
    private Map<Integer,IMsgToClientInterface> msgToClientInterfaceMap = new HashMap<>();
    private IfMsgToClient ifMsgToClient = new IfMsgToClient() {
        @Override
        public void MsgToClient(int pid, String serverName, byte[] msg) {
            DebugPrint.print("server begin send pid [" + pid + "] " + serverName + msg);
            IMsgToClientInterface iMsgToClientInterface = msgToClientInterfaceMap.get(pid);
            if(null != iMsgToClientInterface){
                try {
                    DebugPrint.print("server begin send");
                    int ret = iMsgToClientInterface.MsgToClient(serverName,msg);
                    DebugPrint.print("server end send　ret = " + ret);
                }catch (Exception e){
                    e.printStackTrace();
                }
            }else {
                DebugPrint.print("msgToClientInterfaceMap size = " + msgToClientInterfaceMap.size());
                Iterator<Integer> it = msgToClientInterfaceMap.keySet().iterator();
                while (it.hasNext()) {
                    int s = it.next();
                    DebugPrint.print("msgToClientInterfaceMap　key = " + s);
                }
            }
        }
    };


    public IBinder getIBinder(final Service service){
        if(iBinder == null){
            iBinder = new IRpcAidlInterface.Stub() {
                @Override
                public int MsgToServer(int pid, byte[] msg) throws RemoteException {
                    DebugPrint.print("server recv pid = " + pid + " msg");
                    int ret = jniFunc.MsgToServer(pid,service.getClass().getName(),msg);
                    return ret;
                }

                @Override
                public void RegCallback(int pid, IMsgToClientInterface msgToClientInterface) throws RemoteException {
                    DebugPrint.print("RegCallback pid = " + pid);
                    msgToClientInterfaceMap.put(pid,msgToClientInterface);
                    jniFunc.RegCallback(ifMsgToClient);
                    DebugPrint.print("server has recv client reg callback");
                }
            };
        }

        return iBinder;
    }
}
