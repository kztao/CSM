package com.westone.rpcclient;

import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import com.westone.rpc.IMsgToClientInterface;
import com.westone.rpc.IRpcAidlInterface;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.util.Iterator;
import java.util.List;

import static com.westone.rpcclient.RpcServerName.map;

public class RpcManager {
    private static final String TAG = "csm_RpcManager";
    private static boolean startedflg = false;
    public static RpcManager getInstance() {
        return rpcManager;
    }
    private Context mContext = null;

    private void getCert(Context context){
        Log.i(TAG,"getCert IN");
        try {
            String[] files = context.getAssets().list("");
            if (files != null) {
                Log.i(TAG,"files num " + files.length);
                for(String s: files){
                    Log.i(TAG,"assert is " + s);
                }
            }else {
                Log.i(TAG,"files null");
            }

        }catch (IOException e){
            Log.i(TAG,"IOException = "+ e.getMessage());
            e.printStackTrace();
        }
    }

    public boolean StartService(Context context, String serverClassName, IfServiceStatus callback){
        ifServiceStatus = callback;
        mContext = context.getApplicationContext();

        if(startedflg){
            Log.i(TAG,"startedflg true");
            if(ifServiceStatus!=null){
                ifServiceStatus.NotifyServiceStatus(true,null);
                return true;
            }
        }
        Log.i(TAG,"startedflg false");
        String packageName = getServerPackage(context.getApplicationContext());
        if(null == packageName){
            if(null != callback){
                callback.NotifyServiceStatus(false,"failed get csm server package info");
            }

            return false;
        }

        Intent intent = new Intent();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.DONUT) {
            intent.setPackage(context.getPackageName());
        }

        intent.setComponent(new ComponentName(packageName,serverClassName));
        intent.putExtra("pid",android.os.Process.myPid());

        try {
            InputStream inputStream = context.getAssets().open("csm.cer");
            Log.i(TAG,"csm.cer len = " + inputStream.available());
            byte[] out = new byte[inputStream.available()];
            int num = inputStream.read(out);
            if(num<0){
                Log.w(TAG,"input read fail");
            }
            intent.putExtra("cert",out);
            inputStream.close();
        }catch (Exception e){
            e.printStackTrace();
            Log.i(TAG,"Except is " + e.getMessage());
        }


        DebugPrint.print("begin bind service ,packageName = " + packageName + ",serverClassName = " + serverClassName);
        boolean flg = context.getApplicationContext().bindService(intent,serviceConnection, Service.BIND_AUTO_CREATE);
        DebugPrint.print("bind service flg = " + flg);

        if(flg == false && null != callback){
            callback.NotifyServiceStatus(false,"error bind service");
        }
        return flg;
    }

    public void StopService(Context context){
        if(null != context){
            context.getApplicationContext().unbindService(serviceConnection);
        }
    }


    private RpcManager(){

    }

    public void SendBc(String ac,int codes){
        if(mContext != null){
            Intent intent = new Intent();
            intent.setAction("com.westone.csmmanager.statuschange");
            intent.setPackage(getServerPackage(mContext));
            intent.putExtra(ac,codes);
            mContext.sendBroadcast(intent);
        }
    }

    private String getServerPackage(Context context){
        PackageManager packageManager = context.getApplicationContext().getPackageManager();

        if(null == packageManager){
            DebugPrint.print("packageManager = " + packageManager);
            return context.getApplicationContext().getPackageName();
        }
        ApplicationInfo applicationInfo = null;
        int priority = 0;
        String retName = "";
        int i = 0;

        for(String k : map){
            try {
                DebugPrint.print("try " + k);
                applicationInfo = packageManager.getApplicationInfo(k,0);
                if(null != applicationInfo){
                    retName = applicationInfo.packageName;
                    DebugPrint.print("get server name is  " + retName);
                    break;
                }

            }catch (Exception e){
                DebugPrint.print(e.getMessage());
            }
        }

        DebugPrint.print("end get server name is  " + retName);

        if(retName.equals("")){

            retName = context.getPackageName();
            DebugPrint.print("retName = " + retName);
        }
        return retName;
    }

    private IfServiceStatus ifServiceStatus = null;
    private JniFunc jniFunc = new JniFunc();
    private static RpcManager rpcManager = new RpcManager();
    private IRpcAidlInterface iRpcAidlInterface = null;

    private IMsgToClientInterface iCallbackAidlInterface = new IMsgToClientInterface.Stub(){
        @Override
        public int MsgToClient(String server,byte[] msg) {
            DebugPrint.print("client recv server = " + server + msg);
            return jniFunc.ParseServerMsg(server,msg);
        }
    };

    private ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(final ComponentName name, IBinder service) {
            iRpcAidlInterface = IRpcAidlInterface.Stub.asInterface(service);
            DebugPrint.print("onServiceConnected name = " + name);
            try {
                int pid = android.os.Process.myPid();
                IRpcAidlInterface.Stub.asInterface(service).RegCallback(pid,iCallbackAidlInterface);
                DebugPrint.print("Success RegCallback");
            }catch (Exception e){
                Log.i(TAG,"Except is " + e.getMessage());
                e.printStackTrace();
            }


            jniFunc.RegRemoteCallFunc(name.getClassName(), new IfMsgToServer() {
                @Override
                public int MsgToServer(byte[] msg) {
                    int ret = -1;
                    try {
                        Log.i("wjr","begin send msg to server");
                        ret = iRpcAidlInterface.MsgToServer(android.os.Process.myPid(),msg);
                    }catch (Exception e){
                        e.printStackTrace();
                        ret = -1;
                    }

                    return ret;
                }
            });

            if(null != ifServiceStatus){
                startedflg = true;
                ifServiceStatus.NotifyServiceStatus(true,null);
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            if(null != ifServiceStatus){
                startedflg = false;
                jniFunc.resetClientChannel();
                ifServiceStatus.NotifyServiceStatus(false,"CSM service Disconnected!!!");
            }
        }
    };
}
