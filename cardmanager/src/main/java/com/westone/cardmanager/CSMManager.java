package com.westone.cardmanager;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.IntentFilter;
import android.util.Log;

import com.westone.SimStatusBc;
import com.westone.rpcclient.IfServiceStatus;
import com.westone.rpcclient.RpcManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

public class CSMManager {
    private static final String TAG = "csm_manager";
    private static ServiceCallback globeCallback = null;
    private String P11ServerClassName = "com.westone.csm.CSM";
    private RpcManager rpcManager = RpcManager.getInstance();
    private boolean flg = false;
    private boolean initlogcatflg = false;

    //private static CSMAidlInterface aidlInterface = null;
    private static CSMManager csmManager = new CSMManager();

    private CSMManager(){
    }

    public static CSMManager getInstance() {
        return csmManager;
    }

    void Initlogcat(Context context){
        if(initlogcatflg){
            return;
        }
        int pid = android.os.Process.myPid();
        initlogcatflg = true;
        try {
            @SuppressLint("DefaultLocale") String fileName = String.format("%s%s%s.txt",
                    Objects.requireNonNull(context.getExternalFilesDir(null)).getParent(),
                    "/logs/","logcat");

            Log.i(TAG,"path = "+fileName);
            Runtime.getRuntime().exec(String.format("logcat --pid=%d -r 5120 -n 10 -f %s", pid,fileName));
        }catch (IOException e){
            e.printStackTrace();
            Log.e(TAG,"IOException: "+ e.getMessage());
        }
    }

    /**
     * Blankj LogUtils日志初始化
     */
    private void initLog(Context context) {

        LogUtils.Config config = LogUtils.getConfig()
                // 设置 log 总开关，包括输出到控制台和文件，默认开
                .setLogSwitch(true)
                // 设置是否输出到控制台开关，默认开
                .setConsoleSwitch(false)
                // 设置 log 全局标签，默认为空
                .setGlobalTag("csmjava-log")
                // 当全局标签不为空时，我们输出的 log 全部为该 TAG，
                // 为空时，如果传入的 TAG 为空那就显示类名，否则显示 TAG
                // 设置 log 头信息开关，默认为开
                .setLogHeadSwitch(true)
                // 打印 log 时是否存到文件的开关，默认关
                .setLog2FileSwitch(true)
                // 当自定义路径为空时，写入应用的/cache/log/目录中
                .setDir(context.getExternalFilesDir(null).getParent()+"/logs/")
                // 当文件前缀为空时，默认为"util"，即写入文件为"util-MM-dd.txt"
                .setFilePrefix("csm")
                // 输出日志是否带边框开关，默认开
                .setBorderSwitch(true)
                // 一条日志仅输出一条，默认开，为美化 AS 3.1 的 Logcat
                .setSingleTagSwitch(true)
                // log 的控制台过滤器，和 logcat 过滤器同理，默认 Verbose
                .setConsoleFilter(LogUtils.V)
                // log 文件过滤器，和 logcat 过滤器同理，默认 Verbose
                .setFileFilter(LogUtils.V)
                // log 栈深度，默认为 1
                .setStackDeep(1)
                // 设置栈偏移，比如二次封装的话就需要设置，默认为 0
                .setStackOffset(0);
        LogUtils.d(config.toString());
    }

    IfServiceStatus ifServiceStatus = new IfServiceStatus() {
        @Override
        public void NotifyServiceStatus(boolean status, String reason) {
            LogUtils.i("csmmanager","service callback: " + status );
            flg = status;
            if(CSMManager.globeCallback != null){
                CSMManager.globeCallback.ServiceStatus(status,reason);
            }
        }
    };

    private SimStatusBc simStatusBc = new SimStatusBc();

    public int StartService(Context context, final ServiceCallback callback){

        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction("com.westone.csm.statuschange");
        context.getApplicationContext().registerReceiver(simStatusBc,intentFilter);

        initLog(context);
        Initlogcat(context);
//        CSMManager.context = context.getApplicationContext();
        CSMManager.globeCallback = callback;
        context.getExternalFilesDir(null);

        boolean serviceflg = rpcManager.StartService(context, P11ServerClassName, ifServiceStatus);

        if(!serviceflg && callback != null){
            LogUtils.e("csmmanager","startservice fails");
            callback.ServiceStatus(false,"Error bind " + P11ServerClassName + " service!!!");

        }

        return 0;
    }

    public int StopService(Context context){
        context.getApplicationContext().unregisterReceiver(simStatusBc);

        if (flg){
            rpcManager.StopService(context);
        }

        if(null != globeCallback){
            globeCallback.ServiceStatus(false,"Stop Service");
        }

        return 0;
    }


    public int createSkfSoftCard(Context context){
        String skf_card_path = context.getDir("skf_soft_card",Context.MODE_PRIVATE).getPath();
        File file = new File(skf_card_path);
        if(!file.exists()){
            if(!file.mkdir()){
                Log.i(TAG,file.getPath() + "mkdir result failed");
                return -1;
            }
        }

        file = new File(skf_card_path + "/AuthKey");

        if(!file.exists()){
            try {
                if(!file.createNewFile()){
                    Log.i(TAG,file.getPath() + " createNewFile result failed");
                    return -1;
                }
            } catch (IOException e) {
                e.printStackTrace();
                Log.i(TAG,file.getPath() + e.getMessage());
                return -1;
            }


            try(OutputStream outputStream = new FileOutputStream(file)) {
                    outputStream.write("1234567812345678".getBytes());
                    outputStream.flush();

            }catch (Exception e){
                Log.i(TAG,file.getPath() + e.getMessage());
                return -1;
            }
        }else {
            try (InputStream inputStream = new FileInputStream(file);){
                int len = inputStream.read(new byte[16]);
                inputStream.close();

                if(len != 16){
                    try(OutputStream outputStream = new FileOutputStream(file)){
                        outputStream.write("1234567812345678".getBytes());
                        outputStream.flush();
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                Log.i(TAG,"\n-------------\n"+e.getMessage());
                return -1;
            }
        }

        SoftSkf.setSkfSoftPath(skf_card_path);
        return 0;
    }

    static boolean delFile(File file) {
        if (!file.exists()) {
            return false;
        }

        if (file.isDirectory()) {
            File[] files = file.listFiles();
            for (File f : files) {
                delFile(f);
            }
        }

        return file.delete();
    }

    public int destroySkfSoftCard(Context context){
        String skf_card_path = context.getDir("skf_soft_card",Context.MODE_PRIVATE).getPath();
        File file = new File(skf_card_path);
        SoftSkf.setSkfSoftPath(null);
        return delFile(file)?0:-1;
    }


}
