package com.westone.csm;

import android.Manifest;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Environment;
import android.os.IBinder;
import android.os.storage.StorageManager;
import android.telephony.TelephonyManager;
import android.util.Log;

import com.westone.rpcserver.RpcServerManager;
import com.westone.skfwrapper.Xindun;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

public class CSM extends Service {
    private static final String TAG = "csm_service";
    private BroadcastReceiver broadcastReceiver;
    private Context context = null;
    private CSMNative csmNative = new CSMNative();
    private Xindun xindun = new Xindun();
    private TelephonyManager telephonyManager;

    private RpcServerManager rpcServerManager = new RpcServerManager();
    public static IBinder iBinder = null;

    private PublicKey publicKey = null;


    BroadcastReceiver bcSim = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i("wjr","bcSim action is " + intent.getAction());
            int status = intent.getIntExtra("android.intent.action.SIM_STATE_CHANGED",0);
            Log.i("wjr","bcSim action is " + status);
        }
    };

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


    public CSM(){
        context = this;
        DebugPrint.print("csm instance = " + context);
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        LogUtils.i(TAG,"CSM onTaskRemoved");
        super.onTaskRemoved(rootIntent);
    }

    void Initlogcat(Context context){
        String ppPath = context.getExternalFilesDir(null).getParent();
        String dirName = "/logs/";

        Date date = new Date();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd");
        String fileName = String.format("%s%s%s",ppPath,dirName,simpleDateFormat.format(date));

        try {
            Log.i(TAG,"path = "+fileName);
            Runtime.getRuntime().exec(String.format("logcat -r 5120 -n 10 -f %s", fileName));
        }catch (IOException e){
            Log.e(TAG,"Initlogcat exception: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();

        try {
            InputStream inputStream = getAssets().open("puk");
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
            publicKey = (PublicKey) objectInputStream.readObject();

        }catch (Exception e){
            Log.i(TAG,"\n-------------\n"+e.getMessage());
        }

        initLog(getApplicationContext());

        Initlogcat(this);
        LogUtils.i(TAG,"CSM onCreate");
        RegReceiver();
        String[] permissions = checkPermissions();
        LogUtils.i(TAG, Arrays.toString(permissions));

        CertVerify certVerifyImp = new CertVerifyImp(context);
        telephonyManager = (TelephonyManager) getApplicationContext().getSystemService(Context.TELEPHONY_SERVICE);
        xindun.skfInit(telephonyManager);

        LogUtils.i(TAG,"Build.VERSION.SDK_INT = " + Build.VERSION.SDK_INT + ",Build.VERSION_CODES.N = " + Build.VERSION_CODES.N);

        final String skf_card_path = getDir("skf_soft_card",Context.MODE_PRIVATE).getPath();
        File file = new File(skf_card_path);
        Log.i(TAG,"\n-------------\npath = " + skf_card_path + file.exists());

        LogUtils.i(TAG,"xindun skf init end");
        csmNative.Init(certVerifyImp);
        csmNative.setMountFlag(isSDMounted());
    }

    @Override
    public IBinder onBind(Intent intent) {
        String callingApp = intent.getPackage();
        LogUtils.i("wjr","calling App = " + callingApp);

        PackageManager packageManager = getPackageManager();
        try {
            PackageInfo packageInfo = packageManager.getPackageInfo(callingApp,PackageManager.GET_SIGNATURES);
            for (int i = 0; i < packageInfo.signatures.length;i++){
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(packageInfo.signatures[i].toByteArray()));
                certificate.verify(certificate.getPublicKey());

                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                messageDigest.update(certificate.getEncoded());
                byte[] hash = messageDigest.digest();

                byte[] cert = intent.getByteArrayExtra("cert");
                if(cert != null){
                    InputStream inputStream = new ByteArrayInputStream(cert);
                    CertificateFactory factory = CertificateFactory.getInstance("X.509");
                    X509Certificate x509Certificate = (X509Certificate)factory.generateCertificate(inputStream);
                    x509Certificate.verify(x509Certificate.getPublicKey());
                    String principal = x509Certificate.getSubjectDN().toString();
                    if (principal == null || principal.equals("")){
                        throw new UnsupportedOperationException("getSubjectDN is null");
                    }


                    String[] strings = principal.split(",");
                    if(null == strings){
                        throw new UnsupportedOperationException("getSubjectDN is null");
                    }

                    int loop = 0;
                    for (;loop < strings.length;loop++){
                        if(strings[loop].contains("CN=")){
                            if(callingApp.equals(strings[loop].substring(strings[loop].indexOf("CN=") + "CN=".length()))){
                                break;
                            }
                        }
                    }

                    if(loop == strings.length){
                        throw new UnsupportedOperationException("Error SubjectDN() format");
                    }

                    if(!x509Certificate.getPublicKey().equals(publicKey)){
                        LogUtils.i(TAG, callingApp + "csm checkcert fail");
                        throw new UnsupportedOperationException("csm public Key is not verifyed!!!");
                    }

                    byte[] ext = x509Certificate.getExtensionValue("1.3.5");
                    if(ext == null || ext.length != 34 || ext[0] != 4 || ext[1] != 32){
                        LogUtils.i(TAG,"error x509Certificate.getExtensionValue");
                    }else {
                        byte[] cmp = new byte[32];
                        System.arraycopy(ext,2,cmp,0,32);
                        if(!Arrays.equals(cmp,hash)){
                            LogUtils.i(TAG,"cmp = "+Arrays.toString(cmp));
                            LogUtils.i(TAG,"hash = "+Arrays.toString(hash));
                            LogUtils.i(TAG, callingApp + "checkcert fail");
                            throw new UnsupportedOperationException("Cert finger is not verifyed!!!");
                        }
                    }

                }else {
                    if(!csmNative.checkClientCert(callingApp,hash)){
                        LogUtils.i(TAG, callingApp + "checkcert fail");
                        throw new UnsupportedOperationException("Cert finger is not verifyed!!!");
                    }
                }
            }
        }catch (Exception e){
            e.printStackTrace();
            throw new UnsupportedOperationException(e.getMessage());
        }


        int pid = intent.getIntExtra("pid",0);
        csmNative.NotifyClientStatus(pid,CSM.this.getClass().getName(),0);
        iBinder= rpcServerManager.getIBinder(CSM.this);
        LogUtils.i(TAG, callingApp + "+++++OnBind+++++");
        return iBinder;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        LogUtils.i(TAG,"CSM onDestroy");
 //       csmNative.TFCardPlugin(true);      //need to delete the server?
        unregisterReceiver(broadcastReceiver);
        unregisterReceiver(bcSim);
        LogUtils.i(TAG,"CSM onDestroy OUT");

        Runtime.getRuntime().exit(0);
    }

    @Override
    public boolean onUnbind(Intent intent) {
        LogUtils.i(TAG,"CSM onUnbind");
        String appname = intent.getPackage();
        LogUtils.i(TAG,"CSM onUnbind: " + appname);
        if(!appname.isEmpty()){
            csmNative.NotifyBinderDisconnect(appname);
        }

        return true;
    }

    @Override
    public void onRebind(Intent intent) {
        LogUtils.i(TAG,"CSM onRebind");
    }

    private void RegReceiver(){
        broadcastReceiver = new SdcardHotPlugin();
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(Intent.ACTION_MEDIA_EJECT);
        intentFilter.addAction(Intent.ACTION_MEDIA_MOUNTED);
        intentFilter.addDataScheme("file");
        registerReceiver(broadcastReceiver,intentFilter);

        IntentFilter it = new IntentFilter();
        it.addAction("com.westone.csmmanager.statuschange");
        registerReceiver(bcSim,it);
    }



    private String[] checkPermissions(){
        String [] permissions = {
                Manifest.permission.WRITE_EXTERNAL_STORAGE,
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.INTERNET,
                Manifest.permission.READ_PHONE_STATE
        };
        
        for (int i=0; i < permissions.length;i++){

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ){
                if(checkSelfPermission(permissions[i]) !=
                        PackageManager.PERMISSION_GRANTED){
                    LogUtils.i("csm_checkPermissions","permissions " + permissions[i] + " Not_PERMISSION_GRANTED");
                    return permissions;
                }
            }
        }

        return new String[0];
    }


    private boolean isSDMounted() {
        boolean isMounted = false;
        StorageManager sm = (StorageManager) getSystemService(Context.STORAGE_SERVICE);
        try {
            Method getVolumList = StorageManager.class.getMethod("getVolumeList", (Class[])null);
            getVolumList.setAccessible(true);
            Object[] results = (Object[]) getVolumList.invoke(sm, (Object[])null);
            if (results != null) {
                for (Object result : results) {
                    Method mRemoveable = result.getClass().getMethod("isRemovable", (Class[])null);
                    Boolean isRemovable = (Boolean) mRemoveable.invoke(result, (Object[])null);
                    if (isRemovable) {
                        Method getPath = result.getClass().getMethod("getPath", (Class[])null);
                        String path = (String) getPath.invoke(result, (Object[])null);
                        Method getState = sm.getClass().getMethod("getVolumeState", String.class);
                        String state = (String) getState.invoke(sm, path);
                        if (state.equals(Environment.MEDIA_MOUNTED)) {
                            isMounted = true;
                            break;
                        }
                    }
                }
            }
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            e.printStackTrace();
        }

        LogUtils.i(TAG, "isSDMounted: " + isMounted);
        return isMounted;
    }


}
