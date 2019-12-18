package com.westone.csmmanager;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.RadioGroup;
import android.widget.TextView;

import com.westone.cardmanager.CSMManager;
import com.westone.cardmanager.Card;
import com.westone.cardmanager.ServiceCallback;
import com.westone.rpcclient.RpcManager;
import com.westone.skf.SKFException;
import com.westone.skf.SkfWrapper;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static com.westone.cardmanager.Card.GetCard;

public class MainActivity extends AppCompatActivity{
    private static final String tag = "csm_TestApp";
    private String time;
    private boolean serviceflg = false;

    private final String serviceName = "com.westone.csm.CSM"/*"com.westone.bindertest.binderServer"*/;
    class ServiceStatusImp implements ServiceCallback{
        @Override
        public void ServiceStatus(boolean b, String s) {
            if (b){
                Log.i(tag,"ServiceStatus success");
                serviceflg = true;
                GetFunctionTest();
            }
            else{
                Log.e(tag,"ServiceStatus fail");
                serviceflg = false;
                csmManager.StartService(getApplicationContext(),serviceCallback);
            }
        }
    }

    private RadioGroup radioGroup;
    private CheckBox[] FuncMan = new CheckBox[10];
    private boolean[] flgs = new boolean[10];
    private int PerNum = 0;
    CSMManager csmManager = CSMManager.getInstance();

    private ServiceCallback serviceCallback = new ServiceStatusImp();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //Demo.Run();


        GetTestInfo();
        RunFunc();
//        StartCSM();
//        StartCSM();
        serviceflg = true;
        GetFunctionTest();
        //for cer and ssp
        try{
            SDKUtils.copyAssetDirToFiles(getApplicationContext(),"cert");
        }catch(IOException e) {
            Log.e("Import Asset","CMAssetCopyTofiles Error");}
        try{
            SDKUtils.createDirInFiles(getApplicationContext(),"ssp");
        }catch(IOException e) {
            Log.e("Crate File","createDirInFiles Error");
        }
        //end for cer and ssp

        radioGroup = findViewById(R.id.性能测试);
        Button button = findViewById(R.id.执行性能测试);
        Button button_restart= findViewById(R.id.重启);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this,PerformanceActivity.class);
                intent.putExtra("PerNum",PerNum);
                startActivity(intent);
            }
        });


        radioGroup.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                switch (checkedId){
                    case R.id.SM2性能测试:
                        Log.i(tag,"SM2性能测试");
                        PerNum = 0 ;
                        break;
                    case R.id.SM4性能测试:
                        Log.i(tag,"SM4性能测试");
                        PerNum = 1;
                        break;
                    case R.id.ZUC性能测试:
                        Log.i(tag,"ZUC性能测试");
                        PerNum = 2;
                        break;
                }
            }
        });

        button_restart.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                relaunchAppForKillPid(getApplicationContext(), 2000);
            }
        });
    }

    private void StartCSM(){

        Log.i(tag,"Begin Start Service");
        csmManager.StartService(getApplicationContext(),serviceCallback);
//        boolean flg = rpcManager.StartService(getApplicationContext(), serviceName,null);
        Log.i(tag,"Begin End Service");
    }

    private EditText editTextUser;
    private EditText editTextSo;

    private void RunFunc(){
        Button run = (Button) findViewById(R.id.运行函数);
        editTextUser = (EditText) findViewById(R.id.UserPin);
        editTextSo = (EditText)findViewById(R.id.SOPin);

        //editTextUser.setText("123456");
        run.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(!serviceflg){
                    csmManager.StartService(getApplicationContext(),serviceCallback);
                }

                Intent Result = new Intent(MainActivity.this,ResultActivity.class);
                Result.putExtra("funcFlgs",flgs);

                SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy年MM月dd日 HH:mm:ss");
                Date date = new Date(System.currentTimeMillis());
                time = simpleDateFormat.format(date);

                Result.putExtra("Time",time);
                Result.putExtra("UserPin",editTextUser.getText().toString());
                Result.putExtra("SoPin",editTextSo.getText().toString());
                startActivity(Result);
            }
        });

        Button his = findViewById(R.id.生产软卡);

        his.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                String token = "2B659360-C99E-4353-9C08-8EC7AE1C9EE8";
                String userName = "13618079709";
                String licServerAddr = "192.168.2.118 39069 39068";
                String csppaddr = "192.168.2.118 39069 39068";
                long ret = 0;
                Log.i(tag,"softCreateCipherCard start");
                ret = Card.softCreateCipherCard(token,userName,licServerAddr,csppaddr);
                Log.i(tag,"End softcreatecard,ret = " + ret);

                TextView Desc = (TextView) findViewById(R.id.测试描述);
                Desc.setMovementMethod(ScrollingMovementMethod.getInstance());
                String s = "" + Desc.getText();
                s += "\n-----------------------";
                s += "End softcreatecard,ret = " + ret + "-----------\n";


//                ret = Card.DestroyCipherCard();
//                s += "End DestroyCipherCard,ret = " + ret + "-----------\n";
                Desc.setText(s);

/*
                List<String> szNameList = new ArrayList();;
                try{
                    skfWrapper.SKF_EnumDev(szNameList);
                }catch (SKFException e){
                    e.printStackTrace();
                }
                Log.i(tag,"list size: " + szNameList.size());

                String[] cards = GetCard();
                Log.i(tag,"cardnum: ");
*/

                /*String[] cards = GetCard();
                if(ret == 0){
                    ret = Login("软卡,卫士通","123456");
                }*/

  //              Log.i(tag,"cardnum: " + cards.length+ " ret = " + ret);

//                String[] cards2 = GetTFCard();
//                Log.i(tag,"cardnum2: " + cards2.length);

  /*              if(cards.length>0)
                {
                    JniCardInfo testinfo = GetCardVersionInfo(cards[0]);
                    Log.i(tag,"get card info:");
                    Log.i(tag,"pLibVersion: " + testinfo.pLibVersion);
                    Log.i(tag,"pCardCosVersion: " + testinfo.pCardCosVersion);
                    Log.i(tag,"pSerialNo: " + testinfo.pSerialNo);
                    Log.i(tag,"pCardHardWareVersion: " + testinfo.pCardHardWareVersion);
                    Log.i(tag,"pP11LibVersion: " + testinfo.pP11LibVersion);
                    Log.i(tag,"pManufacturerID: " + testinfo.pManufacturerID);
                    Log.i(tag,"pCryServerVersion: " + testinfo.pCryServerVersion);

                }
*/
//                Intent Result = new Intent(MainActivity.this,ResultActivity.class);
//                startActivity(Result);
            }
        });

    }


    private void GetFunctionTest(){


        FuncMan[0] = (CheckBox) findViewById(R.id.基础函数);
        FuncMan[1] = (CheckBox)findViewById(R.id.对象管理函数);
        FuncMan[2] = (CheckBox)findViewById(R.id.密钥管理函数);
        FuncMan[3] = (CheckBox)findViewById(R.id.加解密函数);
        FuncMan[4] = (CheckBox)findViewById(R.id.消息摘要函数);
        FuncMan[5] = (CheckBox)findViewById(R.id.签名验证函数);
        FuncMan[6] = (CheckBox)findViewById(R.id.随机数函数);
        FuncMan[7] = (CheckBox)findViewById(R.id.扩展函数);
        FuncMan[8] = (CheckBox)findViewById(R.id.软卡初始设置流程);
        FuncMan[9] = (CheckBox)findViewById(R.id.打电话流程);

        flgs[0] = true;
        for(CheckBox funcMan : FuncMan){
            funcMan.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {

                    switch (buttonView.getId()){
                        case R.id.基础函数:
                            flgs[0] = isChecked;
                            break;
                        case R.id.对象管理函数:
                            flgs[1] = isChecked;
                            break;
                        case R.id.密钥管理函数:
                            flgs[2] = isChecked;
                            break;
                        case R.id.加解密函数:
                            flgs[3] = isChecked;
                            break;
                        case R.id.消息摘要函数:
                            flgs[4] = isChecked;
                            break;
                        case R.id.签名验证函数:
                            flgs[5] = isChecked;
                            break;
                        case R.id.随机数函数:
                            flgs[6] = isChecked;
                            break;
                        case R.id.扩展函数:
                            flgs[7] = isChecked;
                            break;
                        case R.id.软卡初始设置流程:
                            flgs[8] = isChecked;
                            break;
                        case R.id.打电话流程:
                            flgs[9] = isChecked;
                            break;
                        default:
                            break;
                        }
                    }
            });
        }
    }


    private void GetTestInfo(){
        TextView Desc = (TextView) findViewById(R.id.测试描述);
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy年MM月dd日 HH:mm:ss");
        Date date = new Date(System.currentTimeMillis());
        time = simpleDateFormat.format(date);
        String Brand = Build.BRAND + "," + Build.HARDWARE;

        String Model = Build.MODEL;
        String SystemVersion = Build.VERSION.RELEASE;
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("测试描述：" + "\n");
        stringBuilder.append("测试时间 = " + time + "\n");
        stringBuilder.append("手机产商 = " + Brand + "\n");
        stringBuilder.append("手机型号 = " + Model + "\n");
        stringBuilder.append("系统版本号 = " + SystemVersion + "\n");
        Desc.setText(stringBuilder.toString().toCharArray(),0,stringBuilder.toString().length());
    }

    public void onBackPressed() {
        super.onBackPressed();//注释掉这行,back键不退出activity
        android.os.Process.killProcess(android.os.Process.myPid());
        Log.i(tag, "onBackPressed");
    }

    /**
     * 重启app，杀掉进程
     * @param context
     * @param millisecond seconds=millisecond/1000
     */
    public void relaunchAppForKillPid(Context context, long millisecond){
        Log.i(tag, "relaunchAppForKillPid");
        Intent intent = context.getPackageManager()
                .getLaunchIntentForPackage(context.getPackageName());
        PendingIntent restartIntent = PendingIntent.getActivity(context.getApplicationContext(), 0, intent, PendingIntent.FLAG_ONE_SHOT);
        AlarmManager mgr = (AlarmManager)context.getSystemService(Context.ALARM_SERVICE);
        mgr.set(AlarmManager.RTC, System.currentTimeMillis() + millisecond, restartIntent);
        Log.i(tag, "relaunchAppForKillPid 2");
        System.exit(0);
    }

}
