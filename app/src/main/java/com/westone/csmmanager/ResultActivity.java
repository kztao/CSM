package com.westone.csmmanager;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.westone.cardmanager.CSMManager;

import java.util.Iterator;
import java.util.Vector;

public class ResultActivity extends AppCompatActivity {
    private boolean[] flgs;
    private String testTime;
    ReturnInfo returnInfo;
    private Vector<ReturnInfo> vector = new Vector<>();

    private TextView textView;
    private static StringBuffer stringBuffer= new StringBuffer();
    private StringBuffer st = new StringBuffer();

    private String userName;
    private String soName;
    private static int testCount = 0;
//    private Thread testthread;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.i("csm_testApp","result activity 111");
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_result);
        flgs = getIntent().getBooleanArrayExtra("funcFlgs");
        testTime = getIntent().getStringExtra("Time");
        textView = (TextView) findViewById(R.id.测试记录);

        userName = getIntent().getStringExtra("UserPin");
        soName = getIntent().getStringExtra("SoPin");
        Log.i("csm_testApp","result activity 222");
        //create another thread

//        testthread = new Thread(new Runnable() {
//            @Override
//            public void run() {
//                Log.i("csm_testApp","testthread TestThreadRun IN");
//                TestThreadRun();
//                Log.i("csm_testApp","testthread TestThreadRun OUT");
//            }
//        });
//        testthread.start();

        textView.setText(stringBuffer);
        Log.i("csm_testApp","FuncRun IN");
        FuncRun();
        Log.i("csm_testApp","FuncRun OUT");
    }

/*    private void TestThreadRun() {
         P11TestNative.testThreadRun(userName);
    }
*/
    private void Save(ReturnInfo returnInfo){
        Log.i("csm_testApp","len = " +returnInfo.funcArrays.length);

        st.append("\n*************"+ ++testCount + "times test ***************\n" + "--------- " + returnInfo.desc + " test time = " + testTime + "---------\n");
        for(int i = 0; i < returnInfo.funcArrays.length;i++){
            st.append(returnInfo.funcArrays[i].name + ",");
            st.append("return " + String.format("0x%08x,",returnInfo.funcArrays[i].returnCode));
            st.append(String.format("time = %d msec\n",returnInfo.funcArrays[i].msec));
            st.append(returnInfo.funcArrays[i].otherInfo + "\n");
        }

        Log.i("csm_testApp",st.toString());
        textView.setText(st.toString());
        stringBuffer.append(st);
    }

    class CallBack implements TFStatus{
        @Override
        public void TFStatusNotify(long slotID, String status) {
            Log.i("csm_testApp"," IN CallBack");
            NotificationManager manager = (NotificationManager)getSystemService(NOTIFICATION_SERVICE);
            Notification.Builder builder = new Notification.Builder(ResultActivity.this);
            PendingIntent intent = PendingIntent.getActivity(ResultActivity.this,
                    100, new Intent(ResultActivity.this, ResultActivity.class),
                    PendingIntent.FLAG_NO_CREATE);

            //设置通知栏标题
            builder.setContentTitle("Slot ID = " + slotID + ",Status changed!!!");
            //设置通知栏内容
            builder.setContentText(status);
            //设置跳转
            builder.setContentIntent(intent);
            //设置图标
            builder.setSmallIcon(R.mipmap.card);
            //设置
            builder.setDefaults(Notification.DEFAULT_ALL);
            //创建通知类
            Notification notification = builder.build();
            //显示在通知栏
            manager.notify(0, notification);
        }
    }
    private static CallBack callBack;

    private void FuncRun(){
        vector.clear();
        if(null == flgs){
            return;
        }

        if(flgs[0]){
            if(callBack == null){
                callBack = new CallBack();
            }

            returnInfo = P11TestNative.BaseFunctionTest(userName,soName,callBack);
            vector.add(returnInfo);
        }

        if(flgs[1]){
            returnInfo = P11TestNative.ObjFunctionTest();
            vector.add(returnInfo);
        }

        if(flgs[2]){
            returnInfo = P11TestNative.KeyFunctionTest();
            vector.add(returnInfo);
        }

        if(flgs[3]){
            returnInfo = P11TestNative.EncFunctionTest();
            vector.add(returnInfo);
        }

        if(flgs[4]){
            returnInfo = P11TestNative.DigFunctionTest();
            vector.add(returnInfo);
        }

        if(flgs[5]){
            returnInfo = P11TestNative.SignFunctionTest();
            vector.add(returnInfo);
        }

        if(flgs[6]){
            returnInfo = P11TestNative.RndFunctionTest();
            vector.add(returnInfo);
        }

        if(flgs[7]){
            returnInfo = P11TestNative.ExtFunctionTest();
            vector.add(returnInfo);
        }

        if(flgs[8]){
            returnInfo = P11TestNative.SCSetUp();
            vector.add(returnInfo);
        }

        if(flgs[9]){
            returnInfo = P11TestNative.CallTest();
            vector.add(returnInfo);
        }

        Iterator<ReturnInfo> it = vector.iterator();
        while (it.hasNext()){
            ReturnInfo info = it.next();
            Save(info);
        }

    }
}
