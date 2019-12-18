package com.westone.csmmanager;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;

public class PerformanceActivity extends AppCompatActivity {
    private StringBuffer stringBuffer = new StringBuffer();
    private String per;
 /*   private String[] sm4Style = {
        "CBC模式",
        "OFB模式",
        "ECB模式",
        "CFB模式"
    };*/

    /*class ZucTest implements ZucSaveTime{
        public void Save(String info,long[] msec){

            Log.i(TAG,"Save 1");
            fileSave.makeFilePath(file.getPath() + "/ZucTest",info);
            Log.i(TAG,"Save 2");

            StringBuffer stringBuffer = new StringBuffer();
            if(null != msec){
                for(int i = 0; i < msec.length;i++){
                    stringBuffer.append(msec[i] + "\n");
                }
            }

            Log.i(TAG,"Save 3");
            fileSave.writeTxtToFile(stringBuffer.toString(),file.getPath() + "/ZucTest",info);
            Log.i(TAG,"Save 4");
        }
    }*/

    private PerReturnInfo perReturnInfo;
    private int numCount;
    private int lengthCount;
    public TextView testResult;
    private View view;
    private RadioGroup radioGroup;
    private boolean sm4Mod = false;
    private ChartView chartView = null;
    private File file;
    private FileSave fileSave = new FileSave();
    private static final String TAG = "csm_testApp";

    private void ShowChart(long[] data){
        chartView = findViewById(R.id.折线图);
        chartView.InitData(data);
        chartView.fresh();
    }
    private String s = "";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_performance);


        final int perNum = getIntent().getIntExtra("PerNum",0);
        final TextView textView = findViewById(R.id.标头);
        Button button = findViewById(R.id.执行Per);
        testResult = findViewById(R.id.JG);
        view = findViewById(R.id.分割SM4);
        radioGroup = findViewById(R.id.SM4工作模式);

        switch (perNum){
            case 0:
                sm4Mod = false;
                per = "SM2性能测试";
                break;
            case 1:
                sm4Mod = true;
                per = "SM4性能测试";
                view.setTop(radioGroup.getBottom());
                radioGroup.setVisibility(View.VISIBLE);
                break;
            case 2:
                sm4Mod = false;
                per = "ZUC性能测试";
                break;
            default:
                break;
        }
        textView.setText(per);

        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                EditText num = findViewById(R.id.测试次数);
                EditText length = findViewById(R.id.测试长度);

                try {
                    numCount = Integer.parseInt(num.getText().toString());
                    lengthCount = Integer.parseInt(length.getText().toString());

                    switch (perNum){
                        case 0:
                            perReturnInfo = P11TestNative.SM2Test(numCount,lengthCount);
                            break;
                        case 1:
                            Log.i(TAG,"before SM4Test");
                            perReturnInfo = P11TestNative.SM4Test(numCount,lengthCount);
                            Log.i(TAG,"End SM4Test");
                            break;
                        case 2:
                            perReturnInfo = P11TestNative.ZucTest(numCount,lengthCount);
                            break;
                        default:
                            break;
                    }
                    if(null != testResult){
                        Log.i(TAG,"before text show");
                        stringBuffer.delete(0,stringBuffer.length());
                        stringBuffer.append(perReturnInfo.info);
                        stringBuffer.append("测试次数 = " + perReturnInfo.count);
                        stringBuffer.append(",测试长度 = ");
                        stringBuffer.append(perReturnInfo.length);

                        long tMax = 0;
                        long tMin = 0;
                        long tAve = 0;
                        long thread = 9;
                        long abovethread = 0;
                        float rate;
                        boolean minFlg = false;


                        if(perReturnInfo.times.length > 0){

                            for(long t : perReturnInfo.times){
                                if(minFlg == false){
                                    tMin = t;
                                    minFlg = true;
                                }

                                //                         Log.i(TAG,"Java recv times = " + t);

                                if(t > tMax){
                                    tMax = t;
                                }

                                if(t < tMin){
                                    tMin = t;
                                }

                                if(t>thread)
                                {
                                    abovethread++;
                                }

                                tAve += t;
                                s = s + t +"\n";


                            }

                            tAve = tAve / perReturnInfo.times.length;
                            rate = ((abovethread*100)/perReturnInfo.times.length)*1000/1000;
                            Log.i(TAG,"abovethread = " +abovethread + ",rate = " + rate);
                            Log.i(TAG,"tMax = " +tMax + ",tMin = " + tMin + ",tAve = " + tAve);
                            stringBuffer.append("\n-------------\n");
                            stringBuffer.append("Max time = " + tMax + " ms\n");
                            stringBuffer.append("Min time = " + tMin + " ms\n");
                            stringBuffer.append("Ave time = " + tAve + " ms\n");
                            stringBuffer.append("Above " + thread + "ms: " + rate + "%");
                            stringBuffer.append("-------------\n");
                        }

                        testResult.setText(stringBuffer.toString());
                        ShowChart(perReturnInfo.times);

                        String filePath = "/sdcard/Test/";
                        String fileName = "csm.xlsx";
                        fileSave.deleteFilePath(filePath,fileName);
                        fileSave.writeTxtToFile(s,filePath,fileName);
                    }
                }catch (Exception e){
                    e.printStackTrace();
                    Toast.makeText(PerformanceActivity.this,
                            "测试次数或测试长度输入框内容不是数字，请检查输入内容后重试!!",
                            Toast.LENGTH_LONG).show();
                }





            }
        });

    }
}
