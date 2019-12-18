package com.westone.csmmanager;

import android.Manifest;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Toast;

import com.westone.cardmanager.CSMManager;
import com.westone.cardmanager.ServiceCallback;
import com.westone.testdemo.CJActivity;
import com.westone.testdemo.DevManagerActivity;

import java.lang.ref.WeakReference;

public class launcher extends AppCompatActivity {

    RadioGroup rg1;
    RadioGroup rg2;
    RadioGroup rg3;
    Button button;


    RadioButton rg1_b2;
    RadioButton rg2_b2;
    RadioButton rg3_b2;

    CheckBox rgb;
    CheckBox delCard;


    final CSMManager csmManager = CSMManager.getInstance();

    RadioGroup.OnCheckedChangeListener onCheckedChangeListener = new RadioGroup.OnCheckedChangeListener() {
        @Override
        public void onCheckedChanged(RadioGroup group, int checkedId) {
            if(!rg1_b2.isChecked()){
                rg3.setVisibility(View.GONE);
                delCard.setVisibility(View.GONE);
                rgb.setVisibility(View.GONE);
                rg2_b2.setChecked(true);
            }else {
                rgb.setVisibility(View.VISIBLE);
                if(rg2_b2.isChecked()){
                    rg3.setVisibility(View.GONE);
                    delCard.setVisibility(View.GONE);
                }else {
                    rg3.setVisibility(View.VISIBLE);
                    delCard.setVisibility(View.GONE);
                    if(!rg3_b2.isChecked()){
                        delCard.setVisibility(View.VISIBLE);
                    }
                }
            }

        }
    };

    View.OnClickListener onClickListener = new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            Intent intent = new Intent();

            if(rg2_b2.isChecked()){
                csmManager.StartService(launcher.this, new ServiceCallback() {
                    @Override
                    public void ServiceStatus(boolean b, String s) {
                        if(b){
                            Toast.makeText(launcher.this,"CSM 服务启动成功",Toast.LENGTH_SHORT).show();
                        }else {
                            Toast.makeText(launcher.this,"CSM 服务启动失败",Toast.LENGTH_SHORT).show();
                        }
                    }
                });

            }

            if(!rg1_b2.isChecked()){
                intent.setClass(launcher.this, MainActivity.class);
            }else {

                if(!rg2_b2.isChecked()){
                    if(rg3_b2.isChecked()){
                        intent.putExtra("libName","libSafetyCardLib.so");
                    }else {
                        intent.putExtra("create",true);

                        if(delCard.isChecked()){
                            intent.putExtra("delete",true);
                        }

                        intent.putExtra("libName","libSoftSkf.so");
                    }

                }

                if(rgb.isChecked()){
                    intent.setClass(launcher.this, CJActivity.class);
                }else {
                    intent.setClass(launcher.this, DevManagerActivity.class);
                }
            }

            startActivity(intent);

        }
    };

    void checkPermission(){
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            requestPermissions(new String[]{
                    Manifest.permission.WRITE_EXTERNAL_STORAGE,
                    Manifest.permission.READ_PHONE_STATE,
                    Manifest.permission.READ_EXTERNAL_STORAGE
            },0);
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_launcher);
        initView();

        checkPermission();

    }

    void initView(){
        rg1 = findViewById(R.id.rg1);
        rg2 = findViewById(R.id.rg2);
        rg3 = findViewById(R.id.rg3);
        button = findViewById(R.id.jump);

        rg1_b2 = findViewById(R.id.rg1_b2);
        rg2_b2 = findViewById(R.id.rg2_b2);
        rg3_b2 = findViewById(R.id.rg3_b2);

        rgb = findViewById(R.id.cjcs);
        delCard = findViewById(R.id.del_card);
        rg1.setOnCheckedChangeListener(onCheckedChangeListener);
        rg2.setOnCheckedChangeListener(onCheckedChangeListener);
        rg3.setOnCheckedChangeListener(onCheckedChangeListener);
        button.setOnClickListener(onClickListener);
    }
}
