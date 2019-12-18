package com.westone.testdemo;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.SpinnerAdapter;
import android.widget.TextView;

import com.westone.cardmanager.CSMManager;
import com.westone.csmmanager.R;
import com.westone.skf.SkfWrapper;

import static com.westone.testdemo.ChangJing.skfcjFuncs;

public class CJActivity extends AppCompatActivity implements View.OnClickListener {

    Spinner spinner = null;
    TextView t1 = null;
    TextView t2 = null;
    Button b1 = null;
    int position = 0;

    Handler handler;
    SpinnerAdapter spinnerAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_cj);
        String s = getIntent().getStringExtra("dd");
        if(s != null && s.length() > 0){
            SKFDemoMACRO.skfWrapper = new SkfWrapper(CJActivity.this,s);
        }

        initView();
        initData();

        String libName = getIntent().getStringExtra("libName");
        boolean createFlg = getIntent().getBooleanExtra("create",false);
        boolean deleteFlg = getIntent().getBooleanExtra("delete",false);

        if(libName != null && libName.length() > 0){
            SKFDemoMACRO.skfWrapper = new SkfWrapper(this,libName);
        }else {
            SKFDemoMACRO.skfWrapper = new SkfWrapper(this,null);
        }

        if(createFlg){
            CSMManager.getInstance().createSkfSoftCard(this);
        }

        if(deleteFlg){
            CSMManager.getInstance().destroySkfSoftCard(this);
        }
    }

    @Override
    public void onClick(View v) {

        switch (v.getId()){
            case R.id.b1:
                Message message = new Message();
                message.obj = skfcjFuncs[position].func();
                handler.sendMessage(message);
                break;
        }
    }

    void initView(){
        spinner = findViewById(R.id.sp);
        t1 = findViewById(R.id.t1);
        t2 = findViewById(R.id.t2);
        b1 = findViewById(R.id.b1);
        b1.setOnClickListener(this);

        t1.setMovementMethod(ScrollingMovementMethod.getInstance());
        t2.setMovementMethod(ScrollingMovementMethod.getInstance());

        handler = new Handler(){
            @Override
            public void handleMessage(@NonNull Message msg) {
                t2.setText((String)msg.obj);
            }
        };

        spinnerAdapter = new ArrayAdapter<>(this,android.R.layout.simple_list_item_1,ChangJing.getList());

        spinner.setAdapter(spinnerAdapter);
        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                CJActivity.this.position = position;
                initData();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {

            }
        });
    }

    void initData(){
        t1.setText(ChangJing.cjms[position]);
    }

}
