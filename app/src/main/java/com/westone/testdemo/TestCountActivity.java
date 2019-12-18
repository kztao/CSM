package com.westone.testdemo;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Toast;

import com.westone.csmmanager.R;

public class TestCountActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_test_count);

        int times = getIntent().getIntExtra("testCount",0);
        Toast.makeText(this,"test times = " + times,Toast.LENGTH_SHORT).show();
    }
}
