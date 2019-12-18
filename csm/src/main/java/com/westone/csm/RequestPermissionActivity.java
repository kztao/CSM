package com.westone.csm;

import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Toast;

public class RequestPermissionActivity extends AppCompatActivity{
    public static final String LABEL = "Permissions";
    private static final int REQUEST_CODE = 1;
    private static final String TAG = "csm_permission";

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode){
            case REQUEST_CODE:

                for(int i = 0;i <(permissions.length > grantResults.length ? grantResults.length:permissions.length);i++){

                    if(grantResults[i] != PackageManager.PERMISSION_GRANTED){
                        LogUtils.i(TAG,"permissions = "+ permissions[i] + ",ret = "+grantResults[i]);
                        Toast.makeText(this,"Your reject some permissions",Toast.LENGTH_SHORT).show();
                        finish();
                        //return;
                    }
                }

                finish();
                break;
            default:
                break;
        }
    }



    private void requestPermission(Activity activity,String[] permissions){
        LogUtils.i(TAG,"requestPermissionActivity IN,permissions = "+permissions.length);
        ActivityCompat.requestPermissions(activity,permissions, REQUEST_CODE);

    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        LogUtils.i(TAG,"requestPermissionActivity IN");
        super.onCreate(savedInstanceState);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        if(getSupportActionBar() != null){
            getSupportActionBar().hide();
        }
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FIRST_SYSTEM_WINDOW);//remove notification bar  即全屏
        //setContentView(android.R.layout.activity_request_permission);
        //setContentView(R.layout.activity_request_permission);

        Bundle bundle = this.getIntent().getExtras();
        String[] permissions = bundle.getStringArray(LABEL);
        requestPermission(RequestPermissionActivity.this,permissions);
    }

    /*public static void RegPermissionCallback(PermissionCallback callback){
        globeCallBack = callback;
    }*/

}
