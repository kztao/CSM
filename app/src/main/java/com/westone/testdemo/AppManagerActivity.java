package com.westone.testdemo;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.GridView;
import android.widget.ListAdapter;
import android.widget.RadioGroup;
import android.widget.Spinner;
import android.widget.SpinnerAdapter;
import android.widget.TextView;
import android.widget.Toast;

import com.westone.csmmanager.R;
import com.westone.skf.PinInfo;
import com.westone.skf.PinRetryCount;
import com.westone.skf.SKFException;
import com.westone.skf.SkfDefines;
import com.westone.skf.SkfWrapper;


public class AppManagerActivity extends Activity {

    private Button scan;
    private GridView gridViewFunc;
    private GridView gridViewType;
    private TextView result;
    private Spinner spinner;

    private Intent intent = new Intent();
    private void initView(){
        scan = findViewById(R.id.scan);
        result = findViewById(R.id.result);
        gridViewFunc = findViewById(R.id.gridview_func);
        gridViewType = findViewById(R.id.gridview_type);
        spinner = findViewById(R.id.spinner);

        spinner.setPrompt(SKFDemoMACRO.spinner_promt_app);
    }

    private void setViewValue(){
        scan.setText(SKFDemoMACRO.scan_app);

        ListAdapter listAdapterFunc = new GridViewFuncAdapter(AppManagerActivity.this,R.layout.gridview_func,SKFDemoMACRO.gridview_func_app);
        gridViewFunc.setAdapter(listAdapterFunc);
        gridViewFunc.setNumColumns(2);


        ListAdapter listAdapterType = new GridViewTypeAdapter(AppManagerActivity.this,R.layout.gridview_func,SKFDemoMACRO.gridview_type);
        gridViewType.setAdapter(listAdapterType);

        if(SKFDemoMACRO.list_app.size() > 0){
            SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(AppManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_app);
            spinner.setAdapter(spinnerAdapter);
            SKFDemoMACRO.select_app_name = (String) SKFDemoMACRO.list_app.get(0);
        }
    }

    private void clickType(){

        gridViewType.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {

                switch (position){
                    case 0:
                        //设备管理
                        intent.setClass(AppManagerActivity.this,DevManagerActivity.class);
                        break;
                    case 1:
                        //跳转到访问控制
                        intent.setClass(AppManagerActivity.this,AccessActivity.class);
                        break;
                    case 3:
                        //跳转到文件管理
                        intent.setClass(AppManagerActivity.this,FileManagerActivity.class);
                        break;
                    case 4:
                        //跳转到容器管理
                        intent.setClass(AppManagerActivity.this,ContainerManagerActivity.class);
                        break;
                    case 5:
                        //跳转到密码运算
                        intent.setClass(AppManagerActivity.this,AlgActivity.class);
                        break;

                    default:
                        return;
                }

                startActivity(intent);
                finish();
            }
        });
    }

    private void clickFunc(){
        scan.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                try {
                    SKFDemoMACRO.list_app.clear();
                    SKFDemoMACRO.skfWrapper.SKF_EnumApplication(SKFDemoMACRO.devhandle,SKFDemoMACRO.list_app);
                    if(SKFDemoMACRO.list_app.size() > 0){
                        SKFDemoMACRO.select_app_name = (String)SKFDemoMACRO.list_app.get(0);
                    }
                    StringBuilder stringBuilder = new StringBuilder();
                    stringBuilder.append("SKF_EnumApplication 成功！！！，共有 " + SKFDemoMACRO.list_app.size() + " 个应用存在---");
                    for(int i = 0; i < SKFDemoMACRO.list_app.size();i++){
                        stringBuilder.append("\n");
                        stringBuilder.append("第" + (i + 1) + " 个应用名称为" + SKFDemoMACRO.list_app.get(i));
                    }

                    funcResultString(stringBuilder.toString());

                }catch (SKFException e){
                    e.printStackTrace();
                    funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                }

                SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(AppManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_app);
                spinner.setAdapter(spinnerAdapter);
            }
        });



        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {

                SKFDemoMACRO.select_app_name = (String)SKFDemoMACRO.list_app.get(position);

            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {

            }
        });


        gridViewFunc.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                final AlertDialog alertDialog = new AlertDialog.Builder(AppManagerActivity.this).setPositiveButton("确定",null).create();
                //TODO
                if(SKFDemoMACRO.list_app.size() == 0 && 5 != position){
                    ToastUtil.showToast(AppManagerActivity.this,"请确认已插入密码卡，并完成应用扫描！！！",Toast.LENGTH_SHORT);
                }else {
                    switch (position){
                        case 0:
                            //change pin
                            View view_change_pin = View.inflate(AppManagerActivity.this,R.layout.change_pin,null);
                            alertDialog.setView(view_change_pin);
                            alertDialog.show();

                            final EditText oldPw = view_change_pin.findViewById(R.id.old_pw);
                            final EditText newPw = view_change_pin.findViewById(R.id.new_pw);
                            final long[] usrType = {SkfDefines.USER_TYPE};

                            RadioGroup radioGroupUsrType = view_change_pin.findViewById(R.id.usr_type);
                            radioGroupUsrType.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
                                @Override
                                public void onCheckedChanged(RadioGroup group, int checkedId) {
                                    switch (checkedId){
                                        case R.id.admin:
                                            usrType[0] = SkfDefines.ADMIN_TYPE;
                                            break;
                                        case R.id.user:
                                            usrType[0] = SkfDefines.USER_TYPE;
                                            break;
                                    }
                                }
                            });

                            alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                                @Override
                                public void onClick(View v) {
                                    PinRetryCount pinRetryCount = new PinRetryCount();
                                    try {
                                        SKFDemoMACRO.skfWrapper.SKF_ChangePIN(SKFDemoMACRO.happlication,usrType[0],oldPw.getText().toString(),newPw.getText().toString(),pinRetryCount);
                                        funcResultString("SKF_ChangePIN Success" + ",recrycount = " + pinRetryCount.getRetryCount());
                                        alertDialog.dismiss();
                                    } catch (SKFException e){
                                        funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                                    }
                                    alertDialog.dismiss();
                                }
                            });

                            break;
                        case 1:
                            //get pin info
                            View view_get_pin = View.inflate(AppManagerActivity.this,R.layout.get_pin_info,null);
                            alertDialog.setView(view_get_pin);
                            alertDialog.show();
                            final PinInfo pinInfo = new PinInfo();
                            final long[] usrTypePinInfo = {SkfDefines.USER_TYPE};

                            RadioGroup radioGroupUsrPinInfo = view_get_pin.findViewById(R.id.get_pin_usr_type);
                            radioGroupUsrPinInfo.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
                                @Override
                                public void onCheckedChanged(RadioGroup group, int checkedId) {
                                    switch (checkedId){
                                        case R.id.get_pin_admin:
                                            usrTypePinInfo[0] = SkfDefines.ADMIN_TYPE;
                                            break;
                                        case R.id.get_pin_user:
                                            usrTypePinInfo[0] = SkfDefines.USER_TYPE;
                                            break;
                                    }
                                }
                            });

                            alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                                @Override
                                public void onClick(View v) {
                                    try {
                                        SKFDemoMACRO.skfWrapper.SKF_GetPINInfo(SKFDemoMACRO.happlication,usrTypePinInfo[0],pinInfo);
                                        funcResultString("SKF_GetPINInfo Success,MaxRetryCount = " + pinInfo.getMaxRetryCount() + ",RemainRetryCount = " + pinInfo.getRemainRetryCount() + ",is defaultPin = "+pinInfo.isDefaultPin());
                                    }catch (SKFException e){
                                        e.printStackTrace();
                                        funcResultString("SKF_GetPINInfo Error,MaxRetryCount = " + pinInfo.getMaxRetryCount() + ",RemainRetryCount = " + pinInfo.getRemainRetryCount()+ ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                                    }
                                    alertDialog.dismiss();
                                }
                            });

                            break;
                        case 2:
                            //verify pin
                            View view_verify_pin = View.inflate(AppManagerActivity.this,R.layout.verify_pin,null);
                            alertDialog.setView(view_verify_pin);
                            alertDialog.show();

                            final EditText pw = view_verify_pin.findViewById(R.id.verify_pw);
                            RadioGroup type = view_verify_pin.findViewById(R.id.verify_usr_type);
                            final long[] verifyType = {SkfDefines.USER_TYPE};
                            final PinRetryCount pinRetryCount = new PinRetryCount();

                            type.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
                                @Override
                                public void onCheckedChanged(RadioGroup group, int checkedId) {
                                    switch (checkedId){
                                        case R.id.verify_admin:
                                            verifyType[0] = SkfDefines.ADMIN_TYPE;
                                            break;
                                        case R.id.verify_user:
                                            verifyType[0] = SkfDefines.USER_TYPE;
                                            break;
                                    }
                                }
                            });

                            alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                                @Override
                                public void onClick(View v) {
                                    try{
                                        SKFDemoMACRO.skfWrapper.SKF_VerifyPIN(SKFDemoMACRO.happlication,verifyType[0],pw.getText().toString(),pinRetryCount);
                                        funcResultString("SKF_VerifyPIN Success,RetryCount = " + pinRetryCount.getRetryCount());
                                    }catch (SKFException e){
                                        e.printStackTrace();
                                        funcResultString("SKF_VerifyPIN Error,RetryCount = " + pinRetryCount.getRetryCount() + ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                                    }
                                    alertDialog.dismiss();
                                }
                            });

                            break;
                        case 3:
                            //unblock pin
                            View view_unblock_pin = View.inflate(AppManagerActivity.this,R.layout.unblock_pin,null);
                            alertDialog.setView(view_unblock_pin);
                            alertDialog.show();

                            final EditText unblockAdmin = view_unblock_pin.findViewById(R.id.unblock_admin_pin);
                            final EditText unblockUsr = view_unblock_pin.findViewById(R.id.unblock_new_pw);
                            final PinRetryCount pinRetryCountUnblock = new PinRetryCount();

                            alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                                @Override
                                public void onClick(View v) {
                                    try {
                                        SKFDemoMACRO.skfWrapper.SKF_UnblockPIN(SKFDemoMACRO.happlication,unblockAdmin.getText().toString(),unblockUsr.getText().toString(),pinRetryCountUnblock);
                                        funcResultString("SKF_UnblockPIN Success,Admin RetryCount = " + pinRetryCountUnblock.getRetryCount());
                                    }catch (SKFException e){
                                        e.printStackTrace();
                                        funcResultString("SKF_UnblockPIN Error,RetryCount = " + pinRetryCountUnblock.getRetryCount() + ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                                    }
                                    alertDialog.dismiss();
                                }
                            });
                            break;
                        case 4:
                            //clear secure
                            try {
                                SKFDemoMACRO.skfWrapper.SKF_ClearSecureState(SKFDemoMACRO.happlication);
                                funcResultString("SKF_ClearSecureState Success");
                            }catch (SKFException e){
                                e.printStackTrace();
                                funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                            }
                            break;
                        case 5:
                            //create application
                            final View view_create_app = View.inflate(AppManagerActivity.this,R.layout.create_app,null);
                            alertDialog.setView(view_create_app);
                            alertDialog.show();
                            final EditText appName = view_create_app.findViewById(R.id.create_app_name);
                            final EditText appAdmin = view_create_app.findViewById(R.id.create_app_admin);
                            final EditText appAdminCount = view_create_app.findViewById(R.id.create_app_admin_count);
                            final EditText appUser = view_create_app.findViewById(R.id.create_app_user);
                            final EditText appUserCount = view_create_app.findViewById(R.id.create_app_user_count);
                            final RadioGroup radioGroup = view_create_app.findViewById(R.id.create_app_right);

                            final long[] right = {SkfDefines.SECURE_USER_ACCOUNT};

                            radioGroup.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
                                @Override
                                public void onCheckedChanged(RadioGroup group, int checkedId) {
                                    switch (checkedId){
                                        case R.id.create_app_right_anyone:
                                            right[0] = SkfDefines.SECURE_ANYONE_ACCOUNT;
                                            break;
                                        case R.id.create_app_right_nothing:
                                            right[0] = SkfDefines.SECURE_NEVER_ACCOUNT;
                                            break;
                                        case R.id.create_app_right_admin:
                                            right[0] = SkfDefines.SECURE_ADM_ACCOUNT;
                                            break;
                                        case R.id.create_app_right_user:
                                            right[0] = SkfDefines.SECURE_USER_ACCOUNT;
                                            break;
                                    }
                                }
                            });

                            alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                                @Override
                                public void onClick(View v) {

                                    try {
                                        SKFDemoMACRO.skfWrapper.SKF_CreateApplication(SKFDemoMACRO.devhandle,appName.getText().toString(),appAdmin.getText().toString(),
                                                Long.parseLong(appAdminCount.getText().toString()),appUser.getText().toString(),Long.parseLong(appUserCount.getText().toString()),right[0],
                                                SKFDemoMACRO.happlication);
                                        funcResultString("Success create application "+appName.getText().toString());
                                        SKFDemoMACRO.list_app.add(appName.getText().toString());

                                        SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(AppManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_app);
                                        spinner.setAdapter(spinnerAdapter);

                                    }catch (Exception e){
                                        e.printStackTrace();
                                        funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                                    }
                                    alertDialog.dismiss();
                                }
                            });
                            break;
                        case 6:
                            //delete application
                            try {
                                SKFDemoMACRO.skfWrapper.SKF_DeleteApplication(SKFDemoMACRO.devhandle,SKFDemoMACRO.select_app_name);
                                funcResultString("SKF_DeleteApplication Success"+
                                        ",select app name = " + SKFDemoMACRO.select_app_name);
                                SKFDemoMACRO.list_app.remove(SKFDemoMACRO.select_app_name);

                                SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(AppManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_app);
                                spinner.setAdapter(spinnerAdapter);

                                if(SKFDemoMACRO.list_app.size() > 0){
                                    SKFDemoMACRO.select_app_name = (String) SKFDemoMACRO.list_app.get(0);
                                }else {
                                    SKFDemoMACRO.select_app_name = "";
                                }

                            }catch (SKFException e){
                                e.printStackTrace();
                                funcResultString("SKF_DeleteApplication Error = "+
                                        String.format("0x%08x",SKFException.getLastError()) +
                                        ",select app name = " + SKFDemoMACRO.select_app_name);
                            }
                            break;
                        case 7:
                            //open application
                            try{
                                SKFDemoMACRO.skfWrapper.SKF_OpenApplication(SKFDemoMACRO.devhandle,SKFDemoMACRO.select_app_name,SKFDemoMACRO.happlication);
                                funcResultString("SKF_OpenApplication " + SKFDemoMACRO.select_app_name + " Success");
                            }catch (SKFException e){
                                e.printStackTrace();
                                funcResultString("SKF_OpenApplication " + SKFDemoMACRO.select_app_name + " Error = " + String.format("0x%08x",SKFException.getLastError()));
                            }
                            break;
                        case 8:
                            //close application
                            try{
                                SKFDemoMACRO.skfWrapper.SKF_CloseApplication(SKFDemoMACRO.happlication);
                                funcResultString("SKF_CloseApplication " + SKFDemoMACRO.select_app_name + " Success");
                            }catch (SKFException e){
                                e.printStackTrace();
                                funcResultString("SKF_CloseApplication " + SKFDemoMACRO.select_app_name + " Error = " + String.format("0x%08x",SKFException.getLastError()));
                            }
                            break;
                    }
                }

            }
        });
    }



    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_base);

        setTitle("设备名称 " + SKFDemoMACRO.select_dev_name);

        initView();
        setViewValue();
        clickFunc();
        clickType();
    }

    private void funcResultString(String s){
        if(null != s){
            result.setText(s);
        }
    }
}
