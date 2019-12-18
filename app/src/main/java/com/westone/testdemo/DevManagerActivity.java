package com.westone.testdemo;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.support.v4.app.NavUtils;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.GridView;
import android.widget.ListAdapter;
import android.widget.Spinner;
import android.widget.SpinnerAdapter;
import android.widget.TextView;
import android.widget.Toast;

import com.westone.cardmanager.CSMManager;
import com.westone.csmmanager.R;
import com.westone.rpcclient.IfServiceStatus;
import com.westone.rpcclient.RpcManager;
import com.westone.skf.DEVINFO;
import com.westone.skf.DevEvent;
import com.westone.skf.DevState;
import com.westone.skf.PinRetryCount;
import com.westone.skf.SKFException;
import com.westone.skf.SkfWrapper;
import com.westone.skflist.SkfListActivity;

import java.util.Arrays;

public class DevManagerActivity extends Activity {

//    private final String serviceName = "com.westone.csm.CSM"/*"com.westone.bindertest.binderServer"*/;
//    private RpcManager rpcManager = null;
    private Button scan;
    private GridView gridViewFunc;
    private GridView gridViewType;
    private TextView result;
    private Spinner spinner;
    private EditText editText;
    private Button button;

    private DevState state = new DevState();
    private DEVINFO devinfo = new DEVINFO();

    private final Intent intent = new Intent();

    private void initView(){
        scan = findViewById(R.id.scan);
        result = findViewById(R.id.result);
        gridViewFunc = findViewById(R.id.gridview_func);
        gridViewType = findViewById(R.id.gridview_type);
        spinner = findViewById(R.id.spinner);

        spinner.setPrompt(SKFDemoMACRO.spinner_promt_dev);

        editText = findViewById(R.id.testCount);
        button = findViewById(R.id.testCountRun);


        button.setVisibility(View.VISIBLE);
        editText.setText("0");
        editText.setVisibility(View.GONE);
        button.setText("SKF函数列表");

        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent2 = new Intent(DevManagerActivity.this, SkfListActivity.class);
                startActivity(intent2);
            }
        });
    }

    private void setViewValue(){
        scan.setText(SKFDemoMACRO.scan_dev);

        ListAdapter listAdapterFunc = new GridViewFuncAdapter(DevManagerActivity.this,R.layout.gridview_func,SKFDemoMACRO.gridview_func_dev);
        gridViewFunc.setAdapter(listAdapterFunc);
        gridViewFunc.setNumColumns(2);


        ListAdapter listAdapterType = new GridViewTypeAdapter(DevManagerActivity.this,R.layout.gridview_func,SKFDemoMACRO.gridview_type);
        gridViewType.setAdapter(listAdapterType);

        if(SKFDemoMACRO.list_dev.size() > 0){
            SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(DevManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_dev);
            spinner.setAdapter(spinnerAdapter);
            if(SKFDemoMACRO.list_dev.size() > 0){
                SKFDemoMACRO.select_dev_name = (String) SKFDemoMACRO.list_dev.get(0);
            }
        }
    }

    private void clickType(){

        gridViewType.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                switch (position){
                    case 1:
                        //跳转到访问控制
                        intent.setClass(DevManagerActivity.this,AccessActivity.class);
                        break;
                    case 2:
                        //跳转到应用管理
                        intent.setClass(DevManagerActivity.this,AppManagerActivity.class);
                        break;
                    case 3:
                        //跳转到文件管理
                        intent.setClass(DevManagerActivity.this,FileManagerActivity.class);
                        break;
                    case 4:
                        //跳转到容器管理
                        intent.setClass(DevManagerActivity.this,ContainerManagerActivity.class);
                        break;
                    case 5:
                        //跳转到密码运算
                        intent.setClass(DevManagerActivity.this,AlgActivity.class);
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
                    SKFDemoMACRO.list_dev.clear();
                    SKFDemoMACRO.skfWrapper.SKF_EnumDev(SKFDemoMACRO.list_dev);

                    StringBuilder stringBuilder = new StringBuilder();
                    stringBuilder.append("SKF_EnumDev 成功！！！，共有 " + SKFDemoMACRO.list_dev.size() + " 个设备存在---");
                    for(int i = 0; i < SKFDemoMACRO.list_dev.size();i++){
                        stringBuilder.append("\n");
                        stringBuilder.append("第" + (i + 1) + " 个设备名称为" + SKFDemoMACRO.list_dev.get(i));
                    }

                    funcResultString(stringBuilder.toString());

                }catch (SKFException e){
                    e.printStackTrace();
                    ToastUtil.showToast(DevManagerActivity.this,"SKF_EnumDev Error = 0x" + String.format("%08X",SKFException.getLastError()),Toast.LENGTH_SHORT);
                }

                SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(DevManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_dev);
                spinner.setAdapter(spinnerAdapter);
                if(SKFDemoMACRO.list_dev.size() > 0){
                    SKFDemoMACRO.select_dev_name = (String) SKFDemoMACRO.list_dev.get(0);
                }

            }
        });



        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                SKFDemoMACRO.select_dev_name = (String) SKFDemoMACRO.list_dev.get(position);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {

            }
        });

        gridViewFunc.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                //TODO
                if(SKFDemoMACRO.list_dev.size() == 0){
                    ToastUtil.showToast(DevManagerActivity.this,"请确认已插入密码卡，并完成设备扫描！！！",Toast.LENGTH_SHORT);
                }else {
                    switch (position){
                        case 0:
                            try {
                                SKFDemoMACRO.skfWrapper.SKF_ConnectDev(SKFDemoMACRO.select_dev_name,SKFDemoMACRO.devhandle);
                                LogDebug.log("Success SKF_ConnectDev");
                                funcResultString("SKF_ConnectDev 成功");
                            }catch (SKFException e){
                                e.printStackTrace();
                                ToastUtil.showToast(DevManagerActivity.this,"SKF_ConnectDev Error = 0x"+String.format("%08X",SKFException.getLastError()),Toast.LENGTH_SHORT);
                            }
                            break;
                        case 1:
                            try {
                                SKFDemoMACRO.skfWrapper.SKF_DisConnectDev(SKFDemoMACRO.devhandle);
                                funcResultString("SKF_DisConnectDev 成功");
                            }catch (SKFException e){
                                e.printStackTrace();
                                ToastUtil.showToast(DevManagerActivity.this,"SKF_DisConnectDev Error = 0x"+String.format("%08X",SKFException.getLastError()),Toast.LENGTH_SHORT);
                                funcResultString("SKF_DisConnectDev Error = 0x"+String.format("%08X",SKFException.getLastError()));
                            }
                            break;
                        case 2:
                            try {
                                SKFDemoMACRO.skfWrapper.SKF_GetDevState(SKFDemoMACRO.select_dev_name,state);
                                funcResultString("SKF_GetDevState 成功," + "dev state is " + state.getDevState());
                            }catch (SKFException e){
                                e.printStackTrace();
                                ToastUtil.showToast(DevManagerActivity.this,"SKF_GetDevState Error = 0x"+String.format("%08X",SKFException.getLastError()),Toast.LENGTH_SHORT);
                            }
                            break;
                        case 3:
                            try {
                                SKFDemoMACRO.skfWrapper.SKF_GetDevInfo(SKFDemoMACRO.devhandle,devinfo);
                                StringBuilder stringBuilder = new StringBuilder();
                                stringBuilder.append("SKF_GetDevInfo 成功\n");
                                stringBuilder.append("Version " + String.format("%02X",devinfo.getVersion().getMajor()) + String.format("%02X",devinfo.getVersion().getMinor()) + "\n");
                                stringBuilder.append("Manufacturer " + devinfo.getManufacturer() + " size: " + devinfo.getManufacturer().length() + " bytes: " + Arrays.toString(devinfo.getManufacturer().getBytes()) + "\n");
                                stringBuilder.append("AlgSymCap " + String.format("0x%08x",devinfo.getAlgSymCap()) + "\n");
                                stringBuilder.append("AlgAsymCap " + String.format("0x%08x",devinfo.getAlgAsymCap()) + "\n");
                                stringBuilder.append("AlgHashCap " + String.format("0x%08x",devinfo.getAlgHashCap()) + "\n");
                                stringBuilder.append("DevAuthAlgId " + String.format("0x%08x",devinfo.getDevAuthAlgId()) + "\n");
                                stringBuilder.append("DevInfo "+ devinfo.getLabel());

                                funcResultString(stringBuilder.toString());
                            }catch (SKFException e){
                                e.printStackTrace();
                                ToastUtil.showToast(DevManagerActivity.this,"SKF_GetDevInfo Error = 0x"+String.format("%08X",SKFException.getLastError()),Toast.LENGTH_SHORT);
                            }
                            break;

                        case 4:
                            final AlertDialog alertDialog = new AlertDialog.Builder(DevManagerActivity.this).setPositiveButton("确定",null).create();
                            View view_set_label = View.inflate(DevManagerActivity.this,R.layout.set_dev_label, null);
                            alertDialog.setView(view_set_label);
                            alertDialog.show();

                            final EditText editTextsetlable = view_set_label.findViewById(R.id.set_label);
                            alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                                @Override
                                public void onClick(View v) {
                                    if(editTextsetlable.getText() == null || editTextsetlable.getText().toString() == null || editTextsetlable.getText().toString().equals("")){
                                        Toast.makeText(DevManagerActivity.this,"请输入正确的字符",Toast.LENGTH_SHORT).show();
                                        alertDialog.dismiss();
                                    }else {
                                        try {
                                            SKFDemoMACRO.skfWrapper.SKF_SetLabel(SKFDemoMACRO.devhandle,editTextsetlable.getText().toString());
                                            alertDialog.dismiss();
                                            StringBuilder stringBuilder = new StringBuilder();
                                            stringBuilder.append("SKF_SetLabel 成功,可重新获取设备信息\n");
                                            funcResultString(stringBuilder.toString());
                                        } catch (SKFException e){
                                            funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                                        }
                                        alertDialog.dismiss();
                                    }
                                }
                            });
                            break;

                        case 5:
                            DevEvent devEvent = new DevEvent() {
                                @Override
                                public void notifyDevEvent(String s, int i) {
                                    Toast.makeText(getApplicationContext(),"has recv dev event msg is " + s + ",status is " + i,Toast.LENGTH_SHORT).show();
                                }
                            };

                            try {
                                SKFDemoMACRO.skfWrapper.SKF_WaitForDevEvent(devEvent);
                                StringBuilder stringBuilder = new StringBuilder();
                                stringBuilder.append("SKF_WaitForDevEvent 成功\n");
                                funcResultString(stringBuilder.toString());
                            } catch (SKFException e) {
                                e.printStackTrace();
                            }
                            break;

                        case 6:
                            try {
                                SKFDemoMACRO.skfWrapper.SKF_CancelWaitForDevEvent();
                                StringBuilder stringBuilder = new StringBuilder();
                                stringBuilder.append("SKF_CancelWaitForDevEvent 成功\n");
                                funcResultString(stringBuilder.toString());
                            } catch (SKFException e) {
                                e.printStackTrace();
                            }
                            break;
                    }
                }

            }
        });
    }

    private void funcResultString(String s){
        if(null != s){
            result.setText(s);
        }
    }


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_base);
        String libName = getIntent().getStringExtra("libName");
        boolean createFlg = getIntent().getBooleanExtra("create",false);
        boolean deleteFlg = getIntent().getBooleanExtra("delete",false);

        if(createFlg){
            CSMManager.getInstance().createSkfSoftCard(this);
        }

        if(deleteFlg){
            CSMManager.getInstance().destroySkfSoftCard(this);
        }

        if(libName != null && libName.length() > 0){
            Log.i("skf",DevManagerActivity.class.toString() + ",libName = " + libName);
            SKFDemoMACRO.skfWrapper = new SkfWrapper(this,libName);
        }else {
            SKFDemoMACRO.skfWrapper = new SkfWrapper(this,null);
        }

        initView();
        setViewValue();
        clickFunc();
        clickType();
    }
}
