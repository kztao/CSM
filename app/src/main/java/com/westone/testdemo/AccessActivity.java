package com.westone.testdemo;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.GridView;
import android.widget.ListAdapter;
import android.widget.Spinner;
import android.widget.TextView;

import com.westone.csmmanager.R;
import com.westone.skf.HANDLE;
import com.westone.skf.SKFException;
import com.westone.skf.SkfDefines;

public class AccessActivity extends Activity {

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

        spinner.setPrompt(SKFDemoMACRO.spinner_promt_dev);
    }

    private void setViewValue(){
        scan.setVisibility(View.GONE);
        spinner.setVisibility(View.GONE);

        ListAdapter listAdapterFunc = new GridViewFuncAdapter(AccessActivity.this,R.layout.gridview_func,SKFDemoMACRO.gridview_func_acc);
        gridViewFunc.setAdapter(listAdapterFunc);
        gridViewFunc.setNumColumns(2);


        ListAdapter listAdapterType = new GridViewTypeAdapter(AccessActivity.this,R.layout.gridview_func,SKFDemoMACRO.gridview_type);
        gridViewType.setAdapter(listAdapterType);
    }

    private void clickType(){

        gridViewType.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                switch (position){
                    case 0:
                        //跳转到访问控制
                        intent.setClass(AccessActivity.this,DevManagerActivity.class);
                        break;
                    case 2:
                        //跳转到应用管理
                        intent.setClass(AccessActivity.this,AppManagerActivity.class);
                        break;
                    case 3:
                        //跳转到文件管理
                        intent.setClass(AccessActivity.this,FileManagerActivity.class);
                        break;
                    case 4:
                        //跳转到容器管理
                        intent.setClass(AccessActivity.this,ContainerManagerActivity.class);
                        break;
                    case 5:
                        //跳转到密码运算
                        intent.setClass(AccessActivity.this,AlgActivity.class);
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
        gridViewFunc.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                //TODO
                final EditText editText = new EditText(AccessActivity.this);
                editText.setText("31323334353637383132333435363738");
                switch(position){
                    case 0:
                        new AlertDialog.Builder(AccessActivity.this).setTitle("请输入认证密钥").setView(editText).setPositiveButton("确定", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                //TODO

                                try {
                                    byte[] auth = new byte[16];
                                    byte[] rnd = SKFDemoMACRO.skfWrapper.SKF_GenRandom(SKFDemoMACRO.devhandle,8);
                                    System.arraycopy(rnd,0,auth,0,8);
                                    HANDLE handle = new HANDLE();
                                    //skfWrapper.SKF_SetSymmKey(SKFDemoMACRO.devhandle,editText.getText().toString().getBytes(),SkfDefines.SGD_SMS4_ECB,handle);
                                    SKFDemoMACRO.skfWrapper.SKF_SetSymmKey(SKFDemoMACRO.devhandle, HexByte.hexToByte(editText.getText().toString()), SkfDefines.SGD_SMS4_ECB, handle);
                                    SKFDemoMACRO.skfWrapper.SKF_EncryptInit(handle,null,0,16 * 8);
                                    byte[] cipher = SKFDemoMACRO.skfWrapper.SKF_Encrypt(handle,auth);
                                    SKFDemoMACRO.skfWrapper.SKF_CloseHandle(handle);
                                    SKFDemoMACRO.skfWrapper.SKF_DevAuth(SKFDemoMACRO.devhandle,cipher);
                                    funcResultString("设备认证成功！！！");
                                }catch (SKFException e){
                                    e.printStackTrace();
                                    funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }
                            }
                        }).show();
                        break;
                    case 1:

                        new AlertDialog.Builder(AccessActivity.this).setTitle("请输入新的认证密钥").setView(editText).setPositiveButton("确定", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                //TODO

                                try {
                                    //skfWrapper.SKF_ChangeDevAuthKey(SKFDemoMACRO.devhandle,editText.getText().toString().getBytes());
                                    SKFDemoMACRO.skfWrapper.SKF_ChangeDevAuthKey(SKFDemoMACRO.devhandle, HexByte.hexToByte(editText.getText().toString()));
                                    funcResultString("设备认证密钥修改成功！！！");
                                }catch (SKFException e){
                                    e.printStackTrace();
                                    funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }
                            }
                        }).show();
                        break;
                    default:
                        break;
                }
            }
        });
    }



    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_base);

        setTitle("设备名称" + SKFDemoMACRO.select_dev_name);

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
