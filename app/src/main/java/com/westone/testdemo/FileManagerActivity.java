package com.westone.testdemo;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
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

import com.westone.csmmanager.R;
import com.westone.skf.FILEATTRIBUTE;
import com.westone.skf.HAPPLICATION;
import com.westone.skf.SKFException;
import com.westone.skf.SkfDefines;
import com.westone.skf.SkfWrapper;

import java.util.ArrayList;
import java.util.List;

public class FileManagerActivity extends Activity {

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

        spinner.setPrompt(SKFDemoMACRO.spinner_promt_file);
    }

    private void setViewValue(){
        scan.setText(SKFDemoMACRO.scan_file);

        ListAdapter listAdapterFunc = new GridViewFuncAdapter(FileManagerActivity.this,R.layout.gridview_func,SKFDemoMACRO.gridview_func_file);
        gridViewFunc.setAdapter(listAdapterFunc);
        gridViewFunc.setNumColumns(2);


        ListAdapter listAdapterType = new GridViewTypeAdapter(FileManagerActivity.this,R.layout.gridview_func,SKFDemoMACRO.gridview_type);
        gridViewType.setAdapter(listAdapterType);

        if(SKFDemoMACRO.list_file.size() > 0) {
            SKFDemoMACRO.select_file_name = (String)SKFDemoMACRO.list_file.get(0);
            SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(FileManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_file);
            spinner.setAdapter(spinnerAdapter);
        }
    }

    private void clickType(){

        gridViewType.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                Log.i("wjr","position = " + position);
                switch (position){
                    case 0:
                        intent.setClass(FileManagerActivity.this,DevManagerActivity.class);
                        break;
                    case 1:
                        //跳转到访问控制
                        intent.setClass(FileManagerActivity.this,AccessActivity.class);
                        break;
                    case 2:
                        //跳转到应用管理
                        intent.setClass(FileManagerActivity.this,AppManagerActivity.class);
                        break;
                    case 3:
                        //跳转到文件管理
                        intent.setClass(FileManagerActivity.this,FileManagerActivity.class);
                        break;
                    case 4:
                        //跳转到容器管理
                        intent.setClass(FileManagerActivity.this,ContainerManagerActivity.class);
                        break;
                    case 5:
                        //跳转到密码运算
                        intent.setClass(FileManagerActivity.this,AlgActivity.class);
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
                //TODO enum dev
                try {
                    SKFDemoMACRO.list_file.clear();
                    SKFDemoMACRO.skfWrapper.SKF_EnumFiles(SKFDemoMACRO.happlication,SKFDemoMACRO.list_file);
                    StringBuilder stringBuilder = new StringBuilder();
                    stringBuilder.append("SKF_EnumFiles 成功！！！，共有 " + SKFDemoMACRO.list_file.size() + " 个文件存在---");
                    for(int i = 0; i < SKFDemoMACRO.list_file.size();i++){
                        stringBuilder.append("\n");
                        stringBuilder.append("第" + (i + 1) + " 个文件名称为" + SKFDemoMACRO.list_file.get(i));
                    }

                    funcResultString(stringBuilder.toString());

                }catch (SKFException e){
                    e.printStackTrace();
                    funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                }

                if(SKFDemoMACRO.list_file.size() > 0) {
                    SKFDemoMACRO.select_file_name = (String)SKFDemoMACRO.list_file.get(0);
                }

                SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(FileManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_file);
                spinner.setAdapter(spinnerAdapter);
            }
        });



        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                SKFDemoMACRO.select_file_name = (String)SKFDemoMACRO.list_file.get(position);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {

            }
        });

        gridViewFunc.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                final AlertDialog alertDialog = new AlertDialog.Builder(FileManagerActivity.this).setPositiveButton("确定", null).create();

                switch (position){
                    case 0:
                        //create file
                        final View create_file_view = View.inflate(FileManagerActivity.this,R.layout.create_file,null);
                        alertDialog.setView(create_file_view);
                        alertDialog.show();

                        final EditText create_file_name = create_file_view.findViewById(R.id.create_file_name);
                        final EditText create_file_size = create_file_view.findViewById(R.id.create_file_size);
                        final Spinner spinner_read = create_file_view.findViewById(R.id.create_file_read);
                        final Spinner spinner_write = create_file_view.findViewById(R.id.create_file_write);
                        final long[] rights = {SkfDefines.SECURE_USER_ACCOUNT,SkfDefines.SECURE_USER_ACCOUNT};

                        spinner_read.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                            @Override
                            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                                switch (position){
                                    case 0:
                                        rights[0] = SkfDefines.SECURE_ANYONE_ACCOUNT;
                                        break;
                                    case 1:
                                        rights[0] = SkfDefines.SECURE_USER_ACCOUNT;
                                        break;
                                    case 2:
                                        rights[0] = SkfDefines.SECURE_ADM_ACCOUNT;
                                        break;
                                    case 3:
                                        rights[0] = SkfDefines.SECURE_NEVER_ACCOUNT;
                                        break;
                                }
                            }

                            @Override
                            public void onNothingSelected(AdapterView<?> parent) {

                            }
                        });

                        spinner_write.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                            @Override
                            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                                switch (position){
                                    case 0:
                                        rights[1] = SkfDefines.SECURE_ANYONE_ACCOUNT;
                                        break;
                                    case 1:
                                        rights[1] = SkfDefines.SECURE_USER_ACCOUNT;
                                        break;
                                    case 2:
                                        rights[1] = SkfDefines.SECURE_ADM_ACCOUNT;
                                        break;
                                    case 3:
                                        rights[1] = SkfDefines.SECURE_NEVER_ACCOUNT;
                                        break;
                                }
                            }

                            @Override
                            public void onNothingSelected(AdapterView<?> parent) {

                            }
                        });

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try {
                                    SKFDemoMACRO.skfWrapper.SKF_CreateFile(SKFDemoMACRO.happlication,create_file_name.getText().toString(),
                                            Long.parseLong(create_file_size.getText().toString()),rights[0],rights[1]);
                                    funcResultString("SKF_CreateFile " + create_file_name.getText().toString() + "Success !!!");
                                    SKFDemoMACRO.list_file.add(create_file_name.getText().toString());
                                    SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(FileManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_file);
                                    spinner.setAdapter(spinnerAdapter);

                                }catch (Exception e){
                                    e.printStackTrace();
                                    funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }
                                alertDialog.dismiss();
                            }
                        });
                        break;
                    case 1:
                        //read file
                        final View read_file_view = View.inflate(FileManagerActivity.this,R.layout.read_file,null);
                        alertDialog.setView(read_file_view);
                        alertDialog.show();

                        final EditText read_file = read_file_view.findViewById(R.id.read_file_name);
                        final EditText read_file_offset = read_file_view.findViewById(R.id.read_file_offset);
                        final EditText read_file_len = read_file_view.findViewById(R.id.read_file_len);

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try {
                                    byte[] out = SKFDemoMACRO.skfWrapper.SKF_ReadFile(SKFDemoMACRO.happlication,read_file.getText().toString(),Long.parseLong(read_file_offset.getText().toString()),
                                            Long.parseLong(read_file_len.getText().toString()));
                                    if(out != null){
                                        funcResultString("SKF_ReadFile Success ,read len = " + out.length+ ",content = " + new String(out));
                                    }

                                }catch (Exception e){
                                    funcResultString(e.getMessage());
                                }
                                alertDialog.dismiss();
                            }
                        });
                        break;
                    case 2:
                        //write file
                        final View write_file_view = View.inflate(FileManagerActivity.this,R.layout.write_file,null);
                        alertDialog.setView(write_file_view);
                        alertDialog.show();

                        final EditText write_file_name = write_file_view.findViewById(R.id.write_file_name);
                        final EditText write_file_offset = write_file_view.findViewById(R.id.write_file_offset);
                        final EditText write_file_content = write_file_view.findViewById(R.id.write_file);

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try {
                                    SKFDemoMACRO.skfWrapper.SKF_WriteFile(SKFDemoMACRO.happlication,write_file_name.getText().toString(),Long.parseLong(write_file_offset.getText().toString()),write_file_content.getText().toString().getBytes());
                                    funcResultString("SKF_WriteFile Success");
                                }catch (Exception e){
                                    funcResultString(e.getMessage());
                                }
                                alertDialog.dismiss();
                            }
                        });
                        break;
                    case 3:
                        //delete file
                        final View delete_file_view = View.inflate(FileManagerActivity.this,R.layout.delete_file,null);
                        alertDialog.setView(delete_file_view);
                        alertDialog.show();
                        final EditText delete_file_name = delete_file_view.findViewById(R.id.delete_file_name);

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try {
                                    SKFDemoMACRO.skfWrapper.SKF_DeleteFile(SKFDemoMACRO.happlication,delete_file_name.getText().toString());
                                    funcResultString("SKF_DeleteFile Success");
                                    SKFDemoMACRO.list_file.remove(delete_file_name.getText().toString());
                                    SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(FileManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_file);
                                    spinner.setAdapter(spinnerAdapter);

                                }catch (Exception e){
                                    funcResultString(e.getMessage());
                                }
                                alertDialog.dismiss();
                            }
                        });
                        break;
                    case 4:
                        //get file
                        final View get_file_view = View.inflate(FileManagerActivity.this,R.layout.get_file,null);
                        alertDialog.setView(get_file_view);
                        alertDialog.show();

                        final EditText get_file_name = get_file_view.findViewById(R.id.get_file_name);
                        final FILEATTRIBUTE fileattribute = new FILEATTRIBUTE();

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try {
                                    SKFDemoMACRO.skfWrapper.SKF_GetFileInfo(SKFDemoMACRO.happlication,get_file_name.getText().toString(),fileattribute);
                                    funcResultString("SKF_GetFileInfo Success name = " + fileattribute.getFileName() + ",size = "+fileattribute.getFileSize() + ",read = "+String.format("0x%08x",fileattribute.getReadRights()) +
                                            ",write = "+String.format("0x%08x",fileattribute.getWriteRights()));

                                }catch (Exception e){
                                    funcResultString(e.getMessage());
                                }
                                alertDialog.dismiss();
                            }
                        });
                        break;

                }
            }
        });
    }



    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_base);

        setTitle("应用名称" + SKFDemoMACRO.select_app_name);
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
