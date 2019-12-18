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
import android.widget.RadioGroup;
import android.widget.Spinner;
import android.widget.SpinnerAdapter;
import android.widget.TextView;
import com.westone.csmmanager.R;
import com.westone.skf.ECCCIPHERBLOB;
import com.westone.skf.HANDLE;
import com.westone.skf.SKFException;
import com.westone.skf.SkfDefines;
import com.westone.skf.SkfWrapper;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;

public class ContainerManagerActivity extends Activity {

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

        spinner.setPrompt(SKFDemoMACRO.spinner_promt_container);
    }

    private void setViewValue(){
        scan.setText(SKFDemoMACRO.scan_container);

        ListAdapter listAdapterFunc = new GridViewFuncAdapter(ContainerManagerActivity.this,R.layout.gridview_func,SKFDemoMACRO.gridview_func_container);
        gridViewFunc.setAdapter(listAdapterFunc);
        gridViewFunc.setNumColumns(2);


        ListAdapter listAdapterType = new GridViewTypeAdapter(ContainerManagerActivity.this,R.layout.gridview_func,SKFDemoMACRO.gridview_type);
        gridViewType.setAdapter(listAdapterType);

        if(SKFDemoMACRO.list_container.size() > 0){
            SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(ContainerManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_container);
            spinner.setAdapter(spinnerAdapter);
            SKFDemoMACRO.select_container_name = (String) SKFDemoMACRO.list_container.get(0);
        }
    }

    private void clickType(){

        gridViewType.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                Log.i("wjr","position = " + position);
                switch (position){
                    case 0:
                        intent.setClass(ContainerManagerActivity.this,DevManagerActivity.class);
                        break;
                    case 1:
                        //跳转到访问控制
                        intent.setClass(ContainerManagerActivity.this,AccessActivity.class);
                        break;
                    case 2:
                        //跳转到应用管理
                        intent.setClass(ContainerManagerActivity.this,AppManagerActivity.class);
                        break;
                    case 3:
                        //跳转到文件管理
                        intent.setClass(ContainerManagerActivity.this,FileManagerActivity.class);
                        break;
                    case 4:
                        //跳转到容器管理
                        intent.setClass(ContainerManagerActivity.this,ContainerManagerActivity.class);
                        break;
                    case 5:
                        //跳转到密码运算
                        intent.setClass(ContainerManagerActivity.this,AlgActivity.class);
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
                try{
                    SKFDemoMACRO.list_container.clear();
                    SKFDemoMACRO.skfWrapper.SKF_EnumContainer(SKFDemoMACRO.happlication,SKFDemoMACRO.list_container);
                    StringBuilder stringBuilder = new StringBuilder();
                    stringBuilder.append("SKF_EnumContainer 成功！！！，共有 " + SKFDemoMACRO.list_container.size() + " 个容器存在---");
                    for(int i = 0; i < SKFDemoMACRO.list_container.size();i++){
                        stringBuilder.append("\n");
                        stringBuilder.append("第" + (i + 1) + " 个容器名称为" + SKFDemoMACRO.list_container.get(i));
                    }

                    funcResultString(stringBuilder.toString());

                }catch (SKFException e){
                    e.printStackTrace();
                    funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                }

                SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(ContainerManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_container);
                spinner.setAdapter(spinnerAdapter);
            }
        });



        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                SKFDemoMACRO.select_container_name = (String) SKFDemoMACRO.list_container.get(position);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {

            }
        });

        gridViewFunc.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, final int position, long id) {
                final AlertDialog alertDialog = new AlertDialog.Builder(ContainerManagerActivity.this).setPositiveButton("确定",null).create();
                switch (position){
                    case 0:
                    case 1:
                    case 2:
                    case 3:
                        View view_container = View.inflate(ContainerManagerActivity.this,R.layout.container,null);
                        alertDialog.setView(view_container);
                        alertDialog.show();
                        final EditText container_name = view_container.findViewById(R.id.container_name);
//("创建容器","删除容器","打开容器","关闭容器","创建ECC密钥对","导入ECC密钥对","签名","导出会话密钥","导出公钥","导入会话密钥");
                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                switch (position){
                                    case 0:
                                        //create container
                                        try {
                                            SKFDemoMACRO.skfWrapper.SKF_CreateContainer(SKFDemoMACRO.happlication,container_name.getText().toString(),SKFDemoMACRO.hcontainer);
                                            funcResultString("SKF_CreateContainer Success");
                                            SKFDemoMACRO.list_container.add(container_name.getText().toString());
                                            SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(ContainerManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_container);
                                            spinner.setAdapter(spinnerAdapter);

                                        }catch (Exception e){
                                            e.printStackTrace();
                                            funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                                        }
                                        break;
                                    case 1:
                                        //delete container
                                        try {
                                            SKFDemoMACRO.skfWrapper.SKF_DeleteContainer(SKFDemoMACRO.happlication,container_name.getText().toString());
                                            funcResultString("SKF_DeleteContainer Success");
                                            SKFDemoMACRO.list_container.remove(container_name.getText().toString());
                                            SpinnerAdapter spinnerAdapter = new ArrayAdapter<>(ContainerManagerActivity.this,android.R.layout.simple_list_item_1,SKFDemoMACRO.list_container);
                                            spinner.setAdapter(spinnerAdapter);

                                        }catch (Exception e){
                                            e.printStackTrace();
                                            funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                                        }
                                        break;
                                    case 2:
                                        //open container
                                        try {
                                            SKFDemoMACRO.skfWrapper.SKF_OpenContainer(SKFDemoMACRO.happlication,container_name.getText().toString(),SKFDemoMACRO.hcontainer);
                                            funcResultString("SKF_OpenContainer Success");
                                        }catch (Exception e){
                                            e.printStackTrace();
                                            funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                                        }
                                        break;
                                    case 3:
                                        //close container
                                        try {
                                            SKFDemoMACRO.skfWrapper.SKF_CloseContainer(SKFDemoMACRO.hcontainer);
                                            funcResultString("SKF_CloseContainer Success");
                                        }catch (Exception e){
                                            e.printStackTrace();
                                            funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                                        }
                                        break;
                                    default:
                                        break;
                                }
                                alertDialog.dismiss();
                            }
                        });
                        break;
                    case 4:
                        //create ecc
                        try {
                            SKFDemoMACRO.skfWrapper.SKF_GenECCKeyPair(SKFDemoMACRO.hcontainer,SkfDefines.SGD_SM2_1);
                            funcResultString("SKF_GenECCKeyPair Success");
                        }catch (Exception e){
                            e.printStackTrace();
                            funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                        }
                        break;
                    case 5:
                        //import ecc

                        View view_import_ecc = View.inflate(ContainerManagerActivity.this,R.layout.import_ecc,null);
                        alertDialog.setView(view_import_ecc);
                        alertDialog.show();

                        final EditText import_ecc_pri = view_import_ecc.findViewById(R.id.import_ecc_pri);
                        final EditText import_ecc_puk = view_import_ecc.findViewById(R.id.import_ecc_puk);
                        final EditText import_ecc_cipher = view_import_ecc.findViewById(R.id.import_ecc_cipher);

                        import_ecc_pri.setText("9e5f9627324d2b4597ebccf0a37f1ac76d926e57671e068a3a5d37a3418918de");
                        import_ecc_puk.setText("792b5975d47446e5d81369274ec4cc744a318d39c4823279d8e4014d3813daf823f20104162d9ffed36ab3cffacc9a539e38edd1e2c9df666574b5e0d83e4524");

                        import_ecc_pri.setEnabled(false);
                        import_ecc_puk.setEnabled(false);
                        import_ecc_cipher.setVisibility(View.GONE);

                        final byte[] keyPlain = new byte[]{
                                (byte)0x31,(byte)0x32,(byte)0x33,(byte)0x34,(byte)0x35,(byte)0x36,(byte)0x37,(byte)0x38,
                                (byte)0x31,(byte)0x32,(byte)0x33,(byte)0x34,(byte)0x35,(byte)0x36,(byte)0x37,(byte)0x38
                        };

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try {

                                    byte[] puk = SKFDemoMACRO.skfWrapper.SKF_ExportPublicKey(SKFDemoMACRO.hcontainer,true);
                                    ECCCIPHERBLOB ecccipherblob = SKFDemoMACRO.skfWrapper.SKF_ExtECCEncrypt(SKFDemoMACRO.devhandle,puk,keyPlain);

                                    HANDLE handle = new HANDLE();
                                    SKFDemoMACRO.skfWrapper.SKF_SetSymmKey(SKFDemoMACRO.devhandle,keyPlain,SkfDefines.SGD_SMS4_ECB,handle);

                                    SKFDemoMACRO.skfWrapper.SKF_EncryptInit(handle,null,0,0);

                                    SKFDemoMACRO.skfWrapper.SKF_ImportECCKeyPair(SKFDemoMACRO.hcontainer,SKFDemoMACRO.skfWrapper.SKF_Encrypt(handle,HexByte.hexToByte(import_ecc_pri.getText().toString())),
                                        HexByte.hexToByte(import_ecc_puk.getText().toString()),ecccipherblob);
                                    SKFDemoMACRO.skfWrapper.SKF_CloseHandle(handle);

                                    funcResultString("SKF_ImportECCKeyPair Success!!!");
                                }catch (Exception e){
                                    e.printStackTrace();
                                    funcResultString(e.getMessage() + "Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }
                                alertDialog.dismiss();
                            }
                        });

                        break;
                    case 6:
                        //ecc sign
                        View view_ecc_sign = View.inflate(ContainerManagerActivity.this,R.layout.ecc_sign,null);
                        alertDialog.setView(view_ecc_sign);
                        alertDialog.show();

                        final EditText ecc_sign_src = view_ecc_sign.findViewById(R.id.ecc_sign);
                        final TextView ecc_sign_hash = view_ecc_sign.findViewById(R.id.ecc_sign_hash);
                        final TextView ecc_sign_result = view_ecc_sign.findViewById(R.id.ecc_sign_result);

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try {
                                    HANDLE handle = new HANDLE();
                                    SKFDemoMACRO.skfWrapper.SKF_DigestInit(SKFDemoMACRO.devhandle,SkfDefines.SGD_SM3,null,null,handle);
                                    byte[] hash = SKFDemoMACRO.skfWrapper.SKF_Digest(handle,ecc_sign_src.getText().toString().getBytes());
                                    byte[] sign = SKFDemoMACRO.skfWrapper.SKF_ECCSignData(SKFDemoMACRO.hcontainer,hash);
                                    SKFDemoMACRO.skfWrapper.SKF_CloseHandle(handle);
                                    ecc_sign_hash.setText(HexByte.byteToHex(hash));
                                    ecc_sign_result.setText(HexByte.byteToHex(sign));
                                    funcResultString("SKF_ECCSignData Success");
                                }catch (Exception e){
                                    funcResultString(e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }
                            }
                        });
                        break;
                    case 7:
                        //export session key
                        View view_ecc_export_sess = View.inflate(ContainerManagerActivity.this,R.layout.ecc_export_sess,null);
                        alertDialog.setView(view_ecc_export_sess);
                        alertDialog.show();

                        final EditText ecc_export_sess_puk = view_ecc_export_sess.findViewById(R.id.ecc_export_sess_puk);
                        final TextView ecc_export_sess_cipher = view_ecc_export_sess.findViewById(R.id.ecc_export_sess_cipher);
                        final Spinner ecc_export_sess_spinner = view_ecc_export_sess.findViewById(R.id.ecc_export_sess_spinner);

                        ecc_export_sess_puk.setVisibility(View.GONE);
                        ecc_export_sess_cipher.setVisibility(View.GONE);

                        final long[] algId = new long[1];

                        ecc_export_sess_spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                            @Override
                            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                                switch (position){
                                    case 0:
                                        algId[0] = SkfDefines.SGD_SMS4_ECB;
                                        break;
                                    case 1:
                                        algId[0] = SkfDefines.SGD_SMS4_OFB;
                                        break;
                                    case 2:
                                        algId[0] = SkfDefines.SGD_SMS4_CBC;
                                        break;
                                    default:
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
                                HANDLE handle = new HANDLE();
                                try {
                                    /*ECCCIPHERBLOB ecccipherblob = */SKFDemoMACRO.skfWrapper.SKF_ECCExportSessionKey(SKFDemoMACRO.hcontainer,algId[0],
                                            SKFDemoMACRO.skfWrapper.SKF_ExportPublicKey(SKFDemoMACRO.hcontainer,false),
                                            handle);

                                    funcResultString("SKF_ECCExportSessionKey Success");
                                    alertDialog.dismiss();

                                }catch (Exception e){
                                    funcResultString(e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }
                            }
                        });
                        break;
                    case 8:
                        //export puk
                        View view_export_puk = View.inflate(ContainerManagerActivity.this,R.layout.export_puk,null);
                        alertDialog.setView(view_export_puk);
                        alertDialog.show();

                        final boolean[] flg = new boolean[1];
                        final RadioGroup export_puk = view_export_puk.findViewById(R.id.export_puk);
                        export_puk.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
                            @Override
                            public void onCheckedChanged(RadioGroup group, int checkedId) {
                                switch (checkedId){
                                    case R.id.export_puk_sign:
                                        flg[0] = true;
                                        break;

                                    case R.id.export_puk_encrypt:
                                        flg[0] = false;
                                        break;
                                    default:
                                        break;
                                }
                            }
                        });

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try {
                                    byte[] puk = SKFDemoMACRO.skfWrapper.SKF_ExportPublicKey(SKFDemoMACRO.hcontainer,flg[0]);
                                    Log.i("skf","导出的公钥为\n" + HexByte.byteToHex(puk));
                                    funcResultString("导出的公钥为\n" + HexByte.byteToHex(puk));
                                }catch (Exception e){
                                    funcResultString(e.getMessage() + ",Error = " + String.format("0x%02x",SKFException.getLastError()));
                                }
                                alertDialog.dismiss();
                            }
                        });
                        break;


                    case 9:
                        //import session key
                        View view_import_sess = View.inflate(ContainerManagerActivity.this,R.layout.import_sess,null);
                        alertDialog.setView(view_import_sess);
                        alertDialog.show();

                        final Spinner import_sess_spinner = view_import_sess.findViewById(R.id.import_sess);
                        final EditText import_sess_cipher = view_import_sess.findViewById(R.id.import_sess_cipher);
                        final long[] alg = new long[1];
                        import_sess_cipher.setVisibility(View.GONE);

                        import_sess_spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                            @Override
                            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                                switch (position){
                                    case 0:
                                        alg[0] = SkfDefines.SGD_SMS4_ECB;
                                        break;
                                    case 1:
                                        alg[0] = SkfDefines.SGD_SMS4_OFB;
                                        break;
                                    case 2:
                                        alg[0] = SkfDefines.SGD_SMS4_CBC;
                                        break;
                                    default:
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
                                    HANDLE handle = new HANDLE();
                                    SKFDemoMACRO.skfWrapper.SKF_ImportSessionKey(SKFDemoMACRO.hcontainer,alg[0],SKFDemoMACRO.skfWrapper.SKF_ExtECCEncrypt(SKFDemoMACRO.devhandle,
                                            SKFDemoMACRO.skfWrapper.SKF_ExportPublicKey(SKFDemoMACRO.hcontainer,false),new byte[]{
                                            1,2,3,4,
                                            1,2,3,4,
                                            1,2,3,4,
                                            1,2,3,4
                                    }),handle);
                                    byte[] iv = {
                                            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
                                    };
                                    byte[] plaintext = {
                                            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
                                    };
                                    Log.i("skf","sm4 iv:"+HexByte.byteToHex(iv));
                                    SKFDemoMACRO.skfWrapper.SKF_EncryptInit(handle, iv, 0, 16*8);
                                    byte [] ciphertext = SKFDemoMACRO.skfWrapper.SKF_Encrypt(handle, plaintext);
                                    if(ciphertext != null){
                                        Log.i("skf","sm4 ciphertext:"+HexByte.byteToHex(ciphertext));
                                        SKFDemoMACRO.skfWrapper.SKF_DecryptInit(handle, iv, 0, 16*8);
                                        byte [] plaintext1 = SKFDemoMACRO.skfWrapper.SKF_Decrypt(handle, ciphertext);

                                        if(plaintext1 != null){
                                            Log.i("skf","sm4 plaintext:"+HexByte.byteToHex(plaintext1));
                                            if(!Arrays.equals(plaintext, plaintext1)){
                                                //Log.i(tag, "plaintext and plaintext are different!");
                                                funcResultString("SKF_ImportSessionKey Failed4.");
                                            }else {
                                                //Log.i(tag, "plaintext and plaintext are same");
                                                SKFDemoMACRO.skfWrapper.SKF_CloseHandle(handle);
                                                funcResultString("SKF_ImportSessionKey Success");
                                            }
                                        }else {
                                            funcResultString("SKF_ImportSessionKey Failed3.");
                                        }
                                    }else {
                                        funcResultString("SKF_ImportSessionKey Failed2.");
                                    }
                                    alertDialog.dismiss();
                                }catch (Exception e){
                                    funcResultString(e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }
                            }
                        });
                        break;

                    case 10:
                        //import cert
                        View view_import_cert = View.inflate(ContainerManagerActivity.this,R.layout.certificate,null);
                        alertDialog.setView(view_import_cert);
                        alertDialog.show();

                        final boolean[] flg1 = new boolean[1];
                        final EditText cert_content = view_import_cert.findViewById(R.id.cert_content);
                        final RadioGroup cert = view_import_cert.findViewById(R.id.cert);
                        cert.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
                            @Override
                            public void onCheckedChanged(RadioGroup group, int checkedId) {
                                switch (checkedId){
                                    case R.id.cert_sign:
                                        flg1[0] = true;
                                        break;
                                    case R.id.cert_encrypt:
                                        flg1[0] = false;
                                        break;
                                    default:
                                        break;
                                }
                            }
                        });

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try {
                                    SKFDemoMACRO.skfWrapper.SKF_ImportCertificate(SKFDemoMACRO.hcontainer,flg1[0],HexByte.hexToByte(cert_content.getText().toString()));
                                    funcResultString("SKF_ImportCertificate Success");
                                }catch (Exception e){
                                    funcResultString(e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }
                                alertDialog.dismiss();
                            }
                        });
                        break;
                    case 11:
                        //export cert
                        View view_export_cert = View.inflate(ContainerManagerActivity.this,R.layout.certificate,null);
                        alertDialog.setView(view_export_cert);
                        alertDialog.show();

                        final boolean[] flg2 = new boolean[1];
                        final EditText cert_content1 = view_export_cert.findViewById(R.id.cert_content);
                        final RadioGroup cert2 = view_export_cert.findViewById(R.id.cert);
                        cert2.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
                            @Override
                            public void onCheckedChanged(RadioGroup group, int checkedId) {
                                switch (checkedId){
                                    case R.id.cert_sign:
                                        flg2[0] = true;
                                        break;
                                    case R.id.cert_encrypt:
                                        flg2[0] = false;
                                        break;
                                        default:
                                            break;
                                }
                            }
                        });

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try {
                                    byte[] content = SKFDemoMACRO.skfWrapper.SKF_ExportCertificate(SKFDemoMACRO.hcontainer,flg2[0]);
                                    if(content != null){
                                        cert_content1.setText(HexByte.byteToHex(content));
                                        cert_content1.setClickable(false);
                                        funcResultString("SKF_ExportCertificate Success,cert is \n" + HexByte.byteToHex(content));
                                    }else{
                                        funcResultString("SKF_ExportCertificate Success,cert is null. \n");
                                    }
                                }catch (Exception e){
                                    funcResultString(e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }
                            }
                        });
                        break;
                    case 12:
                        //get container type
                        try {
                            long ret = SKFDemoMACRO.skfWrapper.SKF_GetContainerType(SKFDemoMACRO.hcontainer);
                            String s = "";
                            if(ret == 0 ){
                                s = "空容器";
                            }else if(ret == 1){
                                s = "RSA容器";
                            }else if (ret == 2){
                                s= "SM2容器";
                            }

                            funcResultString("SKF_GetContainerType Success" + "type = " + s);
                        }catch (Exception e){
                            funcResultString(e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                        }

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
        setTitle("应用名称 "+SKFDemoMACRO.select_app_name);
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
