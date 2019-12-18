package com.westone.testdemo;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.GridView;
import android.widget.ListAdapter;
import android.widget.RadioGroup;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import com.westone.csmmanager.R;
import com.westone.skf.ECCCIPHERBLOB;
import com.westone.skf.HANDLE;
import com.westone.skf.SKFException;
import com.westone.skf.SkfDefines;
import com.westone.skf.SkfWrapper;

import java.util.Arrays;
import java.util.zip.GZIPInputStream;

public class AlgActivity extends Activity {

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
        //scan.setText(SKFDemoMACRO.scan_dev);
        scan.setVisibility(View.GONE);
        spinner.setVisibility(View.GONE);

        ListAdapter listAdapterFunc = new GridViewFuncAdapter(AlgActivity.this,R.layout.gridview_func,SKFDemoMACRO.gridview_func_alg);
        gridViewFunc.setAdapter(listAdapterFunc);
        gridViewFunc.setNumColumns(2);


        ListAdapter listAdapterType = new GridViewTypeAdapter(AlgActivity.this,R.layout.gridview_func,SKFDemoMACRO.gridview_type);
        gridViewType.setAdapter(listAdapterType);
    }

    private void clickType(){

        gridViewType.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                Log.i("wjr","position = " + position);
                switch (position){
                    case 0:
                        intent.setClass(AlgActivity.this,DevManagerActivity.class);
                        break;
                    case 1:
                        //跳转到访问控制
                        intent.setClass(AlgActivity.this,AccessActivity.class);
                        break;
                    case 2:
                        //跳转到应用管理
                        intent.setClass(AlgActivity.this,AppManagerActivity.class);
                        break;
                    case 3:
                        //跳转到文件管理
                        intent.setClass(AlgActivity.this,FileManagerActivity.class);
                        break;
                    case 4:
                        //跳转到容器管理
                        intent.setClass(AlgActivity.this,ContainerManagerActivity.class);
                        break;
                    case 5:
                        //跳转到密码运算
                        intent.setClass(AlgActivity.this,AlgActivity.class);
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

                final AlertDialog alertDialog = new AlertDialog.Builder(AlgActivity.this).setPositiveButton("确定",null).create();
                switch (position){
                    case 0:
                        //gen random
                        View view_gen_random = View.inflate(AlgActivity.this,R.layout.gen_random,null);
                        alertDialog.setView(view_gen_random);
                        alertDialog.show();

                        final EditText gen_random_len = view_gen_random.findViewById(R.id.gen_random_len);
                        final TextView gen_random_content = view_gen_random.findViewById(R.id.gen_random_content);

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try{
                                    byte[] rnd = SKFDemoMACRO.skfWrapper.SKF_GenRandom(SKFDemoMACRO.devhandle,Long.parseLong(gen_random_len.getText().toString()));
                                    gen_random_content.setText(HexByte.byteToHex(rnd));
                                    funcResultString("SKF_GenRandom Success rnd = \n" + HexByte.byteToHex(rnd));
                                }catch (Exception e){
                                    funcResultString(e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }
                            }
                        });
                        break;
                    case 1:
                        //ecc verify
                        View view_ecc_verify = View.inflate(AlgActivity.this,R.layout.ecc_verify,null);
                        alertDialog.setView(view_ecc_verify);
                        alertDialog.show();

                        final EditText ecc_verify_hash = view_ecc_verify.findViewById(R.id.ecc_verify_hash);
                        final EditText ecc_verify_puk = view_ecc_verify.findViewById(R.id.ecc_verify_puk);
                        final EditText ecc_verify_sign = view_ecc_verify.findViewById(R.id.ecc_verify_sign);

                        ecc_verify_hash.setText("207cf410"+"532f92a4"+"7dee245c"+ "e9b11ff7" +
                                "1f578ebd" +"763eb3bb"+ "ea44ebd0"+ "43d018fb");

                        ecc_verify_puk.setText("64f54d53"+ "ba1f256c" +"5be07503"+ "8e0f109b" +
                                "5ed4baa4" +"bfc35016" + "8598bb18" +"1d3829c3" +
                                "37ff9513" +"4300b835" +"58e41919" +"3590cbf2" +
                                "8af8d645" +"9c1f7206" +"bd9b6ea3" +"51dc30f4");

                        ecc_verify_sign.setText("d235b6b5" +"20dbd9cc" +"aefa7ef2" +"f08c2406" +
                                "68f00e33" +"1aae50fe" +"248c8ff6" +"eb949019" +
                                "ce2fac34" +"185ed520" +"523a8dca" +"c2cf15c6" +
                                "5dc4ff57" +"cd296445" +"30c07a09" +"0134fbd5");

                        ecc_verify_hash.setEnabled(false);
                        ecc_verify_puk.setEnabled(false);
                        ecc_verify_sign.setEnabled(false);

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try{
                                    SKFDemoMACRO.skfWrapper.SKF_ECCVerify(SKFDemoMACRO.devhandle,HexByte.hexToByte(ecc_verify_puk.getText().toString()),
                                            HexByte.hexToByte(ecc_verify_hash.getText().toString()),HexByte.hexToByte(ecc_verify_sign.getText().toString()));

                                    //skfWrapper.SKF_ExtECCVerify(SKFDemoMACRO.devhandle,HexByte.hexToByte(ecc_verify_puk.getText().toString()),
                                            //HexByte.hexToByte(ecc_verify_hash.getText().toString()),HexByte.hexToByte(ecc_verify_sign.getText().toString()));

                                    funcResultString("SKF_ECCVerify / SKF_ExtECCVerify Success");

                                }catch (Exception e){
                                    funcResultString(e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }

                                alertDialog.dismiss();
                            }

                        });

                        break;
                    case 2:
                        //ext ecc encrypt
                        View view_ext_ecc_encrypt = View.inflate(AlgActivity.this,R.layout.ext_ecc_encrypt,null);
                        alertDialog.setView(view_ext_ecc_encrypt);
                        alertDialog.show();

                        final EditText ext_ecc_encrypt_puk = view_ext_ecc_encrypt.findViewById(R.id.ext_ecc_encrypt_puk);
                        final EditText ext_ecc_encrypt_plain = view_ext_ecc_encrypt.findViewById(R.id.ext_ecc_encrypt_plain);
                        final TextView ext_ecc_encrypt_cipher = view_ext_ecc_encrypt.findViewById(R.id.ext_ecc_encrypt_cipher);

                        ext_ecc_encrypt_puk.setText("64f54d53ba1f256c5be075038e0f109b" +
                                "5ed4baa4bfc350168598bb181d3829c3" +
                                "37ff95134300b83558e419193590cbf2" +
                                "8af8d6459c1f7206bd9b6ea351dc30f4");

                        ext_ecc_encrypt_plain.setText("3c2f01c14940e1b502b7859af7d0d591");

                        ext_ecc_encrypt_puk.setEnabled(false);
                        ext_ecc_encrypt_plain.setEnabled(false);
                        ext_ecc_encrypt_cipher.setVisibility(View.GONE);
                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try{
                                    ECCCIPHERBLOB ecccipherblob = SKFDemoMACRO.skfWrapper.SKF_ExtECCEncrypt(SKFDemoMACRO.devhandle,HexByte.hexToByte(ext_ecc_encrypt_puk.getText().toString()),ext_ecc_encrypt_plain.getText().toString().getBytes());
                                    funcResultString("SKF_ExtECCEncrypt Success");
                                    //ext_ecc_encrypt_cipher.setText(HexByte.byteToHex(cipher));

                                }catch (Exception e){
                                    funcResultString(e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }
                                alertDialog.dismiss();
                            }

                        });

                        break;
                    case 3:
                        //ext ecc decrypt
                        View view_ext_ecc_decrypt = View.inflate(AlgActivity.this,R.layout.ext_ecc_encrypt,null);
                        alertDialog.setView(view_ext_ecc_decrypt);
                        alertDialog.show();

                        final EditText ext_ecc_decrypt_pri = view_ext_ecc_decrypt.findViewById(R.id.ext_ecc_encrypt_puk);
                        final EditText ext_ecc_decrypt_cipher = view_ext_ecc_decrypt.findViewById(R.id.ext_ecc_encrypt_plain);
                        final TextView ext_ecc_decrypt_plain = view_ext_ecc_decrypt.findViewById(R.id.ext_ecc_encrypt_cipher);

                        ext_ecc_decrypt_pri.setHint("请输入私钥");
                        ext_ecc_decrypt_cipher.setHint("请输入密文");
                        ext_ecc_decrypt_plain.setHint("解密的结果为");

                        ext_ecc_decrypt_pri.setText("7cbbeb97ffbf02de7f6fb710ef687922" +
                                "f5975cec265f41bcffcec1bffbffc7bc");
                        ext_ecc_decrypt_cipher.setVisibility(View.GONE);
                        final byte[] xy = new byte[]{
                                (byte)0x2f,(byte)0xea,(byte)0x3f,(byte)0x78,
                                (byte)0x74,(byte)0xb4,(byte)0xfb,(byte)0x39,
                                (byte)0x3f,(byte)0xa9,(byte)0x3c,(byte)0xb7,
                                (byte)0x47,(byte)0x8a,(byte)0xd1,(byte)0xe9,
                                (byte)0x02,(byte)0xbf,(byte)0xa7,(byte)0x85,
                                (byte)0x95,(byte)0x97,(byte)0x75,(byte)0xdd,
                                (byte)0x68,(byte)0x61,(byte)0x5f,(byte)0xb4,
                                (byte)0xf6,(byte)0x7b,(byte)0x22,(byte)0x67,

                                (byte)0x6e,(byte)0xc3,(byte)0x30,(byte)0x6b,
                                (byte)0x39,(byte)0x7d,(byte)0xec,(byte)0x38,
                                (byte)0xb3,(byte)0x4b,(byte)0x00,(byte)0x1a,
                                (byte)0xf2,(byte)0x77,(byte)0x75,(byte)0xb2,
                                (byte)0x62,(byte)0xd5,(byte)0xb0,(byte)0x90,
                                (byte)0x9f,(byte)0x79,(byte)0xc1,(byte)0xab,
                                (byte)0x19,(byte)0xc3,(byte)0x1e,(byte)0xe5,
                                (byte)0xb6,(byte)0x41,(byte)0x62,(byte)0x9d
                        };

                        final byte[] cipher = new byte[]{
                                (byte)0xed,(byte)0x49,(byte)0x2e,(byte)0xcd,
                                (byte)0x41,(byte)0x95,(byte)0xd1,(byte)0x0d,
                                (byte)0xf2,(byte)0x59,(byte)0xd6,(byte)0x41,
                                (byte)0x4a,(byte)0x57,(byte)0xbc,(byte)0x0f
                        };

                        final byte[] hash = new byte[]{
                                (byte)0x30,(byte)0x2a,(byte)0x9c,(byte)0x0f,
                                (byte)0x2d,(byte)0x07,(byte)0xa5,(byte)0x0f,
                                (byte)0x4a,(byte)0x54,(byte)0x94,(byte)0xe1,
                                (byte)0xd5,(byte)0xbd,(byte)0xf7,(byte)0xfc,
                                (byte)0xef,(byte)0x7b,(byte)0x54,(byte)0xa4,
                                (byte)0x55,(byte)0xd4,(byte)0x88,(byte)0x4c,
                                (byte)0x59,(byte)0x2d,(byte)0x47,(byte)0x8d,
                                (byte)0xde,(byte)0x95,(byte)0xee,(byte)0xa3
                        };

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try{
                                    ECCCIPHERBLOB ecccipherblob = new ECCCIPHERBLOB();
                                    ecccipherblob.setCipher(cipher);
                                    ecccipherblob.setCipherLen(cipher.length);
                                    ecccipherblob.setXCoordinate(Arrays.copyOf(xy,32));
                                    ecccipherblob.setYCoordinate(Arrays.copyOfRange(xy,32,64));
                                    ecccipherblob.setHASH(hash);

                                    byte[] dec = SKFDemoMACRO.skfWrapper.SKF_ExtECCDecrypt(SKFDemoMACRO.devhandle,HexByte.hexToByte(ext_ecc_decrypt_pri.getText().toString()),ecccipherblob);
                                    ext_ecc_decrypt_plain.setText(HexByte.byteToHex(dec));
                                    funcResultString("SKF_ExtECCDecrypt Success");
                                }catch (Exception e){
                                    funcResultString(e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }

                            }

                        });
                        break;
                    case 4:
                        //ext ecc sign
                        View view_ext_ecc_sign = View.inflate(AlgActivity.this,R.layout.ext_ecc_sign,null);
                        alertDialog.setView(view_ext_ecc_sign);
                        alertDialog.show();

                        final EditText ext_ecc_sign_pri = view_ext_ecc_sign.findViewById(R.id.ext_ecc_sign_pri);
                        final EditText ext_ecc_sign = view_ext_ecc_sign.findViewById(R.id.ext_ecc_sign);
                        final TextView ext_ecc_sign_hash = view_ext_ecc_sign.findViewById(R.id.ext_ecc_sign_hash);
                        final TextView ext_ecc_sign_result = view_ext_ecc_sign.findViewById(R.id.ext_ecc_sign_result);

                        ext_ecc_sign_pri.setText("7cbbeb97ffbf02de7f6fb710ef687922" +
                                "f5975cec265f41bcffcec1bffbffc7bc");

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                try{
                                    HANDLE handle = new HANDLE();
                                    SKFDemoMACRO.skfWrapper.SKF_DigestInit(SKFDemoMACRO.devhandle,SkfDefines.SGD_SM3,null,null,handle);
                                    byte[] hash = SKFDemoMACRO.skfWrapper.SKF_Digest(handle,HexByte.hexToByte(ext_ecc_sign.getText().toString()));
                                    byte[] sign = SKFDemoMACRO.skfWrapper.SKF_ExtECCSign(SKFDemoMACRO.devhandle,HexByte.hexToByte(ext_ecc_sign_pri.getText().toString()),hash);
                                    ext_ecc_sign_hash.setText(HexByte.byteToHex(hash));
                                    ext_ecc_sign_result.setText(HexByte.byteToHex(sign));
                                    funcResultString("SKF_ExtECCSign Success");
                                }catch (Exception e){
                                    funcResultString(e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()));
                                }

                            }

                        });
                        break;
                    case 5:
                        View view_enc_dec = View.inflate(AlgActivity.this,R.layout.alg,null);
                        alertDialog.setView(view_enc_dec);
                        alertDialog.show();


                        final RadioGroup alg_test = view_enc_dec.findViewById(R.id.alg_choose);
                        final int[] choose = new int[1];
                        final HANDLE handle = new HANDLE();

                        alg_test.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
                            @Override
                            public void onCheckedChanged(RadioGroup group, int checkedId) {
                                switch (checkedId){
                                    case R.id.alg_choose_enc:
                                        //加密
                                        choose[0] = 0;
                                        break;
                                    case R.id.alg_choose_dec:
                                        //解密
                                        choose[0] = 1;
                                        break;
                                    case R.id.alg_choose_dig:
                                        //摘要
                                        choose[0] = 2;
                                        break;
                                }
                            }
                        });

                        alertDialog.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View v) {
                                AlertDialog alertDialogCalc = new AlertDialog.Builder(AlgActivity.this).setPositiveButton("确定",null).create();
                                View view_calc = View.inflate(AlgActivity.this,R.layout.enc_dec,null);
                                alertDialogCalc.setView(view_calc);
                                alertDialogCalc.show();



                                final StringBuffer stringBuffer = new StringBuffer("");

                                final EditText key = view_calc.findViewById(R.id.enc_dec_key);
                                final Spinner alg = view_calc.findViewById(R.id.enc_dec_alg);
                                final EditText iv = view_calc.findViewById(R.id.enc_dec_init_iv);
                                final Button init = view_calc.findViewById(R.id.enc_dec_init);
                                final Button update = view_calc.findViewById(R.id.enc_dec_update);
                                final Button fil = view_calc.findViewById(R.id.enc_dec_final);
                                final Button once = view_calc.findViewById(R.id.enc_dec_once);
                                final EditText in = view_calc.findViewById(R.id.enc_dec_in);
                                final TextView out = view_calc.findViewById(R.id.enc_dec_result);

                                switch (choose[0]){
                                    case 0:
                                        break;
                                    case 1:
                                        break;
                                    case 2:
                                        key.setVisibility(View.GONE);
                                        alg.setVisibility(View.GONE);
                                        iv.setVisibility(View.GONE);
                                        break;

                                }
                                alertDialog.dismiss();

                                final long[] alg_choose = {SkfDefines.SGD_SMS4_ECB};

                                byte[] keyByte = {
                                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
                                };

                                key.setText(HexByte.byteToHex(keyByte));
                                iv.setText(HexByte.byteToHex(keyByte));

                                init.setOnClickListener(new View.OnClickListener() {
                                    @Override
                                    public void onClick(View v) {

                                        out.setText("");
                                        stringBuffer.delete(0,stringBuffer.length());

                                        try {

                                            if(choose[0] == 0){
                                                SKFDemoMACRO.skfWrapper.SKF_SetSymmKey(SKFDemoMACRO.devhandle,HexByte.hexToByte(key.getText().toString()),alg_choose[0],handle);
                                                SKFDemoMACRO.skfWrapper.SKF_EncryptInit(handle,HexByte.hexToByte(iv.getText().toString()),0,16 * 8);
                                            }else if(choose[0] == 1){
                                                SKFDemoMACRO.skfWrapper.SKF_SetSymmKey(SKFDemoMACRO.devhandle,HexByte.hexToByte(key.getText().toString()),alg_choose[0],handle);
                                                SKFDemoMACRO.skfWrapper.SKF_DecryptInit(handle,HexByte.hexToByte(iv.getText().toString()),0,16 * 8);
                                            }else if(choose[0] == 2){
                                                SKFDemoMACRO.skfWrapper.SKF_DigestInit(SKFDemoMACRO.devhandle,SkfDefines.SGD_SM3,null,null,handle);
                                            }

                                            ToastUtil.showToast(AlgActivity.this,"Init Success",Toast.LENGTH_SHORT);
                                        }catch (Exception e){
                                            ToastUtil.showToast(AlgActivity.this,e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()),Toast.LENGTH_SHORT);
                                        }
                                    }
                                });

                                update.setOnClickListener(new View.OnClickListener() {
                                    byte[] out_put = null;
                                    @Override
                                    public void onClick(View v) {
                                        try {
                                            if(choose[0] == 0){
                                                out_put = SKFDemoMACRO.skfWrapper.SKF_EncryptUpdate(handle,HexByte.hexToByte(in.getText().toString()));
                                                if(null != out_put){
                                                    stringBuffer.append(HexByte.byteToHex(out_put));
                                                }
                                            }else if(choose[0] == 1){
                                                out_put = SKFDemoMACRO.skfWrapper.SKF_DecryptUpdate(handle,HexByte.hexToByte(in.getText().toString()));
                                                if(null != out_put){
                                                    stringBuffer.append(HexByte.byteToHex(out_put));
                                                }
                                            }else if(choose[0] == 2){
                                                SKFDemoMACRO.skfWrapper.SKF_DigestUpdate(handle,HexByte.hexToByte(in.getText().toString()));
                                            }

                                        }catch (Exception e){
                                            ToastUtil.showToast(AlgActivity.this,e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()),Toast.LENGTH_SHORT);
                                        }

                                    }
                                });

                                fil.setOnClickListener(new View.OnClickListener() {
                                    byte[] out_put = null;
                                    @Override
                                    public void onClick(View v) {
                                        try {
                                            if(choose[0] == 0){
                                                out_put = SKFDemoMACRO.skfWrapper.SKF_EncryptFinal(handle);
                                            }else if(choose[0] == 1){
                                                out_put = SKFDemoMACRO.skfWrapper.SKF_DecryptFinal(handle);
                                            }else if(choose[0] == 2){
                                                out_put = SKFDemoMACRO.skfWrapper.SKF_DigestFinal(handle);
                                            }

                                            if(null != out_put){
                                                stringBuffer.append(HexByte.byteToHex(out_put));
                                            }

                                            out.setText(stringBuffer.toString());
                                        }catch (Exception e){
                                            ToastUtil.showToast(AlgActivity.this,e.getMessage() + ",Error = " + String.format("0x%08x",SKFException.getLastError()),Toast.LENGTH_SHORT);
                                        }
                                    }
                                });

                                once.setOnClickListener(new View.OnClickListener() {
                                    @Override
                                    public void onClick(View v) {
                                        byte [] out_put = null;
                                        try {
                                            if(choose[0] == 0){
                                                out_put = SKFDemoMACRO.skfWrapper.SKF_Encrypt(handle,HexByte.hexToByte(in.getText().toString()));
                                            }else if(choose[0] == 1){
                                                out_put = SKFDemoMACRO.skfWrapper.SKF_Decrypt(handle,HexByte.hexToByte(in.getText().toString()));
                                            }else if(choose[0] == 2){
                                                out_put = SKFDemoMACRO.skfWrapper.SKF_Digest(handle,HexByte.hexToByte(in.getText().toString()));
                                            }

                                            if(null != out_put){
                                                out.setText(HexByte.byteToHex(out_put));
                                            }
                                        }catch (Exception e){

                                        }
                                    }
                                });

                                alg.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                                    @Override
                                    public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                                        switch (position){
                                            case 0:
                                                alg_choose[0] = SkfDefines.SGD_SMS4_ECB;
                                                iv.setVisibility(View.GONE);
                                                break;
                                            case 1:
                                                alg_choose[0] = SkfDefines.SGD_SMS4_OFB;
                                                iv.setVisibility(View.VISIBLE);
                                                break;
                                            case 2:
                                                alg_choose[0] = SkfDefines.SGD_SMS4_CBC;
                                                iv.setVisibility(View.VISIBLE);
                                                break;
                                        }
                                    }

                                    @Override
                                    public void onNothingSelected(AdapterView<?> parent) {

                                    }
                                });


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
