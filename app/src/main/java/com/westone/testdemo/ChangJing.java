package com.westone.testdemo;

import android.util.Log;

import com.westone.skf.DEVHANDLE;
import com.westone.skf.DEVINFO;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

abstract class SKFCJFunc{
    String name;
    SKFCJFunc(String name){
        this.name = name;
    }

    abstract String func();
}

final class ChangJing {
    static private List<String> list = new ArrayList<>();
    static private String dot = "\n---------------------\n";
    //如果有新的测试项请在此处添加测试描述
static String[] cjms = new String[]{
        "通用测试",
            "设备管理和应用创建-C",
            "应用访问控制-C",
            "容器管理和双证书导入-C",
            "密码运算-C"

    };

    private ChangJing() { throw new IllegalStateException("Utility class"); }

static List<String> getList(){
    list.clear();
    for (int i = 0; i < cjms.length;i++){
        list.add("场景" + (i + 1));
    }

    return list;
}

static SKFCJFunc[] skfcjFuncs = new SKFCJFunc[]{

        new SKFCJFunc(cjms[0]) {
        @Override
        public String func() {
            StringBuilder stringBuilder = new StringBuilder();
            List<String> list_1 = new ArrayList<>();
            List<DEVHANDLE> devhandles = new ArrayList<>();

            try {
                SKFDemoMACRO.skfWrapper.SKF_EnumDev(list_1);
                stringBuilder.append("SKF_EnumDev Success\ndev name is ").append(Arrays.toString(list_1.toArray())).append(dot);
                if(list_1.size() > 0 ){
                    Iterator<String> iterator = list_1.iterator();
                    while (iterator.hasNext()){
                        String devName = iterator.next();
                        DEVHANDLE devhandle = new DEVHANDLE();
                        SKFDemoMACRO.skfWrapper.SKF_ConnectDev(devName,devhandle);
                        devhandles.add(devhandle);
                        stringBuilder.append("SKF_ConnectDev Success\ndevhandle is ").append(devhandle).append(dot);
                    }

                    if(devhandles.size() > 0){
                        Iterator<DEVHANDLE> devhandleIterator = devhandles.iterator();
                        while (devhandleIterator.hasNext()){
                            DEVHANDLE devhandle = devhandleIterator.next();
                            DEVINFO devinfo = new DEVINFO();
                            SKFDemoMACRO.skfWrapper.SKF_GetDevInfo(devhandle,devinfo);
                            stringBuilder.append("SKF_GetDevInfo Success\ndevinfo is ").append(devinfo).append(dot);

                            SKFDemoMACRO.skfWrapper.SKF_DisConnectDev(devhandle);
                            stringBuilder.append("SKF_DisConnectDev Success\n").append(dot);
                        }
                    }

                }


            }catch (Exception e){
                stringBuilder.append(e.getMessage());
            }

            return stringBuilder.toString();
        }
        },

        new SKFCJFunc(cjms[1]) {
        @Override
        public String func() {
            StringBuilder stringBuilder = new StringBuilder();
            List<String> list_2 = new ArrayList<>();
            String res = "";

            res = skfTestNative.DevandAppTest();
            Log.i("skftestC","111");
            if(!res.isEmpty()){
                stringBuilder.append(res);
            }
            else{
                stringBuilder.append("Success!");
            }

            return stringBuilder.toString();
        }
        },

        new SKFCJFunc(cjms[2]) {
            @Override
            public String func() {
                StringBuilder stringBuilder = new StringBuilder();
                List<String> list_3 = new ArrayList<>();
                try {
                    SKFDemoMACRO.skfWrapper.SKF_EnumDev(list_3);
                }catch (Exception e){
                    stringBuilder.append(e.getMessage());
                }

                return stringBuilder.toString();
            }
        }
};

}
