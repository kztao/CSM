package com.westone.csm;

import android.util.Log;

class CheckSign {
    private CheckSign() {throw new IllegalStateException("Utility class");}

    public static void CheckPackage(String packageName,byte[] fingerPrint)throws Exception{
        LogUtils.i("csm_"+CheckSign.class.toString(),"len = " + fingerPrint.length);
        StringBuilder stringBuilder = new StringBuilder();
        for(Byte a:fingerPrint){
            stringBuilder.append(String.format("%02X",a.intValue() & 0xFF));
        }
        LogUtils.i("csm_"+CheckSign.class.toString(),"len = "+stringBuilder.length()+","+stringBuilder.toString());
    }
}
