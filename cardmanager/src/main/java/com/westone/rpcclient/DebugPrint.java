package com.westone.rpcclient;

import android.util.Log;

final class DebugPrint {
    private DebugPrint() { throw new IllegalStateException("Utility class"); }
    public static void print(String msg){
        Log.i("wjr", msg);
    }
}
