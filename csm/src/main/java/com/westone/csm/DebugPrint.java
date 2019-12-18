package com.westone.csm;

import android.util.Log;

final class DebugPrint {
    private DebugPrint() { throw new IllegalStateException("Utility class"); }
    static public void print(String msg){
        Log.i("wjr", msg);
    }
}
