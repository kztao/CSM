package com.westone.skfwrapper;

import android.telephony.TelephonyManager;

public class Xindun {
    static {
        System.loadLibrary("skfWrapper");
    }
    public native void skfInit(TelephonyManager telephonyManager);
}
