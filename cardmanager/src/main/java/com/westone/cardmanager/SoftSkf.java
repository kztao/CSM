package com.westone.cardmanager;

class SoftSkf {
    static {
        System.loadLibrary("SoftSkf");
    }

    public static native void setSkfSoftPath(String path);
}
