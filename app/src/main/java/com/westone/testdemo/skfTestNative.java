package com.westone.testdemo;

public class skfTestNative {
    private static final String SKF_CLIENT_LIB = "skfTest";
    static {
        System.loadLibrary(SKF_CLIENT_LIB);
    }
    private skfTestNative() { throw new IllegalStateException("Utility class");}

    public static native String DevandAppTest();


}
