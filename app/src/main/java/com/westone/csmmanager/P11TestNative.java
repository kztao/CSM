package com.westone.csmmanager;

public class P11TestNative {
    private static final String P11_CLIENT_LIB = "Test";
    static {
        System.loadLibrary(P11_CLIENT_LIB);
    }
    private P11TestNative() { throw new IllegalStateException("Utility class");}

    public static long sm4_modle = 0;

    public static native ReturnInfo BaseFunctionTest(String userPin,String SoPin,TFStatus tfStatus);

    public static native ReturnInfo ObjFunctionTest();

    public static native ReturnInfo KeyFunctionTest();

    public static native ReturnInfo EncFunctionTest();

    public static native ReturnInfo DigFunctionTest();

    public static native ReturnInfo SignFunctionTest();

    public static native ReturnInfo RndFunctionTest();

    public static native ReturnInfo ExtFunctionTest();
    public static native ReturnInfo SCSetUp();
    public static native ReturnInfo CallTest();
    public static native void testThreadRun(String userPin);

    public static native PerReturnInfo SM2Test(int count,int len);
    public static native PerReturnInfo SM4Test(int count,int len);
    public static native PerReturnInfo ZucTest(int count,int len);

}
