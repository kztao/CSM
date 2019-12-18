package com.westone.csmmanager;

public class PerReturnInfo {
    public String info;
    public int count;
    public int length;
    public long[] times;
    public PerReturnInfo(int count){
        times = new long[count];
    }

}
