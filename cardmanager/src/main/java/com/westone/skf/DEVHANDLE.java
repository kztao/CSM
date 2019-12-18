package com.westone.skf;

/**
 * 设备句柄
 */
public class DEVHANDLE {
    private long pointer;

    /**
     * 构造函数
     */
    public DEVHANDLE(){
        this.pointer = 0;
    }

    /**
     * 获取pointer
     * @return pointer
     */
    long getPointer(){
        return pointer;
    }

    /**
     * 设置pointer
     * @param p pointer
     */
    void setPointer(long p){
        pointer = p;
    }

    @Override
    public boolean equals(Object obj) {
        if(null == obj){
            return false;
        }

        DEVHANDLE devhandle = (DEVHANDLE)obj;
        return (devhandle.pointer == pointer);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        Long l = pointer;
        hash = 31*hash+l.hashCode();
        return hash;
    }

    @Override
    public String toString() {
        return ""+pointer;
    }
}
