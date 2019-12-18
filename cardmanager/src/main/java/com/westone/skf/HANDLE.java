package com.westone.skf;

/**
 * 句柄
 */
public class HANDLE {
    private long pointer = 0;

    /**
     * 获取pointer
     * @return pointer
     */
    long getPointer() {
        return pointer;
    }

    /**
     * 设置pointer
     * @param pointer pointer
     */
    void setPointer(long pointer) {
        this.pointer = pointer;
    }

    @Override
    public boolean equals(Object obj) {
        if(null == obj){
            return false;
        }

        HANDLE devhandle = (HANDLE)obj;
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
