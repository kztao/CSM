package com.westone.skf;

/**
 * 容器句柄
 */
public class HCONTAINER {
    private long pointer = 0;

    /** 设置pointer
     * @param pointer pointer
     */
    void setPointer(long pointer) {
        this.pointer = pointer;
    }

    /**
     * 获取pointer
     * @return pointer
     */
    long getPointer() {
        return pointer;
    }

    @Override
    public boolean equals(Object obj) {
        if(null == obj){
            return false;
        }

        HCONTAINER devhandle = (HCONTAINER) obj;
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
