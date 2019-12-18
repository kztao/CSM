package com.westone.skf;

/**
 * 设备状态
 */
public class DevState {
    private long devState;

    /**
     * 构造函数
     */
    public DevState(){
        devState = 0;
    }

    /**
     * 获取设备状态
     * @return 设备状态
     */
    public long getDevState() {
        return devState;
    }

    /**
     * 设置设备状态
     * @param devState 设备状态
     */
    void setDevState(long devState) {
        this.devState = devState;
    }

}
