package com.westone.skf;

/**
 * 设备事件接口
 */
public interface DevEvent {
    /**
     * 通知设备事件
     * @param devName 设备名
     * @param event 事件
     */
    void notifyDevEvent(String devName, int event);
}
