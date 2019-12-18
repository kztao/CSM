package com.westone.skf;

/**
 * PIN码信息
 */
public class PinInfo {
    long maxRetryCount;
    long remainRetryCount;
    boolean defaultPin;

    /**
     * 构造函数
     */
    public PinInfo(){
        maxRetryCount = 0;
        remainRetryCount = 0;
        defaultPin = false;
    }

    /**
     * 获取最大重试次数
     * @return 最大重试次数
     */
    public long getMaxRetryCount() {
        return maxRetryCount;
    }

    /**
     * 获取剩余重试次数
     * @return 剩余重试次数
     */
    public long getRemainRetryCount() {
        return remainRetryCount;
    }

    /**
     * 是否为默认PIN码
     * @return 结果
     */
    public boolean isDefaultPin() {
        return defaultPin;
    }

    /** 设置最大重试次数
     * @param maxRetryCount 最大重试次数
     */
    void setMaxRetryCount(long maxRetryCount) {
        this.maxRetryCount = maxRetryCount;
    }

    /** 设置剩余重试次数
     * @param remainRetryCount 剩余重试次数
     */
    void setRemainRetryCount(long remainRetryCount) {
        this.remainRetryCount = remainRetryCount;
    }


    /**
     * 设置是否为默认PIN码
     * @param defaultPin 是否为默认PIN码
     */
    void setDefaultPin(boolean defaultPin) {
        this.defaultPin = defaultPin;
    }
}
