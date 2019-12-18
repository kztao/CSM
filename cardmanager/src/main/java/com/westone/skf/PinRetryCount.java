package com.westone.skf;

/**
 * PIN码重试次数
 */
public class PinRetryCount {
    private long retryCount;

    /**
     * 构造函数
     */
    public PinRetryCount(){
        retryCount = 0;
    }

    /**
     * 获取重试次数
     * @return 重试次数
     */
    public long getRetryCount() {
        return retryCount;
    }


    /**
     * 设置重试次数
     * @param retryCount 重试次数
     */
    void setRetryCount(long retryCount) {
        this.retryCount = retryCount;
    }
}
