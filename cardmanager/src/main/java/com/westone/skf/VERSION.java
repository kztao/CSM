package com.westone.skf;

/**
 * 版本号
 */
public class VERSION {
    private byte major = 0;
    private byte minor = 0;

    /**
     * 构造函数
     */
    public VERSION(){
        major = 0;
        minor = 0;
    }

    /**
     * 设置主版本号
     * @param major 主版本号
     */
    void setMajor(byte major) {
        this.major = major;
    }


    /**
     * 设置次版本号
     * @param minor 次版本号
     */
    void setMinor(byte minor) {
        this.minor = minor;
    }

    /**
     * 获取主版本号
     * @return 主版本号
     */
    public byte getMajor() {
        return major;
    }

    /**
     * 获取次版本号
     * @return 次版本号
     */
    public byte getMinor() {
        return minor;
    }
}
