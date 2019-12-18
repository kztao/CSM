package com.westone.skf;

/**
 * 设备信息
 */
public class DEVINFO {

    private VERSION Version;
    private String Manufacturer;                    //设备厂商信息
    private String Issuer;                          //应用发行者信息
    private String Label;
    private String SerialNumber;                    //标签
    private VERSION HWVersion;                      //序列号
    private VERSION FirmwareVersion;                //设备硬件版本
    private long AlgSymCap;                         //设备本身固件版本
    private long AlgAsymCap;                        //支持对称算法标志
    private long AlgHashCap;                        //支持非对称算法标志
    private long DevAuthAlgId;                      //支持杂凑算法标志
    private long TotalSpace;                        //设备认证采用的算法标识
    private long FreeSpace;                         //设备存储空间
    private long MaxECCBufferSize;                  //设备剩余空间
    private long MaxBufferSize;                     //能够处理的ECC加密数据大小
    private byte[] Reserved;                        //保留扩展

    /**
     * 构造函数
     */
    public DEVINFO(){
        Version = new VERSION();
        Version.setMajor((byte) 0);
        Version.setMinor((byte)0);

        Manufacturer = "";
        Issuer = "";
        Label = "";
        SerialNumber = "";

        HWVersion = new VERSION();
        HWVersion.setMajor((byte) 0);
        HWVersion.setMinor((byte)0);

        FirmwareVersion = new VERSION();
        FirmwareVersion.setMajor((byte) 0);
        FirmwareVersion.setMinor((byte)0);

        AlgSymCap = 0;
        AlgAsymCap = 0;
        AlgHashCap = 0;
        DevAuthAlgId = 0;
        TotalSpace = 0;
        FreeSpace = 0;
        MaxECCBufferSize = 0;
        MaxBufferSize = 0;
        Reserved = new byte[64];
    }


    /**
     * 获取版本号
     * @return 版本号
     */
    public VERSION getVersion() {
        return Version;
    }

    /**
     * 获取制造商
     * @return 制造商
     */
    public String getManufacturer() {
        return Manufacturer;
    }

    /**
     * 获取发行者
     * @return 发行者
     */
    public String getIssuer() {
        return Issuer;
    }

    /**
     * 获取标签
     * @return 标签
     */
    public String getLabel() {
        return Label;
    }

    /**
     * 获取序列号
     * @return 序列号
     */
    public String getSerialNumber() {
        return SerialNumber;
    }

    /**
     * 获取硬件版本号
     * @return 硬件版本号
     */
    public VERSION getHWVersion() {
        return HWVersion;
    }

    /**
     * 获取固件版本号
     * @return 固件版本号
     */
    public VERSION getFirmwareVersion() {
        return FirmwareVersion;
    }

    /**
     * 获取分组密码算法标识
     * @return 分组密码算法标识
     */
    public long getAlgSymCap() {
        return AlgSymCap;
    }

    /**
     * 获取非对称密码算法标识
     * @return 非对称密码算法标识
     */
    public long getAlgAsymCap() {
        return AlgAsymCap;
    }

    /**
     * 获取密码杂凑算法标识
     * @return 密码杂凑算法标识
     */
    public long getAlgHashCap() {
        return AlgHashCap;
    }

    /**
     * 获取设备认证使用的分组密码算法标识
     * @return 设备认证使用的分组密码算法标识
     */
    public long getDevAuthAlgId() {
        return DevAuthAlgId;
    }

    /**
     * 获取设备总空间
     * @return 设备总空间
     */
    public long getTotalSpace() {
        return TotalSpace;
    }

    /**
     * 获取设备剩余空间
     * @return 设备剩余空间
     */
    public long getFreeSpace() {
        return FreeSpace;
    }

    /**
     * 获取能够处理的ECC加密数据大小
     * @return 能够处理的ECC加密数据大小
     */
    public long getMaxECCBufferSize() {
        return MaxECCBufferSize;
    }

    /**
     * 获取缓冲区最大长度
     * @return 缓冲期最大长度
     */
    public long getMaxBufferSize() {
        return MaxBufferSize;
    }

    /**
     * 获取保留字段
     * @return 保留字段
     */
    public byte[] getReserved() {
        return Reserved;
    }

    /**
     * 设备版本号
     * @param version
     */
    void setVersion(VERSION version) {
        if(null == version){
            return;
        }

        Version.setMajor(version.getMajor());
        Version.setMinor(version.getMinor());
    }

    /**
     * 设置分组密码算法标识
     * @param algSymCap 分组密码算法标识
     */
    void setAlgSymCap(long algSymCap) {
        AlgSymCap = algSymCap;
    }

    /**
     * 设置设备认证使用的分组密码算法标识
     * @param devAuthAlgId 设备认证使用的分组密码算法标识
     */
    void setDevAuthAlgId(long devAuthAlgId) {
        DevAuthAlgId = devAuthAlgId;
    }

    /**
     * 设置固件版本号
     * @param firmwareVersion 固件版本号
     */
    void setFirmwareVersion(VERSION firmwareVersion) {
        if(null == firmwareVersion){
            return;
        }

        FirmwareVersion.setMajor(firmwareVersion.getMajor());
        FirmwareVersion.setMinor(firmwareVersion.getMinor());
    }

    /**
     * 设置设备剩余空间
     * @param freeSpace 设备剩余空间
     */
    void setFreeSpace(long freeSpace) {
        FreeSpace = freeSpace;
    }

    /**
     * 设置硬件版本号
     * @param hwVesion 硬件版本号
     */
    void setHWVersion(VERSION hwVesion) {
        if(null == hwVesion){
            return;
        }

        HWVersion.setMajor(hwVesion.getMajor());
        HWVersion.setMinor(hwVesion.getMinor());
    }

    /**
     * 设置发行者
     * @param issuer 发行者
     */
    void setIssuer(String issuer) {
        Issuer = issuer;
    }

    /**
     * 设置标签
     * @param label 标签
     */
    void setLabel(String label) {
        Label = label;
    }

    /**
     * 设置制造商
     * @param manufacturer 制造商
     */
    void setManufacturer(String manufacturer) {
        Manufacturer = manufacturer;
    }

    /**
     * 设置缓冲区最大长度
     * @param maxBufferSize 缓冲区最大长度
     */
    void setMaxBufferSize(long maxBufferSize) {
        MaxBufferSize = maxBufferSize;
    }

    /**
     * 设置能够处理的ECC加密数据大小
     * @param maxECCBufferSize 能够处理的ECC加密数据大小
     */
    void setMaxECCBufferSize(long maxECCBufferSize) {
        MaxECCBufferSize = maxECCBufferSize;
    }

    /**
     * 设置保留字段
     * @param reserved 保留字段
     */
    void setReserved(byte[] reserved) {
        if(null == reserved || reserved.length > 64){
            return;
        }

        System.arraycopy(reserved,0,Reserved,0,reserved.length);
    }

    /**
     * 设置序列号
     * @param serialNumber 序列号
     */
    void setSerialNumber(String serialNumber) {
        SerialNumber = serialNumber;
    }

    /**
     * 设置设备总空间
     * @param totalSpace 设备总空间
     */
    void setTotalSpace(long totalSpace) {
        TotalSpace = totalSpace;
    }

    /**
     * 设置非对称密码算法标识
     * @param algAsymCap 非对称密码算法标识
     */
    void setAlgAsymCap(long algAsymCap) {
        AlgAsymCap = algAsymCap;
    }

    /**
     * 设置密码杂凑算法标识
     * @param algHashCap 密码杂凑算法标识
     */
    void setAlgHashCap(long algHashCap) {
        AlgHashCap = algHashCap;
    }
}
