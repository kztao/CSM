package com.westone.skf;

class BLOCKCIPHERPARAM {

    private byte[] IV;
    private long IVLen;
    private long PaddingType;
    private long FeedBitLen;

    /**
     * 构造函数
     */
    BLOCKCIPHERPARAM(){
        IV = new byte[SkfDefines.MAX_IV_LEN];
        IVLen = 0;
        PaddingType  = 0;
        FeedBitLen = 0;
    }

    /**
     * 获取初始向量
     * @return 初始向量
     */
    byte[] getIV() {
        return IV;
    }

    /**
     * 获取初始向量长度
     * @return 初始向量长度
     */
    long getIVLen() {
        return IVLen;
    }

    /**
     * 获取反馈值的位长
     * @return 反馈值的位长
     */
    long getFeedBitLen() {
        return FeedBitLen;
    }

    /**
     * 获取填充方式
     * @return
     */
    long getPaddingType() {
        return PaddingType;
    }

    /**
     * 设置反馈值的位长
     * @param feedBitLen 反馈值的位长
     */
    void setFeedBitLen(long feedBitLen) {
        FeedBitLen = feedBitLen;
    }

    /**
     * 设置初始向量
     * @param iv 初始向量
     */
    void setIV(byte[] iv) {
        if(iv == null || iv.length > SkfDefines.MAX_IV_LEN){
            return;
        }

        System.arraycopy(iv,0,this.IV,0,iv.length);
    }

    /**
     * 设置初始向量长度
     * @param IVLen 初始向量长度
     */
    void setIVLen(long IVLen) {
        this.IVLen = IVLen;
    }

    /**
     * 设置填充方式
     * @param paddingType 填充方式
     */
    void setPaddingType(long paddingType) {
        PaddingType = paddingType;
    }
}
