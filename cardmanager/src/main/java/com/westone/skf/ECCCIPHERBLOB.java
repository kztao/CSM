package com.westone.skf;

public class ECCCIPHERBLOB {

    private byte[] XCoordinate;
    private byte[] YCoordinate;
    private byte[] HASH;
    private long CipherLen;
    private byte[] Cipher;

    /**
     * 构造函数
     */
    public ECCCIPHERBLOB(){
        XCoordinate = new byte[SkfDefines.ECC_MAX_XCOORDINATE_BITS_LEN / 8];
        YCoordinate = new byte[SkfDefines.ECC_MAX_YCOORDINATE_BITS_LEN / 8];
        HASH = new byte[32];
        Cipher = null;
        CipherLen = 0;
    }

    /**
     * 获取X坐标
     * @return X坐标
     */
    public byte[] getXCoordinate() {
        return XCoordinate;
    }

    /**
     * 获取Y坐标
     * @return Y坐标
     */
    public byte[] getYCoordinate() {
        return YCoordinate;
    }

    /**
     * 获取哈希值
     * @return 哈希值
     */
    public byte[] getHASH() {
        return HASH;
    }

    /**
     * 获取密文数据长度
     * @return 密文数据长度
     */
    public long getCipherLen() {
        return CipherLen;
    }

    /**
     * 获取密文数据
     * @return 密文数据
     */
    public byte[] getCipher() {
        return Cipher;
    }

    /**
     * 设置X坐标
     * @param xCoordinate X坐标
     */
    public void setXCoordinate(byte[] xCoordinate) {
        if(null == xCoordinate || xCoordinate.length > SkfDefines.ECC_MAX_XCOORDINATE_BITS_LEN / 8){
            return;
        }

        System.arraycopy(xCoordinate,0,XCoordinate,64 - xCoordinate.length,xCoordinate.length);
    }

    /**
     * 设置Y坐标
     * @param yCoordinate Y坐标
     */
    public void setYCoordinate(byte[] yCoordinate) {
        if(null == yCoordinate || yCoordinate.length > SkfDefines.ECC_MAX_YCOORDINATE_BITS_LEN / 8){
            return;
        }

        System.arraycopy(yCoordinate,0,YCoordinate,64 - yCoordinate.length,yCoordinate.length);
    }

    /**
     * 设置哈希值
     * @param hASH 哈希值
     */
    public void setHASH(byte[] hASH) {
        if(null == hASH || hASH.length > 32){
            return;
        }

        System.arraycopy(hASH,0,HASH,0,hASH.length);
    }

    /**
     * 设置密文数据长度
     * @param cipherLen 密文数据长度
     */
    public void setCipherLen(long cipherLen) {
        CipherLen = cipherLen;
    }

    /**
     * 设置密文数据
     * @param cipher 密文数据
     */
    public void setCipher(byte[] cipher) {
        if(null == cipher){
            return;
        }

        Cipher = new byte[cipher.length];
        System.arraycopy(cipher,0,Cipher,0,cipher.length);
        CipherLen = cipher.length;
    }
}
