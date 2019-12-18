package com.westone.skf;

class ECCPUBLICKEYBLOB {
    private long BitLen = 0;
    private byte[] XCoordinate = new byte[SkfDefines.ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    private byte[] YCoordinate = new byte[SkfDefines.ECC_MAX_YCOORDINATE_BITS_LEN / 8];

    /**
     * 获取位长
     * @return 位长
     */
    long getBitLen() {
        return BitLen;
    }

    /**
     *  获取X坐标
     * @return X坐标
     */
    byte[] getXCoordinate() {
        return XCoordinate;
    }

    /**
     * 获取Y坐标
     * @return Y坐标
     */
    byte[] getYCoordinate() {
        return YCoordinate;
    }

    /**
     * 设置位长
     * @param bitLen 位长
     */
    void setBitLen(long bitLen) {
        BitLen = bitLen;
    }

    /**
     * 设置X坐标
     * @param xCoordinate X坐标
     */
    void setXCoordinate(byte[] xCoordinate) {
        if(null == xCoordinate || xCoordinate.length > SkfDefines.ECC_MAX_XCOORDINATE_BITS_LEN / 8){
            return;
        }

        System.arraycopy(xCoordinate,0,XCoordinate,0,xCoordinate.length);
    }

    /**
     * 设置Y坐标
     * @param yCoordinate Y坐标
     */
    void setYCoordinate(byte[] yCoordinate) {
        if(null == yCoordinate || yCoordinate.length > SkfDefines.ECC_MAX_YCOORDINATE_BITS_LEN / 8){
            return;
        }

        System.arraycopy(yCoordinate,0,YCoordinate,0,yCoordinate.length);
    }
}
