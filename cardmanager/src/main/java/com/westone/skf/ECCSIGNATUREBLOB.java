package com.westone.skf;

class ECCSIGNATUREBLOB {
    private byte[] r = new byte[SkfDefines.ECC_MAX_XCOORDINATE_BITS_LEN / 8];
    private byte[] s = new byte[SkfDefines.ECC_MAX_YCOORDINATE_BITS_LEN / 8];

    /**
     * 获取签名结果R部分
     * @return 签名结果R部分
     */
    byte[] getR() {
        return r;
    }

    /**
     * 获取签名结果S部分
     * @return 签名结果S部分
     */
    byte[] getS() {
        return s;
    }

    /**
     * 设置签名结果R部分
     * @param R 签名结果R部分
     */
    void setR(byte[] R) {
        if(null == R || R.length > SkfDefines.ECC_MAX_XCOORDINATE_BITS_LEN / 8){
            return;
        }

        System.arraycopy(R,0,r,0,R.length);

    }

    /**
     * 设置签名结果S部分
     * @param S 签名结果S部分
     */
    void setS(byte[] S) {
        if(null == S || S.length > SkfDefines.ECC_MAX_YCOORDINATE_BITS_LEN / 8){
            return;
        }

        System.arraycopy(S,0,s,0,S.length);
    }
}
