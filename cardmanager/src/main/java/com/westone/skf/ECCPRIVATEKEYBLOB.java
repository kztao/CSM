package com.westone.skf;

class ECCPRIVATEKEYBLOB {

    private long BitLen = 0;
    private byte[] PrivateKey = new byte[SkfDefines.ECC_MAX_MODULUS_BITS_LEN / 8];

    /**
     * 获取位长
     * @return 位长
     */
    long getBitLen() {
        return BitLen;
    }

    /**
     * 获取私钥
     * @return 私钥
     */
    byte[] getPrivateKey() {
        return PrivateKey;
    }

    /**
     * 设置位长
     * @param bitLen 位长
     */
    void setBitLen(long bitLen) {
        BitLen = bitLen;
    }

    /**
     * 设置私钥
     * @param privateKey 私钥
     */
    void setPrivateKey(byte[] privateKey) {
        if(null == privateKey || privateKey.length > SkfDefines.ECC_MAX_MODULUS_BITS_LEN / 8){
            return;
        }

        System.arraycopy(privateKey,0,PrivateKey,0,privateKey.length);
    }
}
