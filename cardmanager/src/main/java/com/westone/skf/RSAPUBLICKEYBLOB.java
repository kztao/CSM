package com.westone.skf;

class RSAPUBLICKEYBLOB {
    private long AlgID = 0;
    private long BitLen = 0;
    private byte[] Modulus = new byte[SkfDefines.MAX_RSA_MODULUS_LEN];
    private byte[] PublicExponent = new byte[SkfDefines.MAX_RSA_EXPONENT_LEN];

    /**
     * 获取位长
     * @return 位长
     */
    long getBitLen() {
        return BitLen;
    }

    /**
     * 获取算法ID
     * @return 算法ID
     */
    long getAlgID() {
        return AlgID;
    }

    /**
     * 获取公开密钥 e
     * @return 公开密钥 e
     */
    byte[] getPublicExponent() {
        return PublicExponent;
    }

    /**
     * 获取模数 n = p * q
     * @return 模数 n = p * q
     */
    byte[] getModulus() {
        return Modulus;
    }

    /**
     * 设置位长
     * @param bitLen 位长
     */
    void setBitLen(long bitLen) {
        BitLen = bitLen;
    }

    /**
     * 设置算法ID
     * @param algID 算法ID
     */
    void setAlgID(long algID) {
        AlgID = algID;
    }

    /**
     * 设置模数 n = p * q
     * @param modulus 模数 n = p * q
     */
    void setModulus(byte[] modulus) {
        if(null == modulus || modulus.length > SkfDefines.MAX_RSA_MODULUS_LEN){
            return;
        }

        System.arraycopy(modulus,0,this.Modulus,0,modulus.length);
    }

    /**
     * 设置公开密钥 e
     * @param publicExponent 公开密钥 e
     */
    void setPublicExponent(byte[] publicExponent) {
        if(null == publicExponent || publicExponent.length > SkfDefines.MAX_RSA_EXPONENT_LEN){
            return;
        }

        System.arraycopy(publicExponent,0,this.PublicExponent,0,publicExponent.length);
    }
}
