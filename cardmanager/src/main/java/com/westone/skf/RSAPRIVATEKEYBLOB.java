package com.westone.skf;

/*
 *RSA私钥交换数据块
 */
class RSAPRIVATEKEYBLOB {
    private long AlgID = 0;                             //算法标识号
    private long BitLen = 0;                            //模数的实际位长度，必须是8的倍数
    private byte[] Modulus = new byte[SkfDefines.MAX_RSA_MODULUS_LEN];                         //模数n=p*q，实际长度为BitLen/8字节
    private byte[] PublicExponent = new byte[SkfDefines.MAX_RSA_EXPONENT_LEN];                  //公开密钥e， 一般为00010001
    private byte[] PrivateExponent = new byte[SkfDefines.MAX_RSA_MODULUS_LEN];                 //私有密钥d，实际长度为BitLen/8字节
    private byte[] Prime1 = new byte[SkfDefines.MAX_RSA_MODULUS_LEN/2];                          //素数p，实际长度为BitLen/16字节
    private byte[] Prime2 = new byte[SkfDefines.MAX_RSA_MODULUS_LEN/2];                          //素数q，实际长度为BitLen/16字节
    private byte[] Prime1Exponent = new byte[SkfDefines.MAX_RSA_MODULUS_LEN/2];                  //d mod (p-1)的值, 实际长度为BitLen/16字节
    private byte[] Prime2Exponent = new byte[SkfDefines.MAX_RSA_MODULUS_LEN/2];                  //d mod (q-1)的值，实际长度为BitLen/16字节
    private byte[] Coefficient = new byte[SkfDefines.MAX_RSA_MODULUS_LEN/2];                     //q模p的乘法逆元，实际长度为BitLen/16字节

    /**
     * 获取算法ID
     * @return 算法ID
     */
    long getAlgID() {
        return AlgID;
    }

    /**
     * 获取位长
     * @return 位长
     */
    long getBitLen() {
        return BitLen;
    }

    /**
     * 获取模数 n = p * q
     * @return 模数 n = p * q
     */
    byte[] getModulus() {
        return Modulus;
    }

    /**
     * 获取公开密钥 e
     * @return 公开密钥 e
     */
    byte[] getPublicExponent() {
        return PublicExponent;
    }

    /**
     * 获取私有密钥 d
     * @return 私有密钥 d
     */
    byte[] getPrivateExponent() {
        return PrivateExponent;
    }

    /**
     * 获取素数p
     * @return 素数p
     */
    byte[] getPrime1() {
        return Prime1;
    }

    /**
     * 获取素数q
     * @return 素数q
     */
    byte[] getPrime2() {
        return Prime2;
    }

    /**
     * 获取d mod (p-1)的值
     * @return d mod (p-1)的值
     */
    byte[] getPrime1Exponent() {
        return Prime1Exponent;
    }

    /**
     * 获取d mod (q -1)的值
     * @return d mod (q -1)的值
     */
    byte[] getPrime2Exponent() {
        return Prime2Exponent;
    }

    /**
     * 获取q 模 p 的乘法逆元
     * @return q 模 p 的乘法逆元
     */
    byte[] getCoefficient() {
        return Coefficient;
    }

    /**
     * 设置算法ID
     * @param algID 算法ID
     */
    void setAlgID(long algID) {
        AlgID = algID;
    }

    /**
     * 设置位长
     * @param bitLen 位长
     */
    void setBitLen(long bitLen) {
        BitLen = bitLen;
    }

    /**
     * 设置模数 n = p * q
     * @param modulus 模数 n = p * q
     */
    void setModulus(byte[] modulus) {
        if(null == modulus || modulus.length > SkfDefines.MAX_RSA_MODULUS_LEN){
            return;
        }

        System.arraycopy(modulus,0,Modulus,0,modulus.length);
    }

    /** 设置公开密钥e
     * @param publicExponent 公开密钥 e
     */
    void setPublicExponent(byte[] publicExponent) {
        if(null == publicExponent || publicExponent.length > SkfDefines.MAX_RSA_EXPONENT_LEN){
            return;
        }

        System.arraycopy(publicExponent,0,PublicExponent,0,publicExponent.length);
    }

    /**
     * 设置私有密钥d
     * @param privateExponent 私有密钥d
     */
    void setPrivateExponent(byte[] privateExponent) {
        if(null == privateExponent || privateExponent.length > SkfDefines.MAX_RSA_MODULUS_LEN){
            return;
        }
        System.arraycopy(privateExponent,0,PrivateExponent,0,privateExponent.length);
    }

    /**
     * 设置素数p
     * @param prime1 素数p
     */
    void setPrime1(byte[] prime1) {
        if(null == prime1 || prime1.length > SkfDefines.MAX_RSA_MODULUS_LEN/2){
            return;
        }

        System.arraycopy(prime1,0,Prime1,0,prime1.length);
    }

    /**
     * 设置素数q
     * @param prime2 素数q
     */
    void setPrime2(byte[] prime2) {
        if(null == prime2 || prime2.length > SkfDefines.MAX_RSA_MODULUS_LEN/2){
            return;
        }
        System.arraycopy(prime2,0,Prime2,0,prime2.length);
    }

    /**
     * 设置d mod (p-1)的值
     * @param prime1Exponent d mod (p-1)的值
     */
    void setPrime1Exponent(byte[] prime1Exponent) {
        if(null == prime1Exponent || prime1Exponent.length > SkfDefines.MAX_RSA_MODULUS_LEN/2){
            return;
        }
        System.arraycopy(prime1Exponent,0,Prime1Exponent,0,prime1Exponent.length);
    }

    /**
     * 设置d mod (q -1)的值
     * @param prime2Exponent d mod (q -1)的值
     */
    void setPrime2Exponent(byte[] prime2Exponent) {
        if(null == prime2Exponent || prime2Exponent.length > SkfDefines.MAX_RSA_MODULUS_LEN/2){
            return;
        }
        System.arraycopy(prime2Exponent,0,Prime2Exponent,0,prime2Exponent.length);
    }

    /** 设置q 模 p 的乘法逆元
     * @param coefficient q 模 p 的乘法逆元
     */
    void setCoefficient(byte[] coefficient) {
        if(null == coefficient || coefficient.length > SkfDefines.MAX_RSA_MODULUS_LEN/2){
            return;
        }
        System.arraycopy(coefficient,0,Coefficient,0,coefficient.length);
    }
}
