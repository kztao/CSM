package com.westone.skf;

class ENVELOPEDKEYBLOB {
    private long Version = 0;                               // 当前版本为 1
    private long ulSymmAlgID = 0;                           // 对称算法标识，限定ECB模式
    private long ulBits = 0;                                // 加密密钥对的密钥位长度
    private byte[] cbEncryptedPriKey = new byte[64];                   // 加密密钥对私钥的密文
    private ECCPUBLICKEYBLOB PubKey = new ECCPUBLICKEYBLOB();                    // 加密密钥对的公钥
    private ECCCIPHERBLOB ECCCipherBlob = new ECCCIPHERBLOB();                // 用保护公钥加密的对称密钥密文

    /**
     * 获取版本号
     * @return 获取版本号
     */
    long getVersion() {
        return Version;
    }

    /**
     * 获取对称算法ID
     * @return 对称算法ID
     */
    long getUlSymmAlgID() {
        return ulSymmAlgID;
    }

    /**
     * 获取加密密钥对的密钥位长度
     * @return 加密密钥对的密钥位长度
     */
    long getUlBits() {
        return ulBits;
    }

    /**
     * 获取加密密钥对私钥的密文
     * @return 加密密钥对私钥的密文
     */
    byte[] getCbEncryptedPriKey() {
        return cbEncryptedPriKey;
    }

    /**
     * 获取加密密钥对的公钥
     * @return 加密密钥对的公钥
     */
    ECCPUBLICKEYBLOB getPubKey() {
        return PubKey;
    }

    /**
     * 获取用保护公钥加密的对称密钥密文
     * @return 保护公钥加密的对称密钥密文
     */
    ECCCIPHERBLOB getECCCipherBlob() {
        return ECCCipherBlob;
    }

    /**
     * 设置版本号
     * @param version 版本号
     */
    void setVersion(long version) {
        Version = version;
    }

    /**
     * 设置对称算法ID
     * @param ulSymmAlgID 对称算法ID(仅支持ECB模式)
     */
    void setUlSymmAlgID(long ulSymmAlgID) {
        this.ulSymmAlgID = ulSymmAlgID;
    }

    /**
     * 设置加密密钥对的密钥位长度
     * @param ulBits 加密密钥对的密钥位长度
     */
    void setUlBits(long ulBits) {
        this.ulBits = ulBits;
    }

    /**
     * 设置加密密钥对私钥的密文
     * @param cbEncryptedPriKey 加密密钥对私钥的密文
     */
    void setCbEncryptedPriKey(byte[] cbEncryptedPriKey) {
        if(null == cbEncryptedPriKey || cbEncryptedPriKey.length > 64){
            return;
        }

        System.arraycopy(cbEncryptedPriKey,0,this.cbEncryptedPriKey,0,cbEncryptedPriKey.length);
    }

    /**
     * 设置用保护公钥加密的对称密钥密文
     * @param ECCCipherBlob 用保护公钥加密的对称密钥密文
     */
    void setECCCipherBlob(ECCCIPHERBLOB ECCCipherBlob) {
        if(null == ECCCipherBlob){
            return;
        }

        this.ECCCipherBlob.setXCoordinate(ECCCipherBlob.getXCoordinate());
        this.ECCCipherBlob.setYCoordinate(ECCCipherBlob.getYCoordinate());
        this.ECCCipherBlob.setHASH(ECCCipherBlob.getHASH());
        this.ECCCipherBlob.setCipherLen(ECCCipherBlob.getCipherLen());
        this.ECCCipherBlob.setCipher(ECCCipherBlob.getCipher());

    }

    /**
     * 设置加密密钥对的公钥
     * @param pubKey 加密密钥对的公钥
     */
    void setPubKey(ECCPUBLICKEYBLOB pubKey) {
        if(null == pubKey){
            return;
        }

        this.PubKey.setBitLen(pubKey.getBitLen());
        this.PubKey.setXCoordinate(pubKey.getXCoordinate());
        this.PubKey.setYCoordinate(pubKey.getYCoordinate());
    }
}
