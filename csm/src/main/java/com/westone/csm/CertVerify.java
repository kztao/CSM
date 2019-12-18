package com.westone.csm;

interface CertVerify {
    boolean verify(String packageName,byte[] fingerPrint);
}
