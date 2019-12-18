package com.westone.testdemo;

final class HexByte {
    public static byte[] hexToByte(String hex){
        int m = 0,n = 0;

        if(null == hex){
            return null;
        }

        int byteLen = hex.length() / 2;
        byte[] ret = new byte[byteLen];
        for(int i= 0; i < byteLen;i++){
            m = i * 2 + 1;
            n = m + 1;
            int intVal = Integer.decode("0x" + hex.substring(i * 2,m) + hex.substring(m,n));
            ret[i] = Byte.valueOf((byte)intVal);
        }

        return ret;
    }

    public static String byteToHex(byte[] bytes){
        String strHex = "";
        StringBuilder stringBuilder = new StringBuilder("");
        for(int i = 0; i < bytes.length;i++){
            strHex = Integer.toHexString(bytes[i] & 0xFF);
            stringBuilder.append((strHex.length() == 1) ? "0" + strHex:strHex);
        }

        return stringBuilder.toString().trim();
    }
}
