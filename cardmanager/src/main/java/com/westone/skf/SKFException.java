package com.westone.skf;

/**
 * SKF异常
 */
public class SKFException extends Exception {
    static private long err = 0;

    /**
     * 构造函数
     * @param msg 异常消息
     * @param e 错误码
     */
    public SKFException(String msg, long e){
        super("csm_SkfException " + msg);
        err = e;
    }

    /**
     * 获取最后一次发生错误时的错误码
     * @return 错误码
     */
    public static long getLastError(){
        return err;
    }
}
