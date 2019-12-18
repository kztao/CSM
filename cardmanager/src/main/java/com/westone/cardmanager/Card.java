package com.westone.cardmanager;

public class Card {
    static {
        System.loadLibrary("TFCardManager");
    }

    private Card() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * GetCard; 获取存在的卡
     *  输入：无
     *  输出：返回获取到的卡的名字
     *
     * GetCardStatus: 获取卡状态
     *  输入：卡的名字（由GetTFCard 获得的）
     *  输出：位置0：返回值。位置1：卡状态
     *
     * RegCardStatusCallback: 注册回调函数
     *  输入：注册获取TF卡状态的回调函数
     *  输出：无
     *
     * Login: 登录
     *  输入：参数1：卡名字；参数2：用户密码
     *  输出：参考中间件和P11错误码。返回0为登录成功。返回0x100为已登录。返回0xA0为密码错误
     *
     * ChangePin: 修改密码
     *  输入：参数1：卡名字；参数2：旧用户密码；参数3：新用户密码
     *  输出：参考中间件和P11错误码。返回0为成功。
     *
     * ResetUserPinwithOTP: 使用OTP PIN重设密码
     *  输入：参数1：卡名字；参数2：OTP PIN；参数3：新用户密码
     *  输出：位置0：参考中间件和P11错误码。返回0为成功。
     *        位置1：OTP PIN剩余可重试次数
     *
     * GetRemainLockedTimes: 获取用户密码剩余可重试次数
     *  输入：参数1：卡名字
     *  输出：位置0：返回值。位置1：可重试次数
     *
     * VerifyPin: 验证用户密码(不改变登录状态)
     *  输入：参数1：卡名字；参数2：用户密码
     *  输出：参考中间件和P11错误码。返回0为成功。返回0xA0为密码错误
     *
     * GetCardVersionInfo：获取卡和中间件相关的版本信息（可在登录前调用）
     *  输入：参数1：卡名字
     *  输出：JniCardInfo：
     *      pLibVersion：客户端版本
     *      pCardCosVersion： 卡的cos版本
     *      pSerialNo：卡的序号
     *      pCardHardWareVersion：卡的固件版本
     *      pP11LibVersion：卡的P11库版本
     *      pManufacturerID：卡的生产厂商
     *      pCryServerVersion：服务端版本
     *
     *
     */

    public static native String[] GetCard();
    public static native int[] GetCardStatus(String des);
    public static native void RegCardStatusCallback(ITFStatus func);
    public static native long Login(String des,String pw);
    public static native long ChangePin(String des,String oldPin,String newPin);
    public static native long[] ResetUserPinwithOTP(String des,String OTPPin,String UserPin);
    public static native long[] GetRemainLockedTimes(String des);
    public static native long VerifyPin(String des,String pw);
    public static native JniCardInfo GetCardVersionInfo(String des);
    public static native long softCreateCipherCard(String token, String userName, String licSesrverAddr, String csppAddr);
    public static native long DestroyCipherCard();
}
