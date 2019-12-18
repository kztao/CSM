package com.westone.skf;

/**
 * SKF常量定义
 */
public class SkfDefines {
    /**
     * 成功
     */
    public final static int SAR_OK = 0x00000000;
    /**
     * 失败
     */
    public final static int SAR_FAIL = 0x0A000001;
    /**
     * 异常错误
     */
    public final static int SAR_UNKNOWNERR = 0x0A000002;
    /**
     * 不支持的服务
     */
    public final static int SAR_NOTSUPPORTYETERR = 0x0A000003;
    /**
     * 文件操作错误
     */
    public final static int SAR_FILEERR = 0x0A000004;
    /**
     * 无效的句柄
     */
    public final static int SAR_INVALIDHANDLEERR = 0x0A000005;
    /**
     * 无效的参数
     */
    public final static int SAR_INVALIDPARAMERR = 0x0A000006;
    /**
     * 读文件错误
     */
    public final static int SAR_READFILEERR = 0x0A000007;
    /**
     * 写文件错误
     */
    public final static int SAR_WRITEFILEERR = 0x0A000008;
    /**
     * 文件名称错误
     */
    public final static int SAR_NAMELENERR = 0x0A000009;
    /**
     * 密钥用途错误
     */
    public final static int SAR_KEYUSAGEERR = 0x0A00000A;
    /**
     * 模的长度错误
     */
    public final static int SAR_MODULUSLENERR = 0x0A00000B;
    /**
     * 未初始化
     */
    public final static int SAR_NOTINITIALIZEERR = 0x0A00000C;
    /**
     * 对象错误
     */
    public final static int SAR_OBJERR = 0x0A00000D;
    /**
     * 内存错误
     */
    public final static int SAR_MEMORYERR = 0x0A00000E;
    /**
     * 超时
     */
    public final static int SAR_TIMEOUTERR = 0x0A00000F;
    /**
     * 输入数据长度错误
     */
    public final static int SAR_INDATALENERR = 0x0A000010;
    /**
     * 输入数据错误
     */
    public final static int SAR_INDATAERR = 0x0A000011;
    /**
     * 生成随机数错误
     */
    public final static int SAR_GENRANDERR = 0x0A000012;
    /**
     * HASH对象错误
     */
    public final static int SAR_HASHOBJERR = 0x0A000013;
    /**
     * HASH运算错误
     */
    public final static int SAR_HASHERR = 0x0A000014;
    /**
     * 产生RSA密钥错误
     */
    public final static int SAR_GENRSAKEYRR = 0x0A000015;
    /**
     * RSA密钥模长错误
     */
    public final static int SAR_RSAMODULUSLENERR = 0x0A000016;
    /**
     * CSP服务导入公钥错误
     */
    public final static int SAR_CSPIMPRTPUBKEYERR = 0x0A000017;
    /**
     * RSA加密错误
     */
    public final static int SAR_RSAENCERR = 0x0A000018;
    /**
     * RSA解密错误
     */
    public final static int SAR_RSADECERR = 0x0A000019;
    /**
     * HASH值不相等
     */
    public final static int SAR_HASHNOTEQUALERR = 0x0A00001A;
    /**
     * 密钥未发现
     */
    public final static int SAR_KEYNOTFOUNDERR = 0x0A00001B;
    /**
     * 证书未发现
     */
    public final static int SAR_CERTNOTFOUNDERR = 0x0A00001C;
    /**
     * 对象未导出
     */
    public final static int SAR_NOTEXPORTERR = 0x0A00001D;
    /**
     * 解密时做补丁错误
     */
    public final static int SAR_DECRYPTPADERR = 0x0A00001E;
    /**
     * MAC长度错误
     */
    public final static int SAR_MACLENERR = 0x0A00001F;
    /**
     * 缓冲区不足
     */
    public final static int SAR_BUFFER_TOO_SMALL = 0x0A000020;
    /**
     * 密钥类型错误
     */
    public final static int SAR_KEYINFOTYPEERR = 0x0A000021;
    /**
     * 无事件错误
     */
    public final static int SAR_NOT_EVENTERR = 0x0A000022;
    /**
     * 设备已移除
     */
    public final static int SAR_DEVICE_REMOVED = 0x0A000023;
    /**
     * PIN不正确
     */
    public final static int SAR_PIN_INCORRECT = 0x0A000024;
    /**
     * PIN被锁死
     */
    public final static int SAR_PIN_LOCKED = 0x0A000025;
    /**
     * PIN无效
     */
    public final static int SAR_PIN_INVALID = 0x0A000026;
    /**
     * PIN长度错误
     */
    public final static int SAR_PIN_LEN_RANGE = 0x0A000027;
    /**
     * 用户已经登录
     */
    public final static int SAR_USER_ALREADY_LOGGED_IN = 0x0A000028;
    /**
     * 没有初始化用户口令
     */
    public final static int SAR_USER_PIN_NOT_INITIALIZED = 0x0A000029;
    /**
     * PIN类型错误
     */
    public final static int SAR_USER_TYPE_INVALID = 0x0A00002A;
    /**
     * 应用名称无效
     */
    public final static int SAR_APPLICATION_NAME_INVALID = 0x0A00002B;
    /**
     * 应用已经存在
     */
    public final static int SAR_APPLICATION_EXISTS = 0x0A00002C;
    /**
     * 用户没有登录
     */
    public final static int SAR_USER_NOT_LOGGED_IN = 0x0A00002D;
    /**
     * 应用不存在
     */
    public final static int SAR_APPLICATION_NOT_EXISTS = 0x0A00002E;
    /**
     * 文件已经存在
     */
    public final static int SAR_FILE_ALREADY_EXIST = 0x0A00002F;
    /**
     * 空间不足
     */
    public final static int SAR_NO_ROOM = 0x0A000030;
    /**
     * 文件不存在
     */
    public final static int SAR_FILE_NOT_EXIST = 0x0A000031;
    /**
     * 已达到最大可管理容器数
     */
    public final static int SAR_REACH_MAX_CONTAINER_COUNT = 0x0A000032;

    /*
    *布尔类型定义
     */

    /**
     * 布尔值为真
     */
    public final static int TRUE = 0x00000001;
    /**
     * 布尔值为假
     */
    public final static int FALSE = 0x00000000;

    /*
     *临界值定义
     */

    /**
     * 初始化向量的最大长度
     */
    public final static int MAX_IV_LEN = 32;
    /**
     * 应用名最大长度
     */
    public final static int MAX_APP_NAME_LEN = 21;
    /**
     * 文件名最大长度
     */
    public final static int MAX_FILE_NAME_LEN = 32;
    /**
     * 容器名最大长度
     */
    public final static int MAX_CONTAINER_NAME_LEN = 64;
    /**
     * 最小的PIN长度
     */
    public final static int MIN_PIN_LEN = 6;

    /**
     * RSA算法模数的最大长度
     */
    public final static int MAX_RSA_MODULUS_LEN = 256;
    /**
     * RSA算法指数的最大长度
     */
    public final static int MAX_RSA_EXPONENT_LEN = 4;

    /**
     * ECC算法X座标的最大长度
     */
    public final static int ECC_MAX_XCOORDINATE_BITS_LEN = 512;
    /**
     * ECC算法Y座标的最大长度
     */
    public final static int ECC_MAX_YCOORDINATE_BITS_LEN = 512;
    /**
     * ECC算法模数的最大长度
     */
    public final static int ECC_MAX_MODULUS_BITS_LEN = 512;

    /*
     *算法标识符
     */

    /**
     * SM1算法ECB加密模式
     */
    public final static int SGD_SM1_ECB = 0x00000101;
    /**
     * SM1算法CBC加密模式
     */
    public final static int SGD_SM1_CBC = 0x00000102;
    /**
     * SM1算法CFB加密模式
     */
    public final static int SGD_SM1_CFB = 0x00000104;
    /**
     * SM1算法OFB加密模式
     */
    public final static int SGD_SM1_OFB = 0x00000108;
    /**
     * SM1算法MAC运算
     */
    public final static int SGD_SM1_MAC = 0x00000110;
    /**
     * SSF33算法ECB加密模式
     */
    public final static int SGD_SSF33_ECB = 0x00000201;
    /**
     * SSF33算法CBC加密模式
     */
    public final static int SGD_SSF33_CBC = 0x00000202;
    /**
     * SSF33算法CFB加密模式
     */
    public final static int SGD_SSF33_CFB = 0x00000204;
    /**
     * SSF33算法OFB加密模式
     */
    public final static int SGD_SSF33_OFB = 0x00000208;
    /**
     * SSF33算法MAC运算
     */
    public final static int SGD_SSF33_MAC = 0x00000210;
    /**
     * SMS4算法ECB加密模式
     */
    public final static int SGD_SMS4_ECB = 0x00000401;
    /**
     * SMS4算法CBC加密模式
     */
    public final static int SGD_SMS4_CBC = 0x00000402;
    /**
     * SMS4算法CFB加密模式
     */
    public final static int SGD_SMS4_CFB = 0x00000404;
    /**
     * SMS4算法OFB加密模式
     */
    public final static int SGD_SMS4_OFB = 0x00000408;
    /**
     * SMS4算法MAC运算
     */
    public final static int SGD_SMS4_MAC = 0x00000410;
    /**
     * DES112算法ECB运算,仅用于测试
     */
    public final static int SGD_DES112_ECB = 0x00001101;

    /*	0x00000400-0x800000xx	为其它分组密码算法预留	*/

    /**
     * RSA算法
     */
    public final static int SGD_RSA = 0x00010000;
    /**
     * 椭圆曲线签名算法
     */
    public final static int SGD_SM2_1 = 0x00020100;
    /**
     * 椭圆曲线密钥交换协议
     */
    public final static int SGD_SM2_2 =	0x00020200;
    /**
     * 椭圆曲线加密算法
     */
    public final static int SGD_SM2_3 =	0x00020400;

    /* 密码杂凑算法标识表 */

    /**
     * SM3 密码杂凑算法
     */
    public final static int SGD_SM3 = 0x00000001;
    /**
     * SHA1 密码杂凑算法
     */
    public final static int SGD_SHA1 = 0x00000002;
    /**
     * SHA256 密码杂凑算法
     */
    public final static int SGD_SHA256 = 0x00000004;

    /*	0x00000010～0x000000FF	为其它密码杂凑算法预留	*/

    /*
     *设备状态
     */

    /**
     * 设备不存在
     */
    public final static int	DEV_ABSENT_STATE = 0x00000000;
    /**
     * 设备存在
     */
    public final static int	DEV_PRESENT_STATE = 0x00000001;
    /**
     * 设备状态未知
     */
    public final static int DEV_UNKNOW_STATE = 0x00000002;

    /*
     *密钥类型
     */

    /**
     * 公钥
     */
    public final static int KT_PUBLIC_KEY = 0x01;
    /**
     * 私钥
     */
    public final static int KT_PRIVATE_KEY = 0x02;
    /**
     * 密钥
     */
    public final static int KT_SECRET_KEY = 0x03;

    /*
     *权限类型
     */

    /**
     * 不允许
     */
    public final static int SECURE_NEVER_ACCOUNT = 0x00000000;
    /**
     * 管理员权限
     */
    public final static int SECURE_ADM_ACCOUNT = 0x00000001;
    /**
     * 用户权限
     */
    public final static int SECURE_USER_ACCOUNT	= 0x00000010;
    /**
     * 任何人
     */
    public final static int SECURE_EVERYONE_ACCOUNT = 0x000000FF;
    /**
     * 任何人
     */
    public final static int SECURE_ANYONE_ACCOUNT = 0x000000FF;

    /*
     *PIN类型
     */

    /**
     * 管理员PIN
     */
    public final static int ADMIN_TYPE = 0;
    /**
     * 用户PIN
     */
    public final static int USER_TYPE =	1;

    /*
     *容器属性
     */

    /**
     * 未知类型容器
     */
    public final static int CONTAINER_PROPERTY_UNKNOWN = 0;
    /**
     * RSA类型容器
     */
    public final static int CONTAINER_PROPERTY_RSA = 1;
    /**
     * ECC类型容器
     */
    public final static int CONTAINER_PROPERTY_ECC = 2;

    /*
     *设备状态
     */

    /**
     * 设备已插入
     */
    public final static int EVENT_DEVICE_INSERTED = 0x0001;
    /**
     * 设备已移除
     */
    public final static int EVENT_DEVICE_REMOVED = 0x0002;
}
