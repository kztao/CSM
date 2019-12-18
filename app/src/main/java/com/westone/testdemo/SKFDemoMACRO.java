package com.westone.testdemo;

import com.westone.skf.DEVHANDLE;
import com.westone.skf.HAPPLICATION;
import com.westone.skf.HCONTAINER;
import com.westone.skf.SkfWrapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

final class SKFDemoMACRO {
    public static final String tag = "csm_skf";


    public static final List gridview_type = Arrays.asList("设备管理","访问控制","应用管理","文件管理","容器管理","密码运算");

    public static final List gridview_func_dev = Arrays.asList("连接设备","断开设备","获取设备连接状态","获取设备信息","设置设备标签","订阅设备状态变化","取消订阅");
    public static final List gridview_func_app = Arrays.asList("修改PIN","获取PIN信息","验证PIN","解锁PIN","安全退出","创建应用","删除应用","打开应用","关闭应用");
    public static final List gridview_func_file = Arrays.asList("创建文件","读文件","写文件","删除文件","获取文件属性");
    public static final List gridview_func_container = Arrays.asList("创建容器","删除容器","打开容器","关闭容器","创建ECC密钥对","导入ECC密钥对","签名","导出会话密钥","导出公钥","导入会话密钥","导入证书","导出证书","获取容器类型");
    public static final List gridview_func_acc = Arrays.asList("设备认证","修改密钥");
    public static final List gridview_func_alg = Arrays.asList("产生随机数","ECC验签","外部ECC加密","外部ECC解密","外部ECC签名","算法测试");

    public static final String scan_dev = "枚举设备";
    public static final String scan_app = "枚举应用";
    public static final String scan_file = "枚举文件";
    public static final String scan_container = "枚举容器";

    public static final String spinner_promt_dev = "设备名称";
    public static final String spinner_promt_app = "应用名称";
    public static final String spinner_promt_file = "文件名称";
    public static final String spinner_promt_container = "容器名称";

    public static final String spinner_promt_dev_handle = "设备句柄";
    public static final String spinner_promt_app_handle = "应用句柄";
    public static final String spinner_promt_file_handle = "文件句柄";
    public static final String spinner_promt_container_handle = "容器句柄";

    public static final List list_dev = new ArrayList();
    public static final List list_app = new ArrayList();
    public static final List list_container = new ArrayList();
    public static final List list_file = new ArrayList();

    public static String select_dev_name = "";
    public static String select_app_name = "";
    public static String select_container_name = "";
    public static String select_file_name = "";

    public static DEVHANDLE devhandle = new DEVHANDLE();
    public static HAPPLICATION happlication = new HAPPLICATION();
    public static HCONTAINER hcontainer = new HCONTAINER();

    public static String EncPri = "7f279cdf5ff611327ef183df78df2876" +
            "f2b51bdbfbebded864fe8ce47ff20ec8";

    public static String EncPuk = "56219ff9a4417a8abead2230e5fcb862" +
            "c2e910e935185bac81cd91231cbcb6b2" +
            "d99342f227681ec275bc8ee4b61aa345" +
            "06e5751cbcd59a5f2a23e5464bc48678";

    public static SkfWrapper skfWrapper = null;


}
