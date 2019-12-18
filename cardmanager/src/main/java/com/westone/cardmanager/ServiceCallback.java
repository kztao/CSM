package com.westone.cardmanager;

/* 密码中间件状态回调接口，应用可通过实现此接口获得中间件的状态
   参数1：表示中间件服务启动或停止的状态。成功为true，失败为false
   参数2：失败时返回失败原因
* */
public interface ServiceCallback {
    void ServiceStatus(boolean status, String reason);
}
