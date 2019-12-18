package com.westone.skf;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

class MediaMount extends BroadcastReceiver {

    private final String tag = "csm_skf";

    /**
     * 接收方法
     * @param context 上下文
     * @param intent intent
     */
    @Override
    public void onReceive(Context context, Intent intent) {

        String action = intent.getAction();
        Log.i(tag, action);
        /* isWait */
        if(SKFDevManager.isWait){
            switch (action){
                /* card insert */
                case Intent.ACTION_MEDIA_MOUNTED:
                /* card eject */
                case Intent.ACTION_MEDIA_EJECT: {
                    List<String> devListNew = new ArrayList<>();
                    SkfWrapper skfWrapper = new SkfWrapper(context);
                    try {
                        if(Intent.ACTION_MEDIA_EJECT != action){
                            skfWrapper.SKF_EnumDev(devListNew);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        Log.i(tag, "error num:" + String.format("%08x", SKFException.getLastError()));
                    }

                    if(action.equals(Intent.ACTION_MEDIA_MOUNTED)){
                        /* add new device name */
                        Iterator<String> currentIt = devListNew.iterator();
                        while (currentIt.hasNext()){
                            String deviceName = currentIt.next();
                            boolean needNotify = true;
                            /* search new device name */
                            if(SKFDevManager.devListOld.contains(deviceName)){
                                needNotify = false;
                            }
                            /* add device name into devListOld */
                            if(needNotify){
                                Log.i(tag, "add dev:" + deviceName + " into devList!");
                                SKFDevManager.devListOld.add(deviceName);
                            }
                            /* notify device event */
                            if(needNotify && SKFDevManager.isWait && (null != SKFDevManager.devEvent)){
                                Log.i(tag, "notify dev event:" + deviceName + " inserted!");
                                SKFDevManager.devEvent.notifyDevEvent(deviceName, SkfDefines.EVENT_DEVICE_INSERTED);
                            }
                        }
                    }else if(action.equals(Intent.ACTION_MEDIA_EJECT)){
                        /* remove old device name(only support single card now) */
                        Iterator<String> globalIt = SKFDevManager.devListOld.iterator();
                        while (globalIt.hasNext()){
                            String deviceName = globalIt.next();
                            boolean needNotify = true;
                            /* search remove device name */
                            if(devListNew.contains(deviceName)){
                                needNotify = false;
                            }
                            /* remove device name from devListOld */
                            if(needNotify){
                                Log.i(tag, "remove dev:" + deviceName + " from devList!");
                                globalIt.remove();
                            }
                            /* notify device event */
                            if(needNotify && SKFDevManager.isWait && (null != SKFDevManager.devEvent)){
                                Log.i(tag, "notify dev event:" + deviceName + " removed!");
                                SKFDevManager.devEvent.notifyDevEvent(deviceName, SkfDefines.EVENT_DEVICE_REMOVED);
                            }
                        }
                    }
                }
                break;
                default:
                    break;
            }
        }
    }
}
