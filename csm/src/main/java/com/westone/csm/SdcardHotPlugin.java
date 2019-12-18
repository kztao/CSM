package com.westone.csm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.util.Objects;

public class SdcardHotPlugin extends BroadcastReceiver {
    CSMNative csmNative = new CSMNative();
    private static final String TAG = "csm_service";
    @Override
    public void onReceive(Context context, Intent intent) {
        LogUtils.i(TAG,"SdcardHotPlugin " + intent.getAction());
        Log.i("skf","SdcardHotPlugin " + intent.getAction());
        switch (Objects.requireNonNull(intent.getAction())){
            case Intent.ACTION_MEDIA_EJECT:
                LogUtils.i(TAG,"SdcardHotPlugin ACTION_MEDIA_EJECT");
                csmNative.TFCardPlugin(false);
                csmNative.setMountFlag(false);
//                Runtime runtime = Runtime.getRuntime();
//                runtime.exit(0);
                break;
            case Intent.ACTION_MEDIA_MOUNTED:
                LogUtils.i(TAG,"SdcardHotPlugin ACTION_MEDIA_MOUNTED1");
                context.getExternalFilesDir(null);
                csmNative.setMountFlag(true);
                csmNative.TFCardPlugin(true);
                break;
            default:
                break;
        }
    }
}
