package com.westone;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.telephony.TelephonyManager;
import android.util.Log;

import com.westone.rpcclient.RpcManager;
import com.westone.skf.SkfWrapper;

import java.util.Objects;

public class SimStatusBc extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if(Objects.equals(intent.getAction(), "android.intent.action.SIM_STATE_CHANGED")){
            TelephonyManager tm = (TelephonyManager) context.getApplicationContext().getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) {
                Log.i("wjr","sim status is " + tm.getSimState());
                switch (tm.getSimState()){
                    case TelephonyManager.SIM_STATE_ABSENT:
                    case TelephonyManager.SIM_STATE_READY:
                        RpcManager.getInstance().SendBc("android.intent.action.SIM_STATE_CHANGED",tm.getSimState());
                        SkfWrapper.setSimStatus(tm.getSimState());
                        break;
                    default:
                        break;
                }
            }
        }

        if(Objects.equals(intent.getAction(), "com.westone.csm.statuschange")){
            Log.i("wjr","has recv csm status changed bc");
        }
    }
}
