package com.westone.csm;

import android.app.Activity;
import java.lang.ref.WeakReference;


class CSMActivityMan {
    private static CSMActivityMan sInstance = new CSMActivityMan();
    private WeakReference<Activity> sCurrentActivityWeakRef;


    private CSMActivityMan() {

    }

    public static CSMActivityMan getInstance() {
        return sInstance;
    }

    public Activity getCurrentActivity() {
        Activity currentActivity = null;
        if (sCurrentActivityWeakRef != null) {
            currentActivity = sCurrentActivityWeakRef.get();
        }
        return currentActivity;
    }

    public void setCurrentActivity(Activity activity) {
        sCurrentActivityWeakRef = new WeakReference<Activity>(activity);
    }
}