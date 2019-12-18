package com.westone.testdemo;

import android.content.Context;
import android.widget.Toast;

class ToastUtil {
    private static Toast myToast;
    private ToastUtil() {
        throw new IllegalStateException("Utility class");
    }

    public static void showToast(Context context, String msg, int length) {

        if (myToast == null) {
            myToast = Toast.makeText(context, msg, length);
        } else {
            myToast.cancel();
            myToast.setText(msg);
        }

        myToast.show();
    }
}
