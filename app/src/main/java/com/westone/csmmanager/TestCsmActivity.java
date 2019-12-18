package com.westone.csmmanager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.widget.TextView;
import com.westone.cardmanager.ServiceCallback;

public class TestCsmActivity extends AppCompatActivity {

    private static StringBuilder stringBuilder = null;

    private void SetTextContent(String s){
        TextView textView = (TextView)findViewById(R.id.Show);

        stringBuilder.append("************************************************************\n");
        stringBuilder.append(s);
        stringBuilder.append("\n");
        textView.setText(stringBuilder);
        textView.setAllCaps(false);
        textView.setMovementMethod(ScrollingMovementMethod.getInstance());
    }

    private static final String TAG = "csm_TestActivity";
    class Callback implements ServiceCallback{
        @Override
        public void ServiceStatus(boolean b, String s) {
            Log.i(TAG,"TestP11Client.Run before");
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

}
