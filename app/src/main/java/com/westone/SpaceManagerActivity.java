package com.westone;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;

import java.io.File;

public class SpaceManagerActivity extends AppCompatActivity {

    static void delPath(String path){
        File file = new File(path);
        if(file.exists()){
            if(file.isDirectory()){
                String[] strings = file.list();
                assert strings != null;
                for (String str : strings){
                    delPath(str);
                }
            }else {
                file.delete();
            }
        }

    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }
}
