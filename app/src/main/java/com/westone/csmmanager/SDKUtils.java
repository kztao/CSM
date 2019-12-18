package com.westone.csmmanager;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Created by Administrator on 2017/11/23.
 */

public class SDKUtils {
    private SDKUtils() {
       throw new IllegalStateException("Utility class");
    }

    public static void copyAssetDirToFiles(Context context, String dirname)
            throws IOException {
        File dir = new File(context.getFilesDir() + "/" + dirname);
        if(!dir.exists()) {
            dir.mkdir();
            AssetManager assetManager = context.getAssets();
            String[] children = assetManager.list(dirname);
            for (String child : children) {
                child = dirname + '/' + child;
                String[] grandChildren = assetManager.list(child);
                if (0 == grandChildren.length)
                    copyAssetFileToFiles(context, child);
                else
                    copyAssetDirToFiles(context, child);
            }
        }
    }


    public static void createDirInFiles(Context context, String dirname)
            throws IOException {
        File dir = new File(context.getFilesDir() + "/" + dirname);
        if(!dir.exists()) {
            dir.mkdir();
        }
    }

    public static void copyAssetFileToFiles(Context context, String filename)
            throws IOException
    {
        InputStream is = context.getAssets().open(filename);
        byte[] buffer = new byte[is.available()];
        int num = is.read(buffer);
        is.close();
        if(num<0){
            return;
        }

        File of = new File(context.getFilesDir() + "/" + filename);
        of.createNewFile();
        try(FileOutputStream os = new FileOutputStream(of)){
            os.write(buffer);
        }
    }



}
