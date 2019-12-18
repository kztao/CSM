package com.westone.csmmanager;

import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

class FileSave {
 /*   private void initData() {
        String filePath = "/sdcard/Test/";
        String fileName = "log.txt";

        try {
            writeTxtToFile("txt content", filePath, fileName);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }*/

    // 将字符串写入到文本文件中
    public void writeTxtToFile(String strcontent, String filePath, String fileName) throws IOException {
        //生成文件夹之后，再生成文件，不然会出错
        makeFilePath(filePath, fileName);

        String strFilePath = filePath+fileName;
        // 每次写入时，都换行写
        String strContent = strcontent + "\r\n";
        RandomAccessFile raf = null;
        try {
            File file = new File(strFilePath);
            if (!file.exists()) {
                Log.i("TestFile", "Create the file:" + strFilePath);
                file.getParentFile().mkdirs();
                file.createNewFile();
            }
            raf = new RandomAccessFile(file, "rwd");
            raf.seek(file.length());
            raf.write(strContent.getBytes());
        } catch (Exception e) {
            Log.e("TestFile", "Error on write File:" + e);
        } finally {
            if(null != raf){
                raf.close();
            }

        }
    }

    // 生成文件
    public File makeFilePath(String filePath, String fileName) {
        File file = null;
        makeRootDirectory(filePath);
        try {
            file = new File(filePath + fileName);
            if (!file.exists()) {
                file.createNewFile();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return file;
    }

    // 删除文件
    public File deleteFilePath(String filePath, String fileName) {
        File file = null;
        makeRootDirectory(filePath);
        try {
            file = new File(filePath + fileName);
            if (file.exists()) {
                file.delete();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return file;
    }

    // 生成文件夹
    public static void makeRootDirectory(String filePath) {
        File file = null;
        try {
            file = new File(filePath);
            if (!file.exists()) {
                file.mkdir();
            }
        } catch (Exception e) {
            Log.i("error:", e+"");
        }
    }
}
