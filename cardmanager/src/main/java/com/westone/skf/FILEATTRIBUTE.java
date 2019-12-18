package com.westone.skf;

/**
 * 文件属性
 */
public class FILEATTRIBUTE {
    private String FileName = "";            //文件名
    private long FileSize = 0;              //文件大小
    private long ReadRights = 0;            //读权限
    private long WriteRights = 0;           //写权限
    private long size;

    /**
     * 获取文件名
     * @return 文件名
     */
    public String getFileName() {
        return FileName;
    }

    /**
     * 获取文件大小
     * @return 文件大小
     */
    public long getFileSize() {
        return FileSize;
    }

    /**
     * 获取读权限
     * @return 读权限
     */
    public long getReadRights() {
        return ReadRights;
    }

    /**
     * 获取写权限
     * @return 写权限
     */
    public long getWriteRights() {
        return WriteRights;
    }

    /**
     * 设置文件名
     * @param fileName 文件名
     */
    void setFileName(String fileName) {
        FileName = fileName;
    }

    /**
     * 设置文件大小
     * @param fileSize 文件大小
     */
    void setFileSize(long fileSize) {
        FileSize = fileSize;
    }

    /**
     * 设置读权限
     * @param readRights 读权限
     */
    void setReadRights(long readRights) {
        ReadRights = readRights;
    }

    /**
     * 设置写权限
     * @param writeRights 写权限
     */
    void setWriteRights(long writeRights) {
        WriteRights = writeRights;
    }
}
