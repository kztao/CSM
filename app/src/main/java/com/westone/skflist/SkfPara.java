package com.westone.skflist;

import com.westone.skf.DEVHANDLE;
import com.westone.skf.HANDLE;
import com.westone.skf.HAPPLICATION;
import com.westone.skf.HCONTAINER;

class SkfPara {
    private String devName;
    private DEVHANDLE devhandle;
    private HAPPLICATION happlication;
    private HCONTAINER hcontainer;
    private HANDLE handle;

    public DEVHANDLE getDevhandle() {
        return devhandle;
    }

    public HANDLE getHandle() {
        return handle;
    }

    public HAPPLICATION getHapplication() {
        return happlication;
    }

    public HCONTAINER getHcontainer() {
        return hcontainer;
    }

    public String getDevName() {
        return devName;
    }

    public void setDevhandle(DEVHANDLE devhandle) {
        this.devhandle = devhandle;
    }

    public void setHandle(HANDLE handle) {
        this.handle = handle;
    }

    public void setDevName(String devName) {
        this.devName = devName;
    }

    public void setHapplication(HAPPLICATION happlication) {
        this.happlication = happlication;
    }

    public void setHcontainer(HCONTAINER hcontainer) {
        this.hcontainer = hcontainer;
    }

}
