package com.westone.csm;

import java.util.HashMap;
import java.util.Map;

final class CSMServerPriority {
    public static Map<String,Integer> map;

    private CSMServerPriority() {
        throw new IllegalStateException("Utility class");
    }

    static {
        map = new HashMap<>();
        map.put("com.cmcc.hemihua",100);
        map.put("com.westone.semanager",90);
        //map.put("com.cetcs.ecmapplication",80);
        map.put("com.zdk.mg.agent",70);


        //测试使用
        map.put("com.westone.csmmanager",2);
        map.put("com.westone.testbinderserver",1);
    }

    public static int getPriority(String name){
        if(map.containsKey(name)){
            return map.get(name);
        }

        return 0;
    }
}
