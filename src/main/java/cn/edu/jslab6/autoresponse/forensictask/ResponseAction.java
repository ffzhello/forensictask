package cn.edu.jslab6.autoresponse.forensictask;

/**
 * Created by zrwang on 2016/12/11.
 */
public enum ResponseAction {
    PcapCap, SuricataDetect, BroDetect;

    public String toString() {
        return name();
    }

    public static void main(String[] args) {
        for (ResponseAction action : values())
            System.out.println(action);
    }
}

