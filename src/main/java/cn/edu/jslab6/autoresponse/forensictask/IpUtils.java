package cn.edu.jslab6.autoresponse.forensictask;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Created by ffzheng on 2017/7/26.
 */
public class IpUtils {
    public static Long ipToLong(String ipStr) {
        if (ipStr == null || ipStr.equals(""))
            return null;

        //若此ip是掩码形式
        if (ipStr.contains("/")) {
            ipStr = ipStr.replaceAll("/.*", "");
        }

        String[] ipStrArr = ipStr.split("\\.");
        if (ipStrArr.length < 4)
            return null;

        Long ipAddr = (Long.parseLong(ipStrArr[0]) << 24)
                | (Long.parseLong(ipStrArr[1]) << 16)
                | (Long.parseLong(ipStrArr[2]) << 8)
                | Long.parseLong(ipStrArr[3]);

        return ipAddr;
    }

    public static String ipLong2Ip(Long ipaddress) {
        if(ipaddress == null){
            return null;
        }
        StringBuffer sb = new StringBuffer("");
        sb.append(String.valueOf((ipaddress >>> 24)));
        sb.append(".");
        sb.append(String.valueOf((ipaddress & 0x00FFFFFF) >>> 16));
        sb.append(".");
        sb.append(String.valueOf((ipaddress & 0x0000FFFF) >>> 8));
        sb.append(".");
        sb.append(String.valueOf((ipaddress & 0x000000FF)));
        return sb.toString();
    }

    public static Integer getMask(String maskIp) {
        if (maskIp == null || maskIp.equals("") || !(maskIp.contains("/")))
            return null;

        int type = Integer.parseInt(maskIp.replaceAll(".*/", ""));
        int mask = 0xFFFFFFFF << (32 - type);
        return mask;
    }

    public static void main(String[] args) throws Exception{
        System.out.println(ipToLong("121.248.60.15"));
        System.out.println(ipLong2Ip(3413138679l));

        SimpleDateFormat dateFormat = new SimpleDateFormat("%Y-%m-%d %H:%M:%S.sss");
        Date date = new Date();
        date = dateFormat.parse("1546676692.385804");
        String format = dateFormat.format(date);

        System.out.println(format);
    }
}
