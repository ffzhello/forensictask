package cn.edu.jslab6.autoresponse.forensictask;

/**
 * Created by ffzheng on 2017/7/26.
 */
public class TestIp {

    public static boolean isInRange(String network, String mask) {
        String[] networkips = network.split("\\.");
        int ipAddr = (Integer.parseInt(networkips[0]) << 24)
                | (Integer.parseInt(networkips[1]) << 16)
                | (Integer.parseInt(networkips[2]) << 8)
                | Integer.parseInt(networkips[3]);
        System.out.println("ipAddr: "+ipAddr);
        int type = Integer.parseInt(mask.replaceAll(".*/", ""));
        System.out.println("type: "+ type);
        int mask1 = 0xFFFFFFFF << (32 - type);
        String maskIp = mask.replaceAll("/.*", "");
        System.out.println("maskIp: " + maskIp);
        String[] maskIps = maskIp.split("\\.");
        int cidrIpAddr = (Integer.parseInt(maskIps[0]) << 24)
                | (Integer.parseInt(maskIps[1]) << 16)
                | (Integer.parseInt(maskIps[2]) << 8)
                | Integer.parseInt(maskIps[3]);
        System.out.println("cidrIpAddr: "+cidrIpAddr);

        return (ipAddr & mask1) == (cidrIpAddr & mask1);
    }

    public static void main(String[] args) {
        System.out.println(isInRange("10.153.48.127", "10.153.48.0/26"));
        System.out.println(isInRange("10.168.1.2", "10.168.0.224/23"));
        System.out.println(isInRange("192.168.0.1", "192.168.0.0/24"));
        System.out.println(isInRange("10.168.0.0", "10.168.0.0/32"));
    }
}
