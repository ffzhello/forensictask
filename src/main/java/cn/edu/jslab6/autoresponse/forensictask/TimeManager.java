package cn.edu.jslab6.autoresponse.forensictask;

import java.math.BigDecimal;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class TimeManager {
    /**
     * 将bro日志时间戳转换为时间
     * @param ts
     * @return
     */
    public static String changeTsToString(String ts) {
        if (ts == null)
            return null;

        String tsStr = null;
        // 保留时间精度

        String[] timeStr = ts.split("\\.");
        if (timeStr.length < 2) {
            return null;
        }

        long stamp = Long.parseLong(timeStr[0]) * 1000L;

        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String d = format.format(stamp);
        try {
            Date date = format.parse(d);
            tsStr = format.format(date);
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return tsStr+ "." +timeStr[1];
    }

    public static void main(String[] args) {
        double a = Double.parseDouble("1547639390.257149");
        double b = Double.parseDouble("0.000005");
        BigDecimal c = BigDecimal.valueOf(a+b);
        System.out.println(c);
        System.out.println(changeTsToString(String.valueOf(c)));
      // System.out.println(changeTsToString("1546676699.976212"));
        System.out.println("sss,eee".contains(","));
        String ssl = "imap,ssl";
        String[] services = ssl.split(",");
        String ss = "";
        for (String service: services) {
            if (BroLogType.protocolLogSet.contains(service+".log")) {
                ss += service + ",";
            }
        }
        System.out.println(ss);
    }
}
