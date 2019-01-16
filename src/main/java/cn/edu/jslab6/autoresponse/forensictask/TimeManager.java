package cn.edu.jslab6.autoresponse.forensictask;

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
        System.out.println(changeTsToString("1546676692.385804"));
        System.out.println(changeTsToString("1546676699.976212"));
    }
}
