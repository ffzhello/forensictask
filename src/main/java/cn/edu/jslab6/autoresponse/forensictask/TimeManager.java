package cn.edu.jslab6.autoresponse.forensictask;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class TimeManager {
    public static String changeTsToString(String ts) {
        if (ts == null)
            return null;

        String tsStr = null;

        String str = ts.replace(".","").substring(0,13);
        long strlong = Long.parseLong(str);

        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        String d = format.format(strlong);
        try {
            Date date = format.parse(d);
            tsStr = format.format(date);
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return tsStr;
    }

    public static void main(String[] args) {
        System.out.println(changeTsToString("1546676692.385804"));
        System.out.println(changeTsToString("1546676699.976212"));
    }
}
