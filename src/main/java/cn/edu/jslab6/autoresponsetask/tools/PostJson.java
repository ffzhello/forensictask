package cn.edu.jslab6.autoresponsetask.tools;

/**
 * Created by ffzheng on 2017/8/8.
 */
     import java.io.InputStream;
     import java.io.OutputStream;
     import java.net.HttpURLConnection;
     import java.net.URL;

     import org.json.JSONArray;
     import org.json.JSONException;
     import org.json.JSONObject;

public class PostJson {
    public static void main(String args[])
    {
        try {
            //JSON
            JSONObject  obj = new JSONObject();
            obj.append("ticketid", "12345");
            obj.append("ipList", "202.112.23.167/32");
            obj.append("action", "PcapCap;SuricataDetect;BroDetect");
            obj.append("priority", "5");
            obj.append("flowDirection", "2");
            obj.append("srcIP", "1");
            obj.append("srcPort", "-1");
            obj.append("dstIP", "1");
            obj.append("srcIPDstIP", "0");
            obj.append("srcPortDstPort", "0");
            obj.append("protocol", "255");
            obj.append("timelen", "300");
            obj.append("thresholdPkts", "20000");
            obj.append("username", "CHAIRS");


            System.out.println(obj);
            // 创建url资源
            URL url = new URL("http://211.65.193.183:6001/hydra/recv-response-task");
            // 建立http连接
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            // 设置允许输出
            conn.setDoOutput(true);

            conn.setDoInput(true);

            // 设置不用缓存
            conn.setUseCaches(false);
            // 设置传递方式
            conn.setRequestMethod("POST");
            // 设置维持长连接
            conn.setRequestProperty("Connection", "Keep-Alive");
            // 设置文件字符集:
            conn.setRequestProperty("Charset", "UTF-8");
            //转换为字节数组
            byte[] data = (obj.toString()).getBytes();
            // 设置文件长度
            conn.setRequestProperty("Content-Length", String.valueOf(data.length));

            // 设置文件类型:
            conn.setRequestProperty("contentType", "application/json");


            // 开始连接请求
            conn.connect();
            OutputStream  out = conn.getOutputStream();
            // 写入请求的字符串
            out.write((obj.toString()).getBytes());
            out.flush();
            out.close();

            System.out.println(conn.getResponseCode());

            // 请求返回的状态
            if (conn.getResponseCode() == 200) {
                System.out.println("连接成功");
                // 请求返回的数据
                InputStream in = conn.getInputStream();
                String a = null;
                try {
                    byte[] data1 = new byte[in.available()];
                    in.read(data1);
                    // 转成字符串
                    a = new String(data1);
                    System.out.println(a);
                } catch (Exception e1) {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
            } else {
                System.out.println("no++");
            }

        } catch (Exception e) {

        }

    }
}