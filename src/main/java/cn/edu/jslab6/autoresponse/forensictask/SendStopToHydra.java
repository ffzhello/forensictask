package cn.edu.jslab6.autoresponse.forensictask;

import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;

public class SendStopToHydra {
    private static Logger LOG = LoggerFactory.getLogger(SendStopToHydra.class);
    private static String hydraUrl = "http://211.65.193.183:6001/hydra/del-response-task";

    public void send(String responseResult) throws IOException {
        //建立连接
        URL url = new URL(hydraUrl);
        HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();

        //设置参数
        httpConn.setDoInput(true);
        httpConn.setDoOutput(true);
        httpConn.setUseCaches(false);
        httpConn.setRequestMethod("POST");

        // 设置请求属性
        //httpConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        httpConn.setRequestProperty("Content-Type", "application/json");
        httpConn.setRequestProperty("Connection", "Keep-Alive");
        httpConn.setRequestProperty("Charset", "UTF-8");

        // 连接，也可以不用明文connect,使用下面的httpConn.getOutputStream()会自动connect
        httpConn.connect();

        //LOG.debug("Send Response Result to {}.", this.recvUrl);
        //建立输入流，向指向的URL传入json格式的案件信息
        OutputStreamWriter osw = new OutputStreamWriter(httpConn.getOutputStream(), "UTF-8");
        osw.write(responseResult);
        //dos.writeUTF(responseResult);
        osw.flush();
        osw.close();

        // 获得响应状态, 并显示回送消息。
        int resultCode = httpConn.getResponseCode();
        if (resultCode == HttpURLConnection.HTTP_OK) {
            StringBuffer sb = new StringBuffer();
            String readLine;
            BufferedReader responseReader = new BufferedReader(new InputStreamReader(
                    httpConn.getInputStream(), "UTF-8"));

            while ((readLine = responseReader.readLine()) != null) {
                sb.append(readLine).append("\n");
            }

            responseReader.close();
        } else {
            LOG.debug("{} return code: {}.", this.hydraUrl, resultCode);
        }
    }

    public static void main(String[] args) {
        ActiveTask activeTask = new ActiveTask();
        activeTask.setId(111);
        activeTask.setIpString("1233");
        System.out.println(new Gson().toJson(activeTask));
    }
}
