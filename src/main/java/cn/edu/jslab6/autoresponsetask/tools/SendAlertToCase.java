package cn.edu.jslab6.autoresponsetask.tools;

import cn.edu.jslab6.autoresponse.forensictask.ResponseResultSender;
import cn.edu.jslab6.autoresponse.forensictask.Utils;
import com.google.gson.Gson;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Created by zrwang on 2017/4/10.
 */
public class SendAlertToCase {
    private static final String RECV_URL = "http://211.65.193.129/MONSTER/RecvMergePcap.php";

    class AlertResult {
        int ticketid;
        String filedata;
    }

    /**
     * 将合并的内容发送回CHAIRS系统
     *
     * @param alertContent
     * @param recvUrl
     * @throws IOException
     */
    public void send(String alertContent, String recvUrl) throws IOException {
        AlertResult alertResult = new AlertResult();
        if (System.getProperty("TicketId") == null) {
            System.out.println("No ticketid !");
            return;
        } else {
            alertResult.ticketid = Integer.parseInt(System.getProperty("TicketId"));
            alertResult.filedata = alertContent;
            ResponseResultSender sender = new ResponseResultSender(recvUrl);
            sender.send(new Gson().toJson(alertResult));
        }
    }

    public static void main(String[] args) throws IOException {
        SendAlertToCase alertSender = new SendAlertToCase();
        if (System.getProperty("SendAlert") != null) {
            String content = Utils.readFileContent(System.getProperty("SendAlert"));
            alertSender.send(content, RECV_URL);
        } else {
            System.out.println("No Send Alert File, exit!");
        }
    }
}
