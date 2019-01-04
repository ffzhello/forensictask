package cn.edu.jslab6.autoresponsetask.tools;

import cn.edu.jslab6.autoresponse.forensictask.ResponseResultSender;
import cn.edu.jslab6.autoresponse.forensictask.SystemConfig;
import cn.edu.jslab6.autoresponse.forensictask.Utils;
import com.google.gson.Gson;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.*;

/**
 * Created by zrwang on 2017/4/9.
 */
public class SendPcapToCase {
    private static final String RECV_URL = "http://211.65.193.129/MONSTER/RecvMergePcap.php";

    class PcapResult {
        int ticketid;
        String filecontent;
    }

    /**
     * 将合并的内容发送回CHAIRS系统
     *
     * @param pcapResult
     * @param recvUrl
     * @throws IOException
     */
    public void send(String pcapContent, String recvUrl) throws IOException {
        PcapResult pcapResult = new PcapResult();
        if (System.getProperty("TicketId") == null) {
            System.out.println("No ticketid !");
            return;
        } else {
            pcapResult.ticketid = Integer.parseInt(System.getProperty("TicketId"));
            pcapResult.filecontent = pcapContent;
            ResponseResultSender sender = new ResponseResultSender(recvUrl);
            sender.send(new Gson().toJson(pcapResult));
        }
    }

    public static void main(String[] args) throws IOException {
        SendPcapToCase pcapSender = new SendPcapToCase();
        if (System.getProperty("SendPcap") != null) {
            String content = new String(Utils.readBinaryFile(System.getProperty("SendPcap")), StandardCharsets.ISO_8859_1);
            pcapSender.send(content, RECV_URL);
        } else {
            System.out.println("No Send Pcap File, exit!");
        }
    }
}

