package cn.edu.jslab6.autoresponsetask.tools;

import cn.edu.jslab6.autoresponse.forensictask.ResponseResultSender;
import cn.edu.jslab6.autoresponse.forensictask.SystemConfig;
import cn.edu.jslab6.autoresponse.forensictask.Utils;
import com.google.gson.Gson;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.*;
import java.util.Arrays;

/**
 * Created by zrwang on 2017/2/23.
 *    1. 根据响应任务的ticketid进行pcap报文的合并
 */
public class MergePcap {
    public static final String OUT_DIR = "/home/monster/merge_pcap";
    public static final int THRESHILD_BYTES = 8 * 1024 * 1024; // 合并的pcap的阈值为8M
    private static final String RECV_URL = "http://211.65.193.129/MONSTER/RecvMergePcap.php";

    private Connection conn = null;
    private Statement statement = null;
    private SystemConfig systemConfig = new SystemConfig();

    public MergePcap() throws IOException {
        systemConfig.load("./system.properties");
        initMysql(systemConfig);
    }

    private void initMysql(SystemConfig systemConfig) {
        this.initMysql(systemConfig.getMysqlIP(), systemConfig.getMysqlPort(), systemConfig.getMysqlUsername(),
                systemConfig.getMysqlPasswd(), systemConfig.getMysqlDatabase());
    }

    private void initMysql(String ip, int port, String username, String passwd, String database) {
        try {
            Class.forName("com.mysql.jdbc.Driver");
            //Class.forName("com.mysql.cj.jdbc.Driver");
            try {
                String url = "jdbc:mysql://" + ip + ":" + port + "/" + database;
                conn = DriverManager.getConnection(url, username, passwd);
                statement = conn.createStatement();
                System.out.println("Connect database " + url);
                //LOG.info("Connect database {}.", url);
            } catch (SQLException e) {
                e.printStackTrace();
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    /**
     * 根据响应任务id来合并历史pcap文件,并发送给CHAIRS
     * @param ticketid: 响应任务id
     */
    public void mergeAndSend(int ticketid) throws IOException {
        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        System.out.println("Begin merge responsetask ticketid = " + ticketid);
        // 根据ticketid, e.g. 16383 读取数据库中的所有filename
        //select filename from (sensorfile join sensortask on sensorfile.sensortaskid = sensortask.id
        // join responsetask on responsetask.id = sensortask.taskid) where responsetask.ticketid = 16383;
        // 拼接文件， 并进行验证
        String sql = "select filename from (sensorfile join sensortask on sensorfile.sensortaskid = sensortask.id " +
                "join responsetask on responsetask.id = sensortask.taskid) where responsetask.ticketid = " + ticketid;
        try {
            ResultSet rs = statement.executeQuery(sql);
            // 第一个报文,保存所有的报文字节，后面的pcap文件需去除pcap header(24个字节)进行拼接
            byte[] totalPcap = null;
            if (rs.next()) {
                String filename = rs.getString(1);
                if (filename != null) {
                    System.out.println("Merge pcap file " + filename);
                    totalPcap = Utils.readBinaryFile(rs.getString(1));
                }
            }

            while(rs.next()) {
                String filename = rs.getString(1);
                if (filename != null) {
                    System.out.println("Merge pcap file " + filename);
                    byte[] pcapcontent = Utils.readBinaryFile(filename);
                    if (pcapcontent.length > 24)
                        totalPcap = Utils.concatBytes(totalPcap,
                                Arrays.copyOfRange(pcapcontent, 24, pcapcontent.length));
                    if (totalPcap.length > THRESHILD_BYTES) break;
                }
            }

            Path outPath = Paths.get(OUT_DIR, String.valueOf(ticketid) + ".pcap");
            System.out.println("Merge result, Pcap file locate at " + outPath.toString());
            BufferedOutputStream bos = new BufferedOutputStream(Files.newOutputStream(outPath));
            if (totalPcap != null)
                bos.write(totalPcap);
            bos.close();

            // 发送给CHAIRS进行历史报文覆盖
            System.out.println("Send Merge Pcap Content to CHARIS, Ticketid = " + ticketid);
            MergePcapResult ret = new MergePcapResult();
            ret.ticketid = ticketid;
            if (totalPcap != null)
                ret.filecontent = new String(totalPcap, StandardCharsets.ISO_8859_1);
            else
                ret.filecontent = "";
            //send(ret, RECV_URL);
//            System.out.println("Finish Send Merge Pcap file to CHAIRS!");
            System.out.println("file size = " + ret.filecontent.length());

        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    class MergePcapResult {
       int ticketid;
       String filecontent;
    }

    /**
     * 将合并的内容发送回CHAIRS系统
      * @param mergeResult
     * @param recvUrl
     * @throws IOException
     */
    public void send(MergePcapResult mergeResult, String recvUrl) throws IOException {
        ResponseResultSender sender = new ResponseResultSender(recvUrl);
        sender.send(new Gson().toJson(mergeResult));
    }

    public static void main(String[] args) throws IOException {
        MergePcap mp = new MergePcap();
        if (System.getProperty("MergeFile") != null) {
            BufferedReader br = new BufferedReader(new FileReader(System.getProperty("MergeFile")));
            String ticketid;
            while ((ticketid = br.readLine()) != null) {
                mp.mergeAndSend(Integer.parseInt(ticketid));
            }

        }
        else
            System.out.println("No Merge ticketid File, exit!");

        /*
        //mp.merge(16383);
        byte[] b = Utils.readBinaryFile("E:\\pcaptest\\0.pcap");
        byte[] b1 = Utils.readBinaryFile("E:\\pcaptest\\1.pcap");
        byte[] b2 = Utils.readBinaryFile("E:\\pcaptest\\2.pcap");
        byte[] trunk1 = Arrays.copyOfRange(b1, 24, b1.length);
        byte[] trunk2 = Arrays.copyOfRange(b2, 24, b2.length);

        byte[] ret  = Utils.concatBytes(Utils.concatBytes(b, trunk1), trunk2);
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("E:\\pcaptest\\merge.pcap"));
        bos.write(ret);
        bos.close();

        BufferedWriter bw = new BufferedWriter(new FileWriter("E:\\pcaptest\\mergebyrange.pcap"));
        bw.write(new String(ret, StandardCharsets.ISO_8859_1));
        bw.close();
        */
    }
}
