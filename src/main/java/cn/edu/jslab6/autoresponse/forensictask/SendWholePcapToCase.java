package cn.edu.jslab6.autoresponse.forensictask;

import com.google.gson.Gson;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.sql.*;

/**
 * Created by zrwang on 2017/2/23.
 *    1. 根据响应任务的ticketid进行pcap报文的合并
 */
public class SendWholePcapToCase {
    private ResponseResultSender resultSender = null;
    private Connection conn = null;
    private Statement statement = null;
    private Statement sensorstatement = null;
    private SystemConfig systemConfig = new SystemConfig();

    public SendWholePcapToCase() throws IOException {
        systemConfig.load("./system.properties");
        resultSender = new ResponseResultSender(systemConfig.getTaskSendUrl());
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
                sensorstatement = conn.createStatement();
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
    public void sendPcaps(int ticketid) throws IOException {
        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        System.out.println("Begin send pcaps ticketid = " + ticketid);

        PcapResponseResult result = new PcapResponseResult();
        result.ticketid = String.valueOf(ticketid);
        result.actionResult.put(ResponseAction.PcapCap, true);
        // 根据ticketid, e.g. 16383 读取数据库中的所有filename
        //select filename from (sensorfile join sensortask on sensorfile.sensortaskid = sensortask.id
        // join responsetask on responsetask.id = sensortask.taskid) where responsetask.ticketid = 16383;
        // 拼接文件， 并进行验证
        //String sql = "select filename from (sensorfile join sensortask on sensorfile.sensortaskid = sensortask.id " +
        //       "join responsetask on responsetask.id = sensortask.taskid) where responsetask.ticketid = " + ticketid;
        String sql = "select sensortask.id from (responsetask join sensortask on responsetask.id = sensortask.taskid)" +
                " where responsetask.ticketid = " + ticketid;
        try {
            ResultSet rs = statement.executeQuery(sql);

            while (rs.next()) {
                int sensorTaskID = rs.getInt(1);
                // 从数据库sensorfile中读取出当前采包的文件路径。
                // XXX: 一个响应任务可能对应有多个文件(文件划分大小的存在),但是在自动应急响应中，报文采集大小
                //      未达到报文分片的大小，所以对于一次采集任务只会有一个pcap文件。
                String sensorSql = "SELECT filename FROM sensorfile WHERE sensortaskid = " + sensorTaskID;
                String filename = "";
                try {
                    ResultSet rrs = sensorstatement.executeQuery(sensorSql);
                    if (rrs.first()) {
                        filename = rrs.getString(1);
                    } else {
                        result.actionResult.put(ResponseAction.PcapCap, false);
                    }
                } catch (SQLException e) {
                    e.printStackTrace();
                }
                result.files.fileName = filename;
                System.out.println("curr filename = " + filename);
                // 读取采集报文样本, 服务器上的报文保存格式为latin-1(ISO_8859_1),发送前将二进制编码为latin-1格式，在服务器端进行
                // 编码转换即可。
                if (!filename.equals("")) {
                    byte[] b;
                    if ((b = Utils.readBinaryFile(filename)) != null) {
                        result.files.fileContent = new String(b, StandardCharsets.ISO_8859_1);
                        System.out.println("Convert file " + result.files.fileName + " to Latin-1 format, binary size = "
                                + b.length);
                    }
                } else {
                    result.files.fileContent = "";
                }

                try {
                    sql = "SELECT firstpkttime, lastpkttime FROM sensortask WHERE id = " + sensorTaskID;
                    ResultSet rrs = sensorstatement.executeQuery(sql);
                    if (rrs.first()) {
                        result.attach.firstpkttime = rrs.getInt(1);
                        result.attach.lastpkttime = rrs.getInt(2);
                    } else {
                        result.attach.firstpkttime = 0;
                        result.attach.lastpkttime = 0;
                    }
                } catch (SQLException e) {
                    e.printStackTrace();
                } finally {
                    System.out.println("firstpkttime = " + result.attach.firstpkttime +
                            ", lastpkttime = " + result.attach.lastpkttime);
                }

                String pcapResult = new Gson().toJson(result);
                try {
                    resultSender.send(pcapResult);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                System.out.println("Finish send file " + filename);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws IOException {
        SendWholePcapToCase swptc = new SendWholePcapToCase();
        if (System.getProperty("MergeFile") != null) {
            BufferedReader br = new BufferedReader(new FileReader(System.getProperty("MergeFile")));
            String ticketid;
            while ((ticketid = br.readLine()) != null) {
                if (ticketid.length() < 1) continue;
                swptc.sendPcaps(Integer.parseInt(ticketid));
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
