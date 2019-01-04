package cn.edu.jslab6.autoresponse.forensictask;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by zrwang on 2016/12/11.
 */

/**
 * 用来解析取证调度模块发送过来的案件信息。
 * 案件信息实例(json format)：
     {
         "ticketid": "12345",
         "ipList": [
             "47.88.192.121/32",
             "8.8.8.8",
             "222.22.2.0/22"
         ],
         "config": {
             "action": "PcapCap;SuricataDetect;BroDetect",
             "Priority": "5",
             "flowDirection": "2",
             "srcIP": "1",
             "srcPort": "65535",
             "dstIP": "1",
             "dstPort": "65535",
             "srcIPDstIP": "0",
             "srcPortDstPort": "0",
             "protocol": "255",
             "threasholdPkts": "30"
             "timelen": "300",
         }
    }
 */
class RawResponseTask {
    String ticketid = "12345";
   // List<String> ipList = Arrays.asList(new String[]{"202.112.23.167/32"});
   List<String> ipList = Arrays.asList(new String[]{"211.65.192.177/32"});
   // List<String> ipList = new ArrayList<String>();

    class Config {
        String action = "PcapCap;SuricataDetect;BroDetect";
        String priority = "5";
        String flowDirection = "2";
        String srcIP = "1";
        String srcPort = "-1";
        String dstIP = "1";
        String dstPort = "-1";
        String srcIPDstIP = "0";
        String srcPortDstPort = "0";
        String protocol = "255";
        String timelen = "300";
        String thresholdPkts = "20000";
    }

    Config config = new Config();
    String username = "CHAIRS";
}

public class ResponseTask implements Comparable<ResponseTask> {
    private int id;  // 数据库表中的id
    private int ticketid;
    private String caseid;
    private List<String> ipList = new ArrayList<String>();

    private List<ResponseAction> actions = new ArrayList<ResponseAction>();
    private String rawActions;

    private int priority = 5;
    private int flowDirection = 2;
    private int srcIP = 1;
    private int srcPort = 65535;
    private int dstIP = 1;
    private int dstPort = 65535;
    private int srcIPDstIP = 0;  //0代表或，1代表且
    private int srcPortDstPort = 0;
    private int protocol;
    private int timelen = 300; // 采集时长(s)
    private int thresholdPkts = 20000; // 采集报文个数
    private final int filesplit = 200;  // 文件切分大小(MB) c采集文件大小切分.
    private String username = "CHAIRS"; // 创建响应任务的用户名

    public int compareTo(ResponseTask task) {
        if (getPriority() < task.getPriority())  return 1;
        if (getPriority() > task.getPriority())  return -1;
        return 0;
    }
    public ResponseTask() {

    }

    public ResponseTask(RawResponseTask rawTask) {
        setTicketid(Integer.parseInt(rawTask.ticketid));
        if (rawTask.ipList.size() <= 10) {
            getIpList().addAll(rawTask.ipList);
        } else {
            getIpList().addAll(rawTask.ipList.subList(0, 10));
        }

        // Split action to ResponseAction Type.
        for (String s : rawTask.config.action.split(";")) {
            //System.out.println(Enum.valueOf(ResponseAction.class, s));
            getActions().add(Enum.valueOf(ResponseAction.class, s));
        }

        setRawActions(rawTask.config.action);
        setPriority(Integer.parseInt(rawTask.config.priority));
        setFlowDirection(Integer.parseInt(rawTask.config.flowDirection));
        setSrcIP(Integer.parseInt(rawTask.config.srcIP));
        setDstIP(Integer.parseInt(rawTask.config.dstIP));
        setSrcPort(Integer.parseInt(rawTask.config.srcPort));
        setDstPort(Integer.parseInt(rawTask.config.dstPort));
        setSrcIPDstIP(Integer.parseInt(rawTask.config.srcPortDstPort));
        setSrcPortDstPort(Integer.parseInt(rawTask.config.srcPortDstPort));
        setProtocol(Integer.parseInt(rawTask.config.protocol));
        setTimelen(Integer.parseInt(rawTask.config.timelen));
        setThresholdPkts(Integer.parseInt(rawTask.config.thresholdPkts));
        setUsername(rawTask.username);
    }

    public String ipListToString() {
        StringBuilder sb = new StringBuilder();
        for (String ip : ipList)
            sb.append(ip).append(";");
        //去除最后一个分号
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    public String getCaseid() {
        return caseid;
    }

    public void setCaseid(String caseid) {
        this.caseid = caseid;
    }

    public int getTicketid() {
        return ticketid;
    }

    public void setTicketid(int ticketid) {
        this.ticketid = ticketid;
    }

    public List<ResponseAction> getActions() {
        return actions;
    }

    public void setActions(List<ResponseAction> actions) {
        this.actions = actions;
    }

    public int getPriority() {
        return priority;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    public int getFlowDirection() {
        return flowDirection;
    }

    public void setFlowDirection(int flowDirection) {
        this.flowDirection = flowDirection;
    }

    public int getSrcIP() {
        return srcIP;
    }

    public void setSrcIP(int srcIP) {
        this.srcIP = srcIP;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDstIP() {
        return dstIP;
    }

    public void setDstIP(int dstIP) {
        this.dstIP = dstIP;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }

    public int getSrcIPDstIP() {
        return srcIPDstIP;
    }

    public void setSrcIPDstIP(int srcIPDstIP) {
        this.srcIPDstIP = srcIPDstIP;
    }

    public int getSrcPortDstPort() {
        return srcPortDstPort;
    }

    public void setSrcPortDstPort(int srcPortDstPort) {
        this.srcPortDstPort = srcPortDstPort;
    }

    public int getProtocol() {
        return protocol;
    }

    public void setProtocol(int protocol) {
        this.protocol = protocol;
    }

    public int getTimelen() {
        return timelen;
    }

    public void setTimelen(int timelen) {
        this.timelen = timelen;
    }

    public int getThresholdPkts() {
        return thresholdPkts;
    }

    public void setThresholdPkts(int thresholdPkts) {
        this.thresholdPkts = thresholdPkts;
    }

    public List<String> getIpList() {
        return ipList;
    }

    public void setIpList(List<String> ipList) {
        this.ipList = ipList;
    }

    public String getRawActions() {
        return rawActions;
    }

    public void setRawActions(String rawActions) {
        this.rawActions = rawActions;
    }

    public int getFilesplit() {
        return filesplit;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public static void main(String[] args) {
        // Use Debugger to check value.
        RawResponseTask rawResponseTask = new RawResponseTask();
        ResponseTask task = new ResponseTask(rawResponseTask);
    }


    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

}


