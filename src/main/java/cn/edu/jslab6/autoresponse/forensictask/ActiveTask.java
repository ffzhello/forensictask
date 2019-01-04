package cn.edu.jslab6.autoresponse.forensictask;
import java.util.*;

import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.Packet;

/**
 * Created by ffzheng on 2017/7/19.
 */
public class ActiveTask {
    //field
    private int id; //活动任务表id
    private int ticketId; //案件编号

    private String ipString = null;
    private List<Long> ipLongList = new ArrayList<>();
    private int priority = 5;

    private List<ResponseAction> actionList = new ArrayList<ResponseAction>();
    private String actions = null;

    private int flowDirection = 2;
    private int srcIP = 1;
    private int srcPort = 65535;
    private int dstIP = 1;
    private int dstPort = 65535;
    private int srcIPDstIP = 0;  //0代表或，1代表且
    private int srcPortDstPort = 0;
    private int protocol;
    private long startTime = 0;  //精确到秒
    private long endTime = 0;
    private int thresholdPkts = 0; //要采集报文个数
    private long sensorpkts = 0;   //已采集报文个数
    private long sensorBytes = 0;   //已采集报文大小
    private int filesplit = 200;    //文件切分大小(MB)
    private int status = 0;

    private List<IpMask> ipMaskList = new ArrayList<IpMask>();

    //案件采集及分析保存目录
    private String  dirPath = "";

    private int tmpDirCount = 0;

    //
    private int patFileCount = 0;
    private int mergedPatFileCount = 0;
    private int megfilecount = 0;

    public PcapResponseResult pcapResponseResult = null;
    public ResponseResult responseResult = null;

    //对端ip信息
    public Map<String, PeerIpInfo> peerIpInfoMap = new HashMap<>();
    //当前周期
    public String cycle = "";
    //当前周期报文数
    public long cyclepkts = 0;
    //当前周期报文大小
    public long cyclebytes = 0;

    //当前周期pcap文件
    private String tmpFilename = "";
    //当前周期pcap文件大小
    private int tmpFileSize = 0;
    //当前周期pcap文件列表
    //private List<String> tmpFilelist = new ArrayList<String>();
    //当前周期合并后的pcap文件
    private String megFilename = "";
    //合并文件集合
    //private List<String> megFileList = new ArrayList<>();
    //任务的总pcap文件
    private String filename = "";

    //private int filecount = 0;

    public PcapDumper dumper = null;
    private List<Packet> packetList = new ArrayList<>();

    private long firstpkttime = 0;
    private long lastpkttime = 0;
    private String username = "CHAIRS"; // 创建响应任务的用户名,默认为CHAIRS

    public ActiveTask() {

    }

    public void setSensorpkts(long sensorpks) {
        this.sensorpkts = sensorpks;
    }

    public long getSensorpkts() {
        return sensorpkts;
    }

    public void setTmpDirCount(int tmpDirCount) {
        this.tmpDirCount = tmpDirCount;
    }

    public int getTmpDirCount() {
        return  tmpDirCount;
    }

    public void setPatFileCount(int patFileCount) {
        this.patFileCount = patFileCount;
    }
    public int getPatFileCount() {
        return patFileCount;
    }

    public void setMergedPatFileCount(int mergedPatFileCount) {
        this.mergedPatFileCount = mergedPatFileCount;
    }

    public int getMergedPatFileCount() {
        return mergedPatFileCount;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public String getFilename() {
        return filename;
    }

    public int getTmpFileSize() {
        return tmpFileSize;
    }

    public void setTmpFileSize(int tmpFileSize) {
        this.tmpFileSize = tmpFileSize;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getTmpFilename() {
        return tmpFilename;
    }

    public void setTmpFilename(String tmpFilename) {
        this.tmpFilename = tmpFilename;
    }

    public void setPacketList(List<Packet> packetList) {
        this.packetList = packetList;
    }

    public List<Packet> getPacketList() {
        return packetList;
    }

    public void addPacketToList(Packet packet) {
        if (packet != null) {
            packetList.add(packet);
        }
    }

    public void setMegFilename(String megFilename) {
        this.megFilename = megFilename;
    }

    public String getMegFilename() {
        return megFilename;
    }


    public int getMegfilecount() {
        return megfilecount;
    }

    public void setMegfilecount(int megfilecount) {
        this.megfilecount = megfilecount;
    }

    /*public void addMegFileToList(String megFilename) {
        megFileList.add(megFilename);
    }*/

    public String getDirPath() {
        return dirPath;
    }

    public void setDirPath(String dirPath) {
        this.dirPath = dirPath;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getTicketId() {
        return ticketId;
    }

    public void setTicketId(int ticketId) {
        this.ticketId = ticketId;
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

    public long getStartTime() {
        return startTime;
    }

    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }

    public long getEndTime() {
        return endTime;
    }

    public void setEndTime(long endTime) {
        this.endTime = endTime;
    }

    public int getThresholdPkts() {
        return thresholdPkts;
    }

    public void setThresholdPkts(int thresholdPkts) {
        this.thresholdPkts = thresholdPkts;
    }

    public long getSensorBytes() {
        return sensorBytes;
    }

    public void setSensorBytes(long sensorBytes) {
        this.sensorBytes = sensorBytes;
    }

    public void setFilesplit(int filesplit) {
            this.filesplit = filesplit;
    }

    public int getFilesplit() {
        return filesplit;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getIpString() {
        return ipString;
    }

    public void setIpString(String ipString) {
        this.ipString = ipString;
        //设置
        //setIpMaskList(ipString);
        //设置ipList
        String[] ipArr;
        if (ipString.contains(";")) {
            ipArr = ipString.split(";");
        }else {
            ipArr = new String[]{ipString};
        }
        for (String ip: ipArr) {
            Long ipLong = IpUtils.ipToLong(ip);
            ipLongList.add(ipLong);
        }
    }

    public List<Long> getIpLongList() {
        return ipLongList;
    }

    private void setIpMaskList(String ipString) {
        if (ipString == null || ipString.isEmpty())
            return;

        String[] ipStrArr = ipString.split(";");
        if (ipStrArr.length > 0) { //有待匹配IP
            for (String str: ipStrArr) {
                Long ip = IpUtils.ipToLong(str);
                Integer mask = IpUtils.getMask(str);

                if (ip != null && mask != null) {
                    IpMask ipMask = new IpMask(ip,mask);
                    ipMaskList.add(ipMask);
                }
            }
        }
    }

    public List<IpMask> getIpMaskList() {
        return ipMaskList;
    }

    public long getFirstpkttime() {
        return firstpkttime;
    }

    public void setFirstpkttime(long firstpkttime) {
        this.firstpkttime = firstpkttime;
    }

    public long getLastpkttime() {
        return lastpkttime;
    }

    public void setLastpkttime(long lastpkttime) {
        this.lastpkttime = lastpkttime;
    }

    public String getActions() {
        return actions;
    }

    public void setActions(String actions) {
        this.actions = actions;
    }

    public List<ResponseAction> getActionList() {
        if (actions != null) {
            String[] actionArr = actions.split(";");
            if(actionArr.length > 0) {
                for (String ac: actionArr) {
                    ResponseAction ra = ResponseAction.valueOf(ac);
                    if(ra != null)
                        actionList.add(ra);
                }
            }
        }
        return actionList;
    }

    public static void main(String[] args) {
        ActiveTask task = new ActiveTask();
        task.setId(1);
        task.setIpString("11.11.11.11/1;2.2.2.2/3;");

        for (IpMask i: task.getIpMaskList()) {
            System.out.println("ip: "+i.getIp()+" ,mask: "+i.getMask());
        }
    }
}
