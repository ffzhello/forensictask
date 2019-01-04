package cn.edu.jslab6.autoresponse.forensictask;

import org.pcap4j.core.PcapDumper;

public class PeerIpInfo {
    private String taskip = ""; //任务ip
    private String peerip = ""; //对端ip
    private long sensorpkts = 0; //采集的报文个数
    private long sensorbytes = 0;//采集的报文大小
    private String detectresults = ""; //检测结果
    public PcapDumper pcapDumper = null; //用于写文件

    public String getTaskip() {
        return taskip;
    }

    public void setTaskip(String taskip) {
        this.taskip = taskip;
    }

    public String getPeerip() {
        return peerip;
    }

    public void setPeerip(String peerip) {
        this.peerip = peerip;
    }

    public long getSensorpkts() {
        return sensorpkts;
    }

    public void setSensorpkts(long sensorpkts) {
        this.sensorpkts = sensorpkts;
    }

    public long getSensorbytes() {
        return sensorbytes;
    }

    public void setSensorbytes(long sensorbytes) {
        this.sensorbytes = sensorbytes;
    }

    public String getDetectresults() {
        return detectresults;
    }

    public void setDetectresults(String detectresults) {
        this.detectresults = detectresults;
    }
}
