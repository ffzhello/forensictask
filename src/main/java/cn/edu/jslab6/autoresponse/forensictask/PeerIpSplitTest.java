package cn.edu.jslab6.autoresponse.forensictask;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import java.util.*;

public class PeerIpSplitTest {
    /**
     * 单个PCAP文件离线分离
     * @param pcapFile
     * @throws PcapNativeException
     * @throws NotOpenException
     * @throws IllegalRawDataException
     * @throws ArrayIndexOutOfBoundsException
     */

    public static Map<Long, Set> ruleToTasks = new HashMap<>();

    private static void splitPcapFile(PcapFileInfo pcapFile) {
        if (pcapFile == null)
            return;

        String pcapFileName = pcapFile.getFilepath();
        if (pcapFileName == null || pcapFileName.equals(""))
            return;

        //周期
        int start = pcapFileName.indexOf("/");
        int end = pcapFileName.indexOf(".");
        String cycle = pcapFileName.substring(++start, end);

        System.out.println(pcapFileName + "分离开始.");
        long size = 0;

        Packet packet;
        PcapHandle handle = null;
        IpV4Packet ipV4Packet;
        IpV4Packet.IpV4Header header;
        Long srcIp;
        Long dstIp;

        try {
            handle = Pcaps.openOffline(pcapFileName);
            while ((packet = handle.getNextPacket()) != null) {

                //数据包大小
                long packetSize = packet.length();
                size += packetSize;

                ipV4Packet = packet.get(IpV4Packet.class);
                header = ipV4Packet.getHeader();

                String src = header.getSrcAddr().getHostAddress();
                String dst = header.getDstAddr().getHostAddress();
                srcIp = IpUtils.ipToLong(src);
                dstIp = IpUtils.ipToLong(dst);

                //匹配任务
                Set<ActiveTask> packetTaskSet = new HashSet<>();
                if (ruleToTasks.containsKey(srcIp)) {
                    packetTaskSet.addAll(ruleToTasks.get(srcIp));
                }
                if(ruleToTasks.containsKey(dstIp)) {
                    packetTaskSet.addAll(ruleToTasks.get(dstIp));
                }
                //写入
                if (!packetTaskSet.isEmpty()) {
                    for (ActiveTask task: packetTaskSet) {
                        if (task.dumper == null) {
                            //当前周期的第一个报文
                            //创建周期目录
                            String path = task.getDirPath() + cycle;
                            FileManager.createDir(path);
                            task.dumper = handle.dumpOpen(path + "/cycle.pcap");
                            task.setFilename(path+"/cycle.pcap");
                        }
                        //写报文到周期文件
                        task.dumper.dump(packet, handle.getTimestamp());

                        //已采集报文个数
                        long sensorpkts = task.getSensorpkts();
                        task.setSensorpkts(++sensorpkts);
                        //已采集报文大小
                        long sensorBytes = task.getSensorBytes();
                        task.setSensorBytes(sensorBytes+packetSize);

                        //写报文到对端ip
                        String taskip = src;
                        String peerip = dst;
                        if (task.getIpString().contains(peerip)) {
                            taskip = dst;
                            peerip = src;
                        }
                        //根据对端ip分类
                        if (!(task.peerIpInfoMap.containsKey(peerip))) {
                            //创建对端ip目录
                            String path = task.getDirPath() + cycle + "/" + taskip + "-" + peerip;
                            FileManager.createDir(path);

                            PeerIpInfo peerIpInfo = new PeerIpInfo();
                            peerIpInfo.setPeerip(peerip);
                            peerIpInfo.pcapDumper = handle.dumpOpen(path + "/" + peerip + ".pcap");

                            task.peerIpInfoMap.put(peerip, peerIpInfo);
                        }
                        //写报文到对端ip pcap文件中
                        PeerIpInfo peerIpInfo = task.peerIpInfoMap.get(peerip);
                        peerIpInfo.pcapDumper.dump(packet, handle.getTimestamp());
                        //报文大小及个数
                        long count = peerIpInfo.getSensorpkts();
                        peerIpInfo.setSensorpkts(++count);

                        long bytes = peerIpInfo.getSensorbytes();
                        peerIpInfo.setSensorbytes(bytes+packetSize);
                        //根据对端ip分类finish
                    }
                }
            }
        } catch (PcapNativeException e) {
            System.out.println("Pcap Native Exception...");
        } catch (NotOpenException e) {
            System.out.println("Not Open Exception...");
        } catch (ArrayIndexOutOfBoundsException e) {
            System.out.println("Array Index Out Of Bounds Exception...");
        } finally {
            //关闭dumper
            if (!ruleToTasks.isEmpty()) {
                for (Map.Entry<Long,Set> entry: ruleToTasks.entrySet()) {
                    Set<ActiveTask> set = entry.getValue();
                    for (ActiveTask t: set) {
                        if(t.dumper != null) {
                            t.dumper.close();
                            t.dumper = null;
                        }
                    }
                }
            }
            if(handle != null) {
                //关闭handle
                handle.close();
            }
            System.out.println("size: " + size);
            System.out.println(pcapFileName + "分离结束.");
        }
    }
    public static void main(String[] args) {
        ActiveTask activeTask = new ActiveTask();
        activeTask.setIpString("111.47.202.209");
        activeTask.setDirPath("E:/test/");
        Long ip = IpUtils.ipToLong("111.47.202.209");
        Set<ActiveTask> set = new HashSet();
        set.add(activeTask);
        ruleToTasks.put(ip, set);

        PcapFileInfo pcapFileInfo = new PcapFileInfo();
        pcapFileInfo.setFilepath("E:/111.47.202.209.pcap");

        splitPcapFile(pcapFileInfo);
    }
}
