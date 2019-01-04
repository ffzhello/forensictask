package cn.edu.jslab6.autoresponse.forensictask;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Created by ffzheng on 2018/6/13.
 */
public class TestHandlerTime {

    private static Set<ActiveTask> activeTaskSet= new HashSet<>();

    private static void splitPcapFile(PcapFileInfo pcapFile) throws PcapNativeException, NotOpenException, IllegalRawDataException, ArrayIndexOutOfBoundsException {
        if (pcapFile == null)
            return;

        String pcapFileName = pcapFile.getFilepath();
        if (pcapFileName == null || pcapFileName.equals(""))
            return;

        System.out.println(pcapFileName + "分离开始.");

        PcapHandle handle = Pcaps.openOffline(pcapFileName);
        Packet packet ;
        //限定每个文件的大小为5M
        final int MAX_TMPFILE_SIZE = 2*1024*1024;

        //处理离线文件中每个报文
        Iterator<ActiveTask> iterator ;
        ActiveTask task ;

        while ((packet = handle.getNextPacket()) != null) {
            int packetSize = packet.length();
            iterator = activeTaskSet.iterator();
            while (iterator.hasNext()) {
                task = iterator.next();
                if (true) {
                    //判断当前文件是否达到容量上限
                    int tmpFileSize = task.getTmpFileSize();
                    if (tmpFileSize + packetSize > MAX_TMPFILE_SIZE) {
                        //关闭dumper
                        if (task.dumper != null) {
                            task.dumper.close();
                            task.dumper = null;
                        }
                    }
                    if (task.dumper == null) {
                        int patFileCount = task.getPatFileCount();
                        task.setPatFileCount(++ patFileCount);
                        String tmpFilename = task.getDirPath() + "PAT" + String .valueOf(patFileCount) + ".pcap";
                        task.setTmpFilename(tmpFilename);
                        task.setTmpFileSize(0);
                        task.dumper = handle.dumpOpen(tmpFilename);
                    }
                    task.dumper.dump(packet, handle.getTimestamp());
                    tmpFileSize = task.getTmpFileSize();
                    task.setTmpFileSize(tmpFileSize + packetSize);
                    //int count = task.getNumPkts();
                    //task.setNumPkts(++count);
                   // long pktTime = handle.getTimestamp().getTime()/1000;
                   // if (count == 1)
                    //    task.setFirstpkttime(pktTime);
                   // task.setLastpkttime(pktTime);
                }
            }
        }
        //关闭dumper
        if(!(activeTaskSet.isEmpty())) {
            for(ActiveTask t: activeTaskSet) {
                if(t.dumper != null) {
                    t.dumper.close();
                    t.dumper = null;
                }
            }
        }
        //关闭handle
        handle.close();
        System.out.println(pcapFileName + "分离结束...");
    }


    public static void main(String[] args) {
            int i = 500;
            for (int j = 0; j < i; j ++ ) {
                ActiveTask t = new ActiveTask();
                t.setId(j);
                t.setDirPath("E://test/" + j);
                activeTaskSet.add(t);
            }
            System.out.println("任务个数：" + activeTaskSet.size());
            PcapFileInfo pcapFileInfo = new PcapFileInfo();
            pcapFileInfo.setFilepath("E://x.pcap");
            SimpleDateFormat  simpleDateFormat = new SimpleDateFormat("YYYY-MM-dd HH:mm:ss");
            System.out.println(simpleDateFormat.format(new Date()));

            try {
                splitPcapFile(pcapFileInfo);
            }catch (Exception e) {
                e.printStackTrace();
            }

            System.out.println(simpleDateFormat.format(new Date()));

    }
}
