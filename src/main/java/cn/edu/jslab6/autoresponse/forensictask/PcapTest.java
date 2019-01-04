package cn.edu.jslab6.autoresponse.forensictask;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

import java.lang.reflect.Array;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.ArrayList;

/**
 * Created by ffzheng on 2017/7/23.
 */
public class PcapTest {
    private static final String dwFilename1 = "D:/1.pcap";
    private static final String dwFilename2 = "D:/2.pcap";
    /*
    pcap文件离线分离后异常问题
     */

    public static void offlineSplit(String filename, ActiveTask task) throws PcapNativeException, NotOpenException{
        PcapHandle handle = Pcaps.openOffline(filename);
        PcapDumper dumper = handle.dumpOpen("D:/111.pcap");
        Packet p ;
        while ((p = handle.getNextPacket()) != null) {
               dumper.dump(p, handle.getTimestamp());
        }

        //
        if(dumper != null) {
            System.out.println(dumper);
            dumper.close();
            System.out.println(dumper);
        }

        if(handle != null)
            handle.close();
    }



    public static void main(String[] args) throws PcapNativeException, NotOpenException,IllegalRawDataException {
        ActiveTask task = new ActiveTask();

       // offlineSplit(dwFilename1, task);
        //offlineSplit(dwFilename2, task);

        long ss = System.currentTimeMillis()/1000;
        System.out.println(ss);
    }
}
