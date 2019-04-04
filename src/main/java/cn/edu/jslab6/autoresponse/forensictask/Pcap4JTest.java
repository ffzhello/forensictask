package cn.edu.jslab6.autoresponse.forensictask;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import java.io.File;
import java.sql.Timestamp;

/**
 * Created by ffzheng on 2018/6/6.
 */
public class Pcap4JTest {

    public static void main(String[] args) throws PcapNativeException, NotOpenException {

            int len = 0;
            int size = 0;
            PcapHandle handle = Pcaps.openOffline("E://1.pcap");
            //PcapDumper dumper = handle.dumpOpen("E://123.pcap");
            Packet p ;
            while ((p = handle.getNextPacket()) != null) {
                len += p.length();
                size += p.getRawData().length;
                //dumper.dump(p, handle.getTimestamp());
                Timestamp timestamp = handle.getTimestamp();
                System.out.println(timestamp);
            }

            /**
            if(dumper != null) {
                System.out.println(dumper);
                dumper.close();
                System.out.println(dumper);
            }
             **/

            if(handle != null)
                handle.close();

        System.out.println("len: " + len);
        System.out.println("size: " + size);
    }
}
