package cn.edu.jslab6.autoresponse.forensictask;

import org.pcap4j.packet.Packet;

import java.sql.Time;
import java.sql.Timestamp;

/**
 * Created by ffzheng on 2017/7/24.
 */
public class PacketTimestamp {
    private Packet packet = null;
    private Timestamp timestamp = null;

    public PacketTimestamp(Packet p, Timestamp t) {
        this.packet = p;
        this.timestamp = t;
    }

    public Packet getPacket() {
        return packet;
    }

    public void setPacket(Packet packet) {
        this.packet = packet;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Timestamp timestamp) {
        this.timestamp = timestamp;
    }
}
