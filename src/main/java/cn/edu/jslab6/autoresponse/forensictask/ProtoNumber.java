package cn.edu.jslab6.autoresponse.forensictask;

/**
 * Created by ffzheng on 2017/7/25.
 */
public enum ProtoNumber {
    TCP(6),UDP(17),ICMP(1),IGMP(2),EGP(8),IGP(9),IPv6(41),OSPF(89);

    private Integer number;

    private ProtoNumber(int number) {
        this.number = number;
    }
}
