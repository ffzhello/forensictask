package cn.edu.jslab6.autoresponse.forensictask;

/**
 * Created by ffzheng on 2017/7/26.
 */
public class IpMask {
    private Long ip;
    private Integer mask;

    public IpMask(Long ip, Integer mask) {
        this.ip = ip;
        this.mask = mask;
    }

    public Long getIp() {
        return ip;
    }

    public void setIp(Long ip) {
        this.ip = ip;
    }

    public Integer getMask() {
        return mask;
    }

    public void setMask(Integer mask) {
        this.mask = mask;
    }
}
