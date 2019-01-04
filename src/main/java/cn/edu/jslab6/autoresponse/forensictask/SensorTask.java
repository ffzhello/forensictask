package cn.edu.jslab6.autoresponse.forensictask;

/**
 * Created by zrwang on 2016/12/13.
 */
public class SensorTask {
    private int id; // 数据库表中的id.
    private int taskid; // 与响应任务编号responsetask.id一致
    private int siteid = 22; // 采集任务点(数据库表siteconfig.id），由配置文件读入
    private long starttime = 0; // 采集任务开始时间戳
    private long endtime = 0; //采集任务结束时间戳
    private short flag = 0x00; //0x00: FLAG_INIT, 0x01: FLAG_READY, 0x02: FLAG_SENSOR, 0x04: FLAG_FORCE_SENSOR,
    // 0x08: FLAG_FORCE_END, 0x09: FLAG_PKT_FORCE_END, 0x10: FLAG_END'
    private long sensorpkts = 0;
    private long sensorbytes = 0;
    private long firstPktTime = 0;
    private long lastPktTime = 0;

    private String filepath; //报文保存路径

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getTaskid() {
        return taskid;
    }

    public void setTaskid(int taskid) {
        this.taskid = taskid;
    }

    public int getSiteid() {
        return siteid;
    }

    public void setSiteid(int siteid) {
        this.siteid = siteid;
    }

    public long getStarttime() {
        return starttime;
    }

    public void setStarttime(long starttime) {
        this.starttime = starttime;
    }

    public long getEndtime() {
        return endtime;
    }

    public void setEndtime(long endtime) {
        this.endtime = endtime;
    }

    public short getFlag() {
        return flag;
    }

    public void setFlag(short flag) {
        this.flag = flag;
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

    public long getFirstPktTime() {
        return firstPktTime;
    }

    public void setFirstPktTime(long firstPktTime) {
        this.firstPktTime = firstPktTime;
    }

    public long getLastPktTime() {
        return lastPktTime;
    }

    public void setLastPktTime(long lastPktTime) {
        this.lastPktTime = lastPktTime;
    }

    public String getFilepath() {
        return filepath;
    }

    public void setFilepath(String filepath) {
        this.filepath = filepath;
    }
}
