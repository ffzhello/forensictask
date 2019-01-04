package cn.edu.jslab6.autoresponse.forensictask;

/**
 * 采集任务的状态信息
 * Created by ffzheng on 2018/5/30.
 */
public enum TaskStatus {
    WAIT_SENSOR("等待采集",0),
    SENSORING("正在采集",1),
    FORCE("强制结束",2),
    FINISHED("完成采集",3);

    private String status;
    private Integer value;

    private TaskStatus(String status, Integer value) {
        this.status = status;
        this.value = value;
    }

    public String getKey() {
        return status;
    }

    public Integer getValue() {
        return value;
    }

}
